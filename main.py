"""Local HTTPS proxy that forwards every request to api.anthropic.com.

Two subcommands:

  uv run main.py gen-certs   Generate a CA + server cert in ./certs
  uv run main.py serve       Run the proxy
"""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import AsyncIterator, Iterable

import click
import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route

HERE = Path(__file__).parent.resolve()
CERTS_DIR = HERE / "certs"
DEFAULT_UPSTREAM = "https://api.anthropic.com"

# Headers we must not forward. RFC 7230 hop-by-hop, plus Host (set per-upstream)
# and Content-Length (httpx recomputes it).
HOP_BY_HOP = frozenset(
    h.lower()
    for h in (
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    )
)

# Headers uvicorn always injects on responses; if we forward upstream's copies we
# end up with duplicates (e.g. `server: cloudflare` next to `server: uvicorn`).
RESP_DROP = HOP_BY_HOP | frozenset({"date", "server"})

log = logging.getLogger("anthropic-proxy")


# --- cert generation ---------------------------------------------------------


def _serial() -> int:
    return int.from_bytes(os.urandom(16), "big") >> 1


def _build_san(names: Iterable[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def generate_certs(out_dir: Path, sans: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Anthropic Proxy Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, sans[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365 * 2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(_build_san(sans), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    pem = serialization.Encoding.PEM
    pkcs8 = serialization.PrivateFormat.PKCS8
    no_enc = serialization.NoEncryption()

    (out_dir / "ca.pem").write_bytes(ca_cert.public_bytes(pem))
    (out_dir / "ca.key").write_bytes(
        ca_key.private_bytes(pem, pkcs8, no_enc)
    )
    (out_dir / "server.crt").write_bytes(server_cert.public_bytes(pem))
    (out_dir / "server.key").write_bytes(
        server_key.private_bytes(pem, pkcs8, no_enc)
    )
    # Convenience bundle: server cert + CA, in case anything wants the chain.
    (out_dir / "server-fullchain.pem").write_bytes(
        server_cert.public_bytes(pem) + ca_cert.public_bytes(pem)
    )

    for name in ("ca.key", "server.key"):
        os.chmod(out_dir / name, 0o600)


# --- proxy app ---------------------------------------------------------------


def build_app(upstream: str) -> Starlette:
    upstream_url = httpx.URL(upstream)
    client_holder: dict[str, httpx.AsyncClient] = {}

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        client_holder["client"] = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15.0, read=600.0, write=60.0, pool=15.0),
            follow_redirects=False,
            http2=False,
        )
        try:
            yield
        finally:
            await client_holder["client"].aclose()

    async def handler(request: Request) -> StreamingResponse:
        client = client_holder["client"]
        target = upstream_url.copy_with(
            path=request.url.path,
            query=request.url.query.encode() if request.url.query else None,
        )

        fwd_headers = [
            (k, v) for k, v in request.headers.raw if k.decode("latin-1").lower() not in HOP_BY_HOP
        ]
        fwd_headers.append((b"host", upstream_url.host.encode("ascii")))

        log.info("-> %s %s", request.method, target)

        upstream_req = client.build_request(
            method=request.method,
            url=target,
            headers=fwd_headers,
            content=request.stream(),
        )
        upstream_resp = await client.send(upstream_req, stream=True)

        log.info(
            "<- %s %s %s",
            upstream_resp.status_code,
            request.method,
            target,
        )

        resp_headers = [
            (k, v)
            for k, v in upstream_resp.headers.raw
            if k.decode("latin-1").lower() not in RESP_DROP
        ]

        async def body_iter():
            try:
                async for chunk in upstream_resp.aiter_raw():
                    yield chunk
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            body_iter(),
            status_code=upstream_resp.status_code,
            headers=dict((k.decode("latin-1"), v.decode("latin-1")) for k, v in resp_headers),
        )

    return Starlette(
        debug=False,
        routes=[
            Route(
                "/{path:path}",
                handler,
                methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
            )
        ],
        lifespan=lifespan,
    )


# --- CLI ---------------------------------------------------------------------


@click.group()
def cli() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@cli.command("gen-certs")
@click.option(
    "--san",
    "sans",
    multiple=True,
    default=(
        "localhost",
        "127.0.0.1",
        "::1",
        "host.docker.internal",
        "anthropic-proxy.local",
    ),
    show_default=True,
    help="Subject Alternative Names for the server certificate. Pass multiple times.",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=CERTS_DIR,
    show_default=True,
)
@click.option("--force/--no-force", default=False, help="Overwrite existing certs.")
def gen_certs_cmd(sans: tuple[str, ...], out_dir: Path, force: bool) -> None:
    """Generate a CA + server cert in OUT_DIR."""
    out_dir = Path(out_dir).resolve()
    ca_pem = out_dir / "ca.pem"
    if ca_pem.exists() and not force:
        click.echo(f"{ca_pem} already exists. Pass --force to overwrite.", err=True)
        sys.exit(1)

    if not sans:
        click.echo("At least one --san is required.", err=True)
        sys.exit(1)

    generate_certs(out_dir, list(sans))
    click.echo(f"Wrote certs to {out_dir}")
    click.echo("  ca.pem")
    click.echo("  ca.key (keep secret)")
    click.echo("  server.crt / server.key")
    click.echo("  server-fullchain.pem")
    click.echo()
    click.echo(f"Server cert SANs: {', '.join(sans)}")


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8443, show_default=True, type=int)
@click.option(
    "--upstream",
    default=DEFAULT_UPSTREAM,
    show_default=True,
    help="Upstream base URL to forward to.",
)
@click.option(
    "--certs-dir",
    type=click.Path(file_okay=False, exists=True, path_type=Path),
    default=CERTS_DIR,
    show_default=True,
)
def serve_cmd(host: str, port: int, upstream: str, certs_dir: Path) -> None:
    """Run the HTTPS proxy."""
    certs_dir = Path(certs_dir).resolve()
    cert_file = certs_dir / "server.crt"
    key_file = certs_dir / "server.key"
    if not cert_file.exists() or not key_file.exists():
        click.echo(
            f"Missing {cert_file} or {key_file}. Run `uv run main.py gen-certs` first.",
            err=True,
        )
        sys.exit(1)

    app = build_app(upstream)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        ssl_certfile=str(cert_file),
        ssl_keyfile=str(key_file),
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        log_level="info",
        access_log=True,
        h11_max_incomplete_event_size=16 * 1024 * 1024,
    )
    server = uvicorn.Server(config)
    click.echo(f"Proxy listening on https://{host}:{port}  ->  {upstream}")
    click.echo(f"Use {certs_dir / 'ca.pem'} as a custom CA.")
    server.run()


if __name__ == "__main__":
    cli()
