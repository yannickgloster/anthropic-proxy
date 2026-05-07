# Anthropic test proxy

Tiny HTTPS proxy that forwards every request to `api.anthropic.com`. Useful for
end-to-end testing the custom certificate authority + custom endpoint flow.

The proxy:

- Generates its own root CA and a server cert signed by that CA.
- Listens on HTTPS using the server cert.
- Streams every request through to `https://api.anthropic.com` (path, query,
  headers, body), and streams the response back, so SSE / streaming completions
  work transparently.

## Quick start

```bash
uv sync
uv run main.py gen-certs
uv run main.py serve
```

## Useful flags

```bash
# add extra hostnames/IPs to the server cert SAN list
uv run main.py gen-certs --san localhost --san 127.0.0.1 --san my-host.local --force

# different port / bind address / upstream
uv run main.py serve --host 0.0.0.0 --port 9443 --upstream https://api.anthropic.com
```


## Files

- `certs/ca.pem` - upload to Tines.
- `certs/ca.key` - CA private key. Keep it secret. Used only to sign the server
  cert; the proxy itself does not need it at runtime.
- `certs/server.crt` / `certs/server.key` - what the proxy serves.
- `certs/server-fullchain.pem` - server cert + CA, in case something wants the
  full chain.
