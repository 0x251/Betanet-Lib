### Betanet Python Library


### structure

- `betanet/core`: frame codec, varint, crypto, session
- `betanet/transport`: TCP client/server, async client/server, fallback, static/ASGI upstream
- `betanet/noise`: Noise XK (sync+async)
- `betanet/bitswap`: demo TCP bitswap
- `betanet/gateway`: HTTP→HTX dev gateway
- `apps`: runnable scripts and templates

### demos

- Echo over HTX (no args):
  - Starts upstream echo and gateway, prints gateway URL
  ```bash
  python apps/run.py
  curl -X POST -d "hello" http://127.0.0.1:8080/echo
  ```

- ASGI over HTX:
  - Runs the ASGI template behind the HTX gateway
  ```bash
  python apps/run_asgi.py
  curl http://127.0.0.1:8081/
  curl http://127.0.0.1:8081/json
  ```

- From config (TOML):
  ```bash
  python apps/start_from_config.py gateway apps/templates/config/gateway.toml
  curl -X POST -d "hi" http://127.0.0.1:8080/echo
  ```

- Static (plain HTTP):
  ```bash
  python apps/dev_server.py --mode static --root apps/templates/static_site --port 9000
  # Visit http://127.0.0.1:9000/
  ```

### Templates

- `apps/templates/static_site`: single-file static page for the dev server
- `apps/templates/asgi_app/app.py`: minimal ASGI entrypoint (no deps)
- `apps/templates/asgi_app_advanced/app.py`: routing and JSON example
- `apps/templates/config/gateway.toml`: sample gateway config for `start_from_config.py`
- `apps/templates/gateway_ticket_policy.md`: example BN-Ticket policy header

### HTX runner details

- Gateway: `betanet.gateway.dev.ProxyServer`
- Upstream echo: `betanet.transport.tcp.HtxTcpServer`
- Upstream static files: `betanet.transport.upstream_static.HtxStaticServer`
- Upstream ASGI: `betanet.transport.upstream_asgi.HtxAsgiServer`





### cryptography and keys

- Key pairs
  - upstream server key: X25519 static keypair generated at startup in demos. Private key stays on the upstream; public key is given to the gateway so it can perform the inner handshake.
  - gateway client key: X25519 key generated at gateway startup. Used as the initiator key for inner handshakes to the upstream.
- Inner handshake (Noise XK)
  - Runs between gateway (initiator) and upstream (responder) using X25519; derives a shared secret K0 via HKDF and splits into per-direction keys. Nonces are derived with per-direction salts and a monotonically increasing counter.
  - Rekeying occurs based on limits (bytes, frames, time).
- Outer tunnel
  - inner handshake and frames inside an origin-mirrored TLS/QUIC tunnel. The demos run the inner handshake directly over TCP for simplicity. Production deployments should embed HTX in the mirrored outer tunnel.

### Demos

- `apps/run.py`
  - upstream: `HtxTcpServer(host, port, server_priv_raw, server_pub)`
  - gateway: `ProxyServer(listen_host, listen_port, upstream_host, upstream_port, client_priv, server_pub, forward_path=...)`
  - `server_priv_raw`: upstream's static private key (bytes)
  - `server_pub`: upstream's static public key (bytes) shared with the gateway
  - `client_priv`: gateway's initiator private key for the inner handshake
  - In the demo, keys are generated in-process for convenience. Do not print or log private keys in production.

### Tickets (BN‑Ticket)

- Client computes an access ticket from an X25519 ECDH with the site’s published `ticketPub`, plus time-bounded salts. The gateway verifies the ticket, enforces duplicate protection and rate-limits, and only then opens HTX streams upstream.

### Frames, streams

- The gateway/gateway-uplink exchange encrypted frames (`STREAM`, `WINDOW_UPDATE`, `KEY_UPDATE`). Payloads for application streams are opaque to the transport.
- In `betanet.transport.upstream_asgi.HtxAsgiServer`, the upstream decodes the payload into a minimal method+path+body tuple for the ASGI app and returns only the body; the gateway wraps it into an HTTP/1.1 response to the client.

### Logging

  - `echo time_ms`, `gateway time_ms`, `upstream time_ms` for server/gateway loops.
  - ASGI handlers log: `method, path, status, bytes, time_ms`.




### Apps (tools & scripts)

- start_server.py
  - Start an HTX echo server or an HTTP→HTX gateway with ticket enforcement.
  - Echo:
    ```bash
    python apps/start_server.py echo 127.0.0.1 35000
    ```
  - Gateway (starts an echo upstream in a thread, then the gateway):
    ```bash
    python apps/start_server.py gateway 127.0.0.1 8080 127.0.0.1 35000 __Host-bn1 4142434445464748
    ```

- start_from_config.py
  - Start echo or gateway from TOML.
  - Echo:
    ```bash
    python apps/start_from_config.py echo apps/templates/config/gateway.toml
    ```
  - Gateway:
    ```bash
    python apps/start_from_config.py gateway apps/templates/config/gateway.toml
    ```

- dev_server.py
  - Local helper server for static HTTP files or simple POST echo.
  - Static site:
    ```bash
    python apps/dev_server.py --mode static --root apps/templates/static_site --port 9000
    ```

- gateway_server.py
  - Standalone HTTP→HTX gateway runner.
  ```bash
  python apps/gateway_server.py 127.0.0.1 8080 
  ```

- dev_gateway_preview.py
  - Minimal preview for the gateway object; useful for tinkering with code paths.
  ```bash
  python apps/dev_gateway_preview.py
  ```

- static_upstream.py
  - HTX upstream server that serves files from a directory.
  ```bash
  python apps/static_upstream.py 127.0.0.1 35000 apps/templates/static_site
  ```

- client_cli.py
  - CLI client to send a single HTX request to a server and print the response.
  ```bash
  python apps/client_cli.py 127.0.0.1 35000 <server_pub_hex> "hello"
  ```

- gateway_client.py
  - Example client for talking to the gateway (ticket paths).

- cas_http.py
  - Minimal HTTP wrapper around the content store to PUT/GET blocks.

- run.py
  - No-args demo: upstream echo + gateway.

- run_asgi.py
  - No-args demo: ASGI behind HTX gateway.

### Core APIs 

- Frames: `betanet.core.frames` (`Frame`, `encode_frame`, `decode_frame`, `STREAM`, `KEY_UPDATE`, `WINDOW_UPDATE`)
- Enums: `betanet.core.enums.FrameType`, `betanet.gateway.enums.TicketCarrier`
- Session: `betanet.core.session.HtxSession` (encrypt/decrypt frames, flow control, rekey)
- Transport (TCP): `betanet.transport.tcp.HtxTcpClient`, `HtxTcpServer`
- Transport base: `betanet.transport.base.TransportClient`, `TransportServer`
- Transport (async): `betanet.transport.asyncio.AsyncClient`, `AsyncServer`
- Noise: `betanet.noise.xk` (sync), `betanet.noise.xk_async` (async)
- Tickets SDK: `betanet.sdk` (helpers), `betanet.tickets` (policy, verifier)
- Misc: `betanet.transition` (control stream CBOR), `betanet.privacy`, `betanet.governance`, `betanet.naming`, `betanet.payments`

### Examples

- End-to-end echo (TCP):
  ```python
  from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
  from betanet.transport.tcp import HtxTcpServer, HtxTcpClient

  host, port = "127.0.0.1", 34567
  srv_priv = X25519PrivateKey.generate()
  srv_pub = srv_priv.public_key().public_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)
  srv_priv_raw = srv_priv.private_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PrivateFormat.Raw, encryption_algorithm=__import__('cryptography').hazmat.primitives.serialization.NoEncryption())
  server = HtxTcpServer(host, port, srv_priv_raw, srv_pub)

  cli_priv = X25519PrivateKey.generate().private_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PrivateFormat.Raw, encryption_algorithm=__import__('cryptography').hazmat.primitives.serialization.NoEncryption())
  client = HtxTcpClient(host, port, cli_priv, srv_pub)
  assert client.roundtrip(1, b"hello") == b"hello"
  ```

- ASGI behind HTX gateway:
  ```bash
  python apps/run_asgi.py
  curl http://127.0.0.1:8081/json
  ```

### Build your own app (no tickets)

```python
import threading, os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from betanet.transport.upstream_asgi import HtxAsgiServer
from betanet.gateway.dev import ProxyServer

async def app(scope, receive, send):
    assert scope["type"] == "http"
    body = b"hello from asgi"
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})

def main():
    up_host, up_port = "127.0.0.1", 35100
    gw_host, gw_port = "127.0.0.1", 8082

    srv_priv = X25519PrivateKey.generate()
    srv_pub = srv_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    srv_priv_raw = srv_priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    cli_priv = X25519PrivateKey.generate().private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

    upstream = HtxAsgiServer(up_host, up_port, srv_priv_raw, app)
    threading.Thread(target=upstreamServe, args=(upstream,), daemon=True).start()

    gw = ProxyServer(gw_host, gw_port, up_host, up_port, cli_priv, srv_pub, forward_path=True)
    threading.Thread(target=gw.serve_forever, daemon=True).start()

    print(f"gateway http://{gw_host}:{gw_port}")

def upstreamServe(s):
    s.serve_forever()

if __name__ == "__main__":
    main()
```

```bash
python your_app.py
curl http://127.0.0.1:8082/
```

### Build your own app (with tickets)

```python
import threading, os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from betanet.transport.upstream_asgi import HtxAsgiServer
from betanet.gateway.dev import ProxyServer
from betanet.tickets import TicketVerifier
from betanet.sdk import make_ticket_params, make_ticket_cookie

COOKIE_NAME = "__Host-bn1"

async def app(scope, receive, send):
    assert scope["type"] == "http"
    body = b"ok"
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})

def main():
    up_host, up_port = "127.0.0.1", 35200
    gw_host, gw_port = "127.0.0.1", 8083

    srv_priv = X25519PrivateKey.generate()
    srv_pub = srv_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    srv_priv_raw = srv_priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    cli_priv = X25519PrivateKey.generate().private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

    ticket_priv = X25519PrivateKey.generate()
    ticket_pub = ticket_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    ticket_key_id8 = os.urandom(8)

    upstream = HtxAsgiServer(up_host, up_port, srv_priv_raw, app)
    threading.Thread(target=upstreamServe, args=(upstream,), daemon=True).start()

    verifier = TicketVerifier(ticket_priv, ticket_key_id8)
    gw = ProxyServer(gw_host, gw_port, up_host, up_port, cli_priv, srv_pub, ticket_verifier=verifier, ticket_cookie_name=COOKIE_NAME, forward_path=True)
    threading.Thread(target=gw.serve_forever, daemon=True).start()

    print("server_pub=", srv_pub.hex())
    print("ticket_pub=", ticket_pub.hex())
    print("ticket_key_id=", ticket_key_id8.hex())
    print(f"gateway http://{gw_host}:{gw_port}")

def upstreamServe(s):
    s.serve_forever()

if __name__ == "__main__":
    main()
```

Client with cookie ticket:

```python
from betanet.sdk import make_ticket_params, make_ticket_cookie


ticket_pub_hex = "..."
ticket_key_id_hex = "..."

params = make_ticket_params(ticket_pub_hex, ticket_key_id_hex)
cookie, cli_pub, nonce = make_ticket_cookie("__Host-bn1", params)
print("Cookie:", cookie)
```

```bash
curl -H "Cookie: $(python make_cookie.py | sed -n 's/^Cookie: //p')" http://127.0.0.1:8083/
```

