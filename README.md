# Betanet Python Library

Updated to 1.2v PR requirement's (:

### structure

- `betanet/core`: frame codec, varint, crypto, session
- `betanet/transport`: TCP client/server, async client/server, fallback, static/ASGI upstream
- `betanet/noise`: Noise XK (sync+async)
- `betanet/bitswap`: demo TCP bitswap
- `betanet/gateway`: HTTP→HTX dev gateway
- `server`: website templates


### HTX runner details 

- Gateway: `betanet.gateway.dev.ProxyServer`
- Upstream (tcp12): `betanet.transport.tcp12.Tcp12Server`
- Legacy upstreams (1.1 demos): `betanet.transport.tcp.HtxTcpServer`,
  `betanet.transport.upstream_static.HtxStaticServer`, `betanet.transport.upstream_asgi.HtxAsgiServer`

For the recommended path, use the ServerRunner/CLI:

```bash
python -m server.run serve --config server/example.toml --plugin server.plugins.dashboard --plugin server.plugins.metrics --templates server/templates
```
=





### Additional features (1.2)

- Transports
  - tcp: legacy 1.1 framing over TCP (`betanet.transport.tcp`)
  - tcp12: 1.2 framing with capability exchange (`betanet.transport.tcp12`)
  - quic: outer/l4 experiments; gateway can try QUIC then fall back to TCP
- PQ toggle
  - Set `BETANET_PQ=1` to enable hybrid Noise name if available; otherwise it falls back automatically
- Capability exchange (tcp12)
  - Server advertises caps on StreamID=1; client sends its caps then selection
  - APIs: `encode_cap_msg`, `decode_cap_msg`, `decide_selection`, `encode_sel_msg`, `decode_sel_msg`
- BN‑Ticket header helper
  - `betanet.core.bn_ticket.validate_header(name, value)` verifies `BN-Ticket` format (`v=v1; tok=<base64url 120 bytes>[; ctx=token]`)
- Vouchers (L6)
  - `betanet.payments.parse_voucher` parses 128‑byte vouchers; `PaymentsVerifier` rate‑limits per keyset and peer
  - Gateway: `require_voucher` and `voucher_header` in config enforce vouchers (403 otherwise)
- Cover decoy fallback
  - UDP/QUIC attempt then TCP fallback with optional cover connections
  - Env `BETANET_COVER_DECOYS="host1:443,host2:443"` enables background short‑lived TCP covers during fallback
  - Dev fast path: set `BETANET_DEV_FAST=1` to skip local backoff delays
- Calibration & TemplateID
  - CLI: `python -m server.run calibrate --origin example.com:443 --pop local`
  - Files are stored under `BETANET_FP_DIR` if set, otherwise OS‑appropriate data dir
  - Policy is DEV by default; REQUIRED will fail on mismatch
- HTTP gateway transports
  - Configurable per `server/example.toml` with `[gateway].transport` = `tcp12` | `tcp`
  - Path forwarding: set `forward_path=True` to send `GET /path` or `POST /path` bodies upstream
- Server plugins & BAR bridge
  - Plugins expose `register(app)`; `server.app.BetanetApp` routes map to BAR via `app.handle_bar`
  - Static files via `app.add_static(b"/static", "server/templates")`
- Metrics
  - `/metrics` exposes Prometheus text including request/error counters and response latencies (avg/last)

### CLI tools

- Tickets
  - `python -m betanet.cli ticket <ticket_pub_hex> <ticket_key_id_hex> <site_name>` → prints cookie/query/body examples
- Stream echo
  - `python -m betanet.cli stream <host> <port> <server_pub_hex> <data>` → opens a tcp echo stream via HTX

### Environment variables

- `BETANET_PROFILE` = MINIMAL | STANDARD | EXTENDED (gateway behavior)
- `BETANET_PQ` = 1 to prefer hybrid Noise where supported
- `BETANET_FP_DIR` = directory for calibration fingerprints/templates
- `BETANET_COVER_DECOYS` = comma‑separated `host:port` list for cover fallback
- `BETANET_DEV_FAST` = 1 to skip certain artificial delays in local dev

### cryptography and keys

- Key pairs
  - upstream server key: X25519 static keypair generated at startup in demos. Private key stays on the upstream; public key is given to the gateway so it can perform the inner handshake.
  - gateway client key: X25519 key generated at gateway startup. Used as the initiator key for inner handshakes to the upstream.
- Inner handshake (Noise XK)
  - Runs between gateway (initiator) and upstream (responder) using X25519; derives a shared secret K0 via HKDF and splits into per-direction keys. Nonces are derived with per-direction salts and a monotonically increasing counter.
  - Rekeying occurs based on limits (bytes, frames, time).
- Outer tunnel
  - inner handshake and frames inside an origin-mirrored TLS/QUIC tunnel



### Tickets (BN‑Ticket)

- Client computes an access ticket from an X25519 ECDH with the site’s published `ticketPub`, plus time-bounded salts. The gateway verifies the ticket, enforces duplicate protection and rate-limits, and only then opens HTX streams upstream.

### Frames, streams

- The gateway/gateway-uplink exchange encrypted frames (`STREAM`, `WINDOW_UPDATE`, `KEY_UPDATE`). Payloads for application streams are opaque to the transport.


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


### Build your own app 

bootstraper using ServerRunner:

```python
from server.main import ServerRunner, RunnerOptions

opts = RunnerOptions(
    plugin_modules=["server.plugins.dashboard", "server.plugins.metrics"],
    plugin_dirs=["server/plugins"],
    template_roots=["server/templates"],
    pool_size=4,
    verbose=False,
)
ServerRunner("server/example.toml", opts).start()
```


# Betanet Server Developer Guide 

#### Quick start

Start with dashboard + metrics plugins and extra template root:

```bash
python -m server.run serve \
  --config server/example.toml \
  --plugin server.plugins.dashboard \
  --plugin server.plugins.metrics \
  --plugin-dir server/plugins \
  --templates server/templates \
  --pool-size 4 \
  --log-level INFO
```

Open:
- Dashboard: http://127.0.0.1:8082/dashboard
- Metrics:   http://127.0.0.1:8082/metrics

#### Plugins & routes

Create `test_plugin_1.py`:

```python
from server.app import BetanetApp
from server.core import Request, Response

def register(app: BetanetApp) -> None:
    @app.route(b"GET", b"/hello/{name}")
    def hello(req: Request) -> Response:
        name = (req.params or {}).get("name", "world")
        return app.text(f"hello {name}")
```

Load it:

```bash
python -m server.run serve --config server/example.toml --plugin test_plugin_1
```

Scan a directory/package for plugins:

```bash
python -m server.run serve --config server/example.toml --plugin-dir server/plugins
```

Blueprint-style mounting:

```python
def register(app: BetanetApp):
    def info(req: Request) -> Response: return app.json({"ok": True})
    routes = [(b"GET", b"/info", info)]
    app.blueprint(b"/api", routes)
```

#### Templates

- Add template roots: `--templates server/templates` or `app.add_template_root("server/templates")`.
- Render: `app.render_template("dashboard.html", {"title": "Home"})` → pass to `app.html(...)`.
- Placeholders: `{{ var }}` (escaped), `{{ raw | safe }}` (unescaped).
- Templates are mtime-cached; edits invalidate automatically.

#### Hooks & error handlers

```python
@app.before_request
def log_request(req): ...

@app.after_request
def add_header(req, resp): ...

def not_found(req, err):
    return app.error(404, "missing")
app.error_handler(404, not_found)
```

#### Static files

Serve files from a directory under a URL prefix (with cache headers):

```python
app.add_static(b"/static", "server/templates")
```

#### Response helpers

- `app.json(obj, status=200)`
- `app.text(str, status=200)`
- `app.html(bytes_or_str, status=200)`
- `app.redirect(url, status=302)`
- `app.error(status, msg="")`

#### Metrics

- `server.plugins.metrics` exposes `/metrics` (Prometheus text) with counters and latencies.

#### CLI flags

- `--plugin MODULE` (repeatable)
- `--plugin-dir PATH` (repeatable)
- `--templates DIR` (repeatable)
- `--pool-size N`
- `--verbose` / `--quiet`
- `--log-level LEVEL`

#### Production notes

- Use BAR native clients
- Enable STANDARD profile (`BETANET_PROFILE=STANDARD`) and disable dev shortcuts.
- Add process supervision, health checks, metrics scraping, and persistent node keys.

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

# values printed by the server
ticket_pub_hex = "..."
ticket_key_id_hex = "..."

params = make_ticket_params(ticket_pub_hex, ticket_key_id_hex)
cookie, cli_pub, nonce = make_ticket_cookie("__Host-bn1", params)
print("Cookie:", cookie)
```

```bash
curl -H "Cookie: $(python make_cookie.py | sed -n 's/^Cookie: //p')" http://127.0.0.1:8083/
```

