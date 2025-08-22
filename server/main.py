import os
import logging as log
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from server.config import load_config
from betanet.transport.tcp12 import Tcp12Server
from betanet.gateway.dev import ProxyServer
from betanet.tickets import TicketVerifier
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from server.app import BetanetApp
from server.core import Request, Response
from server.bar import decode_bar_request
from server.metrics import get_global_metrics


def _ensure_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_raw = X25519PrivateKey.from_private_bytes(priv_raw).public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv_raw, pub_raw


@dataclass
class RunnerOptions:
    plugin_modules: List[str]
    plugin_dirs: List[str]
    template_roots: List[str]
    pool_size: int
    verbose: bool


class ServerRunner:
    def __init__(self, config_path: str, opts: RunnerOptions):
        self.config_path = config_path
        self.opts = opts
        self.app = BetanetApp()

    def _load_plugins(self) -> int:
        count = 0
        for m in self.opts.plugin_modules:
            try:
                self.app.load_plugin(m)
                count += 1
            except Exception as e:
                log.getLogger("server").warning("plugin_load_failed module=%s err=%r", m, e)
        for d in self.opts.plugin_dirs:
            count += self.app.load_plugins_from(d)
        return count

    def _bridge(self, payload: bytes) -> bytes:
        logger = log.getLogger("server")
        met = get_global_metrics()
        import time as _t
        t0 = _t.perf_counter()
        try:
            req = decode_bar_request(payload)
            m = req.method.decode(errors="ignore").upper()
            p = req.path.decode(errors="ignore")
            logger.info("bar req method=%s path=%s", m, p)
        except Exception:
            try:
                if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                    parts = payload.split(b" ", 1)
                    method = parts[0]
                    rest = parts[1] if len(parts) > 1 else b"/"
                    path = rest
                    body = b""
                    if method == b"POST":
                        sep = rest.find(b"\n\n")
                        if sep != -1:
                            path = rest[:sep]
                            body = rest[sep+2:]
                    req = Request(method=method, path=path, headers={}, body=body)
                    logger.info("fw req method=%s path=%s", method.decode(), path.decode(errors="ignore"))
                else:
                    return b""
            except Exception:
                return b""
        resp = self.app.handle(req)
        if resp is None:
            met.record_latency((_t.perf_counter() - t0) * 1000)
            return b""
        body = resp.body
        met.record_latency((_t.perf_counter() - t0) * 1000)
        return body

    def start(self) -> None:
        srv_cfg, gw_cfg = load_config(self.config_path)
        os.environ["BETANET_PROFILE"] = srv_cfg.profile
        if srv_cfg.pq_enabled:
            os.environ["BETANET_PQ"] = "1"
        log.getLogger("server").info("starting profile=%s transport=%s", srv_cfg.profile, srv_cfg.transport)
        if srv_cfg.transport != "tcp12":
            raise SystemExit("only tcp12 transport is supported in this example")
        priv, pub = _ensure_keypair()
        srv_caps = srv_cfg.caps or {"l2": ["betanet/htx/1.2.0"], "l3": ["betanet/mesh/1.2.0"], "l4": [], "l5": []}
        loaded = self._load_plugins()
        for tdir in self.opts.template_roots:
            self.app.add_template_root(tdir)
        if loaded == 0:
            @self.app.route(b"GET", b"/hello/{name}")
            def _hello(req: Request) -> Response:
                name = (req.params or {}).get("name", "world")
                return Response(200, ((b"content-type", b"text/plain"),), f"hello {name}".encode())
            log.getLogger("server").info("no plugins specified; installed example route /hello/{name}")
        srv = Tcp12Server(srv_cfg.host, srv_cfg.port, priv, server_caps=srv_caps, handler=self._bridge)
        log.getLogger("server").info("listening on %s:%d", srv_cfg.host, srv_cfg.port)
        if gw_cfg:
            log.getLogger("server").info("starting http gateway on %s:%d -> %s:%d transport=%s", gw_cfg.listen_host, gw_cfg.listen_port, gw_cfg.upstream_host, gw_cfg.upstream_port, gw_cfg.transport)
            tv = None
            cookie_name = None
            if gw_cfg.ticket_cookie_name and gw_cfg.ticket_key_id_hex and gw_cfg.ticket_priv_hex:
                try:
                    tv_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(gw_cfg.ticket_priv_hex))
                    tv = TicketVerifier(tv_priv, bytes.fromhex(gw_cfg.ticket_key_id_hex))
                    cookie_name = gw_cfg.ticket_cookie_name
                except Exception:
                    tv = None
                    cookie_name = None
            require_voucher = bool(gw_cfg.require_voucher)
            voucher_header = (gw_cfg.voucher_header or "BN-Voucher").encode()
            gw = ProxyServer(gw_cfg.listen_host, gw_cfg.listen_port, gw_cfg.upstream_host, gw_cfg.upstream_port, priv, pub, ticket_verifier=tv, ticket_cookie_name=cookie_name, require_voucher=require_voucher, voucher_header=voucher_header, forward_path=True, transport=gw_cfg.transport)
            try:
                gw._pool_size = max(1, int(self.opts.pool_size))
                gw.verbose = bool(self.opts.verbose)
            except Exception:
                pass
            import threading
            threading.Thread(target=gw.serve_forever, daemon=True).start()
        srv.serve_forever()


