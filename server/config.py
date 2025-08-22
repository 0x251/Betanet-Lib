import tomllib
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 35100
    transport: str = "tcp12"
    profile: str = "STANDARD"
    caps: Dict[str, List[str]] | None = None
    pq_enabled: bool = False


@dataclass
class GatewayConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8082
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 35100
    transport: str = "tcp12"
    ticket_cookie_name: Optional[str] = None
    ticket_key_id_hex: Optional[str] = None
    ticket_priv_hex: Optional[str] = None
    require_voucher: bool = False
    voucher_header: str = "BN-Voucher"


def load_config(path: str) -> tuple[ServerConfig, Optional[GatewayConfig]]:
    data = tomllib.loads(open(path, "rb").read().decode("utf-8"))
    s = data.get("server", {})
    sc = ServerConfig(
        host=str(s.get("host", "127.0.0.1")),
        port=int(s.get("port", 35100)),
        transport=str(s.get("transport", "tcp12")).lower().strip(),
        profile=str(s.get("profile", "STANDARD")).upper().strip(),
        caps=s.get("caps"),
        pq_enabled=bool(s.get("pq_enabled", False)),
    )
    g = data.get("gateway", None)
    gc: Optional[GatewayConfig] = None
    if isinstance(g, dict):
        gc = GatewayConfig(
            listen_host=str(g.get("listen_host", "127.0.0.1")),
            listen_port=int(g.get("listen_port", 8082)),
            upstream_host=str(g.get("upstream_host", sc.host)),
            upstream_port=int(g.get("upstream_port", sc.port)),
            transport=str(g.get("transport", sc.transport)).lower().strip(),
            ticket_cookie_name=g.get("ticket_cookie_name"),
            ticket_key_id_hex=g.get("ticket_key_id_hex"),
            ticket_priv_hex=g.get("ticket_priv_hex"),
            require_voucher=bool(g.get("require_voucher", False)),
            voucher_header=str(g.get("voucher_header", "BN-Voucher")),
        )
    return sc, gc


