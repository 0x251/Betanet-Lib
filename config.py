import tomllib

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    host: str
    port: int


@dataclass
class GatewayConfig:
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    cookie_name: str
    ticket_key_id_hex: str
    ticket_priv_hex: Optional[str] = None


def parse_server_config(data: bytes) -> ServerConfig:
    cfg = tomllib.loads(data.decode("utf-8"))
    s = cfg.get("server", {})
    return ServerConfig(host=s["host"], port=int(s["port"]))


def parse_gateway_config(data: bytes) -> GatewayConfig:
    cfg = tomllib.loads(data.decode("utf-8"))
    g = cfg.get("gateway", {})
    return GatewayConfig(
        listen_host=g["listen_host"],
        listen_port=int(g["listen_port"]),
        upstream_host=g["upstream_host"],
        upstream_port=int(g["upstream_port"]),
        cookie_name=g["cookie_name"],
        ticket_key_id_hex=g["ticket_key_id_hex"],
        ticket_priv_hex=g.get("ticket_priv_hex"),
    )
