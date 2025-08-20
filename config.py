import os
import json
import tomllib

from dataclasses import dataclass, field
from typing import Optional, List, Dict

from betanet.calibration import CalibrationPolicy


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


def get_calibration_policy_from_env() -> CalibrationPolicy:
    val = os.environ.get("BETANET_CALIBRATION", "dev").lower().strip()
    return CalibrationPolicy.REQUIRED if val == "required" else CalibrationPolicy.DEV


def get_fp_dir_from_env() -> Optional[str]:
    v = os.environ.get("BETANET_FP_DIR")
    return v if v else None


@dataclass
class TicketsConfig:
    enabled: bool = False
    cookie_name: str = ""
    ticket_key_id_hex: str = ""
    ticket_priv_hex: Optional[str] = None


@dataclass
class AppConfig:
    mode: str = "dashboard"
    transport: str = "tcp"
    dev_fast: bool = False
    calibration_policy: str = "dev"
    cover_decoys: List[str] = field(default_factory=list)
    pq_enabled: bool = False
    gateway: Optional[ServerConfig] = None
    upstream: Optional[ServerConfig] = None
    upstream_alt_enabled: bool = False
    upstream_alt_port_offset: int = 1
    tickets: TicketsConfig = field(default_factory=TicketsConfig)
    routes: Dict[str, str] = field(default_factory=dict)
    static_root: Optional[str] = None
    asgi_app: Optional[str] = None


def load_app_config(path: str) -> AppConfig:
    data = json.loads(open(path, "r", encoding="utf-8").read())
    mode = str(data.get("mode", "dashboard"))
    transport = str(data.get("transport", "tcp")).lower().strip()
    dev_fast = bool(data.get("dev_fast", False))
    calibration_policy = str(data.get("calibration_policy", "dev")).lower().strip()
    cover_decoys = list(data.get("cover_decoys", []))
    pq_enabled = bool(data.get("pq_enabled", False))
    gw = data.get("gateway", {"host": "127.0.0.1", "port": 8082})
    up = data.get("upstream", {"host": "127.0.0.1", "port": 35100})
    gateway = ServerConfig(host=gw.get("host", "127.0.0.1"), port=int(gw.get("port", 8082)))
    upstream = ServerConfig(host=up.get("host", "127.0.0.1"), port=int(up.get("port", 35100)))
    upstream_alt_enabled = bool(data.get("upstream_alt_enabled", False))
    upstream_alt_port_offset = int(data.get("upstream_alt_port_offset", 1))
    t = data.get("tickets", {})
    tickets = TicketsConfig(
        enabled=bool(t.get("enabled", False)),
        cookie_name=str(t.get("cookie_name", "")),
        ticket_key_id_hex=str(t.get("ticket_key_id_hex", "")),
        ticket_priv_hex=t.get("ticket_priv_hex"),
    )
    routes = data.get("routes", None)
    static_root = data.get("static_root")
    asgi_app = data.get("asgi_app")
    return AppConfig(
        mode=mode,
        transport=transport,
        dev_fast=dev_fast,
        calibration_policy=calibration_policy,
        cover_decoys=cover_decoys,
        pq_enabled=pq_enabled,
        gateway=gateway,
        upstream=upstream,
        upstream_alt_enabled=upstream_alt_enabled,
        upstream_alt_port_offset=upstream_alt_port_offset,
        tickets=tickets,
        routes=routes,
        static_root=static_root,
        asgi_app=asgi_app,
    )
