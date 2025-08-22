import argparse
import sys
import pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import logging as log
from server.logutil import setup as setup_logging
import os
import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from server.config import load_config
from server.main import ServerRunner, RunnerOptions


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="betanet-server", description="Betanet 1.2 example server")
    sub = p.add_subparsers(dest="cmd")
    serve = sub.add_parser("serve", help="Start the server and optional gateway")
    serve.add_argument("--config", required=True, help="Path to TOML config file")
    serve.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING)")
    serve.add_argument("--plugin", action="append", default=[], help="Python module path to a BAR plugin with register(app)")
    serve.add_argument("--plugin-dir", action="append", default=[], help="Directory or package to scan for plugins")
    serve.add_argument("--templates", action="append", default=[], help="Additional template roots")
    serve.add_argument("--pool-size", type=int, default=4, help="Gateway upstream tcp12 client pool size")
    serve.add_argument("--verbose", action="store_true", help="Verbose gateway logs")
    serve.add_argument("--quiet", action="store_true", help="Reduce logging output")
    calib = sub.add_parser("calibrate", help="Calibrate TemplateID for an origin:port")
    calib.add_argument("--origin", required=True, help="host:port of origin to calibrate")
    calib.add_argument("--pop", default="local", help="POP label (default: local)")
    calib.add_argument("--log-level", default="INFO", help="Logging level")
    return p.parse_args()


def ensure_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_raw = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv_raw, pub_raw


def _normalize_origin(o: str) -> tuple[str, int]:
    s = o.strip()
    if s.startswith("http://") or s.startswith("https://"):
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" not in s:
        s = s + ":443"
    host, port_s = s.split(":", 1)
    port = int(port_s) if port_s.isdigit() else 443
    return host, port


def do_calibrate(origin: str, pop: str) -> None:
    import socket as _sock
    from betanet.calibration import TLSFingerprintProvider, ensure_calibrated, compute_template_id, save_template_id, CalibrationPolicy
    host, port = _normalize_origin(origin)
    try:
        _sock.getaddrinfo(host, port)
    except Exception:
        raise SystemExit(f"could not resolve origin host '{host}'. Use a real host:port (e.g., example.com:443)")
    o = f"{host}:{port}"
    fp = ensure_calibrated(o, pop, TLSFingerprintProvider(), policy=CalibrationPolicy.DEV)
    tid = compute_template_id(fp)
    save_template_id(o, pop, tid)
    log.getLogger("server").info("calibrated origin=%s pop=%s template_id=%s", o, pop, tid.hex())


def main() -> None:
    args = parse_args()
    setup_logging(getattr(args, "log_level", "INFO"))
    if args.cmd == "calibrate":
        do_calibrate(args.origin, args.pop)
        return
    log_level = getattr(args, "log_level", "INFO")
    if getattr(args, "quiet", False):
        log_level = "WARNING"
    setup_logging(log_level)
    opts = RunnerOptions(
        plugin_modules=getattr(args, "plugin", []) or [],
        plugin_dirs=getattr(args, "plugin_dir", []) or [],
        template_roots=getattr(args, "templates", []) or [],
        pool_size=int(getattr(args, "pool_size", 4) or 4),
        verbose=bool(getattr(args, "verbose", False)),
    )
    ServerRunner(args.config, opts).start()


if __name__ == "__main__":
    main()


