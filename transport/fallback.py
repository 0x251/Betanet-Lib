import time
import socket
import threading
import random
import ipaddress
import os
from typing import Callable, Optional, List, Tuple
from enum import Enum

from betanet.fallback import make_retry_plan
from betanet.transport.tcp import HtxTcpClient
from betanet.transport.quic import HtxQuicClient
from betanet.transport.masque import MasqueClientBase, MasqueClient


def try_quic_masque(host: str, port: int) -> bool:
    print("quic_attempt=failed host=", host, "port=", port)
    return False


class CoverConnectionMode(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"


class CoverRateLimiterBase:
    def allow_launch(self) -> bool:
        raise NotImplementedError


class SimpleCoverRateLimiter(CoverRateLimiterBase):
    def __init__(self):
        self.ts = []

    def allow_launch(self) -> bool:
        now = time.time()
        cutoff = now - 60.0
        self.ts = [t for t in self.ts if t >= cutoff]
        if len(self.ts) >= 2:
            return False
        self.ts.append(now)
        return True


def _spawn_cover_connection(host: str, port: int, duration_ms: int) -> None:
    def _run():
        s = None
        try:
            s = socket.create_connection((host, port), timeout=0.2)
            time.sleep(max(0, duration_ms) / 1000.0)
        except Exception:
            pass
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
    t = threading.Thread(target=_run, daemon=True)
    t.start()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except Exception:
        return False


def _parse_decoy_env() -> List[Tuple[str, int]]:
    s = os.environ.get("BETANET_COVER_DECOYS", "").strip()
    if not s:
        return []
    out: List[Tuple[str, int]] = []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for p in parts:
        try:
            h, pr = p.rsplit(":", 1)
            out.append((h.strip(), int(pr.strip())))
        except Exception:
            continue
    return out


def _schedule_covers(decoys: List[Tuple[str, int]], offsets_ms: List[int], limiter: "SimpleCoverRateLimiter") -> None:
    if not decoys or not offsets_ms:
        return
    def _run():
        idx = 0
        for off in offsets_ms:
            time.sleep(max(0, off) / 1000.0)
            if not limiter.allow_launch():
                continue
            host, port = decoys[idx % len(decoys)]
            idx += 1
            _spawn_cover_connection(host, port, random.randint(3000, 15000))
    threading.Thread(target=_run, daemon=True).start()


def roundtrip_with_udp_fallback(
    host: str,
    port: int,
    client_priv: bytes,
    server_pub: bytes,
    stream_id: int,
    payload: bytes,
    sleep_ms: Optional[Callable[[int], None]] = None,
    masque: Optional[MasqueClientBase] = None,
    decoy_endpoints: Optional[List[Tuple[str, int]]] = None,
) -> bytes:
    if sleep_ms is None:

        def sleep_ms(n: int) -> None:
            time.sleep(max(0, n) / 1000.0)

    if masque is None:
        masque = MasqueClient()
    _ = masque.attempt_tunnel(host, 443)
    do_quic = not _is_loopback(host)
    try:
        if do_quic:
            q = HtxQuicClient(host, port, client_priv, server_pub)
            _ = q.roundtrip(stream_id, payload)
    except Exception:
        pass
    plan = make_retry_plan(2)
    print("backoff_ms=", plan.backoff_ms)
    print("cover_offsets_ms=", plan.cover_launch_offsets_ms)
    print("htx_delay_ms=", plan.htx_delay_ms)
    limiter = SimpleCoverRateLimiter()
    if decoy_endpoints is None:
        decoy_endpoints = _parse_decoy_env()
    if not _is_loopback(host) and decoy_endpoints:
        _schedule_covers(decoy_endpoints, plan.cover_launch_offsets_ms, limiter)
        for off in plan.cover_launch_offsets_ms:
            print("cover_launch at_ms=", off)
    fast = os.environ.get("BETANET_DEV_FAST", "0") == "1"
    if not (fast and _is_loopback(host)):
        sleep_ms(plan.backoff_ms)
        sleep_ms(plan.htx_delay_ms)
    cli = HtxTcpClient(host, port, client_priv, server_pub)
    resp = cli.roundtrip(stream_id, payload)
    print("tcp_fallback_resp_len=", len(resp))
    return resp
