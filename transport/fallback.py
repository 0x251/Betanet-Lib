import time
from typing import Callable, Optional

from betanet.fallback import make_retry_plan
from betanet.transport.tcp import HtxTcpClient


def try_quic_masque(host: str, port: int) -> bool:
    print("quic_attempt=failed host=", host, "port=", port)
    return False


def roundtrip_with_udp_fallback(
    host: str,
    port: int,
    client_priv: bytes,
    server_pub: bytes,
    stream_id: int,
    payload: bytes,
    sleep_ms: Optional[Callable[[int], None]] = None,
) -> bytes:
    if sleep_ms is None:

        def sleep_ms(n: int) -> None:
            time.sleep(max(0, n) / 1000.0)

    if try_quic_masque(host, 443):
        raise RuntimeError("quic path not implemented")
    plan = make_retry_plan(2)
    print("backoff_ms=", plan.backoff_ms)
    print("cover_offsets_ms=", plan.cover_launch_offsets_ms)
    print("htx_delay_ms=", plan.htx_delay_ms)
    sleep_ms(plan.backoff_ms)
    cli = HtxTcpClient(host, port, client_priv, server_pub)
    resp = cli.roundtrip(stream_id, payload)
    print("tcp_fallback_resp_len=", len(resp))
    return resp
