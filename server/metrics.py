import threading
import time
from dataclasses import dataclass


@dataclass
class Counters:
    requests: int = 0
    errors: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    avg_ms: float = 0.0
    last_ms: float = 0.0


class Metrics:
    def __init__(self) -> None:
        self._c = Counters()
        self._lock = threading.Lock()
        self.started_at = time.time()
        self._latency_sum_ms = 0.0
        self._latency_count = 0
        self._last_ms = 0.0

    def inc_req(self, bytes_in: int) -> None:
        with self._lock:
            self._c.requests += 1
            self._c.bytes_in += bytes_in

    def inc_err(self) -> None:
        with self._lock:
            self._c.errors += 1

    def inc_out(self, n: int) -> None:
        with self._lock:
            self._c.bytes_out += n

    def record_latency(self, ms: float) -> None:
        with self._lock:
            self._last_ms = float(ms)
            self._latency_sum_ms += float(ms)
            self._latency_count += 1

    def snapshot(self) -> Counters:
        with self._lock:
            avg = (self._latency_sum_ms / self._latency_count) if self._latency_count > 0 else 0.0
            return Counters(
                requests=self._c.requests,
                errors=self._c.errors,
                bytes_in=self._c.bytes_in,
                bytes_out=self._c.bytes_out,
                avg_ms=avg,
                last_ms=self._last_ms,
            )


_GLOBAL: Metrics | None = None


def get_global_metrics() -> Metrics:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = Metrics()
    return _GLOBAL


