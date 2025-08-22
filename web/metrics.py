import threading
import time
from dataclasses import dataclass


@dataclass
class Counters:
    requests: int = 0
    errors: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


class Metrics:
    def __init__(self) -> None:
        self._c = Counters()
        self._lock = threading.Lock()
        self.started_at = time.time()

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

    def snapshot(self) -> Counters:
        with self._lock:
            return Counters(
                requests=self._c.requests,
                errors=self._c.errors,
                bytes_in=self._c.bytes_in,
                bytes_out=self._c.bytes_out,
            )


