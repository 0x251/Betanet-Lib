import os
import time
import random

from dataclasses import dataclass
from typing import List, Tuple


def rand_ms(a: int, b: int) -> int:
    return random.randint(a, b)


def fresh_random_bytes(n: int) -> bytes:
    return os.urandom(n)


@dataclass
class RetryPlan:
    backoff_ms: int
    cover_launch_offsets_ms: List[int]
    htx_delay_ms: int
    clienthello_random: bytes
    quic_cids: Tuple[bytes, bytes]


class CoverRateLimiter:
    def __init__(self):
        self.events: List[float] = []

    def allow(self) -> bool:
        now = time.time()
        one_min = now - 60.0
        self.events = [t for t in self.events if t >= one_min]
        if len(self.events) >= 2:
            return False
        self.events.append(now)
        return True


def make_retry_plan(num_covers: int = 2) -> RetryPlan:
    backoff = rand_ms(200, 1200)
    covers = [rand_ms(0, 1000) for _ in range(max(0, num_covers))]
    htx_delay = rand_ms(100, 700)
    chelo_rand = fresh_random_bytes(32)
    quic_cid1 = fresh_random_bytes(8)
    quic_cid2 = fresh_random_bytes(8)
    return RetryPlan(
        backoff_ms=backoff,
        cover_launch_offsets_ms=covers,
        htx_delay_ms=htx_delay,
        clienthello_random=chelo_rand,
        quic_cids=(quic_cid1, quic_cid2),
    )
