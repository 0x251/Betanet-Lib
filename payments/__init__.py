import time
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from abc import ABC, abstractmethod


@dataclass
class Voucher:
    keyset_id: bytes  # 32 bytes
    secret: bytes  # 32 bytes
    signature: bytes  # 64 bytes


def parse_voucher(v: bytes) -> Optional[Voucher]:
    if len(v) != 128:
        return None
    return Voucher(keyset_id=v[0:32], secret=v[32:64], signature=v[64:128])


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill = refill_per_sec
        self.tokens = float(capacity)
        self.ts = time.time()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        delta = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def available(self) -> float:
        return self.tokens


class PaymentsVerifierBase(ABC):
    @abstractmethod
    def add_known_keyset(self, keyset_id: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def verify_and_rate_limit(self, voucher_bytes: bytes, peer_id_or_ip: str) -> Tuple[bool, Dict[str, float]]:
        raise NotImplementedError


class PaymentsVerifier(PaymentsVerifierBase):
    def __init__(
        self,
        per_keyset_capacity: int = 60,
        per_peer_capacity: int = 60,
        refill_per_sec: float = 1.0,
    ):
        self.known_keysets: Dict[bytes, bool] = {}
        self.by_keyset: Dict[bytes, TokenBucket] = {}
        self.by_peer: Dict[str, TokenBucket] = {}
        self.per_keyset_capacity = per_keyset_capacity
        self.per_peer_capacity = per_peer_capacity
        self.refill_per_sec = refill_per_sec

    def add_known_keyset(self, keyset_id: bytes) -> None:
        self.known_keysets[keyset_id] = True

    def _bucket_keyset(self, keyset_id: bytes) -> TokenBucket:
        b = self.by_keyset.get(keyset_id)
        if b is None:
            b = TokenBucket(self.per_keyset_capacity, self.refill_per_sec)
            self.by_keyset[keyset_id] = b
        return b

    def _bucket_peer(self, peer: str) -> TokenBucket:
        b = self.by_peer.get(peer)
        if b is None:
            b = TokenBucket(self.per_peer_capacity, self.refill_per_sec)
            self.by_peer[peer] = b
        return b

    def verify_and_rate_limit(
        self, voucher_bytes: bytes, peer_id_or_ip: str
    ) -> Tuple[bool, Dict[str, float]]:
        status: Dict[str, float] = {}
        v = parse_voucher(voucher_bytes)
        if v is None:
            return False, status
        if v.keyset_id not in self.known_keysets:
            return False, status
        bk = self._bucket_keyset(v.keyset_id)
        bp = self._bucket_peer(peer_id_or_ip)
        ok = bk.allow(1.0) and bp.allow(1.0)
        status["keyset_tokens"] = bk.available()
        status["peer_tokens"] = bp.available()
        return ok, status
