import hashlib
import time
import ipaddress


from typing import List, Tuple, Dict, Optional


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def epoch_day(ts: Optional[int] = None) -> int:
    if ts is None:
        ts = int(time.time())
    return ts // 86400


def beacon_set(ep: int) -> bytes:
    a = sha256(b"drand-" + str(ep).encode())
    b = sha256(b"nist-" + str(ep).encode())
    c = sha256(b"eth-" + str(ep).encode())
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def rendezvous_ids(bset: bytes, count: int = 64) -> List[str]:
    ids: List[str] = []
    for i in range(count):
        h = sha256(b"bn-seed" + bset + i.to_bytes(4, "big"))
        ids.append(h.hex())
    return ids


def leading_zero_bits(b: bytes) -> int:
    bcount = 0
    for by in b:
        if by == 0:
            bcount += 8
            continue
        for bit in range(7, -1, -1):
            if (by >> bit) & 1 == 0:
                bcount += 1
            else:
                return bcount
        return bcount
    return bcount


def verify_pow(challenge: bytes, nonce: int, bits: int) -> bool:
    h = sha256(challenge + nonce.to_bytes(8, "big"))
    return leading_zero_bits(h) >= bits


def find_pow_nonce(challenge: bytes, bits: int, max_iters: int = 200000) -> int:
    n = 0
    while n < max_iters:
        if verify_pow(challenge, n, bits):
            return n
        n += 1
    return -1


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens = float(capacity)
        self.ts = time.time()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        delta = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def available(self) -> float:
        return self.tokens


def ip_key_v4_24(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split(".")
            return ".".join(parts[:3]) + ".0/24"
        return None
    except Exception:
        return None


def ip_key_v6_56(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            net = ipaddress.IPv6Network((addr, 56), strict=False)
            return str(net)
        return None
    except Exception:
        return None


class MultiBucketLimiter:
    def __init__(
        self,
        cap_v4: int = 60,
        cap_v6: int = 60,
        cap_asn: int = 120,
        refill_per_sec: float = 1.0,
    ):
        self.cap_v4 = cap_v4
        self.cap_v6 = cap_v6
        self.cap_asn = cap_asn
        self.refill = refill_per_sec
        self.buckets: Dict[str, TokenBucket] = {}

    def _b(self, key: str, cap: int) -> TokenBucket:
        b = self.buckets.get(key)
        if b is None:
            b = TokenBucket(cap, self.refill)
            self.buckets[key] = b
        return b

    def allow(
        self, ip: str, asn: Optional[str] = None
    ) -> Tuple[bool, Dict[str, float]]:
        statuses: Dict[str, float] = {}
        ok = True
        k4 = ip_key_v4_24(ip)
        if k4 is not None:
            b4 = self._b("v4:" + k4, self.cap_v4)
            ok = b4.allow(1.0) and ok
            statuses["v4"] = b4.available()
        k6 = ip_key_v6_56(ip)
        if k6 is not None:
            b6 = self._b("v6:" + str(k6), self.cap_v6)
            ok = b6.allow(1.0) and ok
            statuses["v6"] = b6.available()
        if asn:
            ba = self._b("asn:" + asn, self.cap_asn)
            ok = ba.allow(1.0) and ok
            statuses["asn"] = ba.available()
        return ok, statuses


def discover_mdns() -> List[str]:
    return ["mdns://_betanet._udp.local:443"]


def discover_dns() -> List[str]:
    return ["dns://bootstrap.betanet.invalid:443"]
