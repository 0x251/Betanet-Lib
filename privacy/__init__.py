import hashlib
from typing import List, Union
from enum import Enum

from betanet.bootstrap import beacon_set, epoch_day


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pick_nodes(seed: bytes, count: int) -> List[str]:
    out: List[str] = []
    cur = seed
    seen = set()
    while len(out) < count:
        cur = sha256(cur)
        tag = cur[:2].hex()
        name = f"mix-{tag}"
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


class PrivacyMode(Enum):
	STRICT = "strict"
	BALANCED = "balanced"
	PERFORMANCE = "performance"


def compute_hops(
    src_peer_id: bytes, dst_peer_id: bytes, stream_nonce: bytes, mode: Union[str, PrivacyMode], trust: float
) -> List[str]:
    ep = epoch_day()
    b = beacon_set(ep)
    seed = sha256(b + src_peer_id + dst_peer_id + stream_nonce)
    if (mode.value if isinstance(mode, PrivacyMode) else mode) == "strict":
        return pick_nodes(seed, 3)
    if (mode.value if isinstance(mode, PrivacyMode) else mode) == "balanced":
        if trust >= 0.8:
            return []
        return pick_nodes(seed, 2)
    return []
