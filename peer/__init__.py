import hashlib
from typing import List, Optional


def sha256(data: bytes) -> bytes:
	return hashlib.sha256(data).digest()


def peer_id(pubkey: bytes) -> bytes:
	return bytes([0x12, 0x20]) + sha256(pubkey)


def negotiate_transport(local: List[str], remote: List[str]) -> Optional[str]:
	order = ["/betanet/htxquic/1.1.0", "/betanet/htx/1.1.0"]
	inter = [t for t in order if t in local and t in remote]
	if inter:
		return inter[0]
	for t in local:
		if t in remote:
			return t
	return None


