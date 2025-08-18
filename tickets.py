import base64
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


TICKET_LABEL = b"betanet-ticket-v1"


def sha256(data: bytes) -> bytes:
	return hashlib.sha256(data).digest()


@dataclass
class TicketPolicy:
	carriers: Dict[str, float]
	min_len: int
	max_len: int


@dataclass
class TicketParams:
	ticket_pub: bytes
	ticket_key_id: bytes
	policy: TicketPolicy


def hkdf(secret: bytes, salt: bytes, length: int) -> bytes:
	return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=b"").derive(secret)


def hour_bucket(ts: Optional[int] = None) -> int:
	if ts is None:
		ts = int(time.time())
	return ts // 3600


def compute_access_ticket(cli_priv: X25519PrivateKey, ticket_pub: X25519PublicKey, ticket_key_id: bytes, now: Optional[int] = None) -> Tuple[bytes, bytes]:
	if len(ticket_key_id) != 8:
		raise ValueError("ticket_key_id must be 8 bytes")
	shared = cli_priv.exchange(ticket_pub)
	hour = hour_bucket(now)
	salt = sha256(TICKET_LABEL + ticket_key_id + int(hour).to_bytes(8, "big"))
	access_ticket = hkdf(shared, salt, 32)
	return access_ticket, salt


def build_payload(cli_pub32: bytes, ticket_key_id8: bytes, nonce32: bytes, access_ticket32: bytes, pad_len: int) -> bytes:
	if not (24 <= pad_len <= 64):
		raise ValueError("pad_len must be in [24, 64]")
	pad = os.urandom(pad_len)
	return b"".join([b"\x01", cli_pub32, ticket_key_id8, nonce32, access_ticket32, pad])


def encode_cookie(site_name: str, payload: bytes) -> str:
	b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
	return f"{site_name}={b64}"


def encode_query(payload: bytes) -> str:
	b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
	return f"bn1={b64}"


def encode_form_body(payload: bytes) -> bytes:
	b64 = base64.urlsafe_b64encode(payload).rstrip(b"=")
	return b"bn1=" + b64


class ReplayWindow:
	def __init__(self):
		self._seen: Dict[Tuple[bytes, int], float] = {}
		self._lock = threading.Lock()

	def seen(self, cli_pub: bytes, hour: int) -> bool:
		key = (cli_pub, hour)
		now = time.time()
		with self._lock:
			cut = now - 2 * 3600
			stale = [k for k, t in self._seen.items() if t < cut]
			for k in stale:
				del self._seen[k]
			if key in self._seen:
				return True
			self._seen[key] = now
			return False


class TokenBucket:
	def __init__(self, capacity: int, refill_per_sec: float):
		self.capacity = capacity
		self.tokens = float(capacity)
		self.refill = float(refill_per_sec)
		self.ts = time.time()
		self._lock = threading.Lock()

	def allow(self, cost: float = 1.0) -> bool:
		with self._lock:
			now = time.time()
			delta = now - self.ts
			self.ts = now
			self.tokens = min(self.capacity, self.tokens + delta * self.refill)
			if self.tokens >= cost:
				self.tokens -= cost
				return True
			return False


class TicketVerifier:
	def __init__(self, ticket_priv: X25519PrivateKey, ticket_key_id8: bytes):
		if len(ticket_key_id8) != 8:
			raise ValueError("ticket_key_id8 must be 8 bytes")
		self.ticket_priv = ticket_priv
		self.ticket_key_id8 = ticket_key_id8
		self.replay = ReplayWindow()
		self.buckets: Dict[str, TokenBucket] = {}

	def _bucket_for(self, src_key: str) -> TokenBucket:
		b = self.buckets.get(src_key)
		if b is None:
			b = TokenBucket(capacity=60, refill_per_sec=1.0)
			self.buckets[src_key] = b
		return b

	def parse_and_verify(self, payload_b64: str, client_ip: str) -> bool:
		pad = '=' * (-len(payload_b64) % 4)
		try:
			blob = base64.urlsafe_b64decode(payload_b64 + pad)
		except Exception:
			return False
		if len(blob) < 1 + 32 + 8 + 32 + 32 + 24:
			return False
		version = blob[0]
		if version != 0x01:
			return False
		cli_pub = blob[1:33]
		key_id = blob[33:41]
		nonce32 = blob[41:73]
		access_ticket = blob[73:105]
		if key_id != self.ticket_key_id8:
			return False
		try:
			client_pub = X25519PublicKey.from_public_bytes(cli_pub)
		except Exception:
			return False
		shared = self.ticket_priv.exchange(client_pub)
		ok = False
		for hb in (hour_bucket(int(time.time()) - 3600), hour_bucket(), hour_bucket(int(time.time()) + 3600)):
			salt = sha256(TICKET_LABEL + self.ticket_key_id8 + int(hb).to_bytes(8, "big"))
			cand = hkdf(shared, salt, 32)
			if hmac.compare_digest(cand, access_ticket):
				ok = True
				break
		if not ok:
			return False
		if self.replay.seen(cli_pub, hb):
			return False
		if not self._bucket_for(client_ip).allow(1.0):
			return False
		return True


def generate_client_payload(params: TicketParams) -> Tuple[bytes, bytes, bytes]:
	cli_priv = X25519PrivateKey.generate()
	cli_pub = cli_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
	nonce32 = os.urandom(32)
	access, _ = compute_access_ticket(cli_priv, X25519PublicKey.from_public_bytes(params.ticket_pub), params.ticket_key_id)
	span = max(1, params.policy.max_len - params.policy.min_len + 1)
	pad_len = int(params.policy.min_len + (os.urandom(1)[0] % span))
	payload = build_payload(cli_pub, params.ticket_key_id, nonce32, access, pad_len)
	return payload, cli_pub, nonce32


def generate_client_cookie(site_name: str, params: TicketParams) -> Tuple[str, bytes, bytes]:
	payload, cli_pub, nonce32 = generate_client_payload(params)
	cookie = encode_cookie(site_name, payload)
	return cookie, cli_pub, nonce32
