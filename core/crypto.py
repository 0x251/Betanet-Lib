from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from betanet.core.detcbor import dumps as detcbor_dumps


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
	return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label).derive(secret)


def hkdf_next(secret: bytes, transcript_hash: bytes, length: int) -> bytes:
	return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=transcript_hash).derive(secret)


def derive_ns(key: bytes) -> bytes:
	return HKDF(algorithm=hashes.SHA256(), length=12, salt=None, info=b"ns").derive(key)


def compute_nonce(ns: bytes, counter: int) -> bytes:
	ctr_bytes = (counter & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + (0).to_bytes(4, "little")
	return bytes(a ^ b for a, b in zip(ns, ctr_bytes))


@dataclass
class DirectionKeys:
	key: bytes
	ns: bytes
	counter: int = 0

	def aead(self) -> ChaCha20Poly1305:
		return ChaCha20Poly1305(self.key)

	def seal(self, aad: bytes, plaintext: bytes) -> bytes:
		nonce = compute_nonce(self.ns, self.counter)
		self.counter += 1
		return self.aead().encrypt(nonce, plaintext, aad)

	def open(self, aad: bytes, ciphertext: bytes) -> bytes:
		nonce = compute_nonce(self.ns, self.counter)
		pt = self.aead().decrypt(nonce, ciphertext, aad)
		self.counter += 1
		return pt

	def try_open_at(self, aad: bytes, ciphertext: bytes, counter: int) -> bytes:
		if counter < 0:
			raise ValueError("counter must be non-negative")
		nonce = compute_nonce(self.ns, counter)
		return self.aead().decrypt(nonce, ciphertext, aad)

	def open_with_lookahead(self, aad: bytes, ciphertext: bytes, max_skip: int = 8) -> bytes:
		start = self.counter
		for i in range(max_skip + 1):
			try:
				pt = self.try_open_at(aad, ciphertext, start + i)
				self.counter = start + i + 1
				return pt
			except Exception:
				continue
		raise Exception("decrypt failed with lookahead")


@dataclass
class InnerKeys:
	client: DirectionKeys
	server: DirectionKeys

	def next(self, transcript_hash: bytes) -> "InnerKeys":
		kc_next = hkdf_next(self.client.key, transcript_hash, 32)
		ks_next = hkdf_next(self.server.key, transcript_hash, 32)
		return InnerKeys(
			client=DirectionKeys(kc_next, derive_ns(kc_next), 0),
			server=DirectionKeys(ks_next, derive_ns(ks_next), 0),
		)


def derive_inner_keys_from_k0(k0: bytes) -> InnerKeys:
	if len(k0) != 64:
		raise ValueError("k0 must be 64 bytes")
	kc = k0[:32]
	ks = k0[32:64]
	return InnerKeys(
		client=DirectionKeys(kc, derive_ns(kc), 0),
		server=DirectionKeys(ks, derive_ns(ks), 0),
	)


def exporter_context_bytes(context: Dict[str, Any]) -> bytes:
	return detcbor_dumps(context)


def derive_inner_keys_from_exporter(ekm: bytes, context: Dict[str, Any]) -> InnerKeys:
	zero = b"\x00" * 32
	_ = detcbor_dumps(context)
	K0 = HKDF(algorithm=hashes.SHA256(), length=32, salt=zero, info=b"").derive(ekm)
	ts_c = hkdf_expand_label(K0, b"ts_c", 32)
	ts_s = hkdf_expand_label(K0, b"ts_s", 32)
	key_c = hkdf_expand_label(ts_c, b"key", 32)
	ns_c = hkdf_expand_label(ts_c, b"nonce", 12)
	key_s = hkdf_expand_label(ts_s, b"key", 32)
	ns_s = hkdf_expand_label(ts_s, b"nonce", 12)
	return InnerKeys(
		client=DirectionKeys(key_c, ns_c, 0),
		server=DirectionKeys(key_s, ns_s, 0),
	)


def new_session12_from_exporter(
    ekm: bytes,
    context: Dict[str, Any],
    is_client: bool,
):
    keys = derive_inner_keys_from_exporter(ekm, context)
    send = keys.client if is_client else keys.server
    recv = keys.server if is_client else keys.client
    from betanet.core.session12 import Session12

    return Session12(send, recv)
