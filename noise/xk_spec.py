import os
from dataclasses import dataclass
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def hkdf_pair(salt: bytes, ikm: bytes) -> Tuple[bytes, bytes]:
    prk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"").derive(ikm)
    out = HKDFExpand(algorithm=hashes.SHA256(), length=64, info=b"betanet/noise").derive(prk)
    return out[:32], out[32:64]


def nonce_from_counter(counter: int) -> bytes:
    return counter.to_bytes(8, "little") + b"\x00\x00\x00\x00"


def aead_encrypt(key: bytes, counter: int, aad: bytes, plaintext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce_from_counter(counter), plaintext, aad)


def aead_decrypt(key: bytes, counter: int, aad: bytes, ciphertext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce_from_counter(counter), ciphertext, aad)


def dh(priv: bytes, pub: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(priv)
    pk = X25519PublicKey.from_public_bytes(pub)
    return sk.exchange(pk)


def handshake_k0_from_hash(h: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"betanet/noise").derive(h)


def sha256_cat(h: bytes, data: bytes) -> bytes:
    x = hashes.Hash(hashes.SHA256())
    x.update(h + data)
    return x.finalize()


@dataclass
class InitiatorState:
    ck: bytes
    h: bytes
    e_priv: bytes
    rs: bytes
    si_priv: bytes


@dataclass
class ResponderState:
    ck: bytes
    h: bytes
    k: bytes
    e_priv: bytes


def initiator_start(si_priv: bytes, rs: bytes) -> Tuple[InitiatorState, bytes]:
    proto = hashes.Hash(hashes.SHA256())
    proto.update(b"Noise_XK_25519_ChaChaPoly_SHA256")
    h = proto.finalize()
    ck = h
    h = sha256_cat(h, rs)
    e = X25519PrivateKey.generate().private_bytes_raw()
    e_pub = X25519PrivateKey.from_private_bytes(e).public_key().public_bytes_raw()
    h = sha256_cat(h, e_pub)
    ck, _ = hkdf_pair(ck, dh(e, rs))
    st = InitiatorState(ck=ck, h=h, e_priv=e, rs=rs, si_priv=si_priv)
    return st, e_pub


def responder_read_msg1(sr_priv: bytes, msg1_e_pub: bytes) -> Tuple[ResponderState, bytes]:
    proto = hashes.Hash(hashes.SHA256())
    proto.update(b"Noise_XK_25519_ChaChaPoly_SHA256")
    h = proto.finalize()
    ck = h
    rs = X25519PrivateKey.from_private_bytes(sr_priv).public_key().public_bytes_raw()
    h = sha256_cat(h, rs)
    h = sha256_cat(h, msg1_e_pub)
    e = X25519PrivateKey.generate().private_bytes_raw()
    e_pub = X25519PrivateKey.from_private_bytes(e).public_key().public_bytes_raw()
    h = sha256_cat(h, e_pub)
    ck, _ = hkdf_pair(ck, dh(e, msg1_e_pub))
    ck, k = hkdf_pair(ck, dh(sr_priv, msg1_e_pub))
    tag = aead_encrypt(k, 0, h, b"")
    st = ResponderState(ck=ck, h=h, k=k, e_priv=e)
    return st, e_pub + tag


def initiator_read_msg2(state: InitiatorState, si_priv: bytes, msg2: bytes) -> Tuple[InitiatorState, bytes, bytes]:
    e_r = msg2[:32]
    tag = msg2[32:]
    h2 = sha256_cat(state.h, e_r)
    ck1, _ = hkdf_pair(state.ck, dh(state.e_priv, e_r))
    ck2, k = hkdf_pair(ck1, dh(si_priv, e_r))
    _ = aead_decrypt(k, 0, h2, tag)
    si_pub = X25519PrivateKey.from_private_bytes(si_priv).public_key().public_bytes_raw()
    ct = aead_encrypt(k, 0, h2, si_pub)
    st = InitiatorState(ck=ck2, h=h2, e_priv=state.e_priv, rs=state.rs, si_priv=state.si_priv)
    return st, ct, h2


def responder_read_msg3(state: ResponderState, msg3_ct: bytes) -> Tuple[ResponderState, bytes, bytes]:
    si_pub = aead_decrypt(state.k, 0, state.h, msg3_ct)
    k0 = handshake_k0_from_hash(state.h)
    st = ResponderState(ck=state.ck, h=state.h, k=state.k, e_priv=state.e_priv)
    return st, state.h, k0


