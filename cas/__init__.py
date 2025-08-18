import hashlib
from typing import Optional
from abc import ABC, abstractmethod


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_cid(content: bytes) -> str:
    # multihash: 0x12 0x20 || sha256
    mh = bytes([0x12, 0x20]) + sha256(content)
    return mh.hex()


class ContentStoreBase(ABC):
    @abstractmethod
    def put(self, content: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def get(self, cid: str) -> Optional[bytes]:
        raise NotImplementedError


class ContentStore(ContentStoreBase):
    def __init__(self):
        self._by_cid: dict[str, bytes] = {}

    def put(self, content: bytes) -> str:
        cid = compute_cid(content)
        self._by_cid[cid] = content
        return cid

    def get(self, cid: str) -> Optional[bytes]:
        return self._by_cid.get(cid)
