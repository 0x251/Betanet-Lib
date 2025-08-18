from abc import ABC, abstractmethod


class TransportServer(ABC):
    @abstractmethod
    def serve_once(self) -> None:
        raise NotImplementedError


class TransportClient(ABC):
    @abstractmethod
    def roundtrip(self, stream_id: int, payload: bytes) -> bytes:
        raise NotImplementedError


