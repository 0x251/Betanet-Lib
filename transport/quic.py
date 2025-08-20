import logging
from typing import Optional

from betanet.transport.base import TransportClient, TransportServer
from betanet.transport.tcp import HtxTcpClientPersistent

logger = logging.getLogger("betanet")


class HtxQuicServer(TransportServer):
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def serve_once(self) -> None:
        raise NotImplementedError


class HtxQuicClient(TransportClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_priv: bytes,
        server_pub: bytes,
        use_masque: bool = True,
        pool_size: int = 0,
    ):
        self.host = host
        self.port = port
        self.client_priv = client_priv
        self.server_pub = server_pub
        self.use_masque = use_masque
        self.pool: Optional[HtxTcpClientPersistent] = None
        if pool_size > 0:
            
            self.pool = HtxTcpClientPersistent(host, port, client_priv, server_pub)

    def roundtrip(self, stream_id: int, payload: bytes) -> bytes:
        try:
            from aioquic.asyncio.client import connect  # type: ignore
            import asyncio

            async def _rt() -> bytes:
                async with connect(self.host, self.port, alpn_protocols=["h3"], verify_mode=False):
                    raise RuntimeError("quic_not_yet_mapped_to_htx")

            created = False
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                created = True
            coro = _rt()
            try:
                return loop.run_until_complete(coro)
            finally:
                try:
                    coro.close()
                except Exception:
                    pass
                if created:
                    try:
                        loop.close()
                    except Exception:
                        pass
        except Exception as e:
            raise e


