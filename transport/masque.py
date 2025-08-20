from dataclasses import dataclass
from typing import Optional
from abc import ABC, abstractmethod

from betanet.transport.enums import MasqueOutcome


@dataclass
class MasqueResult:
    outcome: MasqueOutcome
    reason: Optional[str] = None


class MasqueClientBase(ABC):
    @abstractmethod
    def attempt_tunnel(self, host: str, port: int) -> MasqueResult:
        raise NotImplementedError


class MasqueClient(MasqueClientBase):
    def attempt_tunnel(self, host: str, port: int) -> MasqueResult:
        try:
            from aioquic.asyncio.client import connect  # type: ignore
            import asyncio

            async def _attempt() -> bool:
                try:
                    async with connect(host, port, alpn_protocols=["h3"], verify_mode=False) as client:
                       
                        return True
                except Exception:
                    return False

            created = False
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                created = True
            coro = _attempt()
            try:
                ok = loop.run_until_complete(coro)
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
            if ok:
                return MasqueResult(outcome=MasqueOutcome.ATTEMPTED, reason="h3_ok")
            return MasqueResult(outcome=MasqueOutcome.FALLBACK_TCP, reason="h3_fail")
        except Exception:
            return MasqueResult(outcome=MasqueOutcome.FALLBACK_TCP, reason="no_quic")


class DummyMasqueClient(MasqueClientBase):
    def attempt_tunnel(self, host: str, port: int) -> MasqueResult:
        return MasqueResult(outcome=MasqueOutcome.FALLBACK_TCP, reason="stub")


