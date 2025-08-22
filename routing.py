import time
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class Role:
    ENTRY = "entry"
    CORE = "core"
    EXIT = "exit"


@dataclass
class PeerInfo:
    peer_id: str
    address: Tuple[str, int]
    role: str
    rtt_ms: float = 0.0
    last_ok: float = 0.0
    last_seen: float = 0.0
    failures: int = 0
    health: str = "OK"
    next_retry_at: float = 0.0
    congestion: str = "NONE"
    congestion_until: float = 0.0


class RoutingTable:
    def __init__(self):
        self.peers: Dict[str, PeerInfo] = {}

    def upsert(self, p: PeerInfo) -> None:
        self.peers[p.peer_id] = p

    def mark_ok(self, pid: str, rtt_ms: float) -> None:
        p = self.peers.get(pid)
        if not p:
            return
        p.rtt_ms = rtt_ms
        p.last_ok = time.time()
        p.last_seen = p.last_ok
        p.failures = 0
        p.health = "OK"

    def mark_fail(self, pid: str) -> None:
        p = self.peers.get(pid)
        if not p:
            return
        p.failures += 1
        p.last_seen = time.time()
        if p.failures >= 3:
            p.health = "EVICT"
        backoff = min(600.0, 5.0 * (2 ** p.failures))
        jitter = random.uniform(-0.5, 0.5) * backoff * 0.1
        p.next_retry_at = time.time() + backoff + jitter

    def candidates(self, role: str) -> List[PeerInfo]:
        now = time.time()
        out: List[PeerInfo] = []
        for p in self.peers.values():
            if p.role != role:
                continue
            if p.health != "OK":
                continue
            if now - p.last_seen > 60:
                continue
            if p.next_retry_at and now < p.next_retry_at:
                continue
            out.append(p)
        return out

    def apply_congestion_feedback(self, pid: str, level: str, duration_sec: float = 60.0) -> None:
        p = self.peers.get(pid)
        if not p:
            return
        p.congestion = level
        p.congestion_until = time.time() + duration_sec


class PathSelector:
    def __init__(self, table: RoutingTable):
        self.table = table

    def _pick(self, role: str, exclude: List[str]) -> Optional[PeerInfo]:
        c = [p for p in self.table.candidates(role) if p.peer_id not in exclude]
        if not c:
            return None
        now = time.time()
        non_severe = [p for p in c if not (p.congestion == "SEVERE" and now < p.congestion_until)]
        if not non_severe and any(p.congestion == "SEVERE" and now < p.congestion_until for p in c):
            return None
        pool = non_severe if non_severe else c
        c = sorted(pool, key=lambda p: (p.rtt_ms, random.random()))
        return c[0]

    def build_default_path(self) -> List[PeerInfo]:
        chosen: List[PeerInfo] = []
        for role in (Role.ENTRY, Role.CORE, Role.EXIT):
            p = self._pick(role, [x.peer_id for x in chosen])
            if not p:
                return []
            chosen.append(p)
        ids = [p.peer_id for p in chosen]
        if len(ids) != len(set(ids)):
            return []
        return chosen

    def liveness_probe_targets(self, idle_sec: float = 20.0) -> List[PeerInfo]:
        now = time.time()
        out: List[PeerInfo] = []
        for p in self.table.peers.values():
            if now - p.last_ok >= idle_sec and p.health == "OK":
                out.append(p)
        return out

    def apply_congestion_feedback(self, pid: str, level: str, duration_sec: float = 60.0) -> None:
        p = self.peers.get(pid)
        if not p:
            return
        p.congestion = level
        p.congestion_until = time.time() + duration_sec


