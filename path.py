from dataclasses import dataclass
import time
from typing import List, Optional, Tuple


@dataclass
class PathEndpoint:
    host: str
    port: int
    score: float = 0.0
    last_ok: float = 0.0
    last_fail: float = 0.0


class PathManager:
    def __init__(self, endpoints: Optional[List[PathEndpoint]] = None, max_paths: int = 3):
        self.max_paths = max_paths
        self.paths: List[PathEndpoint] = list(endpoints or [])[: self.max_paths]
        self.idx = 0

    def add(self, host: str, port: int) -> None:
        if any(p.host == host and p.port == port for p in self.paths):
            return
        if len(self.paths) < self.max_paths:
            self.paths.append(PathEndpoint(host=host, port=port))

    def current(self) -> Optional[PathEndpoint]:
        if not self.paths:
            return None
        return self.paths[self.idx % len(self.paths)]

    def mark_ok(self, host: str, port: int, rtt_ms: float = 0.0) -> None:
        now = time.time()
        for p in self.paths:
            if p.host == host and p.port == port:
                p.last_ok = now
                p.score = 0.8 * p.score + 0.2 * (-rtt_ms)
                break

    def mark_fail(self, host: str, port: int) -> None:
        now = time.time()
        for p in self.paths:
            if p.host == host and p.port == port:
                p.last_fail = now
                p.score = p.score - 1.0
                break
        self.rotate()

    def rotate(self) -> None:
        if self.paths:
            self.idx = (self.idx + 1) % len(self.paths)

    def best(self) -> Optional[PathEndpoint]:
        if not self.paths:
            return None
        return sorted(self.paths, key=lambda p: (p.score, p.last_fail))[0]

    def maybe_switch(self) -> Optional[PathEndpoint]:
        if not self.paths:
            return None
        cur = self.current()
        best = self.best()
        if cur is None or best is None:
            return cur
        if best is not cur and best.score > cur.score + 0.5:
            for i, p in enumerate(self.paths):
                if p is best:
                    self.idx = i
                    break
            return best
        return cur


