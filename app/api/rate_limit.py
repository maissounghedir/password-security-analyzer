import time
from collections import defaultdict, deque
from typing import Callable


class RateLimiter:
    """In-memory sliding-window rate limiter, one window per key (e.g. client IP).

    Single-process only: each worker keeps its own counters.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    @property
    def tracked_clients(self) -> int:
        return len(self._hits)

    def allow(self, key: str) -> bool:
        """Record a request for `key`; return False if it exceeds the limit."""
        now = self._clock()

        if len(self._hits) >= self.max_keys:
            self._purge(now)

        hits = self._hits[key]
        while hits and now - hits[0] >= self.window:
            hits.popleft()  # forget requests older than the window

        if len(hits) >= self.max_requests:
            return False  # blocked requests are not recorded

        hits.append(now)
        return True

    def _purge(self, now: float) -> None:
        """Drop clients with no recent activity so memory stays bounded."""
        stale = [
            key for key, hits in self._hits.items()
            if not hits or now - hits[-1] >= self.window
        ]
        for key in stale:
            del self._hits[key]