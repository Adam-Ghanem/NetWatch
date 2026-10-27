"""Bound failed API authentication attempts before expensive identity verification.

This single-process guard deliberately uses the ASGI transport peer address, never
X-Forwarded-For or other client-controlled headers. A trusted TLS edge should
implement its own distributed, client-aware limits in multi-instance deployments.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque


class AuthenticationFailureLimiter:
    """A bounded, monotonic rolling window of failed authentications per peer."""

    def __init__(
        self,
        *,
        max_failures: int = 120,
        window_seconds: int = 60,
        max_peers: int = 4096,
    ) -> None:
        if min(max_failures, window_seconds, max_peers) < 1:
            raise ValueError("Authentication limiter settings must be positive.")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_peers = max_peers
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}
        self._overflow: deque[float] = deque()

    def _expire(self, events: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()

    def _reclaim_stale(self, now: float) -> None:
        for peer, events in list(self._failures.items()):
            self._expire(events, now)
            if not events:
                del self._failures[peer]

    def _bucket(self, peer: str, now: float, *, create: bool) -> deque[float]:
        bucket = self._failures.get(peer)
        if bucket is not None:
            self._expire(bucket, now)
            return bucket
        if not create:
            self._expire(self._overflow, now)
            return self._overflow
        if len(self._failures) >= self.max_peers:
            self._reclaim_stale(now)
        if len(self._failures) >= self.max_peers:
            self._expire(self._overflow, now)
            return self._overflow
        bucket = deque()
        self._failures[peer] = bucket
        return bucket

    def retry_after(self, peer: str) -> int | None:
        """Return a Retry-After delay if failures exhausted the peer budget."""
        now = time.monotonic()
        with self._lock:
            bucket = self._bucket(peer, now, create=False)
            if len(bucket) < self.max_failures:
                return None
            return max(1, math.ceil(self.window_seconds - (now - bucket[0])))

    def record_failure(self, peer: str) -> None:
        """Count only invalid authentication, never credentials or token content."""
        now = time.monotonic()
        with self._lock:
            bucket = self._bucket(peer, now, create=True)
            bucket.append(now)
            # Keep storage bounded if a caller forgot to check before recording.
            while len(bucket) > self.max_failures:
                bucket.popleft()

    def clear(self) -> None:
        """Reset in-memory state, primarily for deterministic test isolation."""
        with self._lock:
            self._failures.clear()
            self._overflow.clear()
