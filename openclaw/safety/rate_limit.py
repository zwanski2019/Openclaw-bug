"""Per-scope async rate limiter. Token bucket algorithm.

Enforced at executor level — every tool call acquires a token before running.
Rate set by scope.rate_limit_rps. Default 5 rps if unset.
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    rate: float           # tokens per second
    capacity: float       # max burst
    tokens: float = 0.0
    last_refill: float = 0.0
    lock: asyncio.Lock = None

    def __post_init__(self):
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self, cost: float = 1.0) -> float:
        """Block until `cost` tokens available. Returns wait time (seconds)."""
        async with self.lock:
            waited = 0.0
            while True:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_refill = now

                if self.tokens >= cost:
                    self.tokens -= cost
                    return waited

                deficit = cost - self.tokens
                sleep_for = deficit / self.rate
                waited += sleep_for
                await asyncio.sleep(sleep_for)


class RateLimiterRegistry:
    """Keeps one bucket per scope name. Shared across agent runs in-process."""

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def get(self, scope_name: str, rps: int) -> TokenBucket:
        async with self._lock:
            if scope_name not in self._buckets:
                self._buckets[scope_name] = TokenBucket(
                    rate=float(rps),
                    capacity=float(max(rps, 1)),
                )
            return self._buckets[scope_name]


_registry: RateLimiterRegistry | None = None


def get_registry() -> RateLimiterRegistry:
    global _registry
    if _registry is None:
        _registry = RateLimiterRegistry()
    return _registry
