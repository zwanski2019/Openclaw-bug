"""Token-bucket rate limiter tests."""
import time
import pytest
from openclaw.safety.rate_limit import TokenBucket, RateLimiterRegistry


@pytest.mark.asyncio
async def test_bucket_immediate_when_tokens_available():
    bucket = TokenBucket(rate=10.0, capacity=10.0)
    waited = await bucket.acquire(1.0)
    assert waited == 0.0


@pytest.mark.asyncio
async def test_bucket_refills_over_time():
    bucket = TokenBucket(rate=10.0, capacity=2.0)
    # Drain the bucket
    await bucket.acquire(2.0)
    # Now next acquire should wait ~100ms for 1 token at 10 rps
    t0 = time.perf_counter()
    await bucket.acquire(1.0)
    elapsed = time.perf_counter() - t0
    # Allow some wiggle, just ensure it actually waited
    assert 0.05 < elapsed < 0.3


@pytest.mark.asyncio
async def test_bucket_enforces_rate_on_many_requests():
    bucket = TokenBucket(rate=5.0, capacity=5.0)
    t0 = time.perf_counter()
    for _ in range(10):
        await bucket.acquire(1.0)
    elapsed = time.perf_counter() - t0
    # 10 requests at 5 rps with capacity 5: first 5 free, next 5 take ~1s
    assert elapsed >= 0.8


@pytest.mark.asyncio
async def test_registry_isolates_scopes():
    reg = RateLimiterRegistry()
    b1 = await reg.get("scope-a", 5)
    b2 = await reg.get("scope-b", 5)
    assert b1 is not b2

    b1_again = await reg.get("scope-a", 5)
    assert b1 is b1_again  # same scope returns same bucket
