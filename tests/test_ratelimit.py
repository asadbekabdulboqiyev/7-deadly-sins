"""Token-bucket rate limiter: chegara, to'ldirish, kalit xavfsizligi."""

from __future__ import annotations

import pytest

from sins.ratelimit import TokenBucketLimiter


class _Clock:
    """Boshqariladigan monotonik vaqt — real `sleep` kerak emas."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr("sins.ratelimit.time.monotonic", fake)
    return fake


async def test_burst_within_capacity_is_allowed(clock) -> None:
    limiter = TokenBucketLimiter(capacity=3, window_seconds=60)

    for _ in range(3):
        allowed, retry_after = await limiter.acquire("k")
        assert allowed is True
        assert retry_after == 0.0


async def test_exceeding_capacity_is_denied_with_retry_after(clock) -> None:
    limiter = TokenBucketLimiter(capacity=2, window_seconds=60)
    await limiter.acquire("k")
    await limiter.acquire("k")

    allowed, retry_after = await limiter.acquire("k")
    assert allowed is False
    assert retry_after > 0


async def test_tokens_refill_over_time(clock) -> None:
    limiter = TokenBucketLimiter(capacity=2, window_seconds=60)  # 30 s / token
    await limiter.acquire("k")
    await limiter.acquire("k")
    assert (await limiter.acquire("k"))[0] is False

    clock.advance(30.1)
    allowed, _ = await limiter.acquire("k")
    assert allowed is True


async def test_refill_is_capped_at_capacity(clock) -> None:
    limiter = TokenBucketLimiter(capacity=1, window_seconds=60)
    clock.advance(10_000)
    assert (await limiter.acquire("k"))[0] is True
    assert (await limiter.acquire("k"))[0] is False


async def test_keys_are_independent(clock) -> None:
    limiter = TokenBucketLimiter(capacity=1, window_seconds=60)

    assert (await limiter.acquire("a"))[0] is True
    assert (await limiter.acquire("b"))[0] is True
    assert (await limiter.acquire("a"))[0] is False


def test_key_for_hashes_api_key_and_hides_raw_value() -> None:
    key = "sins_super-secret-value"
    derived = TokenBucketLimiter.key_for(key, "10.0.0.1")

    assert derived.startswith("key:")
    assert "super-secret" not in derived
    assert TokenBucketLimiter.key_for(key, "10.0.0.2") == derived


def test_key_for_falls_back_to_ip() -> None:
    assert TokenBucketLimiter.key_for(None, "10.1.2.3") == "ip:10.1.2.3"
    assert TokenBucketLimiter.key_for(None, None) == "ip:unknown"


@pytest.mark.parametrize("capacity", [0, -1])
def test_invalid_capacity_is_rejected(capacity: int) -> None:
    with pytest.raises(ValueError):
        TokenBucketLimiter(capacity=capacity)


async def test_bucket_map_is_bounded(clock) -> None:
    limiter = TokenBucketLimiter(capacity=1, window_seconds=60, max_keys=10)

    for index in range(40):
        await limiter.acquire(f"key-{index}")

    assert len(limiter._buckets) <= 10
