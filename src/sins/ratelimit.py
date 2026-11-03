"""Tenant/kalit bo'yicha token-bucket rate limit.

Chegara jarayon ichida, kalitning SHA-256 qismi bo'yicha yuritiladi —
ochiq kalit xotirada saqlanmaydi. Ko'p instansiya uchun aniq global limit
kerak bo'lsa, Redis'ga ko'chiriladi; bitta instansiyada bu yetarli va
hech qanday tashqi bog'liqlik talab qilmaydi.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .security import hash_api_key


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    def __init__(
        self,
        capacity: int,
        window_seconds: float = 60.0,
        *,
        max_keys: int = 20_000,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity >= 1 bo'lishi kerak")
        self.capacity = float(capacity)
        self.window_seconds = window_seconds
        self.rate = self.capacity / window_seconds  # token/sekund
        self.max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def key_for(api_key: str | None, client_ip: str | None) -> str:
        if api_key:
            return f"key:{hash_api_key(api_key)[:24]}"
        return f"ip:{client_ip or 'unknown'}"

    async def acquire(self, key: str) -> tuple[bool, float]:
        """Bitta token oladi. (ruxsat, retry_after_seconds) qaytaradi."""
        now = time.monotonic()
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
                self._evict(now)
            else:
                elapsed = now - bucket.updated
                bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate)
                bucket.updated = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0

            missing = 1.0 - bucket.tokens
            return False, round(missing / self.rate, 3)

    def _evict(self, now: float) -> None:
        """Bucketlar soni chegaradan oshsa — eskilarni tashlaydi."""
        if len(self._buckets) <= self.max_keys:
            return
        ordered = sorted(self._buckets.items(), key=lambda item: item[1].updated)
        for key, _ in ordered[: len(ordered) // 4]:
            if now - self._buckets[key].updated > self.window_seconds:
                self._buckets.pop(key, None)
        if len(self._buckets) > self.max_keys:
            self._buckets.clear()
