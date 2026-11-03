"""API kalitlari va boshqa maxfiy qiymatlar.

Qoida: API kalit bazada OCHIQ saqlanmaydi. Faqat SHA-256 hash.
Kalit foydalanuvchiga bir marta ko'rsatiladi (yaratilganda).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

API_KEY_PREFIX = "sins_"
_PREFIX_LEN = 12  # foydalanuvchiga ko'rsatiladigan qism: "sins_ab12cd3"


def generate_api_key() -> str:
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def hash_api_key(raw: str) -> str:
    """Tez qidiruv uchun SHA-256 (kalit 256 bit entropy — brute-force mumkin emas)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def display_prefix(raw: str) -> str:
    return raw[:_PREFIX_LEN]


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
