"""API keys and other secret values.

Rule: API keys are NEVER stored in plaintext in the database. Only a SHA-256 hash.
The key is shown to the user exactly once (at creation time).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

API_KEY_PREFIX = "sins_"
_PREFIX_LEN = 12  # user-visible prefix: "sins_ab12cd3"


def generate_api_key() -> str:
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def hash_api_key(raw: str) -> str:
    """SHA-256 for fast lookup (256-bit key entropy — brute force is infeasible)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def display_prefix(raw: str) -> str:
    return raw[:_PREFIX_LEN]


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
