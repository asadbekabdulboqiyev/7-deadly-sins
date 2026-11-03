"""API kalitlari: format, hash, taqqoslash."""

from __future__ import annotations

from sins.security import (
    constant_time_eq,
    display_prefix,
    generate_api_key,
    hash_api_key,
)


def test_key_has_prefix_and_entropy() -> None:
    key = generate_api_key()
    assert key.startswith("sins_")
    assert len(key) > 30


def test_keys_are_unique() -> None:
    assert len({generate_api_key() for _ in range(50)}) == 50


def test_hash_is_stable_and_hides_plaintext() -> None:
    key = generate_api_key()
    digest = hash_api_key(key)
    assert digest == hash_api_key(key)
    assert len(digest) == 64
    assert key not in digest
    assert digest != hash_api_key(generate_api_key())


def test_prefix_is_short_and_matches() -> None:
    key = generate_api_key()
    prefix = display_prefix(key)
    assert len(prefix) == 12
    assert key.startswith(prefix)


def test_constant_time_eq() -> None:
    assert constant_time_eq("abc", "abc") is True
    assert constant_time_eq("abc", "abd") is False
