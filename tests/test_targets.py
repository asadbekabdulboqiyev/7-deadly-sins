"""Nishon qoidalari: klassifikatsiya, tozalash, lab-cheklovi."""

from __future__ import annotations

import pytest

from sins.targets import (
    InvalidTarget,
    classify_target,
    extract_host,
    is_lab_target,
    normalize_target,
)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("example.com", "domain"),
        ("sub.example.co.uk", "domain"),
        ("https://example.com/login?x=1", "url"),
        ("http://localhost:8099", "url"),
        ("10.0.0.5", "ip"),
        ("::1", "ip"),
        ("/tmp/project", "path"),
        ("./app", "path"),
    ],
)
def test_classify_target(value: str, kind: str) -> None:
    assert classify_target(value) == kind


def test_extract_host_handles_scheme_port_and_ipv6() -> None:
    assert extract_host("https://Example.COM:8443/path?a=1") == "example.com"
    assert extract_host("example.com:443") == "example.com"
    assert extract_host("[::1]:8080") == "::1"


def test_normalize_url_keeps_scheme_but_drops_trailing_slash() -> None:
    assert normalize_target("https://Example.com/") == "https://Example.com"


def test_normalize_domain_lowercases_and_strips_dot() -> None:
    assert normalize_target("EXAMPLE.com.") == "example.com"


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "-u example.com", "exa mple.com", "a" * 256, "example.com\n--flag"],
)
def test_normalize_rejects_bad_input(bad: str) -> None:
    with pytest.raises(InvalidTarget):
        normalize_target(bad)


@pytest.mark.parametrize(
    "value",
    ["localhost", "127.0.0.1", "10.1.2.3", "http://192.168.1.5:8080", "app.local", "::1"],
)
def test_lab_targets(value: str) -> None:
    assert is_lab_target(value) is True


@pytest.mark.parametrize(
    "value", ["example.com", "8.8.8.8", "http://example.com", "api.github.com"]
)
def test_public_targets_are_not_lab(value: str) -> None:
    assert is_lab_target(value) is False
