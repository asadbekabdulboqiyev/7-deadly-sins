"""Exposure drift - fingerprint, weights, score and age."""

from __future__ import annotations

from types import SimpleNamespace

from sins import drift


def _state(*, status: str = "open", severity: str = "high") -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        severity=severity,
        first_seen_at=None,
        last_seen_at=None,
        resolved_at=None,
    )


def test_fingerprint_is_stable() -> None:
    kwargs = {
        "target": "https://example.com",
        "category": "vuln",
        "title": "Log4j RCE",
        "location": "https://example.com:443/api",
        "cve": ["CVE-2021-44228"],
    }
    assert drift.fingerprint(**kwargs) == drift.fingerprint(**kwargs)


def test_fingerprint_differs_by_target() -> None:
    kwargs = {
        "target": "https://example.com",
        "category": "vuln",
        "title": "Log4j RCE",
        "location": "https://example.com:443/api",
        "cve": ["CVE-2021-44228"],
    }
    other = dict(kwargs, target="https://evil.example")
    assert drift.fingerprint(**kwargs) != drift.fingerprint(**other)


def test_weight_per_severity() -> None:
    assert drift.weight("critical") == 10.0
    assert drift.weight("high") == 5.0
    assert drift.weight("medium") == 2.0
    assert drift.weight("low") == 1.0
    assert drift.weight("info") == 0.0
    assert drift.weight("unknown") == 0.0


def test_exposure_score_is_percentage_of_open_findings() -> None:
    states = [
        _state(severity="critical"),
        _state(severity="high"),
        _state(severity="medium"),
    ]
    # (10 + 5 + 2) / (10 * 3) * 100 = 56.67
    assert drift.exposure_score(states) == 56.67


def test_exposure_score_is_zero_without_open_findings() -> None:
    assert drift.exposure_score([_state(status="resolved", severity="critical")]) == 0.0
    assert drift.exposure_score([]) == 0.0


def test_age_days_counts_from_last_seen() -> None:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    assert drift.age_days(now, now=now) == 0
    assert drift.age_days(now - timedelta(days=3), now=now) == 3
