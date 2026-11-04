"""Exposure lifecycle logic — the differentiator of the product.

A single scanner gives one snapshot. This module gives a timeline: which
findings appeared, how long they stayed open, whether they were resolved and
whether they came back (regression).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from .models import FindingState

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.0,
}


def fingerprint(
    *,
    target: str,
    category: str,
    title: str,
    location: str,
    cve: list[str],
) -> str:
    """Stable fingerprint of one distinct finding on one target."""
    raw = "|".join(
        [
            target.strip().lower(),
            category.strip().lower(),
            title.strip().lower(),
            location.strip().lower(),
            ",".join(sorted(cve)),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def weight(severity: str) -> float:
    """Numeric weight of a severity for the exposure score."""
    return SEVERITY_WEIGHTS.get(str(severity).lower(), 0.0)


def exposure_score(states: list[FindingState]) -> float:
    """Exposure score for a target: 0..100 over its currently open findings."""
    open_states = [s for s in states if s.status == "open"]
    if not open_states:
        return 0.0
    total = sum(weight(s.severity) for s in open_states)
    ceiling = 10.0 * len(open_states)
    return round(100.0 * total / max(1.0, ceiling), 2)


def age_days(last_seen_at: datetime, *, now: datetime | None = None) -> float:
    """Whole days since the last observation of a finding."""
    reference = now or datetime.now(UTC)
    delta = max(0.0, (reference - last_seen_at).total_seconds() / 86400.0)
    return float(int(delta))
