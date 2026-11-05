"""FIRST EPSS: the probability that a CVE is exploited in the next 30 days.

Why EPSS: CVSS describes how bad exploitation would be, not how likely it is.
EPSS is a live, model-driven probability (0-1) with a percentile, so two
findings with the same severity can finally be ordered against each other.
"""

from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"

# The public API accepts a bounded list per request. Keep chunks small so a
# single slow request cannot stall the whole report.
CHUNK_SIZE = 100


def _as_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def parse_scores(payload: dict) -> dict[str, tuple[float | None, float | None]]:
    """``CVE -> (epss, percentile)`` from one EPSS response."""
    rows = payload.get("data")
    if not isinstance(rows, list):
        log.warning("EPSS payload has no `data` list — ignoring")
        return {}

    out: dict[str, tuple[float | None, float | None]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = (_as_float(row.get("epss")), _as_float(row.get("percentile")))
    return out


async def fetch_scores(
    client: httpx.AsyncClient, cves: list[str], *, timeout: float = 8.0
) -> dict[str, tuple[float | None, float | None]]:
    """Scores for every requested CVE. Missing CVEs simply have no entry."""
    scores: dict[str, tuple[float | None, float | None]] = {}

    for start in range(0, len(cves), CHUNK_SIZE):
        chunk = cves[start : start + CHUNK_SIZE]
        try:
            response = await client.get(
                EPSS_URL,
                params={"cve": ",".join(chunk), "limit": len(chunk)},
                timeout=timeout,
            )
            response.raise_for_status()
            scores.update(parse_scores(response.json()))
        except (httpx.HTTPError, ValueError) as exc:
            # A failed chunk must not poison the whole enrichment.
            log.warning("EPSS unavailable for %d CVEs: %s", len(chunk), exc)

    return scores
