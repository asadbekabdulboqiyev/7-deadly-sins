"""Enrich CVEs with CISA KEV and FIRST EPSS.

Both sources are optional. Any failure degrades to "no intel" — a security
report must still be produced when a public API is down, and the report says
which source was consulted.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable

import httpx

from . import epss, kev
from .models import CveIntel, ThreatIntel

log = logging.getLogger(__name__)

USER_AGENT = "7-deadly-sins/1.0 (+security assessment report)"


def normalise_cves(values: Iterable[str]) -> list[str]:
    """Uppercase, de-duplicate, keep only real CVE identifiers."""
    seen: dict[str, None] = {}
    for raw in values:
        cve = str(raw).strip().upper()
        if cve.startswith("CVE-") and len(cve) > 4:
            seen.setdefault(cve, None)
    return list(seen)


async def enrich(
    cves: Iterable[str],
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 8.0,
) -> ThreatIntel:
    """Return intel for the given CVEs. Never raises on network problems."""
    wanted = normalise_cves(cves)
    if not wanted:
        return ThreatIntel()

    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    try:
        catalogue_result, scores_result = await asyncio.gather(
            kev.fetch_catalogue(client, timeout=timeout),
            epss.fetch_scores(client, wanted, timeout=timeout),
            return_exceptions=True,
        )
    finally:
        if own_client:
            await client.aclose()

    if isinstance(catalogue_result, BaseException):
        log.warning("KEV enrichment skipped: %s", catalogue_result)
        catalogue_result = None
    if isinstance(scores_result, BaseException):
        log.warning("EPSS enrichment skipped: %s", scores_result)
        scores_result = {}

    catalogue = catalogue_result or {}
    scores = scores_result or {}

    by_cve: dict[str, CveIntel] = {}
    for cve in wanted:
        entry = CveIntel(cve=cve)
        if cve in catalogue:
            entry.kev = True
            entry.kev_ransomware = bool(catalogue[cve].get("ransomware"))
            entry.kev_added = catalogue[cve].get("added")
        if cve in scores:
            entry.epss, entry.epss_percentile = scores[cve]
        if entry.kev or entry.epss is not None:
            by_cve[cve] = entry

    return ThreatIntel(
        by_cve=by_cve,
        kev_available=catalogue_result is not None,
        epss_available=bool(scores),
    )
