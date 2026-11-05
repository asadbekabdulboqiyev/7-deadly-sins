"""CISA KEV: the catalogue of vulnerabilities known to be exploited in the wild.

Why KEV first: a CVE that appears here is not a theoretical risk. Attackers
already have working exploitation for it, so it sorts above everything else
regardless of CVSS. The catalogue is public, free and updated by CISA.
"""

from __future__ import annotations

import logging
import time

import httpx

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The catalogue is ~1.5 MB and changes at most a few times a day.
# A process-local cache keeps report generation cheap.
_CACHE_TTL_SECONDS = 12 * 60 * 60
_cache: tuple[float, dict[str, dict]] | None = None


def reset_cache() -> None:
    """Drop the cached catalogue (tests, or a forced refresh)."""
    global _cache
    _cache = None


def parse_catalogue(payload: dict) -> dict[str, dict]:
    """Normalise the KEV JSON into ``CVE -> {ransomware, added}``.

    Unknown shapes are skipped instead of raising: a changed upstream schema
    must never break a report.
    """
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        log.warning("KEV payload has no `vulnerabilities` list — ignoring")
        return {}

    out: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = {
            "ransomware": str(item.get("knownRansomwareCampaignUse") or "").strip().lower()
            == "known",
            "added": item.get("dateAdded"),
        }
    return out


async def fetch_catalogue(
    client: httpx.AsyncClient, *, timeout: float = 8.0
) -> dict[str, dict] | None:
    """Return the catalogue, or ``None`` when it cannot be reached.

    ``None`` means "unknown", which is different from ``{}`` ("nothing
    exploited"). The distinction is kept so the report never implies that
    KEV was consulted when it was not.
    """
    global _cache
    if _cache is not None and time.monotonic() - _cache[0] < _CACHE_TTL_SECONDS:
        return _cache[1]

    try:
        response = await client.get(KEV_URL, timeout=timeout)
        response.raise_for_status()
        catalogue = parse_catalogue(response.json())
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("CISA KEV unavailable: %s", exc)
        return None

    _cache = (time.monotonic(), catalogue)
    return catalogue
