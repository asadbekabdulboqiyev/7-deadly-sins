"""Deduplication and correlation.

This is the genuinely hard part of what people call an "aggregator".
A single CVE is found by nuclei, nmap-vulners and trivy all at once.
They must become ONE finding, not three.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from urllib.parse import urlparse

from .schemas import SEVERITY_ORDER, FindingContract, Severity

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_location(location: str) -> str:
    """`https://Example.com:443/path/` -> `example.com:443/path`"""
    raw = location.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path.rstrip("/")
        return f"{host}{port}{path}".lower()
    return raw.rstrip("/").lower()


def dedup_key(*parts: str) -> str:
    """Exact key for removing duplicates within a single tool."""
    raw = "|".join(p.strip().lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")[:80]


def normalize_cve(values: list[str]) -> list[str]:
    """Normalizes CVE IDs to a single format: `cve-2021-44228` -> `CVE-2021-44228`."""
    out = {str(v).strip().upper() for v in values if str(v).strip()}
    return sorted(v for v in out if v.startswith("CVE-"))


def correlate_key(finding: FindingContract) -> str:
    """Key for grouping the same issue found by different tools into one entry."""
    loc = normalize_location(finding.location)
    host = loc.split("/")[0]
    if finding.cve:
        # With a CVE — host + CVE set. Two tools reporting the same CVE merge.
        return f"{host}|cve:{','.join(sorted(finding.cve))}"
    # Without a CVE — title + sub_id. Without sub_id, minor findings
    # would merge incorrectly (e.g. 10 missing headers -> 1 finding).
    return f"{host}|{_slug(finding.title)}|{finding.sub_id or ''}"


def correlate(findings: list[FindingContract]) -> list[FindingContract]:
    """Merges the same issue, keeping the highest severity and all sources."""
    buckets: dict[str, list[FindingContract]] = defaultdict(list)
    for f in findings:
        buckets[correlate_key(f)].append(f)

    merged: list[FindingContract] = []
    for group in buckets.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        merged.append(_merge(group))

    merged.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return merged


def _merge(group: list[FindingContract]) -> FindingContract:
    best = max(group, key=lambda f: (SEVERITY_ORDER[f.severity], f.cvss or 0.0))
    tools: list[str] = []
    for f in group:
        for t in f.source_tools:
            if t not in tools:
                tools.append(t)

    cve = sorted({c for f in group for c in f.cve})
    cwe = sorted({c for f in group for c in f.cwe})

    evidence = {
        "primary": best.evidence,
        "corroborating": [
            {"tool": f.source_tools, "evidence": f.evidence} for f in group if f is not best
        ],
    }

    return best.model_copy(
        update={
            "severity": max((f.severity for f in group), key=SEVERITY_ORDER.__getitem__),
            "cve": cve,
            "cwe": cwe,
            "source_tools": tools,
            "evidence": evidence,
        }
    )


def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.info
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.info
