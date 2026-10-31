"""Deduplikatsiya va korrelyatsiya.

Bu — "aggregator" deb atalgan narsaning haqiqiy qiyin qismi.
Bitta CVE ni nuclei, nmap-vulners va trivy uchtasi ham topadi.
Ularni BITTA finding qilish kerak, uchta emas.
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
    """Bitta tool ichidagi takrorlarni yo'qotish uchun aniq kalit."""
    raw = "|".join(p.strip().lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")[:80]


def normalize_cve(values: list[str]) -> list[str]:
    """CVE ID'larni yagona formatga keltiradi: `cve-2021-44228` -> `CVE-2021-44228`."""
    out = {str(v).strip().upper() for v in values if str(v).strip()}
    return sorted(v for v in out if v.startswith("CVE-"))


def correlate_key(finding: FindingContract) -> str:
    """Turli tool'lar topgan bir xil muammoni bir joyga yig'ish uchun kalit."""
    loc = normalize_location(finding.location)
    host = loc.split("/")[0]
    if finding.cve:
        # CVE bo'lsa — host + CVE to'plami. Ikki tool bir xil CVE topsa, birlashadi.
        return f"{host}|cve:{','.join(sorted(finding.cve))}"
    # CVE yo'q bo'lsa — title + sub_id. sub_id bo'lmasa, mayda topilmalar
    # noto'g'ri birlashib ketadi (masalan 10 ta yo'q header -> 1 ta finding).
    return f"{host}|{_slug(finding.title)}|{finding.sub_id or ''}"


def correlate(findings: list[FindingContract]) -> list[FindingContract]:
    """Bir xil muammoni birlashtiradi, eng yuqori severity va barcha manbalarni saqlaydi."""
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
