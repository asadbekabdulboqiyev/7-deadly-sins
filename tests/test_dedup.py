from __future__ import annotations

from sins.dedup import correlate, dedup_key, normalize_cve, normalize_location
from sins.schemas import Category, FindingContract, Severity


def _finding(**overrides) -> FindingContract:
    base = {
        "category": Category.vuln,
        "title": "Test Finding",
        "severity": Severity.medium,
        "location": "example.com:443/api",
        "dedup_key": "k",
        "source_tools": ["nuclei"],
    }
    return FindingContract(**{**base, **overrides})


def test_normalize_location_strips_scheme_and_slash() -> None:
    assert normalize_location("https://Example.COM:443/api/") == "example.com:443/api"
    assert normalize_location("http://example.com/") == "example.com"


def test_dedup_key_is_stable() -> None:
    a = dedup_key("nuclei", "example.com", "tmpl", "http://example.com/x")
    b = dedup_key("NUCLEI", "example.com", "TMPL", "http://example.com/x")
    assert a == b


def test_normalize_cve() -> None:
    assert normalize_cve(["cve-2021-44228", "CVE-2021-44228", "GHSA-x"]) == ["CVE-2021-44228"]


def test_correlate_merges_same_cve_from_two_tools() -> None:
    a = _finding(cve=["CVE-2021-44228"], severity=Severity.medium, source_tools=["nuclei"])
    b = _finding(cve=["CVE-2021-44228"], severity=Severity.critical, source_tools=["nmap-vulners"])

    merged = correlate([a, b])

    assert len(merged) == 1, "bir xil CVE ikki tool'da topilsa — bitta finding bo'lishi kerak"
    assert merged[0].severity is Severity.critical, "eng yuqori severity saqlanadi"
    assert set(merged[0].source_tools) == {"nuclei", "nmap-vulners"}
    assert "corroborating" in merged[0].evidence


def test_correlate_keeps_distinct_findings_separate() -> None:
    a = _finding(cve=["CVE-2021-44228"], location="example.com:443/api")
    b = _finding(cve=["CVE-2022-0001"], location="example.com:443/api")
    assert len(correlate([a, b])) == 2


def test_correlate_sorts_by_severity() -> None:
    findings = [
        _finding(title="low one", severity=Severity.low, location="a.com"),
        _finding(title="critical one", severity=Severity.critical, location="b.com"),
    ]
    merged = correlate(findings)
    assert merged[0].severity is Severity.critical


def test_correlate_keeps_distinct_matchers_apart() -> None:
    """Bitta template, turli matcher -> turli finding (10 ta header = 10 ta finding)."""
    findings = [
        _finding(title="HTTP Missing Security Headers", location="a.com", sub_id=mid)
        for mid in ("content-security-policy", "x-frame-options", "referrer-policy")
    ]
    assert len(correlate(findings)) == 3
