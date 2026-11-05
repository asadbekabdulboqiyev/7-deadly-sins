"""Threat-intel enrichment: parsing, merging and graceful degradation.

No test in this module touches the network — every request goes through an
``httpx.MockTransport`` so the suite stays deterministic and offline.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from sins.intel import enrich, normalise_cves
from sins.intel import epss as epss_module
from sins.intel import kev as kev_module
from sins.intel.models import CveIntel, ThreatIntel
from sins.report import build_context, render_html, render_pdf
from sins.schemas import Category, FindingContract, Severity

KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "knownRansomwareCampaignUse": "Known",
        },
        {"cveID": "CVE-2023-0001", "dateAdded": "2023-02-01"},
        {"cveID": "not-a-cve", "dateAdded": "2023-02-01"},
        {"nothing": "useful"},
    ]
}

EPSS_PAYLOAD = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97420", "percentile": "0.99900"},
        {"cve": "CVE-2023-0001", "epss": "0.00120", "percentile": "0.21000"},
        {"cve": "CVE-2020-1111", "epss": "0.50000", "percentile": "0.88000"},
        {"cve": "CVE-2020-9999", "epss": "oops", "percentile": None},
    ],
}


def _finding(severity: Severity, title: str, **kw) -> FindingContract:
    return FindingContract(
        category=Category.vuln,
        title=title,
        severity=severity,
        location="example.com",
        dedup_key=title.lower(),
        source_tools=["nuclei"],
        **kw,
    )


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _clear_kev_cache():
    kev_module.reset_cache()
    yield
    kev_module.reset_cache()


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_normalise_cves_dedupes_and_filters() -> None:
    assert normalise_cves(["cve-2021-44228", "CVE-2021-44228", "CWE-79", " "]) == ["CVE-2021-44228"]


def test_kev_catalogue_parsing_skips_malformed_rows() -> None:
    catalogue = kev_module.parse_catalogue(KEV_PAYLOAD)

    assert set(catalogue) == {"CVE-2021-44228", "CVE-2023-0001"}
    assert catalogue["CVE-2021-44228"] == {"ransomware": True, "added": "2021-12-10"}
    assert catalogue["CVE-2023-0001"]["ransomware"] is False


def test_kev_catalogue_without_list_is_empty() -> None:
    assert kev_module.parse_catalogue({"wrong": "shape"}) == {}


def test_epss_parsing_tolerates_bad_numbers() -> None:
    scores = epss_module.parse_scores(EPSS_PAYLOAD)

    assert scores["CVE-2021-44228"] == (0.9742, 0.999)
    assert scores["CVE-2020-9999"] == (None, None)


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------


async def test_enrich_merges_kev_and_epss() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json=KEV_PAYLOAD)
        return httpx.Response(200, json=EPSS_PAYLOAD)

    result = await enrich(
        ["CVE-2021-44228", "CVE-2023-0001", "CVE-2020-1111", "CVE-2019-0000"],
        client=_client(handler),
    )

    assert result.kev_available is True
    assert result.epss_available is True
    log4j = result.by_cve["CVE-2021-44228"]
    assert log4j.kev is True
    assert log4j.kev_ransomware is True
    assert log4j.epss_percent == 97
    assert log4j.epss_label == "97.4%"
    assert log4j.percentile_percent == 100
    # Present in EPSS only, so it is reported — but never as KEV.
    only_epss = result.by_cve["CVE-2020-1111"]
    assert only_epss.kev is False
    assert only_epss.epss_percent == 50
    assert only_epss.epss_label == "50.0%"
    # Unknown to both sources: no invented entry.
    assert "CVE-2019-0000" not in result.by_cve


async def test_enrich_returns_empty_without_cves() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request expected")

    result = await enrich([], client=_client(handler))
    assert result == ThreatIntel()


async def test_enrich_never_raises_when_sources_are_down() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    result = await enrich(["CVE-2021-44228"], client=_client(handler))

    assert result.by_cve == {}
    # "Unknown" must not be presented as "clean".
    assert result.kev_available is False
    assert result.epss_available is False


async def test_enrich_survives_non_json_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    result = await enrich(["CVE-2021-44228"], client=_client(handler))
    assert result.by_cve == {}


def test_for_cves_prefers_kev_then_highest_epss() -> None:
    intel = ThreatIntel(
        by_cve={
            "CVE-2021-0001": CveIntel(cve="CVE-2021-0001", epss=0.9),
            "CVE-2021-0002": CveIntel(cve="CVE-2021-0002", kev=True, epss=0.01),
        }
    )
    best = intel.for_cves(["CVE-2021-0001", "CVE-2021-0002"])
    assert best is not None and best.cve == "CVE-2021-0002"
    assert intel.for_cves(["CVE-1999-0001"]) is None


# --------------------------------------------------------------------------
# Report integration
# --------------------------------------------------------------------------


def _ctx(findings: list[FindingContract], intel: ThreatIntel | None) -> dict:
    return build_context(
        scan_id="scan_intel",
        target="example.com",
        tenant_name="Client",
        findings=findings,
        engines=[{"name": "nuclei", "sin": "Greed", "ok": True, "findings": 1, "duration_ms": 900}],
        duration_ms=900,
        generated_at=datetime(2026, 11, 5, 9, 0, tzinfo=UTC),
        intel=intel,
    )


def test_report_shows_kev_and_epss_for_enriched_cves() -> None:
    intel = ThreatIntel(
        by_cve={
            "CVE-2021-44228": CveIntel(
                cve="CVE-2021-44228",
                kev=True,
                kev_ransomware=True,
                kev_added="2021-12-10",
                epss=0.9742,
                epss_percentile=0.999,
            )
        },
        kev_available=True,
        epss_available=True,
    )
    ctx = _ctx([_finding(Severity.critical, "Log4j RCE", cve=["CVE-2021-44228"])], intel)
    html = render_html(ctx)

    assert ctx["intel_exploited"] == 1
    assert "CISA KEV" in html
    assert "known ransomware use" in html
    assert "97.4% probability of exploitation" in html
    assert "checked against the CISA Known Exploited" in html


def test_pdf_renders_with_threat_intel() -> None:
    intel = ThreatIntel(
        by_cve={
            "CVE-2021-44228": CveIntel(
                cve="CVE-2021-44228", kev=True, kev_added="2021-12-10", epss=0.9742
            )
        },
        kev_available=True,
        epss_available=True,
    )
    ctx = _ctx([_finding(Severity.critical, "Log4j RCE", cve=["CVE-2021-44228"])], intel)
    assert render_pdf(ctx).startswith(b"%PDF")


def test_report_states_intel_was_not_consulted() -> None:
    ctx = _ctx([_finding(Severity.high, "Open redirect", cve=["CVE-2021-44228"])], None)
    html = render_html(ctx)

    assert ctx["intel_exploited"] == 0
    assert "were not consulted" in html
    assert "CISA KEV" not in html


def test_report_marks_unreachable_kev_as_unknown() -> None:
    intel = ThreatIntel(kev_available=False, epss_available=False)
    ctx = _ctx([_finding(Severity.high, "Open redirect", cve=["CVE-2021-44228"])], intel)
    html = render_html(ctx)

    assert "could not be reached" in html
