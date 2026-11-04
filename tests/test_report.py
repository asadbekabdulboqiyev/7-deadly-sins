from __future__ import annotations

from datetime import UTC, datetime

from sins.report import build_context, compute_risk_score, render_html, render_pdf, risk_grade
from sins.schemas import Category, FindingContract, Remediation, Severity


def _f(severity: Severity, title: str, **kw) -> FindingContract:
    return FindingContract(
        category=kw.pop("category", Category.vuln),
        title=title,
        severity=severity,
        location=kw.pop("location", "example.com"),
        dedup_key=title.lower(),
        source_tools=["nuclei"],
        **kw,
    )


MIXED = [
    _f(Severity.critical, "Log4j RCE", cve=["CVE-2021-44228"], cvss=10.0),
    _f(Severity.high, "SQL Injection", location="example.com/login"),
    _f(Severity.medium, "Open Redirect", location="example.com/redirect"),
    _f(Severity.low, "Server Version Disclosure"),
    _f(Severity.info, "Missing CSP Header"),
]


def _ctx(findings: list[FindingContract]) -> dict:
    return build_context(
        scan_id="scan_test_001",
        target="example.com",
        tenant_name="Test Mijoz",
        findings=findings,
        engines=[
            {"name": "nuclei", "sin": "Greed", "ok": True, "findings": 5, "duration_ms": 1200}
        ],
        duration_ms=1200,
        generated_at=datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
    )


def test_risk_score_weights_severity() -> None:
    assert compute_risk_score([]) == 0.0
    assert compute_risk_score(MIXED) > compute_risk_score(MIXED[2:])


def test_risk_score_caps_at_100() -> None:
    many = [_f(Severity.critical, f"crit {i}") for i in range(20)]
    assert compute_risk_score(many) == 100.0


def test_risk_grade_thresholds() -> None:
    assert risk_grade(0) == "NONE"
    assert risk_grade(10) == "LOW"
    assert risk_grade(20) == "MEDIUM"
    assert risk_grade(50) == "HIGH"
    assert risk_grade(90) == "CRITICAL"


def test_context_counts_and_order() -> None:
    ctx = _ctx(MIXED)
    assert ctx["total_findings"] == 5
    assert ctx["counts"]["critical"] == 1
    assert ctx["counts"]["info"] == 1
    # The highest-severity finding must come first
    assert ctx["findings"][0].severity is Severity.critical


def test_html_escapes_user_content() -> None:
    """XSS-safe: the target name must be escaped in the report PDF."""
    ctx = _ctx([_f(Severity.high, "<script>alert(1)</script>")])
    html = render_html(ctx)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_renders() -> None:
    pdf = render_pdf(_ctx(MIXED))
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 5000


def test_pdf_handles_empty_findings() -> None:
    pdf = render_pdf(_ctx([]))
    assert pdf.startswith(b"%PDF")


def test_remediation_rendered() -> None:
    finding = _f(
        Severity.high,
        "Vulnerable dependency",
        category=Category.dependency,
        remediation=Remediation(
            summary="Upgrade lodash to 4.17.21",
            steps=["`lodash@4.17.20` -> `lodash@4.17.21`"],
            fixed_version="4.17.21",
        ),
    )
    html = render_html(_ctx([finding]))
    assert "lodash@4.17.21" in html
    assert "Remediation" in html
