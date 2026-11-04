"""Wrath adapter tests - for the exploit confirmation pass."""

from __future__ import annotations

import json
from typing import Any

from sins.adapters.base import ScanContext
from sins.adapters.wrath import WrathAdapter
from sins.runner import RunResult
from sins.schemas import Category, FindingContract, Severity

_PRIOR = [
    FindingContract(
        category=Category.vuln,
        title="Log4j RCE",
        severity=Severity.critical,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        location="https://example.com:443/api",
        source_tools=["nuclei"],
        dedup_key="nuclei:abc123:log4j",
    ),
]


def _payload(*, template_id: str = "tpl-log4j", cve: list[str] | None = None) -> dict[str, Any]:
    return {
        "template-id": template_id,
        "host": "example.com",
        "matched-at": "example.com:443",
        "type": "http",
        "matcher-name": "log4j-header",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical",
            "description": "RCE via log4j",
            "classification": {
                "cve-id": cve or ["CVE-2021-44228"],
                "cwe-id": ["CWE-94"],
                "cvss-score": 10.0,
            },
        },
    }


def _result(payloads: list[dict[str, Any]]) -> RunResult:
    stdout = "".join(json.dumps(p) + "\n" for p in payloads)
    return RunResult(argv=["nuclei"], returncode=0, stdout=stdout, duration_ms=1)


def test_confirms_prior_finding_that_reproduces() -> None:
    adapter = WrathAdapter(prior=_PRIOR)
    findings = adapter.parse(_result([_payload()]), "https://example.com")

    assert len(findings) == 1
    confirmed = findings[0]
    assert confirmed.title == "Confirmed exploit: Log4j RCE: log4j-header"
    assert confirmed.category is Category.exploit
    assert confirmed.evidence.get("confirmed") is True
    assert confirmed.evidence.get("source") == "wrath"
    assert confirmed.source_tools == ["nuclei", "wrath"]
    assert confirmed.dedup_key.startswith("wrath|")


def test_does_not_confirm_when_no_prior_matches() -> None:
    adapter = WrathAdapter(prior=_PRIOR)
    findings = adapter.parse(
        _result([_payload(template_id="tpl-other", cve=["CVE-2022-0000"])]), "https://example.com"
    )
    assert findings == []


def test_without_prior_findings_nothing_is_confirmed() -> None:
    adapter = WrathAdapter()
    findings = adapter.parse(_result([_payload()]), "https://example.com")
    assert findings == []


def test_run_without_templates_returns_empty() -> None:
    adapter = WrathAdapter()
    assert adapter.run(ScanContext(target="https://example.com")) == []
