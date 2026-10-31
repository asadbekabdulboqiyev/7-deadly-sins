from __future__ import annotations

from pathlib import Path

from sins.adapters.nuclei import NucleiAdapter
from sins.runner import RunResult
from sins.schemas import Category, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei.jsonl"


def _result() -> RunResult:
    return RunResult(argv=["nuclei"], returncode=0, stdout=FIXTURE.read_text(), duration_ms=10)


def test_parses_findings_and_skips_stats() -> None:
    findings = NucleiAdapter().parse(_result(), "http://localhost:8099")
    assert len(findings) == 3, "stats satri topilma sifatida qabul qilinmasligi kerak"


def test_critical_cve_is_normalized() -> None:
    findings = NucleiAdapter().parse(_result(), "http://localhost:8099")
    log4j = next(f for f in findings if "Log4j" in f.title)
    assert log4j.severity is Severity.critical
    assert log4j.cve == ["CVE-2021-44228"], "CVE ID katta harfga keltirilishi kerak"
    assert log4j.cvss == 10.0
    assert log4j.category is Category.vuln
    assert log4j.source_tools == ["nuclei"]


def test_location_is_normalized() -> None:
    findings = NucleiAdapter().parse(_result(), "http://localhost:8099")
    log4j = next(f for f in findings if "Log4j" in f.title)
    assert log4j.location == "localhost:8099/api/login"


def test_missing_classification_does_not_crash() -> None:
    findings = NucleiAdapter().parse(_result(), "http://localhost:8099")
    tech = next(f for f in findings if "Wappalyzer" in f.title)
    assert tech.cve == []
    assert tech.cvss is None
    assert tech.severity is Severity.info


def test_garbage_lines_ignored() -> None:
    result = RunResult(
        argv=["nuclei"], returncode=0, stdout='not json\n{"broken": \n{"a":1}\n', duration_ms=1
    )
    assert NucleiAdapter().parse(result, "http://localhost") == []
