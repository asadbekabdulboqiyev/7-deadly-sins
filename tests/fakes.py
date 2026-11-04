"""Fake orchestrator for tests - no real tool or network needed."""

from __future__ import annotations

from typing import Any

from sins.orchestrator import EngineReport, ScanReport
from sins.schemas import Category, FindingContract, Remediation, Severity


def sample_findings() -> list[FindingContract]:
    return [
        FindingContract(
            category=Category.vuln,
            title="Apache Log4j2 Remote Code Execution",
            severity=Severity.critical,
            cvss=10.0,
            cve=["CVE-2021-44228"],
            location="example.com:443/api",
            dedup_key="k1",
            source_tools=["nuclei"],
            remediation=Remediation(
                summary="Upgrade log4j-core to 2.17.1",
                steps=["log4j-core@2.14.1 -> 2.17.1"],
                fixed_version="2.17.1",
            ),
        ),
        FindingContract(
            category=Category.misconfig,
            title="Server version disclosure detected",
            severity=Severity.low,
            location="example.com",
            dedup_key="k2",
            source_tools=["nuclei"],
        ),
        FindingContract(
            category=Category.dependency,
            title="Prototype Pollution in lodash",
            severity=Severity.high,
            cve=["CVE-2020-8203"],
            location="package.json:lodash@4.17.15",
            dedup_key="k3",
            source_tools=["osv"],
        ),
    ]


class FakeOrchestrator:
    """Instead of `SinsOrchestrator`: the adapter is not called, the result is returned directly."""

    def __init__(self, engines: list[str] | None = None) -> None:
        self.engines = list(
            engines or ["nuclei", "osv", "pride", "envy", "lust", "gluttony", "wrath"]
        )
        self.adapters: list[Any] = list(self.engines)

    async def run(self, ctx: Any, on_engine_done: Any = None) -> ScanReport:
        report = ScanReport(target=ctx.target)
        for name in self.engines:
            engine_report = EngineReport(name=name, sin="Greed", ok=True, findings=1, duration_ms=5)
            report.engines.append(engine_report)
            if on_engine_done is not None:
                await on_engine_done(engine_report)
        report.findings = sample_findings()
        report.duration_ms = 10
        return report
