"""Orchestrator: engine adapters not applicable to the target input are skipped.

These tests guard a regression: `osv-scanner` must not run against a URL
input (real incident). It is now never invoked directly.
"""

from __future__ import annotations

import pytest

from sins.adapters.nuclei import NucleiAdapter
from sins.adapters.osv import OsvAdapter
from sins.orchestrator import EngineReport, SinsOrchestrator
from sins.schemas import Category, FindingContract, Severity


class _FakeAdapter:
    """Adapter shartnomasini bajaradigan eng kichik soxta engine."""

    category = Category.vuln
    sin = "Test"

    def __init__(self, name: str, *, applies: bool, calls: list[str]) -> None:
        self.name = name
        self._applies = applies
        self._calls = calls

    def available(self) -> bool:
        return True

    def applies_to(self, target: str) -> bool:
        return self._applies

    def run(self, ctx) -> list[FindingContract]:
        self._calls.append(self.name)
        return [
            FindingContract(
                category=self.category,
                title=f"{self.name} finding",
                severity=Severity.low,
                location=ctx.target,
                dedup_key=f"{self.name}-1",
                source_tools=[self.name],
            )
        ]


def _orchestrator_with(*adapters) -> SinsOrchestrator:
    # Unknown engine name - nothing is picked from the REGISTRY.
    orch = SinsOrchestrator(["__none__"])
    orch.adapters = list(adapters)
    return orch


@pytest.mark.parametrize("target", ["https://example.com", "example.com", "10.0.0.1"])
def test_nuclei_applies_to_network_targets(target: str) -> None:
    assert NucleiAdapter().applies_to(target) is True


def test_nuclei_does_not_apply_to_local_path() -> None:
    assert NucleiAdapter().applies_to("/tmp/project") is False


@pytest.mark.parametrize("target", ["https://example.com", "example.com", "10.0.0.1"])
def test_osv_does_not_apply_to_network_targets(target: str) -> None:
    assert OsvAdapter().applies_to(target) is False


@pytest.mark.parametrize("target", ["/tmp/project", "./app", "."])
def test_osv_applies_to_local_paths(target: str) -> None:
    assert OsvAdapter().applies_to(target) is True


async def test_run_skips_inapplicable_engine_and_still_reports_progress() -> None:
    calls: list[str] = []
    runner = _FakeAdapter("runner", applies=True, calls=calls)
    skipped = _FakeAdapter("skipped", applies=False, calls=calls)
    orch = _orchestrator_with(runner, skipped)

    seen: list[EngineReport] = []

    async def on_done(engine_report: EngineReport) -> None:
        seen.append(engine_report)

    from sins.adapters import ScanContext

    report = await orch.run(ScanContext(target="https://example.com"), on_done)

    # Mos kelmagan engine umuman ishga tushmadi
    assert calls == ["runner"]

    by_name = {e.name: e for e in report.engines}
    assert by_name["runner"].skipped is False
    assert by_name["runner"].findings == 1
    assert by_name["skipped"].skipped is True
    assert by_name["skipped"].ok is True
    assert "does not apply" in (by_name["skipped"].skip_reason or "")

    # The progress callback fires for both engines - progress reaches 100%
    assert {e.name for e in seen} == {"runner", "skipped"}
    assert len(report.findings) == 1
