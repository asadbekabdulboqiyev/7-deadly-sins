"""Orkestrator retry siyosati: vaqtinchalik xatolar qayta uriniladi, qolganlari yo'q."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sins.adapters import ScanContext
from sins.orchestrator import SinsOrchestrator, _is_retryable
from sins.schemas import Category, FindingContract, Severity


class _FlakyAdapter:
    name = "flaky"
    sin = "Test"
    category = Category.vuln

    def __init__(self, failures: int, exc_type: type[BaseException] = RuntimeError) -> None:
        self.failures = failures
        self.exc_type = exc_type
        self.calls = 0

    def available(self) -> bool:
        return True

    def applies_to(self, target: str) -> bool:
        return True

    def run(self, ctx) -> list[FindingContract]:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.exc_type("temporary failure")
        return [
            FindingContract(
                category=self.category,
                title="retry finding",
                severity=Severity.low,
                location=ctx.target,
                dedup_key="retry-1",
                source_tools=[self.name],
            )
        ]


class ToolNotFound(RuntimeError):
    """Tool not found error — never retried."""


@pytest.fixture
def fast_settings(monkeypatch):
    def _apply(max_attempts: int = 3) -> None:
        monkeypatch.setattr(
            "sins.orchestrator.get_settings",
            lambda: SimpleNamespace(
                adapter_max_attempts=max_attempts,
                adapter_retry_backoff_seconds=0.0,
            ),
        )

    return _apply


def _orchestrator(adapter) -> SinsOrchestrator:
    orch = SinsOrchestrator(["__none__"])
    orch.adapters = [adapter]
    return orch


def _ctx() -> ScanContext:
    return ScanContext(target="http://localhost:8099", max_rps=10, timeout=5)


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("t"),
        ConnectionError("c"),
        OSError("o"),
        RuntimeError("r"),
    ],
)
def test_transient_errors_are_retryable(exc: BaseException) -> None:
    assert _is_retryable(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        FileNotFoundError("f"),
        PermissionError("p"),
        ValueError("v"),
        TypeError("t"),
        ToolNotFound("yo'q"),
    ],
)
def test_permanent_errors_are_not_retryable(exc: BaseException) -> None:
    assert _is_retryable(exc) is False


def test_transient_failure_is_retried_then_succeeds(fast_settings) -> None:
    fast_settings(max_attempts=3)
    adapter = _FlakyAdapter(failures=1)

    report, findings = _orchestrator(adapter)._run_one(adapter, _ctx())

    assert report.ok is True
    assert report.attempts == 2
    assert len(findings) == 1
    assert adapter.calls == 2


def test_permanent_failure_is_not_retried(fast_settings) -> None:
    fast_settings(max_attempts=3)
    adapter = _FlakyAdapter(failures=5, exc_type=ValueError)

    report, findings = _orchestrator(adapter)._run_one(adapter, _ctx())

    assert report.ok is False
    assert report.attempts == 1
    assert findings == []
    assert adapter.calls == 1
    assert "ValueError" in (report.error or "")


def test_attempts_are_capped_at_setting(fast_settings) -> None:
    fast_settings(max_attempts=2)
    adapter = _FlakyAdapter(failures=10)

    report, _ = _orchestrator(adapter)._run_one(adapter, _ctx())

    assert report.ok is False
    assert report.attempts == 2
    assert adapter.calls == 2


def test_successful_first_attempt_reports_one(fast_settings) -> None:
    fast_settings(max_attempts=3)
    adapter = _FlakyAdapter(failures=0)

    report, _ = _orchestrator(adapter)._run_one(adapter, _ctx())

    assert report.ok is True
    assert report.attempts == 1
    assert adapter.calls == 1


async def test_run_collects_findings_after_retry(fast_settings) -> None:
    fast_settings(max_attempts=3)
    adapter = _FlakyAdapter(failures=1)

    report = await _orchestrator(adapter).run(_ctx())

    assert len(report.findings) == 1
    assert report.engines[0].attempts == 2
