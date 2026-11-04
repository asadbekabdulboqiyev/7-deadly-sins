"""Orchestrator — combines the 7 sins into a single scan.

Important: there is no scanning logic here.
Only adapter invocation and result correlation.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .adapters import REGISTRY, Adapter, ScanContext
from .config import get_settings
from .dedup import correlate
from .schemas import FindingContract

log = logging.getLogger(__name__)


@dataclass(slots=True)
class EngineReport:
    name: str
    sin: str
    ok: bool
    findings: int
    duration_ms: int
    error: str | None = None
    # How many attempts were needed (attempts > 1 when retried).
    attempts: int = 1
    # The target type does not apply to this engine — it was not run.
    skipped: bool = False
    skip_reason: str | None = None


@dataclass(slots=True)
class ScanReport:
    target: str
    engines: list[EngineReport] = field(default_factory=list)
    findings: list[FindingContract] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def raw_finding_count(self) -> int:
        return sum(e.findings for e in self.engines)


EngineCallback = Callable[[EngineReport], Awaitable[None]]


def _is_retryable(exc: BaseException) -> bool:
    """Errors for which a retry makes sense."""
    if isinstance(exc, (FileNotFoundError, PermissionError, ValueError, TypeError)):
        return False
    if type(exc).__name__ == "ToolNotFound":
        return False
    return isinstance(
        exc,
        (
            TimeoutError,
            ConnectionError,
            OSError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ),
    )


class SinsOrchestrator:
    def __init__(self, engines: list[str] | None = None) -> None:
        selected = engines or list(REGISTRY)
        self.adapters: list[Adapter] = []
        for name in selected:
            adapter = REGISTRY.get(name)
            if adapter is None:
                log.warning("unknown engine: %s — skipped", name)
                continue
            if not adapter.available():
                log.warning("%s not found — skipped", name)
                continue
            self.adapters.append(adapter)

    async def run(
        self,
        ctx: ScanContext,
        on_engine_done: EngineCallback | None = None,
    ) -> ScanReport:
        started = time.monotonic()
        report = ScanReport(target=ctx.target)

        # Engines that do not apply to the target type are never run.
        # Important: they are still reported via the callback — otherwise progress
        # would never reach 100%.
        applicable: list[Adapter] = []
        for adapter in self.adapters:
            if adapter.applies_to(ctx.target):
                applicable.append(adapter)
                continue
            skipped = EngineReport(
                name=adapter.name,
                sin=adapter.sin,
                ok=True,
                findings=0,
                duration_ms=0,
                skipped=True,
                skip_reason=f"target type of '{ctx.target}' does not apply to {adapter.name}",
            )
            report.engines.append(skipped)
            log.info("%s skipped: target type does not apply", adapter.name)
            if on_engine_done is not None:
                try:
                    await on_engine_done(skipped)
                except Exception:  # noqa: BLE001 — callback errors must not stop the scan
                    log.exception("progress callback error")

        async def _wrapped(adapter: Adapter):
            result = await asyncio.to_thread(self._run_one, adapter, ctx)
            engine_report = result[0]
            if on_engine_done is not None:
                try:
                    await on_engine_done(engine_report)
                except Exception:  # noqa: BLE001 — callback errors must not stop the scan
                    log.exception("progress callback error")
            return result

        results = await asyncio.gather(*(_wrapped(a) for a in applicable), return_exceptions=True)

        raw: list[FindingContract] = []
        for adapter, result in zip(applicable, results, strict=True):
            if isinstance(result, BaseException):
                report.engines.append(
                    EngineReport(
                        name=adapter.name,
                        sin=adapter.sin,
                        ok=False,
                        findings=0,
                        duration_ms=0,
                        error=f"{type(result).__name__}: {result}",
                    )
                )
                continue
            engine_report, findings = result
            report.engines.append(engine_report)
            raw.extend(findings)

        report.findings = correlate(raw)
        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    def _run_one(
        self, adapter: Adapter, ctx: ScanContext
    ) -> tuple[EngineReport, list[FindingContract]]:
        """Runs the engine, retrying on transient errors.

        Retries only for "maybe it will pass" errors: timeout, network,
        resources. `ToolNotFound` or bad arguments — fail immediately.
        """
        settings = get_settings()
        max_attempts = max(1, settings.adapter_max_attempts)
        started = time.monotonic()
        last_error: BaseException | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                findings = adapter.run(ctx)
                return (
                    EngineReport(
                        name=adapter.name,
                        sin=adapter.sin,
                        ok=True,
                        findings=len(findings),
                        duration_ms=int((time.monotonic() - started) * 1000),
                        attempts=attempt,
                    ),
                    findings,
                )
            except Exception as exc:  # noqa: BLE001 — an engine error must not stop the whole scan
                last_error = exc
                if not _is_retryable(exc) or attempt == max_attempts:
                    break
                delay = settings.adapter_retry_backoff_seconds * (2 ** (attempt - 1))
                log.warning(
                    "%s failed (%s) — retrying in %.1f s (%d/%d)",
                    adapter.name,
                    type(exc).__name__,
                    delay,
                    attempt,
                    max_attempts,
                )
                time.sleep(delay)

        log.error("%s failed: %s", adapter.name, last_error, exc_info=last_error)
        return (
            EngineReport(
                name=adapter.name,
                sin=adapter.sin,
                ok=False,
                findings=0,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"{type(last_error).__name__}: {last_error}",
                attempts=attempt,
            ),
            [],
        )
