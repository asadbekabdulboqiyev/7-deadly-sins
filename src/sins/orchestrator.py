"""Orkestrator — 7 ta gunohni bitta skanga yig'adi.

Muhim: bu yerda hech qanday skanerlash logikasi yo'q.
Faqat adapterlarni chaqirish, natijalarni korrelyatsiya qilish.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .adapters import REGISTRY, Adapter, ScanContext
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


@dataclass(slots=True)
class ScanReport:
    target: str
    engines: list[EngineReport] = field(default_factory=list)
    findings: list[FindingContract] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def raw_finding_count(self) -> int:
        return sum(e.findings for e in self.engines)


class SinsOrchestrator:
    def __init__(self, engines: list[str] | None = None) -> None:
        selected = engines or list(REGISTRY)
        self.adapters: list[Adapter] = []
        for name in selected:
            adapter = REGISTRY.get(name)
            if adapter is None:
                log.warning("noma'lum engine: %s — o'tkazib yuborildi", name)
                continue
            if not adapter.available():
                log.warning("%s topilmadi — o'tkazib yuborildi", name)
                continue
            self.adapters.append(adapter)

    async def run(self, ctx: ScanContext) -> ScanReport:
        started = time.monotonic()
        report = ScanReport(target=ctx.target)

        tasks = [asyncio.to_thread(self._run_one, adapter, ctx) for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw: list[FindingContract] = []
        for adapter, result in zip(self.adapters, results, strict=True):
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
        started = time.monotonic()
        try:
            findings = adapter.run(ctx)
            return (
                EngineReport(
                    name=adapter.name,
                    sin=adapter.sin,
                    ok=True,
                    findings=len(findings),
                    duration_ms=int((time.monotonic() - started) * 1000),
                ),
                findings,
            )
        except Exception as exc:  # noqa: BLE001 — engine xatosi butun skanni to'xtatmasin
            log.exception("%s ishlamadi", adapter.name)
            return (
                EngineReport(
                    name=adapter.name,
                    sin=adapter.sin,
                    ok=False,
                    findings=0,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error=f"{type(exc).__name__}: {exc}",
                ),
                [],
            )
