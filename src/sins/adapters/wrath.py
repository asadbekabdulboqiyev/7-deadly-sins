"""Wrath: exploit confirmation.

Goal: turn a detected issue into a confirmed exploit fact, without writing any
exploit code. The pass re-runs an explicitly supplied nuclei template set and
marks findings that reproduce as confirmed.

No exploit payload is generated or executed here - only detection templates
that already exist are executed a second time.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from ..runner import run_tool, which
from ..schemas import Category, FindingContract
from ..targets import InvalidTarget, classify_target
from .base import ScanContext
from .nuclei import NucleiAdapter

log = logging.getLogger(__name__)


class WrathAdapter(NucleiAdapter):
    name: ClassVar[str] = "wrath"
    category: ClassVar[Category] = Category.exploit
    sin: ClassVar[str] = "Wrath"

    def __init__(self, prior: list[FindingContract] | None = None) -> None:
        super().__init__()
        self._prior = list(prior or [])

    def available(self) -> bool:
        return which("nuclei") is not None

    def applies_to(self, target: str) -> bool:
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return True
        return kind in {"domain", "url", "ip"}

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        self._prior = list(ctx.prior_findings or [])
        if not ctx.templates:
            return []
        argv = [
            "nuclei",
            "-u",
            ctx.target,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-disable-update-check",
            "-severity",
            ",".join(ctx.severities),
            "-rate-limit",
            str(max(1, min(ctx.max_rps, 150))),
            "-concurrency",
            "10",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-stats-json",
            "-stats-interval",
            "10",
            "-t",
            ",".join(ctx.templates),
        ]
        try:
            result = run_tool(argv, timeout=ctx.timeout)
        except Exception as exc:  # noqa: BLE001 - engine must degrade, not crash
            log.warning("wrath confirmation failed: %s", exc)
            return []
        return self.parse(result, ctx.target)

    def parse(self, result, target: str) -> list[FindingContract]:
        findings = super().parse(result, target)
        confirmed: list[FindingContract] = []
        for finding in findings:
            if not self._matches_prior(finding):
                continue
            confirmed.append(
                finding.model_copy(
                    update={
                        "category": self.category,
                        "title": f"Confirmed exploit: {finding.title}",
                        "evidence": {**finding.evidence, "confirmed": True, "source": "wrath"},
                        "source_tools": ["nuclei", self.name],
                        "dedup_key": f"wrath|{finding.dedup_key}",
                    }
                )
            )
        return confirmed

    def _matches_prior(self, finding: FindingContract) -> bool:
        for prior in self._prior:
            if prior.dedup_key and prior.dedup_key == finding.dedup_key:
                return True
            if prior.cve and finding.cve and set(prior.cve) & set(finding.cve):
                return True
        return False
