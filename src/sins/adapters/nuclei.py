"""Sin 2 — Greed: zaiflik skanerlash.

Nega nuclei:
  - 10 000+ tayyor template — siz hech qanday payload yozmaysiz
  - `-jsonl` barqaror mashina o'qiydigan format
  - nondestructive detection (exploit validation ham template ichida)

Nega nmap --script vulners EMAS:
  - pullik API key talab qiladi
  - service version -> CVE mapping false positive darajasi juda yuqori
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from ..dedup import dedup_key, normalize_cve, normalize_location, severity_from_cvss
from ..runner import RunResult, ToolNotFound, run_tool, which
from ..schemas import Category, FindingContract, Severity
from .base import ScanContext

log = logging.getLogger(__name__)

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class NucleiAdapter:
    name: ClassVar[str] = "nuclei"
    category: ClassVar[Category] = Category.vuln
    sin: ClassVar[str] = "Greed"

    def available(self) -> bool:
        return which("nuclei") is not None

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        argv = [
            "nuclei",
            "-u", ctx.target,
            "-jsonl",
            "-silent",
            "-no-interactsh",          # tashqi OAST serverga bog'lanmasin
            "-disable-update-check",
            "-severity", ",".join(ctx.severities),
            "-rate-limit", str(max(1, min(ctx.max_rps, 150))),
            "-concurrency", "10",
            "-timeout", "10",
            "-retries", "1",
            "-stats-json",
            "-stats-interval", "10",
        ]
        if ctx.templates:
            argv += ["-t", ",".join(ctx.templates)]

        try:
            result = run_tool(argv, timeout=ctx.timeout)
        except ToolNotFound as exc:
            log.warning("nuclei topilmadi: %s", exc)
            return []

        return self.parse(result, ctx.target)

    # -- parsing ---------------------------------------------------------

    def parse(self, result: RunResult, target: str) -> list[FindingContract]:
        findings: list[FindingContract] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not _is_finding(payload):
                continue  # -stats-json satrlari
            finding = self._to_finding(payload, target)
            if finding:
                findings.append(finding)
        return findings

    def _to_finding(self, payload: dict[str, Any], target: str) -> FindingContract | None:
        info: dict[str, Any] = payload.get("info") or {}
        classification: dict[str, Any] = info.get("classification") or {}

        template_id = payload.get("template-id") or "unknown"
        matched_at = payload.get("matched-at") or payload.get("host") or target
        matcher = payload.get("matcher-name")

        cvss = _as_float(classification.get("cvss-score"))
        raw_sev = str(info.get("severity") or "").lower()
        severity = Severity(raw_sev) if raw_sev in _SEVERITIES else severity_from_cvss(cvss)

        base_title = info.get("name") or template_id
        # Bir template bir nechta matcher bersa — sarlavha aniq bo'lishi kerak,
        # aks holda hisobotda 10 ta bir xil qator ko'rinadi.
        title = f"{base_title}: {matcher}" if matcher else base_title

        return FindingContract(
            category=self.category,
            title=title,
            severity=severity,
            cvss=cvss,
            cve=normalize_cve(_as_list(classification.get("cve-id"))),
            cwe=_as_list(classification.get("cwe-id")),
            location=normalize_location(matched_at),
            evidence={
                "template_id": template_id,
                "matcher": matcher,
                "type": payload.get("type"),
                "curl_command": payload.get("curl-command"),
                "extracted": payload.get("extracted-results"),
                "raw": payload,
            },
            source_tools=[self.name],
            dedup_key=dedup_key(self.name, target, template_id, matched_at, matcher or ""),
            sub_id=matcher,
        )


def _is_finding(payload: dict[str, Any]) -> bool:
    return "template-id" in payload and "info" in payload


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
