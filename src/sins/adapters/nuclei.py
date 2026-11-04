"""Greed: vulnerability scanning.

Why nuclei:
  - 10,000+ ready-made templates — you write no payloads
  - `-jsonl` is a stable machine-readable format
  - nondestructive detection (exploit validation is also a template)

Why NOT nmap --script vulners:
  - requires a paid API key
  - service version -> CVE mapping has a very high false-positive rate
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from ..dedup import dedup_key, normalize_cve, normalize_location, severity_from_cvss
from ..runner import RunResult, ToolNotFound, run_tool, which
from ..schemas import Category, FindingContract, Severity
from ..targets import InvalidTarget, classify_target
from .base import ScanContext

log = logging.getLogger(__name__)

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class NucleiAdapter:
    name: ClassVar[str] = "nuclei"
    category: ClassVar[Category] = Category.vuln
    sin: ClassVar[str] = "Greed"

    def available(self) -> bool:
        return which("nuclei") is not None

    def applies_to(self, target: str) -> bool:
        """Nuclei works with network targets; a local directory is meaningless to it."""
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return True  # let the tool itself judge the format, not the adapter
        return kind in {"domain", "url", "ip"}

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        argv = [
            "nuclei",
            "-u",
            ctx.target,
            "-jsonl",
            "-silent",
            "-no-interactsh",  # do not connect to an external OAST server
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
        ]
        if ctx.templates:
            argv += ["-t", ",".join(ctx.templates)]

        try:
            result = run_tool(argv, timeout=ctx.timeout)
        except ToolNotFound as exc:
            log.warning("nuclei not found: %s", exc)
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
                continue  # -stats-json lines
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
        # When one template yields several matchers, the title must be specific,
        # otherwise the report shows 10 identical rows.
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
