"""Gluttony: resilience posture.

Goal: inspect how the service behaves and how hardened it is, passively.

Checks performed:
  - Server header discloses product / version
  - X-Powered-By discloses implementation
  - Dangerous HTTP methods allowed (OPTIONS probe)

Deliberately not performed:
  - Load / stress testing, traffic flooding, rate-limit enforcement tests
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from typing import ClassVar

from ..dedup import dedup_key
from ..runner import run_tool, which
from ..schemas import Category, FindingContract, Severity
from ..targets import InvalidTarget, classify_target
from .base import ScanContext
from .pride import _resolve_tool, _write_hosts

log = logging.getLogger(__name__)


class GluttonyAdapter:
    name: ClassVar[str] = "gluttony"
    category: ClassVar[Category] = Category.resilience
    sin: ClassVar[str] = "Gluttony"

    def available(self) -> bool:
        return which("httpx") is not None and which("nuclei") is not None

    def applies_to(self, target: str) -> bool:
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return True
        return kind in {"domain", "url", "ip"}

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        binary = _resolve_tool("httpx")
        if binary is None:
            return []
        hosts = [ctx.target]
        path = _write_hosts(hosts)
        try:
            result = run_tool(
                [binary, "-list", path, "-json", "-silent", "-irr", "-x", "GET"],
                timeout=ctx.timeout,
            )
            options = run_tool(
                [binary, "-list", path, "-json", "-silent", "-irr", "-x", "OPTIONS"],
                timeout=ctx.timeout,
            )
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)

        findings: list[FindingContract] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("failed"):
                continue
            headers = payload.get("header") or {}
            server = str(headers.get("server") or "")
            powered = str(headers.get("x-powered-by") or "")
            if server:
                findings.append(
                    self._finding(
                        title="Server header discloses product information",
                        severity=Severity.low,
                        dedup_source="gluttony-server-header",
                        url=str(payload.get("url") or ctx.target),
                        evidence={
                            "server": server,
                            "host": str(payload.get("host") or ctx.target),
                        },
                    )
                )
            if powered:
                findings.append(
                    self._finding(
                        title="X-Powered-By header discloses implementation",
                        severity=Severity.low,
                        dedup_source="gluttony-x-powered-by",
                        url=str(payload.get("url") or ctx.target),
                        evidence={
                            "x_powered_by": powered,
                            "host": str(payload.get("host") or ctx.target),
                        },
                    )
                )
        for line in options.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("failed"):
                continue
            allow = str((payload.get("header") or {}).get("allow") or "")
            methods = {m.strip().upper() for m in allow.replace(",", " ").split() if m.strip()}
            dangerous = methods & {"PUT", "DELETE", "PATCH", "TRACE"}
            if dangerous:
                findings.append(
                    self._finding(
                        title="Dangerous HTTP methods are allowed",
                        severity=Severity.high,
                        dedup_source="gluttony-allowed-methods",
                        url=str(payload.get("url") or ctx.target),
                        evidence={"allow": allow, "methods": sorted(dangerous)},
                    )
                )
        return findings

    def _finding(
        self, *, title: str, severity: Severity, dedup_source: str, url: str, evidence: dict
    ) -> FindingContract:
        return FindingContract(
            category=Category.resilience,
            title=title,
            severity=severity,
            cvss=None,
            cve=[],
            cwe=["CWE-693"],
            location=url,
            evidence=evidence,
            source_tools=["httpx", self.name],
            dedup_key=dedup_key(self.name, url, dedup_source),
            remediation=None,
        )
