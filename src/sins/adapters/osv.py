"""Sin 7 — Sloth: dependency & configuration audit.

Nega osv-scanner:
  - Google'ning rasmiy vositasi, OSV bazasi (GitHub Advisory + PyPA + RustSec ...)
  - `fixed_version` beradi -> remediation avtomatik yoziladi
  - nishonga UMUMAN tegmaydi: faqat lockfile/repo o'qiladi => huquqiy risk 0

Bu — huquqiy jihatdan eng xavfsiz modul va remediation qiymati eng yuqori.
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from ..dedup import dedup_key, severity_from_cvss
from ..runner import RunResult, ToolNotFound, run_tool, which
from ..schemas import Category, FindingContract, Remediation, Severity
from ..targets import InvalidTarget, classify_target
from .base import ScanContext

log = logging.getLogger(__name__)


class OsvAdapter:
    name: ClassVar[str] = "osv"
    category: ClassVar[Category] = Category.dependency
    sin: ClassVar[str] = "Sloth"

    def available(self) -> bool:
        return which("osv-scanner") is not None

    def applies_to(self, target: str) -> bool:
        """osv-scanner faqat lokal papka/lockfile'ni o'qiydi.

        URL yoki domenga qarshi ishga tushirilsa tool osilib qoladi (tarmoqqa
        chiqishga urinadi) va hech qanday natija bermaydi. Shuning uchun
        bunday nishonlarda adapter umuman chaqirilmaydi.
        """
        try:
            return classify_target(target) == "path"
        except InvalidTarget:
            return False

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        # v2 CLI: `osv-scanner scan source -r <path>`
        argv = ["osv-scanner", "scan", "source", "--format", "json", "-r", ctx.target]
        try:
            result = run_tool(argv, timeout=ctx.timeout)
        except ToolNotFound as exc:
            log.warning("osv-scanner topilmadi: %s", exc)
            return []
        return self.parse(result, ctx.target)

    def parse(self, result: RunResult, target: str) -> list[FindingContract]:
        raw = result.stdout.strip()
        if not raw.startswith("{"):
            return []
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[FindingContract] = []
        for source in payload.get("results", []):
            package = (source.get("source") or {}).get("path") or target
            for pkg in source.get("packages", []):
                info = pkg.get("package") or {}
                pkg_name = info.get("name") or "unknown"
                pkg_version = info.get("version") or "?"
                for vuln in pkg.get("vulnerabilities", []):
                    findings.append(self._to_finding(vuln, pkg_name, pkg_version, package, target))
        return findings

    def _to_finding(
        self,
        vuln: dict[str, Any],
        pkg_name: str,
        pkg_version: str,
        package_path: str,
        target: str,
    ) -> FindingContract:
        vuln_id = vuln.get("id") or "OSV-UNKNOWN"
        aliases = vuln.get("aliases") or []
        cve = [a for a in aliases if str(a).startswith("CVE-")] or (
            [vuln_id] if vuln_id.startswith("CVE-") else []
        )
        severity, cvss = _severity_from_vuln(vuln)

        fixed = _fixed_version(vuln, pkg_name)
        if fixed:
            summary = f"{pkg_name} ni {fixed} ga yangilang"
        else:
            summary = f"{pkg_name}: tuzatilgan versiya yo'q — alternativ kutubxona ko'rib chiqing"
        remediation = Remediation(
            summary=summary,
            steps=[f"`{pkg_name}@{pkg_version}` -> `{fixed or 'alternativ'}`"]
            + ([f"`{vuln_id}` bo'yicha advisory ni o'qing"] if not fixed else []),
            fixed_version=fixed,
            references=[r for r in (vuln.get("references") or []) if isinstance(r, str)][:5],
        )

        return FindingContract(
            category=self.category,
            title=vuln.get("summary") or vuln_id,
            severity=severity,
            cvss=cvss,
            cve=cve,
            cwe=[],
            location=f"{package_path}:{pkg_name}@{pkg_version}",
            evidence={"vuln_id": vuln_id, "aliases": aliases, "package": pkg_name, "raw": vuln},
            source_tools=[self.name],
            dedup_key=dedup_key(self.name, target, vuln_id, pkg_name, pkg_version),
            remediation=remediation,
        )


def _severity_from_vuln(vuln: dict[str, Any]) -> tuple[Severity, float | None]:
    """OSV severity: ba'zan raqamli ball, ba'zan CVSS vektori, ba'zan database_specific."""
    for sev in vuln.get("severity") or []:
        raw = str(sev.get("score") or "").strip()
        try:
            value = float(raw)
        except ValueError:
            continue  # CVSS vektori — ball hisoblash uchun alohida kutubxona kerak
        return severity_from_cvss(value), value

    db_sev = (vuln.get("database_specific") or {}).get("severity")
    mapping = {
        "CRITICAL": Severity.critical,
        "HIGH": Severity.high,
        "MODERATE": Severity.medium,
        "MEDIUM": Severity.medium,
        "LOW": Severity.low,
    }
    if isinstance(db_sev, str) and db_sev.upper() in mapping:
        return mapping[db_sev.upper()], None
    return Severity.medium, None


def _fixed_version(vuln: dict[str, Any], pkg_name: str) -> str | None:
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name") != pkg_name:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return None
