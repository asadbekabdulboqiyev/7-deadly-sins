"""Kanonik Finding shartnomasi.

Barcha adapterlar (nuclei, osv, sslyze, ...) aynan shu formatga qaytaradi.
Bu — butun tizimning yuragi. Tool'lar o'zgaradi, bu shartnoma qoladi.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class Category(StrEnum):
    exposure = "exposure"      # Pride   — ochiq portlar, subdomenlar
    vuln = "vuln"              # Greed   — CVE zaifliklar
    auth = "auth"              # Lust    — autentifikatsiya kamchiliklari
    tls = "tls"                # Envy    — SSL/TLS
    resilience = "resilience"  # Gluttony— barqarorlik (past yuklama)
    exploit = "exploit"        # Wrath   — tasdiqlangan ekspluatatsiya
    dependency = "dependency"  # Sloth   — eskirgan kutubxonalar
    misconfig = "misconfig"    # Sloth   — noto'g'ri konfiguratsiya


class Remediation(BaseModel):
    """Tuzatish yo'li. Bu — mahsulotning asosiy qiymati."""

    summary: str
    steps: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingContract(BaseModel):
    """Bitta topilma. Barcha adapterlar shu shaklda qaytaradi."""

    category: Category
    title: str
    severity: Severity = Severity.info
    cvss: float | None = None
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    location: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_tools: list[str] = Field(default_factory=list)
    dedup_key: str
    remediation: Remediation | None = None
    # Bitta template ichidagi farqli natijalarni ajratish uchun
    # (masalan nuclei `matcher-name`: content-security-policy, x-frame-options ...)
    sub_id: str | None = None
