"""Canonical Finding contract.

All adapters (nuclei, osv, sslyze, ...) return exactly this format.
This is the heart of the whole system. Tools change, this contract does not.
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
    exposure = "exposure"  # Pride   — open ports, subdomains
    vuln = "vuln"  # Greed   — CVE vulnerabilities
    auth = "auth"  # Lust    — authentication weaknesses
    tls = "tls"  # Envy    — SSL/TLS
    resilience = "resilience"  # Gluttony— resilience (low load)
    exploit = "exploit"  # Wrath   — confirmed exploitation
    dependency = "dependency"  # Sloth   — outdated libraries
    misconfig = "misconfig"  # Sloth   — misconfiguration


class Remediation(BaseModel):
    """Remediation path. This is the core value of the product."""

    summary: str
    steps: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingContract(BaseModel):
    """A single finding. All adapters return this shape."""

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
    # Distinguishes different results within a single template
    # (e.g. nuclei `matcher-name`: content-security-policy, x-frame-options ...)
    sub_id: str | None = None
