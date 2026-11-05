"""Threat-intel value objects shared by the intel clients and the report."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CveIntel(BaseModel):
    """What the public sources say about one CVE."""

    cve: str
    # CISA KEV — listed means exploitation has been observed in the wild.
    kev: bool = False
    kev_ransomware: bool = False
    kev_added: str | None = None

    # FIRST EPSS — probability of exploitation in the next 30 days (0-1).
    epss: float | None = None
    epss_percentile: float | None = None

    @property
    def epss_percent(self) -> int | None:
        """EPSS as a whole percentage — easier to read in a report table."""
        return None if self.epss is None else round(self.epss * 100)

    @property
    def epss_label(self) -> str | None:
        """One-decimal label, capped at 99.9%.

        A 0.9995 model output must never be printed as "100%": the model says
        "almost certain", not "certain".
        """
        if self.epss is None:
            return None
        return f"{min(self.epss * 100, 99.9):.1f}%"

    @property
    def percentile_percent(self) -> int | None:
        return None if self.epss_percentile is None else round(self.epss_percentile * 100)


class ThreatIntel(BaseModel):
    """Enrichment result for one report.

    ``kev_available`` / ``epss_available`` are explicit because "source was
    unreachable" must never be presented as "nothing is exploited".
    """

    by_cve: dict[str, CveIntel] = Field(default_factory=dict)
    kev_available: bool = False
    epss_available: bool = False

    def for_cves(self, cves: list[str]) -> CveIntel | None:
        """Best entry across a finding's CVEs (KEV first, then highest EPSS)."""
        entries = [self.by_cve[c.strip().upper()] for c in cves if c.strip().upper() in self.by_cve]
        if not entries:
            return None
        return sorted(
            entries,
            key=lambda e: (e.kev, e.epss or 0.0),
            reverse=True,
        )[0]

    @property
    def exploited_count(self) -> int:
        return sum(1 for entry in self.by_cve.values() if entry.kev)
