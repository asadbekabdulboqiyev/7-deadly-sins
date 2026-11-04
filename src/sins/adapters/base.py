"""Adapter contract.

Every "sin" is a thin adapter over an external tool.
An adapter does exactly three things:
  1. checks whether the tool is present
  2. runs the tool
  3. converts the output into a FindingContract

No payloads and no exploit logic are written here —
all of that lives inside the ready-made tools.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from ..schemas import Category, FindingContract


class ScanContext(BaseModel):
    target: str
    max_rps: int = 50
    timeout: int = 900
    templates: list[str] = Field(default_factory=list)
    # `info` is excluded by default — it is noisy (e.g. security headers)
    severities: list[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])
    # Findings of a previous scan — used by the exploit confirmation pass (Wrath).
    prior_findings: list[FindingContract] = Field(default_factory=list)


@runtime_checkable
class Adapter(Protocol):
    name: ClassVar[str]
    category: ClassVar[Category]
    sin: ClassVar[str]  # internal codename

    def available(self) -> bool: ...

    def applies_to(self, target: str) -> bool:
        """Does this adapter logically apply to this target kind?

        Why it matters: `osv-scanner` only works on a local directory/lockfile.
        Run against a URL it hangs and returns nothing.
        When it does not apply, the orchestrator skips the adapter entirely and
        reports it as "skipped" in the report.
        """
        ...

    def run(self, ctx: ScanContext) -> list[FindingContract]: ...
