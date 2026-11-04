"""Request/response models for the API.

Kept separate from the DB models: the API contract lives on its own,
so database changes do not break clients.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ..schemas import Category, Remediation, Severity


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=255, examples=["example.com"])


class VerifyInstructions(BaseModel):
    """What the user must do — exact steps."""

    dns_record: str | None = None
    dns_value: str | None = None
    http_url: str | None = None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    value: str
    kind: str
    verified_at: datetime | None = None
    verify_method: str | None = None
    verify_token: str | None = None
    verify_expires_at: datetime | None = None
    created_at: datetime
    instructions: VerifyInstructions | None = None


class ScanCreate(BaseModel):
    target_id: UUID
    engines: list[str] | None = Field(
        default=None, examples=[["nuclei", "osv"]], description="Empty means all"
    )
    severities: list[str] | None = Field(
        default=None,
        examples=[["critical", "high", "medium", "low"]],
        description="Empty means all levels except info",
    )


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    status: str
    engines: list[str]
    severities: list[str] = []
    progress: int
    current_engine: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    finding_count: int | None = None


class FindingOut(BaseModel):
    id: UUID
    category: Category
    severity: Severity
    title: str
    cvss: float | None = None
    cve: list[str] = []
    cwe: list[str] = []
    location: str
    source_tools: list[str] = []
    remediation: Remediation | None = None
    evidence: dict[str, Any] = {}
    dedup_key: str


class FindingsPage(BaseModel):
    scan_id: UUID
    total: int
    limit: int
    offset: int
    has_more: bool
    severity_counts: dict[str, int] = {}
    items: list[FindingOut]


class DiffFinding(BaseModel):
    """Only the fields needed for a decision inside a diff."""

    dedup_key: str
    severity: Severity
    title: str
    location: str


class ScanDiffOut(BaseModel):
    scan_id: UUID
    against_scan_id: UUID | None = None
    baseline: bool
    new: list[DiffFinding] = []
    resolved: list[DiffFinding] = []
    persisting: int = 0


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    api_key_prefix: str
    created_at: datetime


class RotateKeyOut(BaseModel):
    """The new key is shown only once."""

    api_key: str
    api_key_prefix: str
    warning: str = "The old key stops working immediately. Store the new key securely."


class SeverityCountsPage(BaseModel):
    scan_id: UUID
    counts: dict[str, int]
