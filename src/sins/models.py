"""SQLAlchemy models — PostgreSQL.

Why Postgres: findings are relational, dedup needs JOINs,
jsonb is enough for raw tool output, and RLS provides multi-tenancy.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .schemas import Category, Severity


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ScanStatus(StrEnum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"  # cancelled by the user
    blocked = "blocked"  # failed the authorization gate


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Not the key itself — only its SHA-256 hash. A short prefix for display.
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    api_key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    targets: Mapped[list[Target]] = relationship(back_populates="tenant")


class Target(Base):
    """Target to be scanned. Becomes active only after ownership is proven."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("tenant_id", "value", name="uq_target_per_tenant"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))

    value: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # domain | url | ip

    verify_token: Mapped[str | None] = mapped_column(String(128))
    verify_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verify_method: Mapped[str | None] = mapped_column(String(20))  # dns | http | lab
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="targets")

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        # One tenant must not create two scans with the same Idempotency-Key.
        # Partial index: rows without a key (NULL) do not collide.
        Index(
            "uq_scan_idempotency",
            "tenant_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))

    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.pending)
    engines: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Which severity levels are searched (info is off by default)
    severities: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    error: Mapped[str | None] = mapped_column(Text)
    # Optional: if the same request is sent twice, no new scan is created.
    idempotency_key: Mapped[str | None] = mapped_column(String(80))

    # Progress tracking — for the UI progress bar
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_engine: Mapped[str | None] = mapped_column(String(50))
    # Per-engine result (name, duration, error) — for the PDF report
    engine_stats: Mapped[list[dict]] = mapped_column(JSONB, default=list)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete")
    finding_states: Mapped[list[FindingState]] = relationship(
        back_populates="scan", cascade="all, delete"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "dedup_key", name="uq_finding_per_scan"),
        Index("ix_findings_tenant_severity", "tenant_id", "severity"),
        Index("ix_findings_cve", "cve", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    category: Mapped[Category] = mapped_column(
        Enum(Category, name="finding_category", native_enum=False, length=20)
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity", native_enum=False, length=20), index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float)

    cve: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    cwe: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)

    location: Mapped[str] = mapped_column(String(1000), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    source_tools: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    remediation: Mapped[dict | None] = mapped_column(JSONB)

    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class FindingState(Base):
    """Exposure lifecycle for one finding fingerprint on one target."""

    __tablename__ = "finding_states"
    __table_args__ = (
        UniqueConstraint("target_id", "fingerprint", name="uq_finding_state_per_target"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    location: Mapped[str] = mapped_column(String(1000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    regressions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    scan: Mapped[Scan] = relationship(back_populates="finding_states")
