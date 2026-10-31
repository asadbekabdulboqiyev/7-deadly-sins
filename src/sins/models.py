"""SQLAlchemy modellari — PostgreSQL.

Nega Postgres: finding'lar relatsion, dedup uchun JOIN kerak,
xom tool chiqishi uchun jsonb yetarli, multi-tenancy uchun RLS bor.
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
    String,
    Text,
    UniqueConstraint,
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
    blocked = "blocked"  # authorization gate o'tmadi


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    targets: Mapped[list[Target]] = relationship(back_populates="tenant")


class Target(Base):
    """Tekshiriladigan nishon. Faqat egalik isbotlangandan keyin faol bo'ladi."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("tenant_id", "value", name="uq_target_per_tenant"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))

    value: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # domain | url | ip

    verify_token: Mapped[str | None] = mapped_column(String(128))
    verify_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="targets")

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))

    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.pending)
    engines: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    error: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete")


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
