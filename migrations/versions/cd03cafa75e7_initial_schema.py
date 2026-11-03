"""initial schema

Revision ID: cd03cafa75e7
Revises:
Create Date: 2026-10-31 18:49:42.506172

Boshlang'ich sxema: tenants, targets, scans, findings.
Keyingi o'zgarishlar `alembic revision --autogenerate` bilan qo'shiladi —
`init-db` faqat lokal dev uchun.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "cd03cafa75e7"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=False),
        sa.Column("api_key_prefix", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_tenants_api_key_hash"), "tenants", ["api_key_hash"], unique=True
    )

    op.create_table(
        "targets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("verify_token", sa.String(length=128), nullable=True),
        sa.Column("verify_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verify_method", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "value", name="uq_target_per_tenant"),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("engines", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("severities", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("current_engine", sa.String(length=50), nullable=True),
        sa.Column(
            "engine_stats", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "category",
            sa.Enum(
                "exposure",
                "vuln",
                "auth",
                "tls",
                "resilience",
                "exploit",
                "dependency",
                "misconfig",
                name="finding_category",
                native_enum=False,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="finding_severity",
                native_enum=False,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("cve", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("cwe", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("location", sa.String(length=1000), nullable=False),
        sa.Column(
            "evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("source_tools", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("remediation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedup_key", name="uq_finding_per_scan"),
    )
    op.create_index(
        "ix_findings_cve", "findings", ["cve"], unique=False, postgresql_using="gin"
    )
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(
        "ix_findings_tenant_severity", "findings", ["tenant_id", "severity"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_findings_tenant_severity", table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index("ix_findings_cve", table_name="findings", postgresql_using="gin")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_index(op.f("ix_tenants_api_key_hash"), table_name="tenants")
    op.drop_table("tenants")
