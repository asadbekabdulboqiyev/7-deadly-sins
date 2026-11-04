"""Add finding exposure lifecycle states.

Revision ID: b7c2f4e9a1d3
Revises: 9a1f4c7d2b30
Create Date: 2026-11-04 15:20:00.000000

Adds `finding_states` — the exposure ledger that powers the Exposure Timeline.
Each row tracks one finding fingerprint across scans:
  - first_seen_at / last_seen_at / occurrences
  - resolved_at / status (open | resolved)
  - regression count

Keyed by (target_id, fingerprint) — one row per distinct finding per target.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b7c2f4e9a1d3"
down_revision: str | None = "9a1f4c7d2b30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("location", sa.String(length=1000), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("first_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("resolved_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name="fk_finding_states_scan",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name="fk_finding_states_target",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_states_tenant_id",
        "finding_states",
        ["tenant_id"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_finding_state_per_target",
        "finding_states",
        ["target_id", "fingerprint"],
    )


def downgrade() -> None:
    op.drop_index("ix_finding_states_scan_id", table_name="finding_states")
    op.drop_index("ix_finding_states_target_status", table_name="finding_states")
    op.drop_index("ix_finding_states_tenant_target", table_name="finding_states")
    op.drop_constraint("uq_finding_state_per_target", "finding_states", type_="unique")
    op.drop_table("finding_states")
