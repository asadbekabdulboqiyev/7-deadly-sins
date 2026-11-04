"""Add regressions counter to finding states.

Revision ID: c3d4e5f6a7b8
Revises: b7c2f4e9a1d3
Create Date: 2026-11-04 15:30:00.000000

Adds `regressions` — how many times a finding fingerprint was resolved and
later re-opened on the same target.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b7c2f4e9a1d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "finding_states",
        sa.Column("regressions", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("finding_states", "regressions")
