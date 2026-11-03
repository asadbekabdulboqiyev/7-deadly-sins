"""scan idempotency key

Revision ID: 9a1f4c7d2b30
Revises: cd03cafa75e7
Create Date: 2026-11-02 13:45:00.000000

`Idempotency-Key` sarlavhasi bilan skan yaratishni takrorlanishdan himoya qiladi.
Qisman unique indeks: faqat kalit berilgan qatorlar uchun (NULL'lar to'qnashmaydi).
`scans.status` oddiy satr — `cancelled` qiymati uchun migratsiya kerak emas.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9a1f4c7d2b30"
down_revision: str | Sequence[str] | None = "cd03cafa75e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("idempotency_key", sa.String(length=80), nullable=True))
    op.create_index(
        "uq_scan_idempotency",
        "scans",
        ["tenant_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_scan_idempotency", table_name="scans")
    op.drop_column("scans", "idempotency_key")
