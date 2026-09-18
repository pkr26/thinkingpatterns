"""Index the immutable entry-export cursor.

Entry edits intentionally update ``entry_date``.  Account export therefore
keysets on the immutable receipt timestamp plus id, rather than calendar
date, so an edit between short database pages cannot move an eligible row
before the cursor (omission) or after it (duplicate).  The index supports
the user-scoped cutoff and stable keyset on SQLite and PostgreSQL.

Revision ID: b9e6c4a7d812
Revises: f6a9b4d1e203
Create Date: 2026-09-18 00:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "b9e6c4a7d812"
down_revision: str | Sequence[str] | None = "f6a9b4d1e203"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_entries_user_received_id",
        "entries",
        ["user_id", "received_at", "id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_entries_user_received_id", table_name="entries")
