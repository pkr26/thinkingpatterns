"""Maintained quota counters (wave 4, 2026-09-30)

Revision ID: c8d5f2b6a4e7
Revises: b7c4e2f9a1d5
Create Date: 2026-09-30

Every entry/measure write used to run an O(corpus) COUNT+SUM over the
account's whole table (a per-write scan at the 10k-entry quota). The
counters are maintained transactionally by the write paths and backfilled
here once.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8d5f2b6a4e7"
down_revision: str | Sequence[str] | None = "b7c4e2f9a1d5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("entry_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("entry_blob_bytes", sa.BigInteger(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("measure_count", sa.Integer(), nullable=False, server_default="0")
        )
    # One-time backfill from the live tables (the write paths maintain the
    # counters from here on).
    op.execute(
        """
        UPDATE users SET entry_count = COALESCE((
            SELECT COUNT(*) FROM entries WHERE entries.user_id = users.id
        ), 0)
        """
    )
    # Blob byte length: OCTET_LENGTH on PostgreSQL, LENGTH on SQLite
    # (byte length for BLOBs) — both dialects this project runs.
    bind = op.get_bind()
    length_fn = "OCTET_LENGTH" if bind.dialect.name == "postgresql" else "LENGTH"
    op.execute(
        f"""
        UPDATE users SET entry_blob_bytes = COALESCE((
            SELECT SUM({length_fn}(blob)) FROM entries WHERE entries.user_id = users.id
        ), 0)
        """
    )
    op.execute(
        """
        UPDATE users SET measure_count = COALESCE((
            SELECT COUNT(*) FROM measures WHERE measures.user_id = users.id
        ), 0)
        """
    )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("measure_count")
        batch.drop_column("entry_blob_bytes")
        batch.drop_column("entry_count")
