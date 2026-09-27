"""Add rekey_journal: resumable progress for POST /processing/rekey.

2026-09-26 audit item 11: the rekey used to hold ONE transaction across
every batch's CPU work. It now commits each batch in a short transaction
and journals (stage, cursors, running counts) in this table, atomically
with the batch's blob rewrites — an interrupted rotation resumes from the
journal on the client's retry, skipping rows already under the new key.
The row is deleted in the same transaction that bumps the collection
revisions at completion, so its presence always means "an interrupted
rotation is resumable". user_id is deliberately NOT an FK: the journal
describes an in-flight maintenance operation, not account data, and a
journal row must never block or cascade with account deletion (the
lifecycle fence serializes the two in practice; the non-FK choice keeps
the table's lifetime independent). Schema parity with
app.models.RekeyJournal: no server defaults beyond the documented ones.

Revision ID: d7f1c5a9b3e0
Revises: c6e0b4f8a2d9
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7f1c5a9b3e0"
down_revision: str | Sequence[str] | None = "c6e0b4f8a2d9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rekey_journal",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.String(32), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("entry_cursor", sa.String(32), nullable=True),
        sa.Column("measure_cursor", sa.String(32), nullable=True),
        sa.Column("entries_done", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("insights_done", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("measures_done", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_rekey_journal_user", "rekey_journal", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_rekey_journal_user", table_name="rekey_journal")
    op.drop_table("rekey_journal")
