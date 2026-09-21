"""Add therapist_note_revisions: the note edit history (Phase 3).

2026-09-21, audit Phase 3 clinic-readiness item: notes had updated_at but
no history — a superseded text was destroyed on edit. Every CHANGING
update now preserves the prior blob as an immutable revision row (same
note AAD: client_note_id is stable across revisions, so the portal
decrypts revisions exactly like live notes). Revisions CASCADE with their
note and with the therapist's account.

Revision ID: b8f4e2a7c9d1
Revises: a3e7c9d5f1b2
Create Date: 2026-09-21 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8f4e2a7c9d1"
down_revision: str | Sequence[str] | None = "a3e7c9d5f1b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "therapist_note_revisions",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "note_id",
            sa.String(32),
            sa.ForeignKey("therapist_notes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "therapist_id",
            sa.String(32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_note_revisions_note_created",
        "therapist_note_revisions",
        ["note_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_note_revisions_note_created", table_name="therapist_note_revisions")
    op.drop_table("therapist_note_revisions")
