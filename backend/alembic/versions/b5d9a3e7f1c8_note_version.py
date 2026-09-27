"""Add therapist_notes.version: optimistic concurrency for clinical notes.

2026-09-26 audit item 15: PATCH /therapist/notes/{id} had no concurrency
control — two portal sessions editing the same note silently resolved to
last-write-wins, destroying a clinician's edit without a trace. The note
contract now carries a version (1 on create, +1 on every changing PATCH):
clients send ``base_version`` (absent → 400 version_required, mismatch →
409 version_conflict), and NoteOut echoes the new version on success.

Existing rows backfill to 1 (the value every create has always implied);
there is no migration-time conflict resolution to do because the column
lands atomically and every pre-existing note becomes version 1 for all
readers simultaneously.

Revision ID: b5d9a3e7f1c8
Revises: e8b2d6f4a1c7
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b5d9a3e7f1c8"
down_revision: str | Sequence[str] | None = "e8b2d6f4a1c7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "therapist_notes",
        sa.Column(
            "version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )


def downgrade() -> None:
    op.drop_column("therapist_notes", "version")
