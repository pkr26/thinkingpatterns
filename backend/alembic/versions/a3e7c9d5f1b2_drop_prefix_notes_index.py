"""Drop ix_notes_therapist_patient: strict prefix of the covering index.

2026-09-21 audit B-6: ix_notes_therapist_patient (therapist_id, user_id)
is a strict prefix of ix_notes_therapist_patient_created (therapist_id,
user_id, created_at, id). Every notes query filters on the pair AND
orders by created_at, so only the covering index ever served a plan; the
shorter one added pure write amplification on every note insert and
update. Dropped in both the model and the database.

Revision ID: a3e7c9d5f1b2
Revises: c8d2f6b1a9e4
Create Date: 2026-09-21 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "a3e7c9d5f1b2"
down_revision: str | Sequence[str] | None = "c8d2f6b1a9e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_notes_therapist_patient", table_name="therapist_notes")


def downgrade() -> None:
    op.create_index(
        "ix_notes_therapist_patient",
        "therapist_notes",
        ["therapist_id", "user_id"],
    )
