"""backend hardening: consent policy binding, pairing uniqueness, indexes.

Pairing-code hashes must be unique: a collision is not merely cosmetic,
because lookup selects one matching row and could otherwise bind a patient
to the wrong therapist.  Historical duplicate digest rows are safe to
discard (they contain only short-lived, unconsumed/consumed pairing code
metadata); deleting every member of a duplicate group deliberately forces
the affected therapist to mint a fresh code rather than guessing a winner.

The other indexes support bounded note pages and time-leading retention
deletes without full-table scans.

Revision ID: d52c4e8f14a0
Revises: c41f8a92d5e7
Create Date: 2026-09-17 18:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "d52c4e8f14a0"
down_revision: str | Sequence[str] | None = "c41f8a92d5e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("llm_consent_policy", sa.String(length=64), nullable=True))
    # Do not choose an arbitrary duplicate row: every duplicate code is
    # invalidated, preserving the security invariant after the constraint is
    # added. Pairing codes are ephemeral and carry no patient content.
    op.execute(
        "DELETE FROM pairing_codes WHERE code_hash IN "
        "(SELECT code_hash FROM pairing_codes GROUP BY code_hash HAVING COUNT(*) > 1)"
    )
    with op.batch_alter_table("pairing_codes") as batch_op:
        batch_op.drop_index("ix_pairing_codes_hash")
        batch_op.create_unique_constraint("uq_pairing_codes_code_hash", ["code_hash"])
    op.create_index("ix_pairing_codes_expires_at", "pairing_codes", ["expires_at"])
    op.create_index(
        "ix_notes_therapist_patient_created",
        "therapist_notes",
        ["therapist_id", "user_id", "created_at", "id"],
    )
    op.create_index("ix_access_log_at", "access_log", ["at"])


def downgrade() -> None:
    op.drop_index("ix_access_log_at", table_name="access_log")
    op.drop_index("ix_notes_therapist_patient_created", table_name="therapist_notes")
    op.drop_index("ix_pairing_codes_expires_at", table_name="pairing_codes")
    with op.batch_alter_table("pairing_codes") as batch_op:
        batch_op.drop_constraint("uq_pairing_codes_code_hash", type_="unique")
        batch_op.create_index("ix_pairing_codes_hash", ["code_hash"], unique=False)
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("llm_consent_policy")
