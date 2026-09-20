"""Add the measures table (measurement-based-care module, 2026-09-19).

One opaque AES-GCM blob per patient-recorded questionnaire completion,
the same opacity contract as entries: the server cannot read the score,
the patient's client encrypts under the data key, the therapist portal
decrypts with the consent-wrapped key. Interpretation stays with the
clinician.

Revision ID: b1c7f2e9a4d6
Revises: f0b3d8e5a7c2
Create Date: 2026-09-19 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b1c7f2e9a4d6"
down_revision: str | Sequence[str] | None = "f0b3d8e5a7c2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "measures",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("client_measure_id", sa.String(length=64), nullable=False),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("measure_date", sa.Date(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "client_measure_id", name="uq_user_client_measure"),
    )
    op.create_index("ix_measures_user_date", "measures", ["user_id", "measure_date"])


def downgrade() -> None:
    op.drop_index("ix_measures_user_date", table_name="measures")
    op.drop_table("measures")
