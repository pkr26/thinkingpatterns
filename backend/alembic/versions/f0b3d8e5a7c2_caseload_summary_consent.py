"""Add the encrypted caseload-summary columns to consents (2026-09-19).

At every patient recompute the server writes a small per-consent summary
(pattern count, sensitive-card presence, newest first-seen) wrapped to the
therapist's public key — same ECIES construction as the data-key wrap,
AAD context "caseload-summary". The portal decrypts N small blobs instead
of N full insight blobs when triaging, and a sensitive card becomes
discoverable without opening every chart. All three columns are nullable:
absent until the patient's first post-grant recompute, cleared on revoke.

Revision ID: f0b3d8e5a7c2
Revises: a3f8d1e6c942
Create Date: 2026-09-19 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f0b3d8e5a7c2"
down_revision: str | Sequence[str] | None = "a3f8d1e6c942"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("consents") as batch_op:
        batch_op.add_column(sa.Column("summary_blob", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("summary_eph_pub", sa.String(length=256), nullable=True))
        batch_op.add_column(
            sa.Column("summary_updated_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("consents") as batch_op:
        batch_op.drop_column("summary_updated_at")
        batch_op.drop_column("summary_eph_pub")
        batch_op.drop_column("summary_blob")
