"""Add measures_revision: optimistic snapshot marker for measure pages.

The measures read paths (patient + therapist mirror) used bare offset
paging on a DESC list with no byte bound, no continuation header and no
revision marker (2026-09-21 audit A-3): a concurrent create shifts every
row and an offset continuation silently duplicates or skips ciphertext,
and a legacy 500-row page could carry ~4 MB of base64 on the wire. The
owner account now carries a third monotonic counter advanced by every
successful measure create (and the corpus-wide rekey), so a continuation
can prove its page did not move between requests — the same contract
entries already ships.

Revision ID: c8d2f6b1a9e4
Revises: d7c1f4a8e2b9
Create Date: 2026-09-21 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "c8d2f6b1a9e4"
down_revision: str | Sequence[str] | None = "d7c1f4a8e2b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A server default backfills deployed account rows and also keeps direct
    # administrative inserts compatible with the model's create_all schema.
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "measures_revision",
                sa.BigInteger(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("measures_revision")
