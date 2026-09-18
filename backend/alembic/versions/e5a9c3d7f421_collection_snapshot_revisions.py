"""Add optimistic revisions for offset-paginated encrypted collections.

An offset alone cannot describe a stable snapshot when an entry or note is
inserted, edited, or removed between pages.  The owner account now carries
two monotonic, signed-64-bit counters: one for its journal entries and one
for therapist-private notes written by that therapist.  Existing accounts
begin at zero; the API increments a counter only in the same transaction as
an actual mutation.

Revision ID: e5a9c3d7f421
Revises: b9e6c4a7d812
Create Date: 2026-09-18 02:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "e5a9c3d7f421"
down_revision: str | Sequence[str] | None = "b9e6c4a7d812"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A server default backfills deployed account rows and also keeps direct
    # administrative inserts compatible with the model's create_all schema.
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "entries_revision",
                sa.BigInteger(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "notes_revision",
                sa.BigInteger(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("notes_revision")
        batch_op.drop_column("entries_revision")
