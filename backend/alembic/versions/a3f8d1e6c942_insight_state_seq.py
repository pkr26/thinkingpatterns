"""Add a per-row analysis sequence number to insights (rollback visibility).

AES-GCM authenticates context, not version: without a monotonic counter a
compromised server could replay an earlier, cryptographically valid patterns
or brain-state blob and no client could tell.  Every recompute now stamps
its rows (and embeds the same value inside the encrypted patterns payload);
the API echoes it next to the ciphertext so clients can verify equality and
pin their own high-water mark.

Revision ID: a3f8d1e6c942
Revises: e5a9c3d7f421
Create Date: 2026-09-19 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "a3f8d1e6c942"
down_revision: str | Sequence[str] | None = "e5a9c3d7f421"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # server_default backfills deployed rows (generation 0) and keeps direct
    # administrative inserts compatible with create_all's schema.
    with op.batch_alter_table("insights") as batch_op:
        batch_op.add_column(
            sa.Column(
                "state_seq",
                sa.BigInteger(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("insights") as batch_op:
        batch_op.drop_column("state_seq")
