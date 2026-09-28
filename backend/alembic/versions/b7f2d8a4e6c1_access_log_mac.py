"""Keyed seal (entry_mac) for the access-log forward chain

Revision ID: b7f2d8a4e6c1
Revises: a4e8c1f6b9d3
Create Date: 2026-09-27

Independent audit 2026-09-27: entry_hash is SHA-256 over PUBLIC fields, so
an attacker with arbitrary database write access could rewrite a whole
patient trail and recompute every link — the forward chain alone only
catches PARTIAL tampering. New rows additionally carry entry_mac =
HMAC-SHA256(server secret, user_id:chain_seq:entry_hash); the secret is
resolved from the environment (MINDPATTERN_AUDIT_MAC_SECRET) or derived
from the token secret, never stored in the database. Existing rows keep
NULL (legacy, link-verified); verification counts them honestly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7f2d8a4e6c1"
down_revision: str | Sequence[str] | None = "a4e8c1f6b9d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Plain nullable ADD COLUMN: valid on both PostgreSQL (ADD COLUMN) and
    # SQLite (null add is fine without table rebuild).
    op.add_column("access_log", sa.Column("entry_mac", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("access_log") as batch:
        batch.drop_column("entry_mac")
