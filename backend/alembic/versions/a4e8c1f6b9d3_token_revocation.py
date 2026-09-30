"""Durable single-token logout records

Revision ID: a4e8c1f6b9d3
Revises: f2a8c6d4e9b1
Create Date: 2026-09-27

Independent audit 2026-09-27: logout's jti revocation lived only in the
process-local cache, so a deploy/crash resurrected every logged-out bearer
until its own exp. The table makes the revocation durable; app code
re-hydrates the in-memory cache from it at boot and prunes expired rows
daily (same lifecycle as the access-log retention sweep).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a4e8c1f6b9d3"
down_revision: str | Sequence[str] | None = "f2a8c6d4e9b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "token_revocation",
        sa.Column("jti", sa.String(length=64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_token_revocation_expiry", "token_revocation", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_token_revocation_expiry", table_name="token_revocation")
    op.drop_table("token_revocation")
