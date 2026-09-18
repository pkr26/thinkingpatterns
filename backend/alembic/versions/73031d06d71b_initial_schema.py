"""initial schema

Reproduces the schema historically created by ``Base.metadata.create_all``
in app/db.py. Plain create_index (not batch mode) is dialect-neutral:
render_as_batch in env.py only matters for column ALTERs, which a
create-only revision has none of.

Revision ID: 73031d06d71b
Revises:
Create Date: 2026-09-07 09:12:38.437929

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "73031d06d71b"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("salt", sa.String(length=128), nullable=False),
        sa.Column("verifier", sa.LargeBinary(), nullable=False),
        sa.Column("scrypt_salt", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("token_epoch", sa.Integer(), nullable=False),
        sa.Column("llm_consent", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    op.create_table(
        "entries",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("client_entry_id", sa.String(length=64), nullable=False),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("entry_date", sa.Date(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "client_entry_id", name="uq_user_client_entry"),
    )
    op.create_index("ix_entries_user_date", "entries", ["user_id", "entry_date"], unique=False)

    op.create_table(
        "insights",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("for_date", sa.Date(), nullable=True),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_insights_user_kind_date", "insights", ["user_id", "kind", "for_date"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_insights_user_kind_date", table_name="insights")
    op.drop_table("insights")
    op.drop_index("ix_entries_user_date", table_name="entries")
    op.drop_table("entries")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
