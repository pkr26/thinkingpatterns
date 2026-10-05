"""Authenticated per-entry AAD history; explicit trusted legacy bootstrap."""

import sqlalchemy as sa
from alembic import op

revision = "f4a2d8c6b901"
down_revision = "e1b7c9d3a5f2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "entries",
        sa.Column(
            "aad_guard_version", sa.SmallInteger(), nullable=False, server_default=sa.text("0")
        ),
    )
    op.add_column("entries", sa.Column("aad_guard_key_version", sa.Integer(), nullable=True))
    op.add_column("entries", sa.Column("aad_guard_mac", sa.String(64), nullable=True))
    op.create_table(
        "entry_guard_bootstrap",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute("INSERT INTO entry_guard_bootstrap (id, completed_at) VALUES (1, NULL)")


def downgrade():
    op.drop_table("entry_guard_bootstrap")
    with op.batch_alter_table("entries") as batch:
        batch.drop_column("aad_guard_mac")
        batch.drop_column("aad_guard_key_version")
        batch.drop_column("aad_guard_version")
