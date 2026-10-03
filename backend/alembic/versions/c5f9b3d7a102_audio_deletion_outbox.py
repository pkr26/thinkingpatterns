"""Durable audio object deletion and nonsecret storage locators."""

from alembic import op
import sqlalchemy as sa

revision = "c5f9b3d7a102"
down_revision = "b4e8a2c6f091"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("audio_attachments", sa.Column("storage_locator", sa.String(2048), nullable=True))
    op.create_table(
        "audio_deletions",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("backend", sa.String(8), nullable=False),
        sa.Column("storage_key", sa.String(256), nullable=False),
        sa.Column("storage_locator", sa.String(2048), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.create_index("ix_audio_deletions_not_before", "audio_deletions", ["not_before"])


def downgrade():
    op.drop_table("audio_deletions")
    op.drop_column("audio_attachments", "storage_locator")
