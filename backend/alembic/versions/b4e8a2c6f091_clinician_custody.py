"""Atomic clinician encrypted-key custody and rotation retry markers."""

from alembic import op
import sqlalchemy as sa

revision = "b4e8a2c6f091"
down_revision = "a3f7c1d9b5e2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("notes_keyring_blob", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users",
        sa.Column("custody_version", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column("users", sa.Column("custody_operation_id", sa.String(36), nullable=True))
    op.add_column("users", sa.Column("custody_operation_digest", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("custody_operation_epoch", sa.Integer(), nullable=True))


def downgrade():
    for name in (
        "custody_operation_epoch",
        "custody_operation_digest",
        "custody_operation_id",
        "custody_version",
        "notes_keyring_blob",
    ):
        op.drop_column("users", name)
