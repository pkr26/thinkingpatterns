"""Bind resumable corpus rotation to its atomic credential transaction."""

import sqlalchemy as sa
from alembic import op

revision = "d6a0c4e8b213"
down_revision = "c5f9b3d7a102"
branch_labels = None
depends_on = None


def upgrade():
    for name, typ in (
        ("rekey_operation_id", sa.String(36)),
        ("rekey_operation_digest", sa.String(64)),
        ("rekey_operation_epoch", sa.Integer()),
        ("rekey_operation_result", sa.Text()),
    ):
        op.add_column("users", sa.Column(name, typ, nullable=True))
    for name, size in (
        ("operation_id", 36),
        ("request_digest", 64),
        ("old_key_fingerprint", 64),
        ("new_key_fingerprint", 64),
    ):
        op.add_column("rekey_journal", sa.Column(name, sa.String(size), nullable=True))


def downgrade():
    for name in ("new_key_fingerprint", "old_key_fingerprint", "request_digest", "operation_id"):
        op.drop_column("rekey_journal", name)
    for name in (
        "rekey_operation_result",
        "rekey_operation_epoch",
        "rekey_operation_digest",
        "rekey_operation_id",
    ):
        op.drop_column("users", name)
