"""Key-recovery envelope (wave 3, 2026-09-30)

Revision ID: b7c4e2f9a1d5
Revises: e8a4c2f7b1d6
Create Date: 2026-09-30

The zero-knowledge design means a forgotten password destroys the journal.
The optional recovery envelope adds a second, user-held credential: a
random 32-byte recovery key (shown once as a downloadable kit) whose
scrypt verifier the server stores, plus a client-sealed copy of the data
key that only the recovery key opens. All three columns are nullable —
the feature is strictly opt-in per account.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7c4e2f9a1d5"
down_revision: str | Sequence[str] | None = "e8a4c2f7b1d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("recovery_salt", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("recovery_verifier", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("recovery_wrapped_data_key", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("recovery_set_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("recovery_set_at")
        batch.drop_column("recovery_wrapped_data_key")
        batch.drop_column("recovery_verifier")
        batch.drop_column("recovery_salt")
