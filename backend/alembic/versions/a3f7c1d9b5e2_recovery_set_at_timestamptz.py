"""recovery scheme column + recovery_set_at timezone parity (2026-10-01)

Revision ID: a3f7c1d9b5e2
Revises: c8d5f2b6a4e7
Create Date: 2026-10-01

Two users-table fixes from the 2026-10-01 deep audit:

* M15 — b7c4e2f9a1d5 created users.recovery_set_at as bare sa.DateTime(),
  the only users datetime column not created as DateTime(timezone=True)
  (the model maps it through UTCDateTime -> TIMESTAMPTZ on Postgres). The
  autogenerate parity gate could not see the drift: on SQLite both render
  as DATETIME. Postgres-stored values are all utcnow()-derived (UTC), so
  the ALTER to TIMESTAMPTZ interprets them correctly.
* C1 — nullable recovery_scheme marks which verifier/seal scheme the kit
  uses (NULL and 1 = v1 raw-key; 2 = domain-separated verifier, the
  server never sees key material that can open the sealed data key).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a3f7c1d9b5e2"
down_revision: str | Sequence[str] | None = "c8d5f2b6a4e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "recovery_set_at",
            existing_type=sa.DateTime(),
            type_=sa.DateTime(timezone=True),
            existing_nullable=True,
        )
        batch.add_column(sa.Column("recovery_scheme", sa.SmallInteger(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("recovery_scheme")
        batch.alter_column(
            "recovery_set_at",
            existing_type=sa.DateTime(timezone=True),
            type_=sa.DateTime(),
            existing_nullable=True,
        )
