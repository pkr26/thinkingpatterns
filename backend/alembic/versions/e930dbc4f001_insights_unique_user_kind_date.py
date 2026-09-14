"""insights: unique (user_id, kind, for_date)

Write idempotency for insight rows: the API now upserts dated rows (the
daily question) on this constraint instead of delete-then-insert. Rows with
for_date NULL (the patterns payload, the brain state) never conflict under
it — SQL NULLs are distinct — and stay delete-then-insert under the
per-user recompute lock.

Existing data already satisfies the constraint: the old _replace_insight
deleted any prior row of the same (user, kind[, for_date]) before inserting,
so duplicates cannot exist. batch_alter_table is dialect-neutral here —
on PostgreSQL it issues a plain ALTER TABLE ADD CONSTRAINT; on SQLite
(env.py sets render_as_batch) the table is rebuilt with the constraint.

Revision ID: e930dbc4f001
Revises: 73031d06d71b
Create Date: 2026-09-07 12:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'e930dbc4f001'
down_revision: str | Sequence[str] | None = '73031d06d71b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('insights') as batch_op:
        batch_op.create_unique_constraint(
            'uq_insights_user_kind_date', ['user_id', 'kind', 'for_date']
        )


def downgrade() -> None:
    with op.batch_alter_table('insights') as batch_op:
        batch_op.drop_constraint('uq_insights_user_kind_date', type_='unique')
