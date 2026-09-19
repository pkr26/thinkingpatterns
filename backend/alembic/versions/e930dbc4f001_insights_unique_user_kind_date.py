"""insights: unique (user_id, kind, for_date)

Write idempotency for insight rows: the API now upserts dated rows (the
daily question) on this constraint instead of delete-then-insert. Rows with
for_date NULL (the patterns payload, the brain state) never conflict under
it — SQL NULLs are distinct — and stay delete-then-insert under the
per-user recompute lock.

The normal write path (old _replace_insight deleted the prior row before
inserting) should never have produced duplicates, but "should never" is not
a deploy guarantee: a duplicate pair from a concurrent recompute predating
the per-user lock would abort CREATE UNIQUE at upgrade time and block the
deploy. Deduplicate first (2026-09-18 audit), keeping exactly the row
`_latest_insight()` selects (created_at DESC, id DESC) — the same survivor
rule as f6a9b4d1e203 for the undated partial index. batch_alter_table is
dialect-neutral here — on PostgreSQL it issues a plain ALTER TABLE ADD
CONSTRAINT; on SQLite (env.py sets render_as_batch) the table is rebuilt
with the constraint.

Revision ID: e930dbc4f001
Revises: 73031d06d71b
Create Date: 2026-09-07 12:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e930dbc4f001"
down_revision: str | Sequence[str] | None = "73031d06d71b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM insights
        WHERE id IN (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id, kind, for_date
                        ORDER BY created_at DESC, id DESC
                    ) AS row_number
                FROM insights
                WHERE for_date IS NOT NULL
            ) AS ranked_dated_insights
            WHERE row_number > 1
        )
        """
    )
    with op.batch_alter_table("insights") as batch_op:
        batch_op.create_unique_constraint(
            "uq_insights_user_kind_date", ["user_id", "kind", "for_date"]
        )


def downgrade() -> None:
    with op.batch_alter_table("insights") as batch_op:
        batch_op.drop_constraint("uq_insights_user_kind_date", type_="unique")
