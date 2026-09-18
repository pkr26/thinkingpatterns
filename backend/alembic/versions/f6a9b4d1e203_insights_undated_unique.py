"""Enforce one current undated insight per user and kind.

``uq_insights_user_kind_date`` deliberately permits multiple NULL
``for_date`` values because SQL treats NULLs as distinct.  Patterns and
brain-state rows use that shape, so the application lock alone used to be
the only duplicate prevention.  Retain the same row readers already select
(``created_at DESC, id DESC``), delete older duplicates deterministically,
then add a portable partial unique index.

Revision ID: f6a9b4d1e203
Revises: d52c4e8f14a0
Create Date: 2026-09-18 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "f6a9b4d1e203"
down_revision: str | Sequence[str] | None = "d52c4e8f14a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Keep the exact row `_latest_insight()` has always chosen. The window
    # query is supported by PostgreSQL and every SQLite version supported by
    # current Python/SQLAlchemy; the extra nesting keeps both engines happy
    # when deleting from the same table being ranked.
    op.execute(
        """
        DELETE FROM insights
        WHERE id IN (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id, kind
                        ORDER BY created_at DESC, id DESC
                    ) AS row_number
                FROM insights
                WHERE for_date IS NULL
            ) AS ranked_undated_insights
            WHERE row_number > 1
        )
        """
    )
    op.create_index(
        "uq_insights_user_kind_undated",
        "insights",
        ["user_id", "kind"],
        unique=True,
        sqlite_where=sa.text("for_date IS NULL"),
        postgresql_where=sa.text("for_date IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_insights_user_kind_undated", table_name="insights")
