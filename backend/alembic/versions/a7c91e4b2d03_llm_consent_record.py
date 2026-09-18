"""users: GDPR consent record (llm_consent_at, llm_consent_disclosure)

Article 7 demonstrability: llm_consent as a bare bool cannot show WHEN
consent was given or WHICH disclosure text it answered. PUT
/account/llm-consent now records utcnow + LLM_DISCLOSURE_VERSION on enable
and clears both on withdrawal.

Both columns are nullable and the revision writes NO data: accounts that
opted in before this revision keep their flag with a NULL record (we
honestly do not know when they consented) and pick up the record on their
next toggle. batch_alter_table is dialect-neutral — plain ALTER TABLE ADD
COLUMN on PostgreSQL, a table rebuild on SQLite (env.py sets
render_as_batch).

Revision ID: a7c91e4b2d03
Revises: e930dbc4f001
Create Date: 2026-09-08 10:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a7c91e4b2d03"
down_revision: str | Sequence[str] | None = "e930dbc4f001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("llm_consent_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column("llm_consent_disclosure", sa.String(length=64), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("llm_consent_disclosure")
        batch_op.drop_column("llm_consent_at")
