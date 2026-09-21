"""Add entries.content_version (2026-09-20 audit fix M-2).

A monotonic per-row content generation: 1 on create, +1 on every replaced
blob. Clients bind it into the v2 entry AAD ("entry", user, id, version) so
a compromised server can no longer pair a stale-but-valid ciphertext with a
truthful version echo, and they keep a per-id high-water mark client-side.
Existing rows backfill to 1 (the only generation a pre-versioning row can
be at: every prior replace overwrote in place, and clients treat the first
version-bearing observation as the baseline).

Revision ID: d7c1f4a8e2b9
Revises: b1c7f2e9a4d6
Create Date: 2026-09-20 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7c1f4a8e2b9"
down_revision: str | Sequence[str] | None = "b1c7f2e9a4d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "entries",
        sa.Column(
            "content_version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )


def downgrade() -> None:
    op.drop_column("entries", "content_version")
