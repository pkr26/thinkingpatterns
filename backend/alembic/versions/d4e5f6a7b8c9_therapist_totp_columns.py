"""Optional therapist TOTP columns on users.

2026-09-21 audit C-2/F-4 ("optional TOTP for therapist accounts"),
delivered 2026-09-22. Three nullable columns, no defaults: NULL means
"not enrolled", so this is a plain add on both engines and the
schema-parity gate (compare_type + compare_server_default) stays trivially
green. totp_secret stores the AES-256-GCM-wrapped shared secret (never
plaintext at rest); totp_enabled marks a confirmed enrollment;
totp_last_counter is the newest timestep already consumed (replay fence).

Revision ID: d4e5f6a7b8c9
Revises: b8f4e2a7c9d1
Create Date: 2026-09-22 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | Sequence[str] | None = "b8f4e2a7c9d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.String(length=256), nullable=True))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=True))
    op.add_column("users", sa.Column("totp_last_counter", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "totp_last_counter")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
