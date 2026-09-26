"""Add totp_backup_codes: single-use TOTP recovery codes.

2026-09-26 pentest S-3 (deep-penetration campaign, PENTEST_DEEP_2026-09-26):
a lost authenticator previously required an operator to clear users.totp_*
— an out-of-band, social-engineerable recovery path. Enrollment now mints
a fresh set of 10-char single-use codes (~49.1 bits each, pairing
alphabet), stored ONLY as HMAC-SHA256 digests under a domain-separated
HKDF subkey of the token secret; login redeems one in place of the
six-digit code via an atomic conditional UPDATE on used_at. Rows CASCADE
with the account and are purged in-transaction on TOTP disable.

Schema parity with app.models.TotpBackupCode (compare_type +
compare_server_default gate): datetime columns are sa.DateTime(timezone=
True) exactly like every existing UTCDateTime model column, and there are
no server defaults anywhere in the table.

Revision ID: e8b2d6f4a1c7
Revises: d4e5f6a7b8c9
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e8b2d6f4a1c7"
down_revision: str | Sequence[str] | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "totp_backup_codes",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        op.f("ix_totp_backup_codes_user_id"),
        "totp_backup_codes",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_totp_backup_codes_user_id"), table_name="totp_backup_codes")
    op.drop_table("totp_backup_codes")
