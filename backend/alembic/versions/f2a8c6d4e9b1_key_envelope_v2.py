"""Add v2 key-scheme columns: key_scheme, wrapped_data_key, kdf_params.

2026-09-26 crypto-architecture remediation: v1 accounts derive the data
key directly from the password, so a password change forces an O(corpus)
server-side rekey. v2 accounts keep a RANDOM 32-byte data key wrapped
client-side under a password-derived KEK (security/envelope.py); the
server stores the wrapped blob opaquely (it never holds the KEK), and a
password change becomes an O(1) salt/verifier/envelope swap.

    key_scheme        "v1" (default, every existing account) | "v2"
    wrapped_data_key  NULL on v1; the 60-byte AES-GCM envelope on v2
    kdf_params        NULL on v1; canonical JSON of the versioned client
                      KDF parameters blob (see security.kdf)

The default keeps every existing row v1 — v1 flows remain fully
supported; accounts move to v2 only through the explicit client-driven
paths (v2 registration, POST /account/key-envelope/upgrade, or the
envelope-carrying password change). Schema parity with app.models.User:
server_default "'v1'" mirrors the model's so a fresh create_all schema
and an upgraded one define the same column (the L-33 parity rule).

Revision ID: f2a8c6d4e9b1
Revises: d7f1c5a9b3e0
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f2a8c6d4e9b1"
down_revision: str | Sequence[str] | None = "d7f1c5a9b3e0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("key_scheme", sa.String(8), nullable=False, server_default=sa.text("'v1'")),
    )
    op.add_column("users", sa.Column("wrapped_data_key", sa.LargeBinary(), nullable=True))
    op.add_column("users", sa.Column("kdf_params", sa.String(256), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "kdf_params")
    op.drop_column("users", "wrapped_data_key")
    op.drop_column("users", "key_scheme")
