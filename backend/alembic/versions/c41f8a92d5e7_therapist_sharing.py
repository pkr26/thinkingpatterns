"""therapist sharing: roles, consents, pairing codes, notes, access log

The therapist portal feature (2026-09-16). users grows a role + therapist
key material (public wrap key in the clear, private key only as a
password-encrypted blob); four new tables broker zero-knowledge sharing:
consents (patient->therapist grants carrying the wrapped data key),
pairing_codes (short-lived HMAC-stored single-use codes), therapist_notes
(therapist-private encrypted notes, optionally pattern-attached), and
access_log (who read whose shared data when — plain-string ids, no FK, so
the audit trail outlives account deletion).

Revision ID: c41f8a92d5e7
Revises: a7c91e4b2d03
Create Date: 2026-09-16 16:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "c41f8a92d5e7"
down_revision: str | Sequence[str] | None = "a7c91e4b2d03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # users: role discriminates which router an authenticated token may
    # reach; the wrap_* columns exist only on therapist rows (NULL for
    # patients — the model layer enforces the invariant, a CHECK across
    # roles would just duplicate it in a second dialect).
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("role", sa.String(length=16), nullable=False, server_default="user")
        )
        batch_op.add_column(sa.Column("display_name", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("wrap_pub_key", sa.String(length=256), nullable=True))
        batch_op.add_column(sa.Column("wrap_key_blob", sa.LargeBinary(), nullable=True))

    op.create_table(
        "consents",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "therapist_id",
            sa.String(length=32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="full"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ephemeral_pub", sa.String(length=256), nullable=True),
        sa.Column("wrapped_key", sa.LargeBinary(), nullable=True),
        sa.Column("disclosure", sa.String(length=64), nullable=True),
        sa.UniqueConstraint("user_id", "therapist_id", name="uq_consents_user_therapist"),
    )
    op.create_index("ix_consents_therapist_status", "consents", ["therapist_id", "status"])

    op.create_table(
        "pairing_codes",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column(
            "therapist_id",
            sa.String(length=32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_pairing_codes_hash", "pairing_codes", ["code_hash"])

    op.create_table(
        "therapist_notes",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column(
            "therapist_id",
            sa.String(length=32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(length=32),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("client_note_id", sa.String(length=64), nullable=False),
        sa.Column("pattern_pid", sa.String(length=200), nullable=True),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("therapist_id", "client_note_id", name="uq_notes_therapist_client"),
    )
    op.create_index("ix_notes_therapist_patient", "therapist_notes", ["therapist_id", "user_id"])

    op.create_table(
        "access_log",
        sa.Column("id", sa.String(length=32), primary_key=True),
        # Deliberately NOT FKs: the audit trail outlives the account rows.
        sa.Column("actor_id", sa.String(length=32), nullable=False),
        sa.Column("actor_role", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_access_log_actor", "access_log", ["actor_id", "at"])
    op.create_index("ix_access_log_user", "access_log", ["user_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_access_log_user", table_name="access_log")
    op.drop_index("ix_access_log_actor", table_name="access_log")
    op.drop_table("access_log")
    op.drop_index("ix_notes_therapist_patient", table_name="therapist_notes")
    op.drop_table("therapist_notes")
    op.drop_index("ix_pairing_codes_hash", table_name="pairing_codes")
    op.drop_table("pairing_codes")
    op.drop_index("ix_consents_therapist_status", table_name="consents")
    op.drop_table("consents")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("wrap_key_blob")
        batch_op.drop_column("wrap_pub_key")
        batch_op.drop_column("display_name")
        batch_op.drop_column("role")
