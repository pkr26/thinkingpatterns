"""Voice attachments (VOICE_PLAN.md P2, 2026-09-29): audio_attachments
table + consents.share_voice.

audio_attachments stores OPAQUE client-side ciphertext for kept voice
recordings in object storage (S3 / dev local-dir); the server holds only
metadata. One attachment per (user, client_entry_id); expires_at carries
the 30-day retention (swept periodically, checked lazily per fetch).

consents.share_voice is the patient-toggled, default-false grant letting
the therapist fetch those recordings; the audio route hard-enforces it
and audit-logs every access.

Schema parity with app.models (the L-33 rule): server_defaults mirror the
model columns so a fresh create_all schema and an upgraded one define the
same tables.

Revision ID: e8a4c2f7b1d6
Revises: c3e7f1a9d2b4
Create Date: 2026-09-29 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e8a4c2f7b1d6"
down_revision: str | Sequence[str] | None = "c3e7f1a9d2b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audio_attachments",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "user_id", sa.String(32), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("client_entry_id", sa.String(64), nullable=False),
        sa.Column("backend", sa.String(8), nullable=False),
        sa.Column("storage_key", sa.String(256), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(64), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("content_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "client_entry_id", name="uq_audio_user_client_entry"),
    )
    op.create_index("ix_audio_user_expires", "audio_attachments", ["user_id", "expires_at"])
    with op.batch_alter_table("consents") as batch_op:
        batch_op.add_column(
            sa.Column("share_voice", sa.Boolean(), nullable=False, server_default=sa.text("false"))
        )


def downgrade() -> None:
    with op.batch_alter_table("consents") as batch_op:
        batch_op.drop_column("share_voice")
    op.drop_index("ix_audio_user_expires", table_name="audio_attachments")
    op.drop_table("audio_attachments")
