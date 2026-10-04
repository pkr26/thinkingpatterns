"""Add voice-transcription consent columns (docs/plans/voice-plan.md P1, 2026-09-29).

Voice journaling ships recorded audio to a third-party STT endpoint; the
per-user opt-in gets the same GDPR Art. 7 demonstrability +
policy-fingerprint discipline the LLM consent already has:

    voice_consent           bool, default false (fail closed)
    voice_consent_at        NULL while off; utcnow() on enable
    voice_consent_disclosure  NULL while off; services/stt.py
                            STT_DISCLOSURE_VERSION on enable
    voice_consent_policy    NULL while off; SHA-256 fingerprint of the
                            provider/endpoint/model/retention/policy the
                            user accepted — stale on any operator change,
                            judged per-request by stt.consent_is_current

All four are additive and nullable/defaulted, so the migration is a plain
add on every engine and fresh create_all schemas define the same columns
(the L-33 parity rule — no server_default needed beyond the boolean's).

Revision ID: c3e7f1a9d2b4
Revises: b7f2d8a4e6c1
Create Date: 2026-09-29 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3e7f1a9d2b4"
down_revision: str | Sequence[str] | None = "b7f2d8a4e6c1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("voice_consent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("users", sa.Column("voice_consent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("voice_consent_disclosure", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("voice_consent_policy", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "voice_consent_policy")
    op.drop_column("users", "voice_consent_disclosure")
    op.drop_column("users", "voice_consent_at")
    op.drop_column("users", "voice_consent")
