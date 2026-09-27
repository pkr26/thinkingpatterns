"""Add the access_log forward hash chain (tamper evidence).

2026-09-26 audit item 16: access_log was a plain mutable table — a
database compromise (or an insider with SQL access) could rewrite or
delete audit history undetected. Every row now carries:

  * chain_seq: per-patient insertion order (1-based), unique per patient
    under uq_access_log_user_chain_seq — the writer-side serialization
    backstop (see app/api/_audit.py);
  * prev_hash: the previous row of the SAME patient's chain (NULL on the
    genesis row);
  * entry_hash: SHA-256 over (prev_hash, actor_id, user_id, action, at)
    in the canonical JSON encoding of app/api/_audit.py.

GENESIS BACKFILL (deliberate, stated here): pre-existing rows have no
cryptographic history to anchor on, so this migration deterministically
orders each patient's existing rows by (at, id), numbers them 1..n, and
computes the chain forward from a NULL genesis prev_hash. That makes the
pre-migration history tamper-evident FROM THIS POINT ON; it obviously
cannot prove anything about the period before the chain existed. All new
rows are appended exclusively through app/api/_audit.py's append helper,
which assigns the chain fields at INSERT time.

Indexes: uq_access_log_user_chain_seq is a UNIQUE index on (user_id,
chain_seq) — the per-patient verification walk's traversal order AND the
concurrent-seq backstop. It is an index, not a table constraint, because
the chain lands via ALTER on existing databases and SQLite cannot add
constraints post-hoc; a unique index enforces identically on both engines.
ORDERING IS LOAD-BEARING: the index is created AFTER the genesis backfill,
never before — add_column ships chain_seq with server_default 1, so every
pre-existing row holds seq 1 until the backfill renumbers it, and a unique
index built first would abort `alembic upgrade head` on any populated
database with a UNIQUE constraint failure (the re-audit found exactly
that). The backfill deterministically assigns 1..n per user before the
constraint exists, so the index creation always succeeds.

Revision ID: c6e0b4f8a2d9
Revises: b5d9a3e7f1c8
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy import table, column

revision: str = "c6e0b4f8a2d9"
down_revision: str | Sequence[str] | None = "b5d9a3e7f1c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_access_log = table(
    "access_log",
    column("id", sa.String(32)),
    column("user_id", sa.String(32)),
    column("at", sa.DateTime(timezone=True)),
    column("chain_seq", sa.BigInteger()),
    column("prev_hash", sa.String(64)),
    column("entry_hash", sa.String(64)),
)


def _canonical_at(value) -> str:
    # The SAME canonical encoding as app/api/_audit.py (UTC isoformat of
    # the aware instant); alembic runs sync against the URL's sync driver.
    # A raw sa.text() SELECT bypasses SQLAlchemy type coercion entirely:
    # PostgreSQL hands back datetime objects while SQLite hands back the
    # ISO string the app's UTCDateTime type bound — accept both, normalize
    # to the identical instant either way (a naive value is the historical
    # UTC interpretation, exactly like UTCDateTime.process_result_value).
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _entry_hash(prev_hash: str | None, actor_id: str, user_id: str, action: str, at) -> str:
    payload = json.dumps(
        [prev_hash or "", actor_id, user_id, action, _canonical_at(at)],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.add_column(
        "access_log",
        sa.Column("chain_seq", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column("access_log", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("access_log", sa.Column("entry_hash", sa.String(64), nullable=True))
    # Deterministic genesis backfill, one patient at a time, in (at, id)
    # order — the same order the verification walk reads. It MUST run
    # before uq_access_log_user_chain_seq exists: every pre-existing row
    # still carries the server_default seq 1, and creating the UNIQUE
    # index first fails on any populated database (re-audit, 2026-09-27).
    # The backfill assigns 1..n per user, so by the time the index below
    # is built the per-user seqs are unique by construction.
    conn = op.get_bind()
    user_ids = [row[0] for row in conn.execute(sa.text("SELECT DISTINCT user_id FROM access_log"))]
    for user_id in user_ids:
        rows = conn.execute(
            sa.text(
                "SELECT id, actor_id, user_id, action, at FROM access_log "
                "WHERE user_id = :u ORDER BY at ASC, id ASC"
            ),
            {"u": user_id},
        ).fetchall()
        prev_hash: str | None = None
        for seq, (row_id, actor_id, _uid, action, at) in enumerate(rows, start=1):
            seal = _entry_hash(prev_hash, actor_id, user_id, action, at)
            conn.execute(
                _access_log.update()
                .where(_access_log.c.id == row_id)
                .values(chain_seq=seq, prev_hash=prev_hash, entry_hash=seal)
            )
            prev_hash = seal
    # Only now, with per-row seqs assigned, enforce the invariant.
    op.create_index(
        "uq_access_log_user_chain_seq",
        "access_log",
        ["user_id", "chain_seq"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_access_log_user_chain_seq", table_name="access_log")
    op.drop_column("access_log", "entry_hash")
    op.drop_column("access_log", "prev_hash")
    op.drop_column("access_log", "chain_seq")
