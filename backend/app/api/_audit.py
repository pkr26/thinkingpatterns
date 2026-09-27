"""AccessLog append + forward-chain verification (2026-09-26 audit item 16).

ONE implementation of the audit hash chain, used by every writer and by
the verification walk. The chain scope is one PATIENT (user_id): each
row's ``prev_hash`` is the previous row's ``entry_hash`` in that patient's
insertion order (``chain_seq``), and ``entry_hash`` is SHA-256 over the
canonical encoding of (prev_hash, actor_id, user_id, action, occurred_at).
A database compromise that rewrites or deletes a middle row of a patient's
trail breaks the link of every later row — silent tampering becomes
detectable by :func:`verify_access_log_chain`.

Concurrency: writers serialize per patient on an in-process lock (the
deployment contract is one process per instance; see singleprocess.py).
The database-side ``uq_access_log_user_chain_seq`` constraint is the
cross-process backstop — an insertion that loses the in-process guarantee
fails loudly with IntegrityError instead of forking the chain.

Retention: the daily sweep prunes the OLDEST rows by ``at``. Verification
therefore anchors on the oldest SURVIVING row: its prev_hash is trusted as
the pruned-prefix boundary, and every link after it must hold. chain_seq
follows insertion order while ``at`` follows wall-clock; in practice they
coincide (both monotonic within a patient), so pruning removes a prefix.
A mid-chain prune would surface as a seq GAP and be reported — the honest,
conservative answer for a compliance artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import ApiError
from ..locks import UserLocks
from ..models import AccessLog, new_id, utcnow

# Per-patient serialization for chain-head reads + insert (see module docs).
# Bounded like every registry (idle entries recycle under the cap).
_audit_chain_locks = UserLocks()

# SHA-256 hex digest length, pinned once so column sizes and checks agree.
CHAIN_HASH_HEX = 64

_UTC = timezone.utc

# The access-log cursor grammar (2026-09-26 audit item 18): the keyset is
# "<tz-aware ISO-8601 instant>|<32-hex row id>". fromisoformat happily
# accepts naive and date-only forms; a naive cursor silently compares
# against UTC instants with an implicit local offset, shifting the page by
# hours per host timezone, and a non-id tail accepted any junk. Both are
# rejected with the existing malformed-cursor 422.
_CURSOR_ID_RE = re.compile(r"[0-9a-f]{32}")


def parse_access_log_cursor(cursor: str) -> tuple[datetime, str]:
    """Validate and split an access-log continuation cursor.

    Returns (instant, row id); raises the shared malformed-cursor 422 on a
    naive/date-only timestamp, a missing separator, or a non-32-hex id.
    """
    parts = cursor.split("|", 1)
    if len(parts) != 2 or not _CURSOR_ID_RE.fullmatch(parts[1]):
        raise ApiError(status_code=422, detail="malformed cursor", code="validation_error")
    try:
        cursor_at = datetime.fromisoformat(parts[0])
    except ValueError:
        raise ApiError(  # noqa: B904 (same-envelope discipline as the old inline parse)
            status_code=422, detail="malformed cursor", code="validation_error"
        ) from None
    if cursor_at.tzinfo is None or cursor_at.tzinfo.utcoffset(cursor_at) is None:
        raise ApiError(status_code=422, detail="malformed cursor", code="validation_error")
    return cursor_at, parts[1]


def canonical_occurred_at(value) -> str:
    """The canonical wire form of a row's ``at`` instant.

    UTCDateTime guarantees tz-aware UTC on read for both dialects; the
    canonical form is the UTC isoformat of that instant, so the hash input
    is identical before the write and after a database round-trip on every
    supported engine.
    """
    return value.astimezone(_UTC).isoformat() if value.tzinfo else value.isoformat()


def compute_entry_hash(
    prev_hash: str | None, actor_id: str, user_id: str, action: str, occurred_at
) -> str:
    """SHA-256 over the canonical encoding of the row's chain inputs.

    JSON array with fixed field order and compact separators: one byte-exact
    encoding for writers, the migration backfill, and verification — a NULL
    genesis prev_hash encodes as the empty string.
    """
    payload = json.dumps(
        [prev_hash or "", actor_id, user_id, action, canonical_occurred_at(occurred_at)],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def append_access_log(
    session: AsyncSession,
    *,
    actor_id: str,
    actor_role: str,
    user_id: str,
    action: str,
    at=None,
    row_id: str | None = None,
) -> AccessLog:
    """Append ONE chained audit row inside the caller's transaction.

    Reads the patient's current chain head and flushes the new row with its
    seq/prev/hash under the per-patient in-process lock, so the row is
    chained deterministically at INSERT time and commits (or rolls back)
    with whatever transaction the caller is in — the audit fact and the
    audited action stay atomic. ``at`` (explicit instant) and ``row_id``
    (explicit primary key) exist for deterministic seeding in tests; every
    runtime call site uses the defaults.
    """
    occurred = at if at is not None else utcnow()
    async with _audit_chain_locks.hold(f"audit-chain:{user_id}"):
        head = (
            await session.execute(
                select(AccessLog.chain_seq, AccessLog.entry_hash)
                .where(AccessLog.user_id == user_id)
                .order_by(AccessLog.chain_seq.desc())
                .limit(1)
            )
        ).first()
        chain_seq = int(head[0]) + 1 if head is not None else 1
        prev_hash: str | None = head[1] if head is not None else None
        row = AccessLog(
            id=row_id if row_id is not None else new_id(),
            actor_id=actor_id,
            actor_role=actor_role,
            user_id=user_id,
            action=action,
            at=occurred,
            chain_seq=chain_seq,
            prev_hash=prev_hash,
            entry_hash=compute_entry_hash(prev_hash, actor_id, user_id, action, occurred),
        )
        session.add(row)
        # flush (not commit): the INSERT joins the caller's transaction, so
        # the chain fields (incl. the unique seq) are validated NOW and the
        # row still commits atomically with the audited action.
        await session.flush()
        return row


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking one patient's audit chain."""

    ok: bool
    rows_checked: int
    # The chain_seq of the first row whose seal/link is broken (None when ok
    # or when the trail is empty).
    broken_at_seq: int | None = None
    reason: str | None = None


def _broken(seq: int, reason: str) -> ChainVerification:
    return ChainVerification(ok=False, rows_checked=0, broken_at_seq=seq, reason=reason)


async def verify_access_log_chain(session: AsyncSession, user_id: str) -> ChainVerification:
    """Walk one patient's audit rows in chain order and detect tampering.

    Checks, per surviving row: the recomputed entry_hash matches the stored
    seal, prev_hash links to the previous row's seal, and chain_seq is
    contiguous. The OLDEST surviving row is the anchor: its prev_hash is
    accepted whatever it is (retention may have pruned the prefix it once
    pointed at) unless the row claims to be the genesis (seq 1) while
    carrying a prev_hash, or a non-genesis row carries none.

    This is a pure read path: no admin surface is required to run it (the
    test suite drives it directly against tampered rows).
    """
    rows = (
        (
            await session.execute(
                select(AccessLog)
                .where(AccessLog.user_id == user_id)
                .order_by(AccessLog.chain_seq.asc())
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return ChainVerification(ok=True, rows_checked=0)
    first = rows[0]
    if first.chain_seq == 1 and first.prev_hash is not None:
        return _broken(first.chain_seq, "genesis row carries a prev_hash")
    if first.chain_seq > 1 and first.prev_hash is None:
        return _broken(
            first.chain_seq, "non-genesis row has no prev_hash (pruned prefix cannot be anchored)"
        )
    previous: AccessLog | None = None
    for row in rows:
        if previous is not None and row.chain_seq != previous.chain_seq + 1:
            return _broken(
                row.chain_seq,
                f"chain_seq gap after {previous.chain_seq} (mid-trail deletion or forged insert)",
            )
        if row.entry_hash is None or len(row.entry_hash) != CHAIN_HASH_HEX:
            return _broken(row.chain_seq, "missing or malformed entry_hash")
        expected = compute_entry_hash(row.prev_hash, row.actor_id, row.user_id, row.action, row.at)
        if expected != row.entry_hash:
            return _broken(row.chain_seq, "entry_hash does not match the row's contents")
        if previous is not None and row.prev_hash != previous.entry_hash:
            return _broken(row.chain_seq, "prev_hash does not link to the previous row's seal")
        previous = row
    return ChainVerification(ok=True, rows_checked=len(rows))
