"""AccessLog append + forward-chain verification (2026-09-26 audit item 16).

ONE implementation of the audit hash chain, used by every writer and by
the verification walk. The chain scope is one PATIENT (user_id): each
row's ``prev_hash`` is the previous row's ``entry_hash`` in that patient's
insertion order (``chain_seq``), and ``entry_hash`` is SHA-256 over the
canonical encoding of (prev_hash, actor_id, user_id, action, occurred_at).
A database compromise that rewrites or deletes a middle row of a patient's
trail breaks the link of every later row — silent tampering becomes
detectable by :func:`verify_access_log_chain`.

Independent audit 2026-09-27 — two honest boundaries of that scheme are
now closed:

* ``entry_hash`` is over PUBLIC fields, so an attacker with arbitrary DB
  write access could rewrite a whole trail and recompute every link. New
  rows also carry ``entry_mac`` = HMAC-SHA256(secret held OUTSIDE the
  database, "user_id:chain_seq:entry_hash"); the full-rewrite attack now
  needs the server's MAC key. Pre-column rows keep NULL (legacy,
  link-verified) and are counted by verification.
* A forward chain cannot detect deletion of its NEWEST rows. When
  ``settings.audit_journal_path`` is set, every committed append also
  writes a line to that append-only file (outside the database) and
  verification flags a journal AHEAD of the database head as tail
  truncation. A journal BEHIND the head is benign (crash between commit
  and journal write) and never fails verification.

Concurrency: writers serialize per patient on an in-process lock (the
deployment contract is one process per instance; see singleprocess.py).
The lock covers the append itself, not the caller's COMMIT — request B
can read the chain head before A's uncommitted row lands and lose the
unique-seq race at flush. The append therefore retries on
IntegrityError: the losing INSERT rolls back to its savepoint, the head
re-read (now seeing the committed winner) yields the next seq, and the
audited action survives instead of failing with a 500. The database-side
``uq_access_log_user_chain_seq`` constraint remains the cross-process
backstop — an insertion that loses the in-process guarantee fails loudly
instead of forking the chain.

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
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import ApiError
from ..locks import UserLocks
from ..models import AccessLog, new_id, utcnow

logger = logging.getLogger(__name__)

# Per-patient serialization for chain-head reads + insert (see module docs).
# Bounded like every registry (idle entries recycle under the cap).
_audit_chain_locks = UserLocks()

# SHA-256 hex digest length, pinned once so column sizes and checks agree.
CHAIN_HASH_HEX = 64

# How many times an append re-reads the head after losing the unique-seq
# race (see module docs). Two is the observed worst case (one concurrent
# winner); three tolerates a pathological burst without unbounded retries.
APPEND_MAX_ATTEMPTS = 3

# The MAC key configured at app startup from settings (create_app). A
# module-level handle on the same standing as the lock registries: every
# runtime append then seals without each call site threading the key
# through, while direct/test callers may pass ``mac_key`` explicitly or
# leave rows unsealed (legacy link-only rows) for deterministic seeding.
_configured_mac_key: bytes | None = None


def configure_audit_mac_key(key: bytes | None) -> None:
    """Set (or clear) the process-wide chain MAC key."""
    global _configured_mac_key
    _configured_mac_key = key


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


def compute_entry_mac(mac_key: bytes, user_id: str, chain_seq: int, entry_hash: str) -> str:
    """Keyed seal over the row's chain position (independent audit 2026-09-27).

    Binds user_id + chain_seq + entry_hash: a rewritten row must not only
    recompute its link hashes but forge this HMAC under a key that never
    lives in the database. Binding the seq makes it useless to splice a
    forged row into a different position of the same patient's chain.
    """
    return hmac.new(
        mac_key, f"{user_id}:{chain_seq}:{entry_hash}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _stage_journal_entry(session: AsyncSession, row: AccessLog) -> None:
    """Queue one committed-to-be row for the post-commit journal append.

    Staged on the session (not the row) so the journal write can happen
    strictly AFTER the caller's commit — writing before commit would let a
    rollback leave phantom journal lines AHEAD of the database, which is
    exactly the signal the journal exists to catch. Sessions without an
    ``info`` bag (narrow test doubles) skip staging: the journal is
    best-effort by contract.
    """
    info = getattr(session, "info", None)
    if info is None:
        return
    pending = info.setdefault("mindpattern_audit_journal_pending", [])
    pending.append((row.user_id, row.chain_seq, row.entry_hash or "", row.entry_mac or "-", row.at))


async def flush_audit_journal(session: AsyncSession, journal_path: str) -> int:
    """Append staged rows to the out-of-DB journal; call AFTER commit.

    Best-effort by design: a failed or lost journal write leaves the
    journal BEHIND the database head, which verification treats as benign
    (crash-window semantics) — the anchor must never turn a logging hiccup
    into a false tampering alarm. Returns the number of lines written.
    """
    info = getattr(session, "info", None)
    pending = info.pop("mindpattern_audit_journal_pending", []) if info is not None else []
    if not pending or not journal_path:
        return 0
    lines = []
    for user_id, seq, entry_hash, entry_mac, at in pending:
        lines.append(f"{user_id} {seq} {entry_hash} {entry_mac} {canonical_occurred_at(at)}\n")
    try:
        with open(journal_path, "a", encoding="utf-8") as handle:
            handle.writelines(lines)
            handle.flush()
    except OSError:
        logger.exception("audit journal append failed (journal falls behind; benign)")
        # The staged entries are consumed either way: retrying on the next
        # request would write them out of chain order.
    return len(lines)


def read_journal_head(journal_path: str, user_id: str) -> tuple[int, str] | None:
    """The (chain_seq, at) of the user's last journaled row, or None.

    One linear scan of the append-only file; the daily verification sweep
    is the only runtime caller, so the O(file) walk is fine there.
    """
    return read_journal_heads(journal_path).get(user_id)


def read_journal_heads(journal_path: str) -> dict[str, tuple[int, str]]:
    """Every user's (max chain_seq, at) from the journal — ONE pass.

    2026-09-28 audit M-5: the sweep used to call read_journal_head per
    patient (O(patients × file)); the daily walk now builds this map once
    and hands it to each verification. Corrupt lines contribute no anchor
    (the journal is evidence, not authority) and never raise.
    """
    heads: dict[str, tuple[int, str]] = {}
    try:
        with open(journal_path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) != 5:
                    continue
                try:
                    seq = int(parts[1])
                except ValueError:
                    continue
                best = heads.get(parts[0])
                if best is None or seq > best[0]:
                    heads[parts[0]] = (seq, parts[4])
    except OSError:
        return {}
    return heads


def compact_audit_journal(journal_path: str, cutoff_at: str) -> tuple[int, int]:
    """Drop journal lines whose ``at`` predates the cutoff; (kept, dropped).

    2026-09-28 audit M-5: the database trail is pruned by retention but
    the journal file grew forever, and every verification pass walked all
    of it. Compaction is retention-aligned and SAFE by the journal's own
    contract: a journal behind the database head is benign (crash-window
    semantics), and every line older than the retention cutoff describes
    rows the database no longer has either — the truncation detector only
    ever compares the journal's NEWEST line. Atomic (temp file + replace)
    so a crash mid-compaction leaves the old file intact; best-effort
    (an OSError propagates to the sweep's existing per-cycle catch, which
    logs and retries next cycle — an uncompactable journal must never
    take the app down).
    """
    kept: list[str] = []
    dropped = 0
    with open(journal_path, encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 5 and parts[4] < cutoff_at:
                # ISO-8601 UTC instants sort lexically as chronologically
                # (canonical_occurred_at guarantees the shape on write);
                # unparseable lines are kept, never destroyed.
                dropped += 1
                continue
            kept.append(line)
    tmp_path = f"{journal_path}.compact.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.writelines(kept)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, journal_path)
    return len(kept), dropped


async def append_access_log(
    session: AsyncSession,
    *,
    actor_id: str,
    actor_role: str,
    user_id: str,
    action: str,
    at=None,
    row_id: str | None = None,
    mac_key: bytes | None = None,
) -> AccessLog:
    """Append ONE chained audit row inside the caller's transaction.

    Reads the patient's current chain head and flushes the new row with its
    seq/prev/hash under the per-patient in-process lock, so the row is
    chained deterministically at INSERT time and commits (or rolls back)
    with whatever transaction the caller is in — the audit fact and the
    audited action stay atomic. ``at`` (explicit instant) and ``row_id``
    (explicit primary key) exist for deterministic seeding in tests; every
    runtime call site uses the defaults. ``mac_key`` (from
    ``settings.audit_mac_secret_hex``) seals the row with the keyed MAC;
    rows seeded without one are link-only legacy rows, like pre-column
    rows. On a unique-seq race at flush (a concurrent writer's row
    committed between this head read and the INSERT) the append rolls back
    to its savepoint and retries with the fresh head — the audited action
    must not 500 because two of the patient's own requests overlapped.
    """
    occurred = at if at is not None else utcnow()
    effective_mac_key = mac_key if mac_key is not None else _configured_mac_key
    async with _audit_chain_locks.hold(f"audit-chain:{user_id}"):
        last_conflict: IntegrityError | None = None
        for _attempt in range(APPEND_MAX_ATTEMPTS):
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
            entry_hash = compute_entry_hash(prev_hash, actor_id, user_id, action, occurred)
            row = AccessLog(
                id=row_id if row_id is not None else new_id(),
                actor_id=actor_id,
                actor_role=actor_role,
                user_id=user_id,
                action=action,
                at=occurred,
                chain_seq=chain_seq,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                entry_mac=(
                    compute_entry_mac(effective_mac_key, user_id, chain_seq, entry_hash)
                    if effective_mac_key is not None
                    else None
                ),
            )
            try:
                # flush (not commit): the INSERT joins the caller's
                # transaction, so the chain fields (incl. the unique seq)
                # are validated NOW and the row still commits atomically
                # with the audited action. The savepoint is the retry seam
                # — the documented SQLAlchemy recovery pattern: the row is
                # added INSIDE the nested context because begin_nested()
                # flushes pending state BEFORE creating the savepoint; an
                # add outside it would fail that pre-savepoint flush and
                # poison the caller's whole transaction. On the unique-seq
                # race the context exit rolls back ONLY this INSERT.
                # Session doubles in tests may not implement savepoints —
                # they flush bare (no retry seam, the pre-audit behavior).
                begin_nested = getattr(session, "begin_nested", None)
                if begin_nested is not None:
                    async with session.begin_nested():
                        session.add(row)
                        await session.flush()
                else:
                    session.add(row)
                    await session.flush()
            except IntegrityError as exc:
                # The savepoint's context exit has already rolled the
                # INSERT back (and restored the ORM state); the row object
                # is dead weight from here on.
                last_conflict = exc
                continue
            _stage_journal_entry(session, row)
            return row
        raise ApiError(
            status_code=500,
            detail="audit chain append lost the seq race repeatedly",
            code="internal_error",
        ) from last_conflict


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking one patient's audit chain."""

    ok: bool
    rows_checked: int
    # The chain_seq of the first row whose seal/link is broken (None when ok
    # or when the trail is empty).
    broken_at_seq: int | None = None
    reason: str | None = None
    # Rows sealed before the MAC column existed (or seeded without a key):
    # link-verified only. Honest bookkeeping, not an error — they age out
    # through retention.
    legacy_rows: int = 0


def _broken(seq: int, reason: str) -> ChainVerification:
    return ChainVerification(ok=False, rows_checked=0, broken_at_seq=seq, reason=reason)


async def verify_access_log_chain(
    session: AsyncSession,
    user_id: str,
    *,
    mac_key: bytes | None = None,
    journal_path: str | None = None,
    retention_cutoff=None,
    journal_heads: dict[str, tuple[int, str]] | None = None,
) -> ChainVerification:
    """Walk one patient's audit rows in chain order and detect tampering.

    Checks, per surviving row: the recomputed entry_hash matches the stored
    seal, prev_hash links to the previous row's seal, and chain_seq is
    contiguous. When ``mac_key`` is provided, every row carrying an
    ``entry_mac`` must also verify its keyed seal (rows with NULL macs are
    counted as legacy and link-verified only). The OLDEST surviving row is
    the anchor: its prev_hash is accepted whatever it is (retention may
    have pruned the prefix it once pointed at) unless the row claims to be
    the genesis (seq 1) while carrying a prev_hash, or a non-genesis row
    carries none.

    Independent audit 2026-09-27: when ``journal_path`` is set and the
    journal is AHEAD of the database head for this patient (the journal
    recorded rows the database no longer has), that is tail truncation and
    the walk fails. A journal BEHIND the head is benign — a crash between
    the database commit and the journal append loses lines, it never
    fabricates them. An empty database with fresh journal lines only fails
    when the journal's newest line post-dates ``retention_cutoff`` (an
    empty trail is otherwise legitimate post-retention state).

    This is a pure read path; the daily sweep in main.py runs it for
    recently-active patients, and the test suite drives it directly
    against tampered rows.
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
    legacy = 0
    if not rows:
        if journal_path:
            head = (
                journal_heads.get(user_id)
                if journal_heads is not None
                else read_journal_head(journal_path, user_id)
            )
            if head is not None and retention_cutoff is not None:
                from datetime import datetime as _dt

                try:
                    head_at = _dt.fromisoformat(head[1])
                except ValueError:
                    head_at = None
                if head_at is not None and head_at > retention_cutoff:
                    return ChainVerification(
                        ok=False,
                        rows_checked=0,
                        reason="journal records rows this database no longer has (tail truncation)",
                    )
        return ChainVerification(ok=True, rows_checked=0, legacy_rows=0)
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
        if row.entry_mac is None:
            legacy += 1
        elif mac_key is not None:
            expected_mac = compute_entry_mac(mac_key, row.user_id, row.chain_seq, row.entry_hash)
            # 2026-09-28 audit L-2: the keyed comparison gets the same
            # constant-time discipline as the token signature check
            # (tokens.py) — hmac.compare_digest, never !=.
            if not hmac.compare_digest(expected_mac, row.entry_mac):
                return _broken(
                    row.chain_seq,
                    "entry_mac does not verify (row rewritten without the chain key)",
                )
        previous = row
    if journal_path:
        head = (
            journal_heads.get(user_id)
            if journal_heads is not None
            else read_journal_head(journal_path, user_id)
        )
        if head is not None and head[0] > rows[-1].chain_seq:
            return ChainVerification(
                ok=False,
                rows_checked=len(rows),
                broken_at_seq=rows[-1].chain_seq,
                reason=(
                    f"journal is ahead of the database head "
                    f"(journal seq {head[0]} > db seq {rows[-1].chain_seq}; tail truncation)"
                ),
                legacy_rows=legacy,
            )
    return ChainVerification(ok=True, rows_checked=len(rows), legacy_rows=legacy)
