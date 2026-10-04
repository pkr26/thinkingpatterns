"""AccessLog append + forward-chain verification (2026-09-26 audit item 16).

ONE implementation of the audit hash chain, used by every writer and by
the verification walk. The chain scope is one PATIENT (user_id): each
row's ``prev_hash`` is the previous row's ``entry_hash`` in that patient's
insertion order (``chain_seq``), and ``entry_hash`` is SHA-256 over the
canonical encoding of (prev_hash, actor_id, user_id, action, occurred_at,
actor_role) for current v2 records (historical v1 omitted actor_role).
A database compromise that rewrites or deletes a middle row of a patient's
trail breaks the link of every later row — silent tampering becomes
detectable by :func:`verify_access_log_chain`.

Independent audit 2026-09-27 — two honest boundaries of that scheme are
now closed:

* ``entry_hash`` is over PUBLIC fields, so an attacker with arbitrary DB
  write access could rewrite a whole trail and recompute every link. New
  rows also carry ``entry_mac`` = HMAC-SHA256(secret held OUTSIDE the
  database, "user_id:chain_seq:entry_hash"); the full-rewrite attack now
  needs the server's MAC key. A keyed verification rejects NULL seals,
  including genuine pre-column rows, until an operator independently
  reviews and seals the legacy snapshot with the offline migration tool.
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

Retention: the daily sweep atomically advances an HMAC-sealed retained-prefix
anchor before deleting old rows. Verification requires the oldest survivor
to match that anchor and the database tail to match the sealed high-water
state. A fully pruned trail is accepted only when the sealed head predates
the retention cutoff; a later append continues from that high-water mark.
"""

from __future__ import annotations

import anyio

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
import tempfile
from contextlib import closing
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Callable, Mapping

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import ApiError
from ..locks import UserLocks
from ..models import AccessLog, AuditChainState, AuditSweepCursor, new_id, utcnow

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

# Daily maintenance caps both owner fan-out and each owner's delete. Full
# chain verification is streamed before mutation; a backlog drains over
# successive passes without one transaction monopolizing the database.
AUDIT_MAINTENANCE_OWNER_BATCH = 500
AUDIT_PRUNE_ROW_BATCH = 500
# Keep the aggregate delete/anchor work bounded as well as each owner.  The
# round-robin owner cursor in ``main.py`` supplies fairness between passes.
AUDIT_PRUNE_TOTAL_ROW_BATCH = 5_000
# Independent full verification uses the same cooperative aggregate budget;
# a single very large owner resumes from a durable authenticated checkpoint.
AUDIT_VERIFY_ROW_BATCH = 500
AUDIT_VERIFY_TOTAL_ROW_BATCH = 5_000
# Migration-created state rows are sealed only after a bounded, streamed
# verification pass.  Anything larger belongs in the operator-attested,
# partitioned offline migration documented in scripts/README_audit_migration.md.
AUDIT_LEGACY_SEAL_ROW_BUDGET = 100_000

# The MAC key configured at app startup from settings (create_app). A
# module-level handle on the same standing as the lock registries: every
# runtime append then seals without each call site threading the key
# through, while direct/test callers may pass ``mac_key`` explicitly or
# leave rows unsealed (legacy link-only rows) for deterministic seeding.
_configured_mac_keys: dict[int, bytes] = {}
_configured_current_mac_key_version = 1
_configured_journal_path: str = ""
_journal_io_lock = threading.RLock()
_journal_health_lock = threading.Lock()
_journal_healthy = True
_journal_last_error: str | None = None


def _set_journal_health(healthy: bool, error: str | None = None) -> None:
    global _journal_healthy, _journal_last_error
    with _journal_health_lock:
        _journal_healthy = healthy
        _journal_last_error = error


def audit_journal_health() -> tuple[bool, str | None]:
    """Process-wide journal I/O health without exposing paths or user data."""
    with _journal_health_lock:
        return _journal_healthy, _journal_last_error


def validate_audit_journal_path(journal_path: str) -> None:
    """Create/fsync the journal target or fail startup with a named error."""
    if not journal_path:
        raise RuntimeError("MINDPATTERN_AUDIT_JOURNAL is empty")
    parent = os.path.dirname(os.path.abspath(journal_path)) or "."
    if not os.path.isdir(parent):
        raise RuntimeError("MINDPATTERN_AUDIT_JOURNAL parent directory does not exist")
    try:
        with _journal_io_lock:
            with open(journal_path, "a", encoding="utf-8") as handle:
                handle.flush()
                os.fsync(handle.fileno())
    except OSError as exc:
        _set_journal_health(False, "io_failure")
        raise RuntimeError("MINDPATTERN_AUDIT_JOURNAL is not writable") from exc
    _set_journal_health(True)


def configure_audit_mac_key(
    key: bytes | None,
    journal_path: str = "",
    *,
    key_version: int = 1,
    previous_keys: Mapping[int, bytes] | None = None,
) -> None:
    """Set the versioned process-wide chain key ring and journal anchor."""
    global _configured_mac_keys, _configured_current_mac_key_version, _configured_journal_path
    if os.path.abspath(journal_path or ".") != os.path.abspath(_configured_journal_path or "."):
        close_reusable_journal_evidence_index()
    ring = dict(previous_keys or {})
    if key is not None:
        ring[key_version] = key
    _configured_mac_keys = ring
    _configured_current_mac_key_version = key_version
    _configured_journal_path = journal_path
    _set_journal_health(True)


def _effective_mac_keys(
    mac_key: bytes | None,
    mac_keys: Mapping[int, bytes] | None,
    current_mac_key_version: int | None,
) -> tuple[dict[int, bytes], int]:
    """Resolve legacy one-key callers and the runtime versioned key ring."""
    if mac_keys is not None:
        return dict(mac_keys), current_mac_key_version or 1
    if mac_key is not None:
        return {1: mac_key}, current_mac_key_version or 1
    return dict(_configured_mac_keys), (
        current_mac_key_version or _configured_current_mac_key_version
    )


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
    prev_hash: str | None,
    actor_id: str,
    user_id: str,
    action: str,
    occurred_at,
    *,
    actor_role: str = "",
    record_version: int = 1,
) -> str:
    """SHA-256 over the canonical encoding of the row's chain inputs.

    JSON array with fixed field order and compact separators: one byte-exact
    encoding for writers, the migration backfill, and verification — a NULL
    genesis prev_hash encodes as the empty string.
    """
    fields = [prev_hash or "", actor_id, user_id, action, canonical_occurred_at(occurred_at)]
    if record_version >= 2:
        fields.append(actor_role)
    payload = json.dumps(
        fields,
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


def compute_chain_state_mac(mac_key: bytes, state: AuditChainState) -> str:
    """Seal every durable chain anchor field under the out-of-DB key."""
    payload = json.dumps(
        [
            state.state_version,
            state.mac_key_version,
            state.user_id,
            state.head_seq,
            state.head_hash,
            canonical_occurred_at(state.head_at),
            state.first_retained_seq,
            state.first_retained_hash,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hmac.new(mac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_verification_checkpoint_mac(mac_key: bytes, cursor: AuditSweepCursor) -> str:
    """Authenticate the durable incremental-verification position."""
    payload = json.dumps(
        [
            "mindpattern/audit-verification-checkpoint/v1",
            cursor.id,
            cursor.last_user_id,
            cursor.verification_owner_id,
            cursor.verification_snapshot_head_seq,
            cursor.verification_snapshot_head_hash,
            cursor.verification_next_seq,
            cursor.verification_previous_hash,
            int(cursor.verification_rows_checked or 0),
            cursor.verification_mac_key_version,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hmac.new(mac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _clear_incremental_verification(cursor: AuditSweepCursor) -> None:
    cursor.verification_owner_id = None
    cursor.verification_snapshot_head_seq = None
    cursor.verification_snapshot_head_hash = None
    cursor.verification_next_seq = None
    cursor.verification_previous_hash = None
    cursor.verification_rows_checked = 0


def seal_verification_checkpoint(
    cursor: AuditSweepCursor,
    mac_keys: Mapping[int, bytes],
    current_mac_key_version: int,
) -> None:
    key = mac_keys.get(current_mac_key_version)
    if key is None or len(key) != 32:
        raise ApiError(500, "current audit MAC key is unavailable", "audit_integrity_error")
    cursor.verification_mac_key_version = current_mac_key_version
    cursor.verification_checkpoint_mac = compute_verification_checkpoint_mac(key, cursor)


def authenticate_verification_checkpoint(
    cursor: AuditSweepCursor,
    mac_keys: Mapping[int, bytes],
    current_mac_key_version: int,
) -> None:
    """Verify a checkpoint or safely initialize an unsealed migration row."""
    if cursor.verification_checkpoint_mac is None:
        # Never trust an old, unsealed traversal position. Restarting from
        # the first owner is safe and finite; accepting last_user_id would
        # let a database writer starve an arbitrary prefix of owners.
        cursor.last_user_id = None
        _clear_incremental_verification(cursor)
        seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        return
    version = cursor.verification_mac_key_version
    key = mac_keys.get(version or 0)
    if (
        key is None
        or len(key) != 32
        or not hmac.compare_digest(
            compute_verification_checkpoint_mac(key, cursor),
            cursor.verification_checkpoint_mac,
        )
    ):
        raise ApiError(
            500,
            "audit verification checkpoint does not authenticate",
            "audit_integrity_error",
        )


@dataclass(frozen=True)
class JournalEvidence:
    seq: int
    entry_hash: str
    entry_mac: str
    at: str
    conflict: bool = False


class JournalEvidenceIndex:
    """Disk-spooled journal heads/conflicts with bounded process memory.

    The temporary SQLite file is mode-0600 (``mkstemp``) and contains only
    the same pseudonymous seals already present in the operator-controlled
    journal.  Callers must close it after a maintenance pass.
    """

    def __init__(self, path: str, *, corrupt: bool = False) -> None:
        self.path = path
        self.corrupt = corrupt
        self._closed = False
        self._lock = threading.RLock()

    def get(self, owner: str) -> JournalEvidence | None:
        with self._lock:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                row = connection.execute(
                    """SELECT head_seq, entry_hash, entry_mac, occurred_at, conflict
                         FROM owner_heads WHERE owner = ?""",
                    (owner,),
                ).fetchone()
        if row is None:
            return None
        return JournalEvidence(int(row[0]), row[1], row[2], row[3], bool(row[4]))

    def owner_ids_after(self, owner: str | None, limit: int) -> list[str]:
        with self._lock:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                if owner is None:
                    rows = connection.execute(
                        "SELECT owner FROM owner_heads ORDER BY owner LIMIT ?", (limit,)
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT owner FROM owner_heads WHERE owner > ? ORDER BY owner LIMIT ?",
                        (owner, limit),
                    ).fetchall()
        return [row[0] for row in rows]

    def owner_ids_through(self, owner: str, limit: int) -> list[str]:
        with self._lock:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                rows = connection.execute(
                    "SELECT owner FROM owner_heads WHERE owner <= ? ORDER BY owner LIMIT ?",
                    (owner, limit),
                ).fetchall()
        return [row[0] for row in rows]

    def all_evidence(self) -> dict[str, JournalEvidence]:
        """Compatibility materialization for explicit diagnostic callers."""
        with self._lock:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                rows = connection.execute(
                    """SELECT owner, head_seq, entry_hash, entry_mac, occurred_at, conflict
                         FROM owner_heads"""
                ).fetchall()
        evidence = {
            row[0]: JournalEvidence(int(row[1]), row[2], row[3], row[4], bool(row[5]))
            for row in rows
        }
        if self.corrupt:
            evidence[JOURNAL_CORRUPTION_KEY] = _corrupt_journal_evidence()
        return evidence

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass

    def apply_entries(self, entries) -> None:
        """Add fsynced journal entries without rescanning the source file."""
        with self._lock:
            if self._closed:
                raise RuntimeError("audit journal evidence index is closed")
            with closing(sqlite3.connect(self.path)) as connection, connection:
                for owner, seq, entry_hash, entry_mac, at in entries:
                    _upsert_journal_evidence(
                        connection,
                        owner,
                        int(seq),
                        entry_hash,
                        entry_mac,
                        canonical_occurred_at(at),
                    )

    def __enter__(self) -> JournalEvidenceIndex:
        return self

    def __exit__(self, *_args) -> None:
        self.close()


_journal_index_cache: JournalEvidenceIndex | None = None
_journal_index_cache_source: str | None = None
_journal_index_cache_fingerprint: tuple[int, int, int, int, int] | None = None


# Reserved map entry representing corruption that cannot safely be
# attributed to an owner (truncated/malformed line or journal I/O loss).
# Runtime user ids are exactly 32 lowercase hex characters, so this cannot
# collide with a real chain owner.
JOURNAL_CORRUPTION_KEY = "__journal_corrupt__"
_JOURNAL_OWNER_RE = re.compile(r"[0-9a-f]{32}")
_JOURNAL_HEX_RE = re.compile(r"[0-9a-f]{64}")
_JOURNAL_SEQ_RE = re.compile(r"[1-9][0-9]*")


def _corrupt_journal_evidence() -> JournalEvidence:
    return JournalEvidence(0, "", "", "", True)


def _parse_journal_line(line: str) -> tuple[str, int, str, str, str] | None:
    """Strictly parse one journal line; blank lines are harmless."""
    if not line.strip():
        return None
    parts = line.split()
    if len(parts) != 5:
        raise ValueError("field count")
    owner, seq_text, entry_hash, entry_mac, occurred_at = parts
    if _JOURNAL_OWNER_RE.fullmatch(owner) is None:
        raise ValueError("owner")
    if _JOURNAL_SEQ_RE.fullmatch(seq_text) is None:
        raise ValueError("sequence")
    if _JOURNAL_HEX_RE.fullmatch(entry_hash) is None:
        raise ValueError("entry hash")
    if entry_mac != "-" and _JOURNAL_HEX_RE.fullmatch(entry_mac) is None:
        raise ValueError("entry MAC")
    parsed_at = datetime.fromisoformat(occurred_at)
    if parsed_at.tzinfo is None or parsed_at.tzinfo.utcoffset(parsed_at) is None:
        raise ValueError("timestamp")
    # Compaction compares timestamps lexically.  Accept only the exact UTC
    # representation emitted by ``flush_audit_journal`` so an alternate
    # offset/precision cannot be used to move evidence across the cutoff.
    if canonical_occurred_at(parsed_at) != occurred_at:
        raise ValueError("non-canonical timestamp")
    return owner, int(seq_text), entry_hash, entry_mac, occurred_at


def _upsert_journal_evidence(
    connection: sqlite3.Connection,
    owner: str,
    seq: int,
    entry_hash: str,
    entry_mac: str,
    occurred_at: str,
) -> None:
    prior = connection.execute(
        """SELECT entry_hash, entry_mac, occurred_at
             FROM seals WHERE owner = ? AND seq = ?""",
        (owner, seq),
    ).fetchone()
    conflict = prior is not None and prior != (entry_hash, entry_mac, occurred_at)
    if prior is None:
        connection.execute(
            """INSERT INTO seals
                 (owner, seq, entry_hash, entry_mac, occurred_at)
                 VALUES (?, ?, ?, ?, ?)""",
            (owner, seq, entry_hash, entry_mac, occurred_at),
        )
    head = connection.execute(
        "SELECT head_seq FROM owner_heads WHERE owner = ?", (owner,)
    ).fetchone()
    if head is None:
        connection.execute(
            """INSERT INTO owner_heads
                 (owner, head_seq, entry_hash, entry_mac, occurred_at, conflict)
                 VALUES (?, ?, ?, ?, ?, ?)""",
            (owner, seq, entry_hash, entry_mac, occurred_at, int(conflict)),
        )
    elif seq > int(head[0]):
        connection.execute(
            """UPDATE owner_heads
                  SET head_seq = ?, entry_hash = ?, entry_mac = ?,
                      occurred_at = ?, conflict = conflict OR ?
                WHERE owner = ?""",
            (seq, entry_hash, entry_mac, occurred_at, int(conflict), owner),
        )
    elif conflict:
        connection.execute("UPDATE owner_heads SET conflict = 1 WHERE owner = ?", (owner,))


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


async def flush_audit_journal(
    session: AsyncSession,
    journal_path: str,
    *,
    failure_observer: Callable[[], None] | None = None,
) -> int:
    """Append staged rows to the out-of-DB journal; call AFTER commit.

    A post-commit failure cannot roll back the audited action, so it leaves
    the journal behind the database head (never a false tampering signal),
    returns zero, and latches readiness unhealthy until a later fsynced
    journal operation succeeds. Returns the number of lines actually written.
    """
    info = getattr(session, "info", None)
    pending = info.pop("mindpattern_audit_journal_pending", []) if info is not None else []
    if not pending or not journal_path:
        return 0
    lines = []
    for user_id, seq, entry_hash, entry_mac, at in pending:
        lines.append(f"{user_id} {seq} {entry_hash} {entry_mac} {canonical_occurred_at(at)}\n")

    def _write() -> None:
        global _journal_index_cache_fingerprint
        # Serialize open/write/fsync with compaction's snapshot+replace.  If
        # append opened the old inode during replace, a committed seal could
        # otherwise disappear from the newly published journal.
        with _journal_io_lock:
            source = os.path.abspath(journal_path)
            try:
                before = _journal_source_fingerprint(source)
            except OSError:
                before = None
            cache_matches = (
                _journal_index_cache is not None
                and _journal_index_cache_source == source
                and _journal_index_cache_fingerprint == before
            )
            if _journal_index_cache is not None and not cache_matches:
                _close_reusable_journal_evidence_index_unlocked()
            with open(journal_path, "a", encoding="utf-8") as handle:
                handle.writelines(lines)
                handle.flush()
                os.fsync(handle.fileno())
            if cache_matches and _journal_index_cache is not None:
                try:
                    _journal_index_cache.apply_entries(pending)
                    _journal_index_cache_fingerprint = _journal_source_fingerprint(source)
                except (OSError, sqlite3.Error, RuntimeError):
                    # The journal is already durable. Drop only its derived
                    # cache; the next maintenance pass rebuilds fail-closed.
                    _close_reusable_journal_evidence_index_unlocked()

    try:
        # 2026-10-01 audit M14: the append is blocking file I/O — run it on
        # a worker thread so the event loop never stalls inside the
        # per-request dependency teardown (scrypt's off-loop precedent).
        await anyio.to_thread.run_sync(_write)
    except OSError:
        _set_journal_health(False, "io_failure")
        if failure_observer is not None:
            failure_observer()
        logger.error("audit journal append failed; readiness is now unhealthy")
        # The staged entries are consumed either way: retrying on the next
        # request would write them out of chain order.
        return 0
    _set_journal_health(True)
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
    and hands it to each verification. A malformed non-empty line latches
    journal health unhealthy and adds the global corruption sentinel; valid
    owner heads remain available for diagnosis but verification fails closed.
    """
    return {
        uid: (item.seq, item.at)
        for uid, item in read_journal_evidence(journal_path).items()
        if uid != JOURNAL_CORRUPTION_KEY
    }


def build_journal_evidence_index(journal_path: str) -> JournalEvidenceIndex:
    """Spool one strict journal scan into a mode-0600 temporary index."""
    with _journal_io_lock:
        index = _build_journal_evidence_index_unlocked(journal_path)
    if not index.corrupt:
        _set_journal_health(True)
    return index


def _journal_source_fingerprint(journal_path: str) -> tuple[int, int, int, int, int]:
    status = os.stat(journal_path)
    return (
        int(status.st_dev),
        int(status.st_ino),
        int(status.st_size),
        int(status.st_mtime_ns),
        int(status.st_ctime_ns),
    )


def _close_reusable_journal_evidence_index_unlocked() -> None:
    global _journal_index_cache, _journal_index_cache_source
    global _journal_index_cache_fingerprint
    if _journal_index_cache is not None:
        _journal_index_cache.close()
    _journal_index_cache = None
    _journal_index_cache_source = None
    _journal_index_cache_fingerprint = None


def close_reusable_journal_evidence_index() -> None:
    """Release the one process-scoped disk index and remove its temp file."""
    with _journal_io_lock:
        _close_reusable_journal_evidence_index_unlocked()


def reusable_journal_evidence_index(journal_path: str) -> JournalEvidenceIndex:
    """Reuse one source scan while a stable catch-up generation drains.

    All application-controlled appends update the index under the same lock.
    An unexpected inode/size/time change is treated as an external generation
    change and rebuilt in full before any maintenance decision uses it.
    """
    global _journal_index_cache, _journal_index_cache_source
    global _journal_index_cache_fingerprint
    source = os.path.abspath(journal_path)
    with _journal_io_lock:
        try:
            fingerprint = _journal_source_fingerprint(source)
        except OSError:
            fingerprint = None
        if (
            _journal_index_cache is not None
            and _journal_index_cache_source == source
            and _journal_index_cache_fingerprint == fingerprint
        ):
            return _journal_index_cache
        _close_reusable_journal_evidence_index_unlocked()
        initial_fingerprint = fingerprint
        index = _build_journal_evidence_index_unlocked(source)
        try:
            final_fingerprint = _journal_source_fingerprint(source)
        except OSError:
            final_fingerprint = None
        if final_fingerprint != initial_fingerprint:
            # An external writer does not participate in our journal lock.
            # Never cache a scan that may describe only part of the source
            # generation. Return a fail-closed result once and force the next
            # pass to rebuild after the file settles.
            index.corrupt = True
            _set_journal_health(False, "source_changed_during_index")
            cached_fingerprint = (-1, -1, -1, -1, -1)
        else:
            assert final_fingerprint is not None
            cached_fingerprint = final_fingerprint
        _journal_index_cache = index
        _journal_index_cache_source = source
        _journal_index_cache_fingerprint = cached_fingerprint
        if not index.corrupt:
            _set_journal_health(True)
        return index


def _build_journal_evidence_index_unlocked(journal_path: str) -> JournalEvidenceIndex:
    descriptor, index_path = tempfile.mkstemp(prefix="mindpattern-audit-index-", suffix=".sqlite3")
    os.close(descriptor)
    corrupt = False
    try:
        with closing(sqlite3.connect(index_path)) as connection, connection:
            connection.executescript(
                """
                PRAGMA journal_mode=OFF;
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=FILE;
                PRAGMA cache_size=-2048;
                CREATE TABLE seals (
                    owner TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    entry_hash TEXT NOT NULL,
                    entry_mac TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY (owner, seq)
                );
                CREATE TABLE owner_heads (
                    owner TEXT PRIMARY KEY,
                    head_seq INTEGER NOT NULL,
                    entry_hash TEXT NOT NULL,
                    entry_mac TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    conflict INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            try:
                source = open(journal_path, encoding="utf-8")
            except OSError:
                _set_journal_health(False, "io_failure")
                corrupt = True
            else:
                with source:
                    for line_number, line in enumerate(source, start=1):
                        try:
                            parsed = _parse_journal_line(line)
                        except ValueError:
                            logger.error(
                                "audit journal contains malformed evidence at line %d",
                                line_number,
                            )
                            _set_journal_health(False, "malformed_evidence")
                            corrupt = True
                            continue
                        if parsed is None:
                            continue
                        owner, seq, entry_hash, entry_mac, occurred_at = parsed
                        _upsert_journal_evidence(
                            connection,
                            owner,
                            seq,
                            entry_hash,
                            entry_mac,
                            occurred_at,
                        )
            connection.commit()
    except Exception:
        try:
            os.unlink(index_path)
        except FileNotFoundError:
            pass
        raise
    return JournalEvidenceIndex(index_path, corrupt=corrupt)


def read_journal_evidence(journal_path: str) -> dict[str, JournalEvidence]:
    """Materialize evidence for explicit diagnostic/test callers.

    Runtime maintenance uses :func:`build_journal_evidence_index` directly,
    keeping owner/sequence cardinality on disk. Post-commit journal flushes
    may race, so distinct sequence numbers are reduced order-independently;
    only different seals claiming one owner/sequence conflict.
    """
    with build_journal_evidence_index(journal_path) as evidence_index:
        return evidence_index.all_evidence()


def journal_owner_status(journal_path: str, user_id: str) -> tuple[bool, bool]:
    """Return ``(owner_seen, corrupt)`` in one constant-memory scan."""
    owner_seen = False
    corrupt = False
    try:
        with _journal_io_lock, open(journal_path, encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    parsed = _parse_journal_line(line)
                except ValueError:
                    logger.error(
                        "audit journal contains malformed evidence at line %d", line_number
                    )
                    _set_journal_health(False, "malformed_evidence")
                    corrupt = True
                    continue
                if parsed is not None and parsed[0] == user_id:
                    owner_seen = True
    except OSError:
        _set_journal_health(False, "io_failure")
        corrupt = True
    return owner_seen, corrupt


def compact_audit_journal(journal_path: str, cutoff_at: str) -> tuple[int, int]:
    """Drop journal lines whose ``at`` predates the cutoff; (kept, dropped).

    2026-09-28 audit M-5: the database trail is pruned by retention but
    the journal file grew forever, and every verification pass walked all
    of it. Compaction is retention-aligned and SAFE by the journal's own
    contract: a journal behind the database head is benign (crash-window
    semantics), and every line older than the retention cutoff describes
    rows the database no longer has either — the truncation detector only
    ever compares the journal's NEWEST line. Atomic (temp file + replace)
    so a crash mid-compaction leaves the old file intact. An OSError
    propagates to the sweep, latches journal readiness unhealthy, and is
    retried next cycle without terminating the process.
    """
    try:
        with _journal_io_lock:
            result = _compact_audit_journal_unlocked(journal_path, cutoff_at)
            _close_reusable_journal_evidence_index_unlocked()
    except OSError:
        _set_journal_health(False, "io_failure")
        raise
    _set_journal_health(True)
    return result


def _compact_audit_journal_unlocked(journal_path: str, cutoff_at: str) -> tuple[int, int]:
    evidence_index = _build_journal_evidence_index_unlocked(journal_path)
    if evidence_index.corrupt:
        evidence_index.close()
        raise RuntimeError("audit journal contains malformed or unavailable evidence")
    journal_directory = os.path.dirname(os.path.abspath(journal_path)) or "."
    descriptor, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(journal_path)}.compact-",
        dir=journal_directory,
    )
    try:
        # Bound the hot lookup cache independently of journal cardinality.
        with closing(sqlite3.connect(evidence_index.path)) as connection, connection:

            @lru_cache(maxsize=1024)
            def owner_decision(owner: str) -> tuple[int, bool]:
                row = connection.execute(
                    "SELECT head_seq, conflict FROM owner_heads WHERE owner = ?", (owner,)
                ).fetchone()
                if row is None:  # source changed unexpectedly; preserve, never discard
                    return 0, True
                return int(row[0]), bool(row[1])

            kept = 0
            dropped = 0
            with (
                open(journal_path, encoding="utf-8") as source,
                os.fdopen(descriptor, "w", encoding="utf-8") as destination,
            ):
                descriptor = -1
                for line_number, line in enumerate(source, start=1):
                    try:
                        parsed = _parse_journal_line(line)
                    except ValueError as exc:
                        _set_journal_health(False, "malformed_evidence")
                        raise RuntimeError(
                            f"audit journal contains malformed evidence at line {line_number}"
                        ) from exc
                    retain = parsed is None
                    if parsed is not None:
                        owner, seq, _entry_hash, _entry_mac, occurred_at = parsed
                        head_seq, conflict = owner_decision(owner)
                        # ISO-8601 aware instants are canonical on write and
                        # therefore compare lexically in chronological order.
                        retain = occurred_at >= cutoff_at or conflict or seq == head_seq
                    if retain:
                        destination.write(line)
                        kept += 1
                    else:
                        dropped += 1
                destination.flush()
                os.fsync(destination.fileno())
        os.replace(tmp_path, journal_path)
        # Persist the directory entry update as well as the replacement file;
        # after a power loss the published path must not roll back to the old
        # inode after we reported successful compaction.
        directory_fd = os.open(journal_directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        evidence_index.close()
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    return kept, dropped


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
    mac_keys: Mapping[int, bytes] | None = None,
    current_mac_key_version: int | None = None,
    allow_new_chain: bool = False,
) -> AccessLog:
    """Append ONE chained audit row inside the caller's transaction.

    Reads the patient's current chain head and flushes the new row with its
    seq/prev/hash under the per-patient in-process lock, so the row is
    chained deterministically at INSERT time and commits (or rolls back)
    with whatever transaction the caller is in — the audit fact and the
    audited action stay atomic. ``at`` (explicit instant) and ``row_id``
    (explicit primary key) exist for deterministic seeding in tests; every
    runtime call site uses the defaults. ``mac_key`` preserves the original
    one-key test API; production supplies the versioned ``mac_keys`` ring.
    ``allow_new_chain`` is reserved for account registration in the same
    transaction as the new User row. Every ordinary append fails closed if
    the authenticated state disappeared; it never scans the global journal
    or infers freshness from attacker-mutable database markers.
    Rows seeded without either are link-only legacy rows. On a unique-seq
    race at flush (a concurrent writer's row
    committed between this head read and the INSERT) the append rolls back
    to its savepoint and retries with the fresh head — the audited action
    must not 500 because two of the patient's own requests overlapped.
    """
    occurred = at if at is not None else utcnow()
    effective_mac_keys, effective_version = _effective_mac_keys(
        mac_key, mac_keys, current_mac_key_version
    )
    current_mac_key = effective_mac_keys.get(effective_version)
    if effective_mac_keys and current_mac_key is None:
        raise ApiError(500, "current audit MAC key is unavailable", "audit_integrity_error")
    async with _audit_chain_locks.hold(f"audit-chain:{user_id}"):
        last_conflict: IntegrityError | None = None
        for _attempt in range(APPEND_MAX_ATTEMPTS):
            state = await session.scalar(
                select(AuditChainState)
                .where(AuditChainState.user_id == user_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            db_head = (
                await session.execute(
                    select(AccessLog.chain_seq, AccessLog.entry_hash, AccessLog.at)
                    .where(AccessLog.user_id == user_id)
                    .order_by(AccessLog.chain_seq.desc())
                    .limit(1)
                )
            ).first()
            prev_hash: str | None
            if state is not None:
                if effective_mac_keys:
                    state_key = effective_mac_keys.get(state.mac_key_version or 1)
                    if (
                        state_key is None
                        or state.state_mac is None
                        or not hmac.compare_digest(
                            compute_chain_state_mac(state_key, state), state.state_mac
                        )
                    ):
                        raise ApiError(
                            status_code=500,
                            detail="audit chain state does not verify",
                            code="audit_integrity_error",
                        )
                if db_head is None and state.first_retained_seq is not None:
                    raise ApiError(
                        status_code=500,
                        detail="audit chain head differs from durable state",
                        code="audit_integrity_error",
                    )
                if db_head is not None and (int(db_head[0]), db_head[1]) != (
                    state.head_seq,
                    state.head_hash,
                ):
                    raise ApiError(
                        status_code=500,
                        detail="audit chain head differs from durable state",
                        code="audit_integrity_error",
                    )
                chain_seq = state.head_seq + 1
                prev_hash = state.head_hash
            else:
                if db_head is not None or not allow_new_chain:
                    raise ApiError(
                        status_code=500,
                        detail="audit chain state is missing",
                        code="audit_integrity_error",
                    )
                chain_seq = 1
                prev_hash = None
            record_version = 2
            entry_hash = compute_entry_hash(
                prev_hash,
                actor_id,
                user_id,
                action,
                occurred,
                actor_role=actor_role,
                record_version=record_version,
            )
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
                    compute_entry_mac(current_mac_key, user_id, chain_seq, entry_hash)
                    if current_mac_key is not None
                    else None
                ),
                mac_key_version=effective_version,
                record_version=record_version,
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
                        if state is None:
                            state = AuditChainState(
                                user_id=user_id,
                                head_seq=chain_seq,
                                head_hash=entry_hash,
                                head_at=occurred,
                                first_retained_seq=chain_seq,
                                first_retained_hash=entry_hash,
                                state_version=1,
                                mac_key_version=effective_version,
                                updated_at=occurred,
                            )
                            if current_mac_key is not None:
                                state.state_mac = compute_chain_state_mac(current_mac_key, state)
                            session.add(state)
                        else:
                            state.head_seq = chain_seq
                            state.head_hash = entry_hash
                            state.head_at = occurred
                            state.updated_at = occurred
                            if state.first_retained_seq is None:
                                state.first_retained_seq = chain_seq
                                state.first_retained_hash = entry_hash
                            if current_mac_key is not None:
                                state.mac_key_version = effective_version
                                state.state_mac = compute_chain_state_mac(current_mac_key, state)
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
    # counted only by an explicitly unkeyed walk. Keyed verification fails
    # closed until genuine legacy provenance is independently reviewed.
    legacy_rows: int = 0


def _broken(seq: int, reason: str) -> ChainVerification:
    return ChainVerification(ok=False, rows_checked=0, broken_at_seq=seq, reason=reason)


def _audit_row_integrity_error(
    row: AccessLog,
    effective_mac_keys: Mapping[int, bytes],
) -> str | None:
    """Return a stable failure reason for one row, or ``None``.

    This small primitive is shared by the full diagnostic walk, bounded
    retention-prefix verification, and the incremental maintenance walk.
    Keeping the cryptographic checks in one place prevents a cheaper
    maintenance path from silently accepting less than the diagnostic path.
    """
    if row.entry_hash is None or len(row.entry_hash) != CHAIN_HASH_HEX:
        return "missing or malformed entry_hash"
    expected = compute_entry_hash(
        row.prev_hash,
        row.actor_id,
        row.user_id,
        row.action,
        row.at,
        actor_role=row.actor_role,
        record_version=row.record_version or 1,
    )
    if expected != row.entry_hash:
        return "entry_hash does not match the row's contents"
    if row.entry_mac is None:
        if effective_mac_keys:
            return (
                "missing entry_mac (legacy rows require explicit offline review; "
                "MAC stripping is not accepted)"
            )
        return None
    if effective_mac_keys:
        row_key = effective_mac_keys.get(row.mac_key_version or 1)
        if row_key is None:
            return f"audit MAC key version {row.mac_key_version or 1} is unavailable"
        expected_mac = compute_entry_mac(row_key, row.user_id, row.chain_seq, row.entry_hash)
        if not hmac.compare_digest(expected_mac, row.entry_mac):
            return "entry_mac does not verify (row rewritten without the chain key)"
    return None


def _authenticated_state_error(
    state: AuditChainState,
    effective_mac_keys: Mapping[int, bytes],
) -> str | None:
    if not effective_mac_keys:
        return None
    if state.state_mac is None:
        return "durable audit chain state is unsealed"
    state_key = effective_mac_keys.get(state.mac_key_version or 1)
    if state_key is None:
        return f"audit MAC key version {state.mac_key_version or 1} is unavailable"
    if not hmac.compare_digest(compute_chain_state_mac(state_key, state), state.state_mac):
        return "durable audit chain state MAC does not verify"
    return None


def _journal_evidence_for_owner(
    journal_evidence: Mapping[str, JournalEvidence] | JournalEvidenceIndex | None,
    user_id: str,
) -> JournalEvidence | None:
    if journal_evidence is None:
        return None
    return journal_evidence.get(user_id)


async def verify_access_log_chain(
    session: AsyncSession,
    user_id: str,
    *,
    mac_key: bytes | None = None,
    mac_keys: Mapping[int, bytes] | None = None,
    current_mac_key_version: int | None = None,
    journal_path: str | None = None,
    retention_cutoff=None,
    journal_heads: dict[str, tuple[int, str]] | None = None,
    journal_evidence: Mapping[str, JournalEvidence] | JournalEvidenceIndex | None = None,
) -> ChainVerification:
    """Walk one patient's audit rows in chain order and detect tampering.

    Checks, per surviving row: the recomputed entry_hash matches the stored
    seal, prev_hash links to the previous row's seal, and chain_seq is
    contiguous. When ``mac_key`` is provided, every row must carry a valid
    keyed seal; a NULL seal fails closed. Only an explicitly unkeyed walk
    counts NULL seals as legacy and checks their links. The OLDEST surviving row is
    checked against the sealed retained-prefix state, including the hash at
    the boundary whose predecessor retention may have removed.

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
    effective_mac_keys, _effective_version = _effective_mac_keys(
        mac_key, mac_keys, current_mac_key_version
    )
    state = await session.get(AuditChainState, user_id)
    evidence: JournalEvidence | None = None
    journal_corrupt = False
    legacy_head = journal_heads.get(user_id) if journal_heads is not None else None
    if isinstance(journal_evidence, JournalEvidenceIndex):
        journal_corrupt = journal_evidence.corrupt
        evidence = journal_evidence.get(user_id)
    elif journal_evidence is not None:
        journal_corrupt = JOURNAL_CORRUPTION_KEY in journal_evidence
        evidence = journal_evidence.get(user_id)
    elif journal_path and journal_heads is None:
        with build_journal_evidence_index(journal_path) as evidence_index:
            journal_corrupt = evidence_index.corrupt
            evidence = evidence_index.get(user_id)
    if journal_corrupt:
        return ChainVerification(
            ok=False,
            rows_checked=0,
            reason="audit journal evidence is unavailable or malformed",
        )
    if evidence is not None and evidence.conflict:
        return ChainVerification(ok=False, rows_checked=0, reason="audit journal sequence conflict")
    if state is None and effective_mac_keys:
        # A keyed trail is never allowed to exist without its independently
        # sealed high-water state.  Check this before streaming the owner's
        # rows: a deleted state must fail in one bounded lookup even when a
        # later row was also tampered with, and a journal-only owner is an
        # immediate tail/state-loss signal.
        if evidence is not None or legacy_head is not None:
            return ChainVerification(
                ok=False,
                rows_checked=0,
                reason="durable audit chain state is missing",
            )
        row_exists = await session.scalar(
            select(AccessLog.id).where(AccessLog.user_id == user_id).limit(1)
        )
        if row_exists is not None:
            return ChainVerification(
                ok=False,
                rows_checked=0,
                reason="durable audit chain state is missing",
            )
        return ChainVerification(ok=True, rows_checked=0, legacy_rows=0)
    if state is not None and effective_mac_keys:
        if state.state_mac is None:
            return ChainVerification(
                ok=False, rows_checked=0, reason="durable audit chain state is unsealed"
            )
        state_key = effective_mac_keys.get(state.mac_key_version or 1)
        if state_key is None:
            return ChainVerification(
                ok=False,
                rows_checked=0,
                reason=f"audit MAC key version {state.mac_key_version or 1} is unavailable",
            )
        if not hmac.compare_digest(compute_chain_state_mac(state_key, state), state.state_mac):
            return ChainVerification(
                ok=False, rows_checked=0, reason="durable audit chain state MAC does not verify"
            )

    # Stream in chain order rather than materializing an owner's full
    # retained history.  Only the first/current rows and aggregate count are
    # needed for link, anchor, and head checks.
    first: AccessLog | None = None
    previous: AccessLog | None = None
    last: AccessLog | None = None
    rows_checked = 0
    legacy = 0
    rows = await session.stream_scalars(
        select(AccessLog)
        .where(AccessLog.user_id == user_id)
        .order_by(AccessLog.chain_seq.asc())
        .execution_options(yield_per=500)
    )
    async for row in rows:
        if first is None:
            first = row
            if row.chain_seq == 1 and row.prev_hash is not None:
                return _broken(row.chain_seq, "genesis row carries a prev_hash")
            if row.chain_seq > 1 and row.prev_hash is None:
                return _broken(
                    row.chain_seq,
                    "non-genesis row has no prev_hash (pruned prefix cannot be anchored)",
                )
        if previous is not None and row.chain_seq != previous.chain_seq + 1:
            return _broken(
                row.chain_seq,
                f"chain_seq gap after {previous.chain_seq} (mid-trail deletion or forged insert)",
            )
        if row.entry_hash is None or len(row.entry_hash) != CHAIN_HASH_HEX:
            return _broken(row.chain_seq, "missing or malformed entry_hash")
        expected = compute_entry_hash(
            row.prev_hash,
            row.actor_id,
            row.user_id,
            row.action,
            row.at,
            actor_role=row.actor_role,
            record_version=row.record_version or 1,
        )
        if expected != row.entry_hash:
            return _broken(row.chain_seq, "entry_hash does not match the row's contents")
        if previous is not None and row.prev_hash != previous.entry_hash:
            return _broken(row.chain_seq, "prev_hash does not link to the previous row's seal")
        if row.entry_mac is None:
            legacy += 1
            if effective_mac_keys:
                return _broken(
                    row.chain_seq,
                    "missing entry_mac (legacy rows require explicit offline review; MAC stripping is not accepted)",
                )
        elif effective_mac_keys:
            row_key = effective_mac_keys.get(row.mac_key_version or 1)
            if row_key is None:
                return _broken(
                    row.chain_seq,
                    f"audit MAC key version {row.mac_key_version or 1} is unavailable",
                )
            expected_mac = compute_entry_mac(row_key, row.user_id, row.chain_seq, row.entry_hash)
            if not hmac.compare_digest(expected_mac, row.entry_mac):
                return _broken(
                    row.chain_seq,
                    "entry_mac does not verify (row rewritten without the chain key)",
                )
        rows_checked += 1
        previous = row
        last = row

    if first is None or last is None:
        if state is not None and state.first_retained_seq is not None:
            return ChainVerification(
                ok=False,
                rows_checked=0,
                reason="durable state expects retained rows but the database is empty (tail truncation)",
            )
        if state is not None and (retention_cutoff is None or state.head_at >= retention_cutoff):
            return ChainVerification(
                ok=False,
                rows_checked=0,
                reason="empty retained trail is not explained by the retention cutoff",
            )
        if (evidence is not None or legacy_head is not None) and retention_cutoff is not None:
            if evidence is not None:
                head_at_text = evidence.at
            else:
                assert legacy_head is not None
                head_at_text = legacy_head[1]
            if head_at_text:
                from datetime import datetime as _dt

                try:
                    head_at = _dt.fromisoformat(head_at_text)
                except ValueError:
                    head_at = None
                if head_at is not None and head_at > retention_cutoff:
                    return ChainVerification(
                        ok=False,
                        rows_checked=0,
                        reason="journal records rows this database no longer has (tail truncation)",
                    )
        return ChainVerification(ok=True, rows_checked=0, legacy_rows=0)
    if state is not None and (
        state.first_retained_seq != first.chain_seq or state.first_retained_hash != first.entry_hash
    ):
        return _broken(first.chain_seq, "retained-prefix anchor differs from durable state")
    if state is not None and (
        state.head_seq != last.chain_seq or state.head_hash != last.entry_hash
    ):
        return ChainVerification(
            ok=False,
            rows_checked=rows_checked,
            broken_at_seq=last.chain_seq,
            reason="database tail differs from durable chain head",
            legacy_rows=legacy,
        )
    if evidence is not None:
        if evidence.seq > last.chain_seq:
            return ChainVerification(
                ok=False,
                rows_checked=rows_checked,
                broken_at_seq=last.chain_seq,
                reason=(
                    f"journal is ahead of the database head "
                    f"(journal seq {evidence.seq} > db seq {last.chain_seq}; tail truncation)"
                ),
                legacy_rows=legacy,
            )
        if evidence.seq == last.chain_seq and (
            evidence.entry_hash != last.entry_hash
            or (last.entry_mac is not None and evidence.entry_mac != last.entry_mac)
        ):
            return ChainVerification(
                ok=False,
                rows_checked=rows_checked,
                broken_at_seq=last.chain_seq,
                reason="journal seal conflicts with database head",
                legacy_rows=legacy,
            )
    elif legacy_head is not None:
        if legacy_head[0] > last.chain_seq:
            return ChainVerification(
                ok=False,
                rows_checked=rows_checked,
                broken_at_seq=last.chain_seq,
                reason=(
                    f"journal is ahead of the database head "
                    f"(journal seq {legacy_head[0]} > db seq {last.chain_seq}; tail truncation)"
                ),
                legacy_rows=legacy,
            )
    return ChainVerification(ok=True, rows_checked=rows_checked, legacy_rows=legacy)


@dataclass(frozen=True)
class IncrementalChainVerification:
    ok: bool
    complete: bool
    rows_checked: int
    reason: str | None = None


async def verify_access_log_chain_incremental(
    session: AsyncSession,
    cursor: AuditSweepCursor,
    user_id: str,
    *,
    mac_keys: Mapping[int, bytes],
    current_mac_key_version: int,
    journal_evidence: Mapping[str, JournalEvidence] | JournalEvidenceIndex | None = None,
    retention_cutoff=None,
    row_budget: int = AUDIT_VERIFY_ROW_BATCH,
) -> IncrementalChainVerification:
    """Verify one bounded page and persist an authenticated resume point.

    The snapshot head is captured from the HMAC-sealed chain state. Appends
    may extend the live head without invalidating that finite snapshot.
    Legitimate prefix pruning may advance the live anchor; pages already
    removed were independently authenticated by ``prune_access_logs``.
    """
    if row_budget < 1 or row_budget > AUDIT_VERIFY_TOTAL_ROW_BATCH:
        raise ValueError("audit verification row budget is invalid")
    authenticate_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
    if cursor.verification_owner_id not in (None, user_id):
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="audit verification checkpoint owner differs from requested owner",
        )

    state = await session.scalar(
        select(AuditChainState)
        .where(AuditChainState.user_id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    journal_corrupt = (
        journal_evidence.corrupt
        if isinstance(journal_evidence, JournalEvidenceIndex)
        else bool(journal_evidence is not None and JOURNAL_CORRUPTION_KEY in journal_evidence)
    )
    if journal_corrupt:
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="audit journal evidence is unavailable or malformed",
        )
    evidence = _journal_evidence_for_owner(journal_evidence, user_id)
    if evidence is not None and evidence.conflict:
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="audit journal sequence conflict",
        )
    if state is None:
        row_exists = await session.scalar(
            select(AccessLog.id).where(AccessLog.user_id == user_id).limit(1)
        )
        if evidence is not None or row_exists is not None:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason="durable audit chain state is missing",
            )
        cursor.last_user_id = user_id
        _clear_incremental_verification(cursor)
        seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)

    state_error = _authenticated_state_error(state, mac_keys)
    if state_error is not None:
        return IncrementalChainVerification(
            ok=False, complete=False, rows_checked=0, reason=state_error
        )
    if evidence is not None and (
        evidence.seq > state.head_seq
        or (evidence.seq == state.head_seq and evidence.entry_hash != state.head_hash)
    ):
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="journal differs from durable chain head",
        )
    tail = (
        await session.execute(
            select(AccessLog.chain_seq, AccessLog.entry_hash, AccessLog.entry_mac)
            .where(AccessLog.user_id == user_id)
            .order_by(AccessLog.chain_seq.desc())
            .limit(1)
        )
    ).first()
    if tail is None:
        if state.first_retained_seq is not None:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason="durable state expects retained rows but the database is empty",
            )
        if retention_cutoff is None or state.head_at >= retention_cutoff:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason="empty retained trail is not explained by the retention cutoff",
            )
        cursor.last_user_id = user_id
        _clear_incremental_verification(cursor)
        seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)
    if (int(tail[0]), tail[1]) != (state.head_seq, state.head_hash):
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="database tail differs from durable chain head",
        )
    if evidence is not None and (
        evidence.seq > state.head_seq
        or (
            evidence.seq == state.head_seq
            and (
                evidence.entry_hash != state.head_hash
                or (tail[2] is not None and evidence.entry_mac != tail[2])
            )
        )
    ):
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="journal differs from durable chain head",
        )

    if cursor.verification_owner_id is None:
        cursor.verification_owner_id = user_id
        cursor.verification_snapshot_head_seq = state.head_seq
        cursor.verification_snapshot_head_hash = state.head_hash
        cursor.verification_next_seq = state.first_retained_seq
        cursor.verification_previous_hash = None
        cursor.verification_rows_checked = 0
    snapshot_seq = cursor.verification_snapshot_head_seq
    snapshot_hash = cursor.verification_snapshot_head_hash
    next_seq = cursor.verification_next_seq
    if snapshot_seq is None or snapshot_hash is None:
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="audit verification checkpoint snapshot is incomplete",
        )
    if state.head_seq < snapshot_seq:
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="durable audit head moved behind verification snapshot",
        )
    if state.first_retained_seq is None or state.first_retained_seq > snapshot_seq:
        # The bounded destructive verifier authenticated every removed page.
        cursor.last_user_id = user_id
        _clear_incremental_verification(cursor)
        seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)
    if next_seq is None or next_seq < state.first_retained_seq:
        next_seq = state.first_retained_seq
        cursor.verification_next_seq = next_seq
        cursor.verification_previous_hash = None
        cursor.verification_rows_checked = 0
    if next_seq > snapshot_seq:
        if cursor.verification_previous_hash != snapshot_hash:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason="verification checkpoint does not end at the snapshot head",
            )
        cursor.last_user_id = user_id
        _clear_incremental_verification(cursor)
        seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)

    page = list(
        (
            await session.scalars(
                select(AccessLog)
                .where(
                    AccessLog.user_id == user_id,
                    AccessLog.chain_seq >= next_seq,
                    AccessLog.chain_seq <= snapshot_seq,
                )
                .order_by(AccessLog.chain_seq)
                .limit(row_budget)
            )
        ).all()
    )
    if not page:
        return IncrementalChainVerification(
            ok=False,
            complete=False,
            rows_checked=0,
            reason="verification snapshot row is missing",
        )
    expected_seq = next_seq
    previous_hash = cursor.verification_previous_hash
    for row in page:
        if row.chain_seq != expected_seq:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason=f"chain_seq gap before {row.chain_seq}",
            )
        if previous_hash is None:
            if (row.chain_seq, row.entry_hash) != (
                state.first_retained_seq,
                state.first_retained_hash,
            ):
                return IncrementalChainVerification(
                    ok=False,
                    complete=False,
                    rows_checked=0,
                    reason="retained-prefix anchor differs from durable state",
                )
            if (row.chain_seq == 1 and row.prev_hash is not None) or (
                row.chain_seq > 1 and row.prev_hash is None
            ):
                return IncrementalChainVerification(
                    ok=False,
                    complete=False,
                    rows_checked=0,
                    reason="retained-prefix predecessor is malformed",
                )
        elif row.prev_hash != previous_hash:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=0,
                reason="prev_hash does not link to the verification checkpoint",
            )
        row_error = _audit_row_integrity_error(row, mac_keys)
        if row_error is not None:
            return IncrementalChainVerification(
                ok=False, complete=False, rows_checked=0, reason=row_error
            )
        previous_hash = row.entry_hash
        expected_seq += 1

    cursor.verification_next_seq = expected_seq
    cursor.verification_previous_hash = previous_hash
    cursor.verification_rows_checked = int(cursor.verification_rows_checked or 0) + len(page)
    complete = expected_seq > snapshot_seq
    if complete:
        if previous_hash != snapshot_hash:
            return IncrementalChainVerification(
                ok=False,
                complete=False,
                rows_checked=len(page),
                reason="verification snapshot head hash differs from captured state",
            )
        cursor.last_user_id = user_id
        _clear_incremental_verification(cursor)
    seal_verification_checkpoint(cursor, mac_keys, current_mac_key_version)
    return IncrementalChainVerification(
        ok=True,
        complete=complete,
        rows_checked=len(page),
    )


async def prune_access_logs(
    session: AsyncSession,
    *,
    cutoff,
    mac_key: bytes | None = None,
    mac_keys: Mapping[int, bytes] | None = None,
    current_mac_key_version: int | None = None,
    journal_evidence: Mapping[str, JournalEvidence] | JournalEvidenceIndex | None = None,
    owner_after: str | None = None,
    progress_observer=None,
) -> int:
    """Delete bounded expired prefixes after authenticated verification."""
    # Retention is destructive.  Unlike append/diagnostic verification it
    # must never silently fall back to process-global or link-only state;
    # every caller supplies the validated key material explicitly.
    if mac_keys is None:
        if mac_key is None:
            raise ApiError(500, "current audit MAC key is unavailable", "audit_integrity_error")
        effective_mac_keys = {1: mac_key}
        effective_version = current_mac_key_version or 1
    else:
        effective_mac_keys = dict(mac_keys)
        effective_version = current_mac_key_version or 1
    current_mac_key = effective_mac_keys.get(effective_version)
    if (
        not effective_mac_keys
        or current_mac_key is None
        or not isinstance(effective_version, int)
        or effective_version < 1
        or any(
            not isinstance(version, int)
            or version < 1
            or not isinstance(key, bytes)
            or len(key) != 32
            for version, key in effective_mac_keys.items()
        )
    ):
        raise ApiError(500, "current audit MAC key is unavailable", "audit_integrity_error")
    owned_evidence: JournalEvidenceIndex | None = None
    if journal_evidence is None and _configured_journal_path:
        owned_evidence = build_journal_evidence_index(_configured_journal_path)
        journal_evidence = owned_evidence
    journal_corrupt = (
        journal_evidence.corrupt
        if isinstance(journal_evidence, JournalEvidenceIndex)
        else bool(journal_evidence is not None and JOURNAL_CORRUPTION_KEY in journal_evidence)
    )
    if journal_corrupt:
        if owned_evidence is not None:
            owned_evidence.close()
        raise ApiError(500, "audit journal evidence is unavailable", "audit_integrity_error")

    async def _owner_page(*, after: str | None, limit: int) -> list[str]:
        statement = select(AccessLog.user_id).where(AccessLog.at < cutoff).distinct()
        if after is not None:
            statement = statement.where(AccessLog.user_id > after)
        return list(
            (await session.execute(statement.order_by(AccessLog.user_id).limit(limit))).scalars()
        )

    owner_candidates = await _owner_page(after=owner_after, limit=AUDIT_MAINTENANCE_OWNER_BATCH + 1)
    owners = owner_candidates[:AUDIT_MAINTENANCE_OWNER_BATCH]
    owners_after_page = len(owner_candidates) > AUDIT_MAINTENANCE_OWNER_BATCH
    deleted = 0
    remaining_row_budget = AUDIT_PRUNE_TOTAL_ROW_BATCH
    last_processed_owner: str | None = None
    try:
        for user_id in owners:
            if remaining_row_budget <= 0:
                break
            async with _audit_chain_locks.hold(f"audit-chain:{user_id}"):
                # Row locking extends serialization through COMMIT on PostgreSQL,
                # unlike the in-process append lock (which necessarily ends when
                # append_access_log returns to its caller's transaction).
                state = await session.scalar(
                    select(AuditChainState)
                    .where(AuditChainState.user_id == user_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if state is None:
                    raise ApiError(500, "audit chain state is missing", "audit_integrity_error")
                state_error = _authenticated_state_error(state, effective_mac_keys)
                if state_error is not None:
                    raise ApiError(
                        500,
                        f"audit chain failed verification before retention prune: {state_error}",
                        "audit_integrity_error",
                    )
                evidence = _journal_evidence_for_owner(journal_evidence, user_id)
                if evidence is not None and evidence.conflict:
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "audit journal sequence conflict",
                        "audit_integrity_error",
                    )
                delete_limit = min(AUDIT_PRUNE_ROW_BATCH, remaining_row_budget)
                # Authenticate only the prefix that may be destroyed plus
                # its first survivor.  Independent full-chain surveillance
                # is incremental and must not make every 500-row prune walk
                # an arbitrarily large owner history again.
                prefix_page = list(
                    (
                        await session.scalars(
                            select(AccessLog)
                            .where(AccessLog.user_id == user_id)
                            .order_by(AccessLog.chain_seq)
                            .limit(delete_limit + 1)
                            .with_for_update()
                        )
                    ).all()
                )
                tail = (
                    await session.execute(
                        select(AccessLog.chain_seq, AccessLog.entry_hash, AccessLog.entry_mac)
                        .where(AccessLog.user_id == user_id)
                        .order_by(AccessLog.chain_seq.desc())
                        .limit(1)
                    )
                ).first()
                if tail is None:
                    if state.first_retained_seq is not None:
                        raise ApiError(
                            500,
                            "audit chain failed verification before retention prune: "
                            "durable state expects retained rows but the database is empty",
                            "audit_integrity_error",
                        )
                    last_processed_owner = user_id
                    continue
                if (int(tail[0]), tail[1]) != (state.head_seq, state.head_hash):
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "database tail differs from durable chain head",
                        "audit_integrity_error",
                    )
                if evidence is not None and (
                    evidence.seq > state.head_seq
                    or (
                        evidence.seq == state.head_seq
                        and (
                            evidence.entry_hash != state.head_hash
                            or (tail[2] is not None and evidence.entry_mac != tail[2])
                        )
                    )
                ):
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "journal differs from durable chain head",
                        "audit_integrity_error",
                    )
                if not prefix_page:
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "retained-prefix page disappeared",
                        "audit_integrity_error",
                    )
                first = prefix_page[0]
                if (first.chain_seq, first.entry_hash) != (
                    state.first_retained_seq,
                    state.first_retained_hash,
                ):
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "retained-prefix anchor differs from durable state",
                        "audit_integrity_error",
                    )
                if (first.chain_seq == 1 and first.prev_hash is not None) or (
                    first.chain_seq > 1 and first.prev_hash is None
                ):
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "retained-prefix predecessor is malformed",
                        "audit_integrity_error",
                    )
                previous: AccessLog | None = None
                expired_rows: list[AccessLog] = []
                first_remaining: AccessLog | None = None
                for row in prefix_page:
                    if previous is not None:
                        if row.chain_seq != previous.chain_seq + 1:
                            raise ApiError(
                                500,
                                "audit chain failed verification before retention prune: "
                                f"chain_seq gap after {previous.chain_seq}",
                                "audit_integrity_error",
                            )
                        if row.prev_hash != previous.entry_hash:
                            raise ApiError(
                                500,
                                "audit chain failed verification before retention prune: "
                                "prev_hash does not link to the previous row's seal",
                                "audit_integrity_error",
                            )
                    row_error = _audit_row_integrity_error(row, effective_mac_keys)
                    if row_error is not None:
                        raise ApiError(
                            500,
                            f"audit chain failed verification before retention prune: {row_error}",
                            "audit_integrity_error",
                        )
                    if row.at < cutoff and len(expired_rows) < delete_limit:
                        expired_rows.append(row)
                        previous = row
                        continue
                    first_remaining = row
                    break
                if not expired_rows:
                    last_processed_owner = user_id
                    continue
                if first_remaining is None and int(tail[0]) != expired_rows[-1].chain_seq:
                    raise ApiError(
                        500,
                        "audit chain failed verification before retention prune: "
                        "bounded prefix did not reach a surviving boundary",
                        "audit_integrity_error",
                    )
                state.first_retained_seq = (
                    int(first_remaining.chain_seq) if first_remaining is not None else None
                )
                state.first_retained_hash = (
                    first_remaining.entry_hash if first_remaining is not None else None
                )
                state.updated_at = utcnow()
                state.mac_key_version = effective_version
                state.state_mac = compute_chain_state_mac(current_mac_key, state)
                removed_ids = list(
                    (
                        await session.scalars(
                            delete(AccessLog)
                            .where(AccessLog.id.in_([row.id for row in expired_rows]))
                            .returning(AccessLog.id)
                        )
                    ).all()
                )
                if len(removed_ids) != len(expired_rows):
                    raise ApiError(
                        500,
                        "audit retention prefix changed during deletion",
                        "audit_integrity_error",
                    )
                deleted += len(removed_ids)
                remaining_row_budget -= len(expired_rows)
                last_processed_owner = user_id
        # This is deliberately a capped probe, not a global COUNT.  It gives
        # operators a useful convergence signal once a large backlog drops
        # below one pass while keeping database work bounded by the same
        # aggregate row budget as mutation.
        pending_probe = (
            select(AccessLog.id)
            .where(AccessLog.at < cutoff)
            .order_by(AccessLog.at, AccessLog.id)
            .limit(AUDIT_PRUNE_TOTAL_ROW_BATCH + 1)
            .subquery()
        )
        pending_rows_probe = int(
            await session.scalar(select(func.count()).select_from(pending_probe)) or 0
        )
        oldest_pending_at = await session.scalar(
            select(AccessLog.at)
            .where(AccessLog.at < cutoff)
            .order_by(AccessLog.at, AccessLog.id)
            .limit(1)
        )
        backlog = pending_rows_probe > 0
        page_has_more = owners_after_page or (bool(owners) and last_processed_owner != owners[-1])
        next_owner = last_processed_owner if page_has_more else None
        if progress_observer is not None:
            progress_observer(
                backlog=backlog,
                next_owner=next_owner,
                owners_processed=len(owners),
                rows_deleted=deleted,
                pending_rows_probe=pending_rows_probe,
                oldest_pending_at=oldest_pending_at,
            )
        return deleted
    finally:
        if owned_evidence is not None:
            owned_evidence.close()


async def seal_legacy_audit_states(
    session: AsyncSession,
    mac_key: bytes | None = None,
    *,
    mac_keys: Mapping[int, bytes] | None = None,
    current_mac_key_version: int | None = None,
) -> int:
    """Seal migration-created state rows after independently checking data.

    A NULL state MAC is never trusted by normal verification or appends.
    This boot-time bridge accepts it only when every retained row's link and
    existing row MAC verify and both ends match the migration snapshot.
    """
    effective_mac_keys, effective_version = _effective_mac_keys(
        mac_key, mac_keys, current_mac_key_version
    )
    current_mac_key = effective_mac_keys.get(effective_version)
    if current_mac_key is None:
        raise ApiError(500, "current audit MAC key is unavailable", "audit_integrity_error")
    states = (
        (
            await session.execute(
                select(AuditChainState)
                .where(AuditChainState.state_mac.is_(None))
                .order_by(AuditChainState.user_id)
                .limit(AUDIT_MAINTENANCE_OWNER_BATCH)
            )
        )
        .scalars()
        .all()
    )
    sealed = 0
    scanned_total = 0
    for state in states:
        remaining_budget = AUDIT_LEGACY_SEAL_ROW_BUDGET - scanned_total
        if remaining_budget <= 0:
            break
        rows = await session.stream_scalars(
            select(AccessLog)
            .where(AccessLog.user_id == state.user_id)
            .order_by(AccessLog.chain_seq)
            .limit(remaining_budget + 1)
            .execution_options(yield_per=500)
        )
        first: AccessLog | None = None
        previous: AccessLog | None = None
        last: AccessLog | None = None
        scanned_for_state = 0
        over_budget = False
        valid = True
        try:
            async for row in rows:
                scanned_for_state += 1
                if scanned_for_state > remaining_budget:
                    over_budget = True
                    break
                if first is None:
                    first = row
                    if (row.chain_seq == 1 and row.prev_hash is not None) or (
                        row.chain_seq > 1 and row.prev_hash is None
                    ):
                        valid = False
                        break
                expected = compute_entry_hash(
                    row.prev_hash,
                    row.actor_id,
                    row.user_id,
                    row.action,
                    row.at,
                    actor_role=row.actor_role,
                    record_version=row.record_version or 1,
                )
                row_key = effective_mac_keys.get(row.mac_key_version or 1)
                if row.entry_hash != expected or (
                    previous is not None
                    and (
                        row.chain_seq != previous.chain_seq + 1
                        or row.prev_hash != previous.entry_hash
                    )
                ):
                    valid = False
                    break
                if row.entry_mac is None:
                    # This is the one migration bridge allowed to establish
                    # keyed provenance for pre-MAC rows. Their public chain
                    # and the migration-created endpoints were just checked
                    # in this bounded trusted-upgrade pass; normal runtime
                    # verification never accepts a NULL MAC.
                    row.mac_key_version = effective_version
                    row.entry_mac = compute_entry_mac(
                        current_mac_key, row.user_id, row.chain_seq, row.entry_hash
                    )
                elif row_key is None or not hmac.compare_digest(
                    compute_entry_mac(row_key, row.user_id, row.chain_seq, row.entry_hash),
                    row.entry_mac,
                ):
                    valid = False
                    break
                previous = row
                last = row
        finally:
            await rows.close()
        if over_budget:
            # Earlier owners in this transaction can commit and disappear
            # from the next pass, giving this owner the complete fixed
            # budget then.  One owner larger than the whole budget requires
            # the explicitly reviewed partitioned migration workflow.
            if scanned_total == 0:
                raise ApiError(
                    500,
                    "legacy audit chain exceeds the bounded online sealing budget",
                    "audit_integrity_error",
                )
            break
        scanned_total += scanned_for_state
        if (
            not valid
            or first is None
            or last is None
            or first.chain_seq != state.first_retained_seq
            or first.entry_hash != state.first_retained_hash
            or last.chain_seq != state.head_seq
            or last.entry_hash != state.head_hash
        ):
            raise ApiError(
                500,
                "legacy audit state failed authenticated verification",
                "audit_integrity_error",
            )
        state.mac_key_version = effective_version
        state.state_mac = compute_chain_state_mac(current_mac_key, state)
        state.updated_at = utcnow()
        sealed += 1
    if sealed:
        await session.flush()
    return sealed
