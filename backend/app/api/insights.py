"""Processing sessions, deterministic pattern analysis, and encrypted insights.

The client opens a single-use processing session by sending its data key
into the memory-only keystore over TLS. Recompute consumes that key,
decrypts entries and prior state inside the processing context, updates the
pattern lifecycle, and encrypts the resulting state and surfaced cards.
Owned plaintext buffers and the data-key copy are zeroized on every exit;
immutable parser strings may remain until garbage collection, as documented
in security.enclave.

Baseline accounts decrypt nothing and run no analysis. A supplied pending
session is discarded to avoid retaining an unused key. Analysis starts only
after the active-day threshold and uses deterministic findings throughout;
provider narration is disabled. The account lifecycle lock protects the
fresh authorization check and subsequent processing from concurrent changes.

Corpus and state reads use a short transaction closed before CPU work.
Results are written in a second transaction afterward, avoiding long-lived
database snapshots and connections during analysis. KIND_BRAIN stores the
persistent engine state, KIND_PATTERNS stores the displayed cards, and the
daily question is pinned on its first write.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import time
from contextlib import AsyncExitStack
from dataclasses import replace
from datetime import date as date_type, datetime, timedelta, timezone
from typing import NamedTuple, cast

import anyio.to_thread
from fastapi import APIRouter, Body, Depends, Header, Request
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import (
    ApiError,
    ensure_no_rekey,
    get_session,
    require_regular_user,
    require_rekey_retry_user,
)
from ..locks import (
    UserLocks,
    lifecycle_locks,
    sharing_locks,
    sharing_patient_lock_key,
    sharing_therapist_lock_key,
)
from ..models import (
    KEY_SCHEME_V2,
    KIND_BRAIN,
    KIND_PATTERNS,
    KIND_QUESTION,
    AudioAttachment,
    AudioDeletion,
    Consent,
    Entry,
    Insight,
    Measure,
    RekeyJournal,
    User,
    new_id,
    utcnow,
)
from ..schemas import (
    LANGUAGE_CODE_PATTERN,
    InsightsResponse,
    LocalRecomputeRequest,
    ProcessingSessionRequest,
    ProcessingSessionResponse,
    QuestionResponse,
    RecomputeResponse,
    RekeyRequest,
    RekeyResponse,
)
from ..security import crypto, sharing
from ..security.crypto import TamperError
from ..security.enclave import (
    KeyNotFound,
    KeyStoreFull,
    SecureBuffer,
    SecureProcessingContext,
    zeroize,
)
from ..security.entry_guard import (
    guard_values,
    guarded_entry_aads,
    seal_entry_guard,
    validate_entry_guard,
)
from ..services import brain, questions, threshold
from ..services.patterns import JournalEntry
from ..services.threshold import Phase
from ._sharing_state import advance_sharing_revisions
from .consents import SHARING_DISCLOSURE_VERSION
from .entries import (
    _blob_length as _entry_blob_length,
    _increment_entries_revision,
    _user_locks as _entry_locks,
)
from .measures import _increment_measures_revision

router = APIRouter(tags=["insights"])

# Two concurrent recomputes for one account would interleave their
# delete-then-insert on the same insight rows (last writer wins, and the
# carried-forward brain state each decrypted may already be stale). The
# deployment is single-process, so an in-process per-user lock serializes
# them; distinct users still recompute in parallel.
_recompute_locks = UserLocks()

# Daily question rows accumulate one per recompute day; bound their history
# inside the recompute write transaction (they are encrypted day-questions,
# not data the user asked to keep forever).
QUESTION_RETENTION_DAYS = 90


def _utc_today() -> date_type:
    """Server-UTC calendar day (2026-09-20 audit fix L-1).

    The recompute/question paths used ``date_type.today()``, which answers
    in the HOST's local timezone — the exact drift the L-5 fix removed from
    entries/measures. Question pinning, rotation, and retention must flip on
    the same UTC midnight the entry-date bounds use, or a non-UTC host pins
    a question under a local "today" the rest of the calendar disagrees with.
    """
    return datetime.now(timezone.utc).date()


def _decode_b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(status_code=422, detail=f"{what} must be base64", code="validation_error")


def _dialect_insert(session: AsyncSession):
    """The insert() class with on_conflict_do_update for the session's
    dialect — both sqlite and postgresql ship one; the generic
    sqlalchemy.insert() does not. Two distinct import names (never rebind
    one): the sqlite and postgresql Insert types differ, and mypy flags a
    same-name re-import as an incompatible assignment."""
    if session.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        return pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    return sqlite_insert


async def _replace_insight(
    session: AsyncSession,
    user_id: str,
    kind: str,
    for_date: date_type | None,
    blob: bytes,
    state_seq: int = 0,
) -> None:
    """Write the current insight of (user, kind[, for_date]) idempotently.

    Dated rows (the daily question) UPSERT on the
    uq_insights_user_kind_date constraint. The recompute flow deliberately
    does NOT reach this upsert for a same-day question that already exists
    (H-12, 2026-09-20: the day's question is pinned on first write), so the
    upsert here only ever lands a day's FIRST row or maintenance writes.
    Rows with for_date=None (the patterns payload, the brain state) can
    never upsert: SQL NULLs are distinct, so the unique constraint never
    sees a conflict for them. They stay delete-then-insert under the
    per-user recompute lock — and the delete covers the whole kind, so
    legacy dated rows of that kind are cleaned up too.
    """
    if for_date is None:
        await session.execute(
            delete(Insight).where(Insight.user_id == user_id, Insight.kind == kind)
        )
        session.add(
            Insight(user_id=user_id, kind=kind, for_date=None, blob=blob, state_seq=state_seq)
        )
        return
    now = utcnow()
    stmt = (
        _dialect_insert(session)(Insight)
        .values(
            id=new_id(),
            user_id=user_id,
            kind=kind,
            for_date=for_date,
            blob=blob,
            created_at=now,
            state_seq=state_seq,
        )
        .on_conflict_do_update(
            index_elements=["user_id", "kind", "for_date"],
            set_={"blob": blob, "created_at": now, "state_seq": state_seq},
        )
    )
    await session.execute(stmt)


def _is_fk_violation(exc: IntegrityError) -> bool:
    """The insight write lost its parent user row: DELETE /account committed
    while the recompute was analyzing. Surfaces as 410, never a bare 500."""
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    # 23503 foreign_key_violation: psycopg-style drivers expose pgcode,
    # asyncpg exposes sqlstate.
    if getattr(orig, "pgcode", None) == "23503" or getattr(orig, "sqlstate", None) == "23503":
        return True
    return "foreign key" in str(orig).lower()


async def _fresh_processing_session_user(
    session: AsyncSession, user_id: str, expected_epoch: int
) -> User:
    """Re-authorize a processing-session mint under the lifecycle fence.

    ``require_user`` necessarily ran before the caller acquired that lock.
    A logout can therefore invalidate its otherwise-authenticated token while
    it waits; the epoch equality makes that stale handoff fail closed.
    """
    fresh = await session.get(User, user_id, populate_existing=True)
    if fresh is None or not fresh.is_active or fresh.token_epoch != expected_epoch:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    return fresh


@router.post(
    "/processing/sessions",
    response_model=ProcessingSessionResponse,
    status_code=201,
    dependencies=[
        Depends(
            make_rate_limiter(
                "processing-sessions", "processing_rate_limit", "processing_rate_window"
            )
        )
    ],
)
async def create_processing_session(
    body: ProcessingSessionRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    # Zeroization discipline (2026-09-19 audit fix): the decoded data key is
    # held as a bytearray and scrubbed on EVERY exit path below, matching the
    # enclave's contract that every holder of key material is a buffer this
    # process can overwrite — it used to be an immutable bytes object that
    # lingered until GC after the keystore took its copy. The base64 STRING
    # the JSON parser held is the same documented residual as the enclave's
    # analyzer strings: Python cannot overwrite a str in place.
    data_key = bytearray(_decode_b64(body.data_key, "data_key"))
    if len(data_key) != crypto.KEY_SIZE:
        zeroize(data_key)
        raise ApiError(
            status_code=422,
            detail=f"data_key must be {crypto.KEY_SIZE} bytes",
            code="validation_error",
        )
    settings = request.app.state.settings
    # Authentication ran before this endpoint body. A logout/delete may win
    # while this request is queued, so preserve the epoch it authenticated
    # under and re-check it inside the same lifecycle fence that performs the
    # logout/delete key purge. Merely checking ``is_active`` would still let a
    # pre-logout bearer mint a fresh in-memory data-key token after the purge.
    expected_epoch = user.token_epoch
    try:
        async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
            fresh = await _fresh_processing_session_user(session, user.id, expected_epoch)
            # 2026-09-26 single-token logout: re-check the bearer's jti under
            # the same fence (require_user necessarily ran before the lock was
            # acquired; a logout that revoked THIS token while the request
            # waited must fail closed here exactly like an epoch bump — a
            # logged-out session must not mint fresh key material).
            fence_jti = getattr(request.state, "mindpattern_token_jti", None)
            if fence_jti and await request.app.state.token_revocations.is_revoked_checked(
                session, fence_jti
            ):
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            # Return the pooled connection before touching the in-memory keystore;
            # this is only a short authorization re-check, not a transaction that
            # must remain open for the token's TTL.
            await session.commit()
            try:
                # The keystore copies the buffer into its own zeroizable
                # bytearray; ours is scrubbed in the finally below.
                token = request.app.state.key_store.create(
                    data_key, settings.processing_session_ttl, owner=fresh.id
                )
            except KeyStoreFull:
                # Do not let one account or a fleet of abandoned uploads turn this
                # memory-only key store into an unbounded secret cache. Clients
                # can consume an existing token or wait for its short TTL.
                raise ApiError(
                    status_code=503,
                    detail=(
                        "processing session capacity reached; consume an existing session or retry shortly"
                    ),
                    code="service_unavailable",
                    headers={"Retry-After": "1"},
                ) from None
    finally:
        zeroize(data_key)
    return ProcessingSessionResponse(
        session_token=token, expires_in=settings.processing_session_ttl
    )


# --- data-key rotation (2026-09-20, audit fix H-1) -----------------------------
#
# POST /processing/rekey re-encrypts every stored blob of the account from
# the OLD data key to a NEW one, server-side, inside the same trust envelope
# as a recompute: the client opens one processing session per key (each
# owner-bound, single-use) and proves the OLD password (X-Account-Verifier).
# This is the recovery path that makes a captured key or phished verifier a
# RECOVERABLE event instead of a permanent compromise: rotate the credential
# (PUT /account/credential), rotate the data key (here), then re-wrap each
# live therapist grant (PUT /consents/{id}/rewrap).
#
# Baseline-phase note: unlike /insights/recompute, rekey is allowed in any
# phase. It is user-initiated key maintenance with a password proof, not
# pattern revelation — no analyzer runs and nothing about the content is
# surfaced; the "baseline decrypts nothing" contract governs the ANALYSIS
# path, which still gates on the threshold.
#
# 2026-09-26 audit item 11: transaction structure. The operation used to
# hold ONE transaction across every batch's CPU work (all entries, all
# insights, all measures) — a pooled connection pinned for the whole
# account rotation and a single multi-thousand-row transaction. It now
# commits each batch in a SHORT transaction and persists progress in a
# RekeyJournal row, atomically with that batch's blob rewrites: an
# interrupted rekey (process crash, DB failure) leaves a resumable cursor,
# and the client's retry — it still holds both keys and re-opens both
# processing sessions — continues from the cursor instead of re-walking the
# corpus. Rows the previous run already moved authenticate under the NEW
# key and are skipped (idempotent resume); a row that authenticates under
# NEITHER key is the genuine old-key mismatch (400 rekey_key_mismatch,
# journal retained for resume). The wrong-old-key contract is therefore
# stated honestly per batch: a mismatch aborts the run with already-
# committed batches REMAINING rekeyed (each batch is all-or-nothing), and
# the retry finishes the rest. Keys stay in the same discipline as before:
# zeroizable bytearrays, decrypted only in worker threads, scrubbed on
# every exit in the finally below.

REKEY_BATCH_ROWS = 100


async def _rekey_fresh_user(session: AsyncSession, user_id: str, expected_epoch: int) -> User:
    """Re-authorize a rekey inside the lifecycle fence (recompute's M-2 rule):
    a bearer retired by logout/credential-rotation while this request waited
    must fail closed before any key material is consumed."""
    fresh = await session.get(User, user_id, populate_existing=True)
    if fresh is None or not fresh.is_active or fresh.token_epoch != expected_epoch:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    return fresh


def _rekey_decrypt(
    key: bytearray, blob: bytes, candidates: tuple[bytes, ...] | bytes | None
) -> bytes:
    """Decrypt with a single AAD or the ordered candidate ladder (enclave
    semantics, local copy: the rekey path works on plain values in a worker
    thread, outside SecureProcessingContext)."""
    if candidates is None or isinstance(candidates, (bytes, bytearray)):
        return crypto.decrypt(key, blob, candidates)
    failure: TamperError | None = None
    for candidate in candidates:
        try:
            return crypto.decrypt(key, blob, candidate)
        except TamperError as exc:
            failure = exc
    assert failure is not None
    raise failure


class _RekeyMismatch(Exception):
    """Neither key authenticated a blob: the run aborts, journal retained."""


def _rekey_entry_batch(
    old_key: bytearray,
    new_key: bytearray,
    rows: list[tuple[str, str, int, bytes]],
    user_id: str,
    v2_bound: dict[str, bool] | None = None,
) -> tuple[list[tuple[str, bytes]], int]:
    """Re-encrypt one batch of entry rows in a worker thread (pure values).

    Returns (rows to rewrite, count already under the new key). A row that
    fails the OLD key but authenticates under the NEW one was moved by an
    earlier (interrupted) run — its stored ciphertext is already correct,
    so it is counted and left untouched: the resume is idempotent.

    2026-09-26 remediation (LOW a): every plaintext rides a SecureBuffer
    and is zeroized the moment its re-encryption exists — the batch used
    to hand the re-encrypt path immutable ``bytes`` that lingered until
    GC, so a batch of N rows left N whole journal plaintexts reachable
    from memory for the rest of the rotation. The authentication-only
    "already new" probe discards its plaintext the same way (it needs the
    GCM yes/no, never the content)."""
    out: list[tuple[str, bytes]] = []
    already_new = 0
    for row_id, client_entry_id, version, blob in rows:
        modern_aad = crypto.entry_aad_v2(user_id, client_entry_id, version)
        candidates = (
            (modern_aad,)
            if v2_bound and v2_bound[row_id]
            else crypto.entry_aad_candidates(user_id, client_entry_id, version)
        )
        try:
            plain_buf = SecureBuffer(_rekey_decrypt(old_key, blob, candidates))
        except TamperError:
            try:
                probe = SecureBuffer(_rekey_decrypt(new_key, blob, candidates))
            except TamperError as exc:
                raise _RekeyMismatch() from exc
            try:
                try:
                    modern_probe = SecureBuffer(crypto.decrypt(new_key, blob, modern_aad))
                except TamperError:
                    # An interrupted legacy generation still needs its v2 upgrade.
                    out.append((row_id, crypto.encrypt(new_key, bytes(probe.data), modern_aad)))
                else:
                    modern_probe.zeroize()
                    already_new += 1
            finally:
                probe.zeroize()
            continue
        # Every rekeyed entry is upgraded to the v2 (version-bound) AAD.
        try:
            out.append(
                (
                    row_id,
                    crypto.encrypt(
                        new_key,
                        bytes(plain_buf.data),
                        crypto.entry_aad_v2(user_id, client_entry_id, version),
                    ),
                )
            )
        finally:
            plain_buf.zeroize()
    return out, already_new


def _rekey_blob_batch(
    old_key: bytearray, new_key: bytearray, rows: list[tuple[str, bytes]], aad_for
) -> tuple[list[tuple[str, bytes]], int]:
    """Re-encrypt insight/measure rows under their ORIGINAL AAD (pure values).

    Same already-new-key resume rule as _rekey_entry_batch, and the same
    2026-09-26 scrubbed-buffer discipline: decrypt into a SecureBuffer,
    zeroize as soon as the new ciphertext exists."""
    out: list[tuple[str, bytes]] = []
    already_new = 0
    for row_id, blob in rows:
        try:
            plain_buf = SecureBuffer(_rekey_decrypt(old_key, blob, aad_for(row_id)))
        except TamperError:
            try:
                probe = SecureBuffer(_rekey_decrypt(new_key, blob, aad_for(row_id)))
            except TamperError as exc:
                raise _RekeyMismatch() from exc
            probe.zeroize()
            already_new += 1
            continue
        try:
            out.append((row_id, crypto.encrypt(new_key, bytes(plain_buf.data), aad_for(row_id))))
        finally:
            plain_buf.zeroize()
    return out, already_new


# Retired 2026-09-28 (audit H-1): the resume path used to gate whole stages
# on the journal's stage marker (_REKEY_STAGE_ORDER), which skipped rows the
# interrupted run never walked (random ids land both sides of a stored
# cursor). Stage markers are observability only now; every run re-walks
# every stage and the already-new probe makes that idempotent.


async def _preflight_legacy_rotation(
    session: AsyncSession, user_id: str, old_key: bytearray, new_key: bytearray, settings
) -> None:
    """Authenticate every legacy generation before binding an unbound journal.

    No row/object is changed here. A third key or unavailable object refuses
    adoption, so a repair cannot add another generation to unknown custody.
    """
    from ..services.audio_store import store_for_object
    from .account import _authenticate_blob_only

    for model in (Entry, Insight, Measure, AudioAttachment):
        cursor = None
        while True:
            query = (
                select(model)
                .where(model.user_id == user_id)
                .order_by(model.id)
                .limit(REKEY_BATCH_ROWS)
            )
            if cursor is not None:
                query = query.where(model.id > cursor)
            rows = cast(
                list[Entry | Insight | Measure | AudioAttachment],
                list((await session.scalars(query)).all()),
            )
            await session.commit()
            if not rows:
                break
            cursor = rows[-1].id
            for row in rows:
                aad: bytes | tuple[bytes, ...]
                if isinstance(row, Entry):
                    try:
                        aad = guarded_entry_aads(row, settings)
                    except TamperError:
                        raise ApiError(
                            status_code=400,
                            detail="entry blob failed authentication",
                            code="entry_blob_invalid",
                        ) from None
                    blob = bytes(row.blob)
                elif isinstance(row, Insight):
                    aad = (
                        crypto.build_aad("question", user_id, row.for_date.isoformat())
                        if row.kind == "question" and row.for_date is not None
                        else crypto.build_aad("insights", user_id, row.kind)
                    )
                    blob = bytes(row.blob)
                elif isinstance(row, Measure):
                    aad = crypto.build_aad("measure", user_id, row.client_measure_id)
                    blob = bytes(row.blob)
                else:
                    assert isinstance(row, AudioAttachment)
                    store = store_for_object(settings, row)
                    blob = await store.get(row.storage_key, max_bytes=settings.audio_max_body_bytes)
                    aad = crypto.build_aad(
                        "audio", user_id, row.client_entry_id, str(row.content_version)
                    )
                if not await anyio.to_thread.run_sync(
                    _authenticate_blob_only, old_key, blob, aad
                ) and not await anyio.to_thread.run_sync(
                    _authenticate_blob_only, new_key, blob, aad
                ):
                    raise ApiError(
                        status_code=400,
                        detail="legacy interrupted rotation contains an unknown key generation; no further rows changed",
                        code="rekey_key_mismatch",
                    )


async def _load_or_create_rekey_journal(
    session: AsyncSession,
    user_id: str,
    *,
    body: RekeyRequest,
    digest: str,
    old_key: bytearray,
    new_key: bytearray,
    settings,
) -> RekeyJournal:
    """The account's resumable rekey progress row (created on first run)."""
    journal = (
        (
            await session.execute(
                select(RekeyJournal)
                .where(RekeyJournal.user_id == user_id)
                .order_by(RekeyJournal.created_at.desc(), RekeyJournal.id.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if journal is not None:
        if journal.operation_id is None:
            await _preflight_legacy_rotation(session, user_id, old_key, new_key, settings)
            journal.operation_id = body.operation_id
            journal.request_digest = digest
            journal.old_key_fingerprint = hashlib.sha256(old_key).hexdigest()
            journal.new_key_fingerprint = hashlib.sha256(new_key).hexdigest()
            await session.commit()
        old_fingerprint = hashlib.sha256(old_key).hexdigest()
        new_fingerprint = hashlib.sha256(new_key).hexdigest()
        if (
            journal.operation_id != body.operation_id
            or journal.request_digest != digest
            or journal.old_key_fingerprint != old_fingerprint
            or journal.new_key_fingerprint != new_fingerprint
        ):
            raise ApiError(
                status_code=409,
                detail="resume the original operation with the same credentials and keys",
                code="rekey_operation_conflict",
            )
        return journal
    journal = RekeyJournal(
        user_id=user_id,
        stage="entries",
        operation_id=body.operation_id,
        request_digest=digest,
        old_key_fingerprint=hashlib.sha256(old_key).hexdigest(),
        new_key_fingerprint=hashlib.sha256(new_key).hexdigest(),
    )
    session.add(journal)
    await session.commit()
    return journal


def _rekey_insight_batch(
    old_key: bytearray, new_key: bytearray, rows: list, user_id: str
) -> tuple[list[dict], int]:
    rewritten = []
    already_new = 0
    for row_id, kind, for_date, blob, seq in rows:
        aad = (
            crypto.build_aad("question", user_id, for_date.isoformat())
            if kind == "question" and for_date is not None
            else crypto.build_aad("insights", user_id, kind)
        )
        try:
            plain = SecureBuffer(_rekey_decrypt(old_key, bytes(blob), aad))
        except TamperError:
            try:
                probe = SecureBuffer(_rekey_decrypt(new_key, bytes(blob), aad))
                probe.zeroize()
            except TamperError:
                raise _RekeyMismatch() from None
            already_new += 1
            continue
        try:
            next_seq = int(seq)
            payload = bytes(plain.data)
            if kind in (KIND_BRAIN, KIND_PATTERNS):
                if next_seq >= 2**53 - 1:
                    raise ApiError(
                        status_code=503,
                        detail="analysis generation exhausted",
                        code="service_unavailable",
                    )
                next_seq += 1
                try:
                    value = json.loads(payload)
                    if not isinstance(value, dict):
                        raise ValueError("not an object")
                except (ValueError, UnicodeError):
                    raise ApiError(
                        status_code=409,
                        detail="stored analysis cannot be migrated safely",
                        code="conflict",
                    ) from None
                value["state_seq"] = next_seq
                payload = json.dumps(value, separators=(",", ":")).encode()
            rewritten.append(
                {"id": row_id, "blob": crypto.encrypt(new_key, payload, aad), "state_seq": next_seq}
            )
        finally:
            plain.zeroize()
    return rewritten, already_new


@router.post(
    "/processing/rekey",
    response_model=RekeyResponse,
    dependencies=[
        Depends(
            make_rate_limiter("processing-rekey", "processing_rate_limit", "processing_rate_window")
        )
    ],
)
async def rekey(
    request: Request,
    body: RekeyRequest | None = Body(default=None),
    user: User = Depends(require_rekey_retry_user),
    x_processing_token: str | None = Header(default=None),
    x_new_processing_token: str | None = Header(default=None),
    x_account_verifier: str | None = Header(default=None),
):
    """Rotate every encrypted store and the login credential as one operation.

    Persist the exact request body, old verifier proof, and both keys. Short
    committed batches are resumable; their journal binds operation, credential
    payload and key pair, and fences other writers. Finalization atomically
    swaps credentials, optional v2 envelope, all active consent wraps, epochs,
    revisions and recovery invalidation. Exact committed retries return the
    durable original response before consuming processing tokens; the previous
    signed epoch authorizes that response only. Legacy unbound journals undergo
    full bounded old-or-new-key authentication before adoption.
    """
    from ..security import envelope
    from ..security.kdf import (
        KDF_PARAMS_MIN_PBKDF2_ITERATIONS,
        KdfParamsError,
        canonical_kdf_params_json,
        validate_kdf_params,
    )
    from ._audit import append_access_log, flush_audit_journal
    from .account import _require_verifier
    from .auth import (
        AUTH_KEY_SIZE,
        SALT_BYTES,
        _auth_limiter,
        auth_work_slot,
        hash_verifier_off_loop,
    )

    key_store = request.app.state.key_store
    sessionmaker = request.app.state.sessionmaker

    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    if body is None:
        raise ApiError(
            status_code=409,
            detail="upgrade the client to atomically rotate keys and credentials",
            code="upgrade_required",
        )
    digest = hashlib.sha256(
        json.dumps(
            {"payload": body.model_dump(), "old_verifier": verifier},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    expected_epoch = request.state.mindpattern_token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with sessionmaker() as retry_session:
            fresh = await retry_session.get(User, user.id, populate_existing=True)
            if fresh is None or not fresh.is_active:
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            jti = request.state.mindpattern_token_jti
            if isinstance(
                jti, str
            ) and await request.app.state.token_revocations.is_revoked_checked(retry_session, jti):
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            if fresh.rekey_operation_id == body.operation_id:
                if (
                    fresh.rekey_operation_epoch == fresh.token_epoch
                    and expected_epoch in (fresh.token_epoch, fresh.token_epoch - 1)
                    and hmac.compare_digest(fresh.rekey_operation_digest or "", digest)
                    and fresh.rekey_operation_result
                ):
                    return RekeyResponse.model_validate_json(fresh.rekey_operation_result)
                raise ApiError(
                    status_code=409,
                    detail="operation identifier already used",
                    code="rekey_operation_conflict",
                )
            if fresh.token_epoch != expected_epoch:
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    try:
        salt = base64.b64decode(body.new_salt, validate=True)
        auth_key = base64.b64decode(body.new_verifier, validate=True)
    except (ValueError, binascii.Error):
        raise ApiError(
            status_code=422, detail="invalid credential encoding", code="validation_error"
        ) from None
    if len(salt) != SALT_BYTES or len(auth_key) != AUTH_KEY_SIZE:
        raise ApiError(status_code=422, detail="invalid credential size", code="validation_error")
    wrapped_data_key = None
    params_json = None
    if user.key_scheme == KEY_SCHEME_V2:
        if body.new_wrapped_data_key is None or body.new_kdf_params is None:
            raise ApiError(
                status_code=422,
                detail="v2 rotation requires the new envelope and KDF parameters",
                code="validation_error",
            )
        wrapped_data_key = _decode_b64(body.new_wrapped_data_key, "new_wrapped_data_key")
        if len(wrapped_data_key) != envelope.WRAPPED_DATA_KEY_BYTES:
            raise ApiError(
                status_code=422, detail="invalid data key envelope size", code="validation_error"
            )
        try:
            params_json = canonical_kdf_params_json(
                validate_kdf_params(
                    body.new_kdf_params, min_pbkdf2_iterations=KDF_PARAMS_MIN_PBKDF2_ITERATIONS
                )
            )
        except KdfParamsError as exc:
            raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
    elif body.new_wrapped_data_key is not None or body.new_kdf_params is not None:
        raise ApiError(
            status_code=422,
            detail="v1 rotation cannot install a v2 envelope",
            code="validation_error",
        )
    wraps = {}
    for item in body.consent_wraps:
        if item.consent_id in wraps:
            raise ApiError(
                status_code=422, detail="duplicate consent identifier", code="validation_error"
            )
        try:
            sharing.validate_public_key_b64(item.ephemeral_pub)
            sharing.validate_public_key_b64(item.therapist_wrap_pub_key)
        except sharing.SharingError:
            raise ApiError(
                status_code=422, detail="invalid sharing key", code="validation_error"
            ) from None
        blob = _decode_b64(item.wrapped_key, "wrapped_key")
        if len(blob) != envelope.WRAPPED_DATA_KEY_BYTES:
            raise ApiError(
                status_code=422, detail="invalid consent envelope size", code="validation_error"
            )
        wraps[item.consent_id] = (item, blob)
    # Old-password proof BEFORE consuming the session tokens: a failed proof
    # must not burn the client's uploaded keys. M-B1 (2026-09-26): the proof
    # runs against a freshly re-read row (short read transaction — this
    # endpoint manages its own sessions), so a credential rotation that
    # commits mid-flight retires the old verifier here; the in-fence
    # _rekey_fresh_user epoch check (below) fences the rest.
    async with sessionmaker() as verify_session:
        await _require_verifier(user, verifier, request, verify_session)
    server_salt = os.urandom(16)
    async with auth_work_slot(request):
        verifier_hash = await hash_verifier_off_loop(
            auth_key,
            server_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )

    if not x_processing_token or not x_new_processing_token:
        raise ApiError(
            status_code=422,
            detail="two processing session tokens required (X-Processing-Token, X-New-Processing-Token)",
            code="validation_error",
        )
    try:
        new_key = key_store.pop(x_new_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="new-key processing session missing or expired",
            code="processing_session_invalid",
        ) from None
    try:
        old_key = key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        zeroize(new_key)
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None

    lifecycle_guard = lifecycle_locks.hold(f"llm-lifecycle:{user.id}")
    lifecycle_entered = False
    sharing_guards = AsyncExitStack()
    try:
        await lifecycle_guard.__aenter__()
        lifecycle_entered = True
        async with sessionmaker() as grant_session:
            grant_rows = (
                await grant_session.execute(
                    select(Consent.id, Consent.therapist_id)
                    .join(User, Consent.therapist_id == User.id)
                    .where(
                        Consent.user_id == user.id,
                        Consent.status == "active",
                        User.is_active.is_(True),
                    )
                    .limit(101)
                )
            ).all()
            if len(grant_rows) > 100:
                raise ApiError(
                    status_code=413,
                    detail="active sharing exceeds the supported rotation size",
                    code="payload_too_large",
                )
        for therapist_id in sorted({row.therapist_id for row in grant_rows}):
            await sharing_guards.enter_async_context(
                sharing_locks.hold(sharing_therapist_lock_key(therapist_id))
            )
        await sharing_guards.enter_async_context(
            sharing_locks.hold(sharing_patient_lock_key(user.id))
        )
        # Entry writes take (lifecycle, entries); recomputes take (lifecycle,
        # recompute). Rekey takes all three so a rotation linearizes against
        # every path that could observe either key generation — and HOLDS
        # them across every short transaction below, so the corpus is frozen
        # for the whole operation (no writer can interleave between batches).
        async with _entry_locks.hold(f"entries:{user.id}"):
            async with _recompute_locks.hold(f"insights:{user.id}"):
                # Bootstrap: re-authorize inside the fence, then adopt (or
                # create) the resumable journal in its own short transaction.
                async with sessionmaker() as session:
                    fresh_user = await _rekey_fresh_user(session, user.id, expected_epoch)
                    if isinstance(
                        jti, str
                    ) and await request.app.state.token_revocations.is_revoked_checked(
                        session, jti
                    ):
                        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
                    if hmac.compare_digest(old_key, new_key):
                        raise ApiError(
                            status_code=422,
                            detail="a corpus rotation requires a different new data key",
                            code="validation_error",
                        )
                    owned_wrap_count = (
                        int(
                            await session.scalar(
                                select(func.count(Consent.id)).where(
                                    Consent.user_id == user.id,
                                    Consent.id.in_(list(wraps)),
                                )
                            )
                            or 0
                        )
                        if wraps
                        else 0
                    )
                    pending_rotation = await session.scalar(
                        select(RekeyJournal).where(RekeyJournal.user_id == user.id).limit(1)
                    )
                    bound_resume = (
                        pending_rotation is not None
                        and pending_rotation.operation_id == body.operation_id
                        and hmac.compare_digest(pending_rotation.request_digest or "", digest)
                    )
                    active = (
                        await session.execute(
                            select(Consent, User.wrap_pub_key)
                            .join(User, Consent.therapist_id == User.id)
                            .where(
                                Consent.user_id == user.id,
                                Consent.status == "active",
                                User.is_active.is_(True),
                            )
                            .limit(101)
                        )
                    ).all()
                    if len(active) > 100:
                        raise ApiError(
                            status_code=413,
                            detail="active sharing exceeds the supported rotation size",
                            code="payload_too_large",
                        )
                    if (
                        not {row[0].id for row in active}.issubset(wraps)
                        or (not bound_resume and owned_wrap_count != len(wraps))
                        or not {row[0].therapist_id for row in active}.issubset(
                            {row.therapist_id for row in grant_rows}
                        )
                    ):
                        raise ApiError(
                            status_code=409,
                            detail="active sharing changed; rebuild the atomic rotation",
                            code="conflict",
                        )
                    if any(wraps[row[0].id][0].therapist_wrap_pub_key != row[1] for row in active):
                        raise ApiError(
                            status_code=409,
                            detail="therapist sharing key changed; rebuild the atomic rotation",
                            code="conflict",
                        )
                    journal = await _load_or_create_rekey_journal(
                        session,
                        user.id,
                        body=body,
                        digest=digest,
                        old_key=old_key,
                        new_key=new_key,
                        settings=request.app.state.settings,
                    )
                journal_id = journal.id
                # 2026-09-28 audit (H-1): a resumed run RE-WALKS every stage
                # from the beginning instead of skipping "completed" ones.
                # The old stage_floor gate skipped entries+insights once the
                # journal said "measures" — but rows written under the OLD
                # key after the interrupted run (ids both above AND below
                # the stored cursor; ids are random hex) were then never
                # rekeyed, finalize reported the stale counts as success,
                # and the credential swap that followed made them
                # permanently undecryptable. The already-new probe in
                # _rekey_entry_batch/_rekey_blob_batch makes the re-walk
                # idempotent (rows under the new key are counted, not
                # re-encrypted), so correctness costs only a cheap GCM
                # authentication per already-done row. The journal's
                # cursors/counters stay per-RUN bookkeeping (observability
                # + crash-resume within a stage), never resume input: every
                # run starts from zero and walks the whole corpus.
                entry_cursor: str | None = None
                measure_cursor: str | None = None
                entries_done = 0
                insights_done = 0
                measures_done = 0
                audio_done = 0

                # --- entries: id-keyset batches, CPU in a worker thread ---
                while True:
                    async with sessionmaker() as session:
                        query = (
                            select(Entry)
                            .where(Entry.user_id == fresh_user.id)
                            .order_by(Entry.id.asc())
                            .limit(REKEY_BATCH_ROWS)
                        )
                        if entry_cursor is not None:
                            query = query.where(Entry.id > entry_cursor)
                        guard_rows = list((await session.scalars(query)).all())
                        try:
                            bound = {
                                row.id: validate_entry_guard(row, request.app.state.settings)
                                for row in guard_rows
                            }
                        except TamperError:
                            raise ApiError(
                                status_code=400,
                                detail="entry blob failed authentication",
                                code="entry_blob_invalid",
                            ) from None
                        rows = [
                            (row.id, row.client_entry_id, row.content_version, bytes(row.blob))
                            for row in guard_rows
                        ]
                    if not rows:
                        break
                    entry_cursor = rows[-1][0]

                    def _reencrypt(batch: list[tuple[str, str, int, bytes]] = rows):
                        return _rekey_entry_batch(old_key, new_key, batch, fresh_user.id, bound)

                    reencrypted, already_new = await anyio.to_thread.run_sync(_reencrypt)
                    entries_done += len(reencrypted) + already_new
                    # 2026-09-21 audit B-3 (kept): one executemany
                    # round-trip per batch instead of a per-row UPDATE
                    # await. Item 11: the rewrite and the journal cursor
                    # advance are ONE short transaction — the cursor can
                    # never claim progress the blobs do not have, and a
                    # crash between batches resumes exactly here.
                    async with sessionmaker() as session:
                        rewritten = dict(reencrypted)
                        writes = []
                        for row in guard_rows:
                            row.blob = rewritten.get(row.id, bytes(row.blob))
                            seal_entry_guard(row, request.app.state.settings, v2_bound=True)
                            writes.append(
                                {
                                    "id": row.id,
                                    "blob": bytes(row.blob),
                                    **guard_values(row),
                                }
                            )
                        await session.execute(update(Entry), writes)
                        await session.execute(
                            update(RekeyJournal)
                            .where(RekeyJournal.id == journal_id)
                            .values(
                                entry_cursor=entry_cursor,
                                entries_done=entries_done,
                                updated_at=utcnow(),
                            )
                        )
                        await session.commit()

                # --- insights: bounded (patterns + brain + ≤90d questions) ---
                async with sessionmaker() as session:
                    insight_rows = (
                        await session.execute(
                            select(
                                Insight.id,
                                Insight.kind,
                                Insight.for_date,
                                Insight.blob,
                                Insight.state_seq,
                            ).where(Insight.user_id == fresh_user.id)
                        )
                    ).all()
                plain_rows = list(insight_rows)
                if plain_rows:
                    reencrypted, already_new = await anyio.to_thread.run_sync(
                        lambda: _rekey_insight_batch(old_key, new_key, plain_rows, fresh_user.id)
                    )
                    insights_done += len(reencrypted) + already_new
                    async with sessionmaker() as session:
                        if reencrypted:
                            await session.execute(
                                update(Insight),
                                reencrypted,
                            )
                        await session.execute(
                            update(RekeyJournal)
                            .where(RekeyJournal.id == journal_id)
                            .values(insights_done=insights_done, updated_at=utcnow())
                        )
                        await session.commit()

                # --- measures: same shape, ("measure", user, client id) AAD ---
                while True:
                    async with sessionmaker() as session:
                        measure_query = (
                            select(
                                Measure.id,
                                Measure.client_measure_id,
                                Measure.blob,
                            )
                            .where(Measure.user_id == fresh_user.id)
                            .order_by(Measure.id.asc())
                            .limit(REKEY_BATCH_ROWS)
                        )
                        if measure_cursor is not None:
                            measure_query = measure_query.where(Measure.id > measure_cursor)
                        measure_rows = [
                            (row_id, cid, bytes(blob))
                            for row_id, cid, blob in (await session.execute(measure_query)).all()
                        ]
                    if not measure_rows:
                        break
                    measure_cursor = measure_rows[-1][0]
                    measure_aad_by_id = {
                        row_id: crypto.build_aad("measure", fresh_user.id, cid)
                        for row_id, cid, _blob in measure_rows
                    }
                    reencrypted, already_new = await anyio.to_thread.run_sync(
                        lambda: _rekey_blob_batch(
                            old_key,
                            new_key,
                            [(row_id, blob) for row_id, _cid, blob in measure_rows],
                            lambda row_id: measure_aad_by_id[row_id],
                        )
                    )
                    measures_done += len(reencrypted) + already_new
                    async with sessionmaker() as session:
                        if reencrypted:
                            await session.execute(
                                update(Measure),
                                [
                                    {"id": row_id, "blob": new_blob}
                                    for row_id, new_blob in reencrypted
                                ],
                            )
                        await session.execute(
                            update(RekeyJournal)
                            .where(RekeyJournal.id == journal_id)
                            .values(
                                measure_cursor=measure_cursor,
                                measures_done=measures_done,
                                stage="measures",
                                updated_at=utcnow(),
                            )
                        )
                        await session.commit()

                # Audio objects use copy-on-write. An interrupted run can open
                # either key; the pointer swap and old-object tombstone commit
                # together, and the newly put object has a crash-cleanup lease.
                from ..services import audio_store as audio_storage

                settings = request.app.state.settings
                audio_cursor = None
                while True:
                    async with sessionmaker() as session:
                        audio_query = (
                            select(AudioAttachment)
                            .where(AudioAttachment.user_id == fresh_user.id)
                            .order_by(AudioAttachment.id)
                            .limit(REKEY_BATCH_ROWS)
                        )
                        if audio_cursor is not None:
                            audio_query = audio_query.where(AudioAttachment.id > audio_cursor)
                        attachments = list((await session.scalars(audio_query)).all())
                    if not attachments:
                        break
                    audio_cursor = attachments[-1].id
                    for attachment in attachments:
                        store = audio_storage.store_for_object(settings, attachment)
                        blob = await store.get(
                            attachment.storage_key, max_bytes=settings.audio_max_body_bytes
                        )
                        aad = crypto.build_aad(
                            "audio",
                            fresh_user.id,
                            attachment.client_entry_id,
                            str(attachment.content_version),
                        )
                        reencrypted, _already_new = await anyio.to_thread.run_sync(
                            lambda: _rekey_blob_batch(
                                old_key, new_key, [(attachment.id, blob)], lambda _id: aad
                            )
                        )
                        audio_done += 1
                        if not reencrypted:
                            continue
                        key = audio_storage.new_storage_key(fresh_user.id)
                        locator = audio_storage.storage_locator(store)
                        async with sessionmaker() as session:
                            pending = AudioDeletion(
                                id=new_id(),
                                owner_id=fresh_user.id,
                                backend=store.backend,
                                storage_key=key,
                                storage_locator=locator,
                                not_before=utcnow() + timedelta(hours=1),
                            )
                            session.add(pending)
                            await session.commit()
                            await store.put(key, reencrypted[0][1])
                            current = await session.get(
                                AudioAttachment, attachment.id, populate_existing=True
                            )
                            if current is None or current.storage_key != attachment.storage_key:
                                raise ApiError(
                                    status_code=409,
                                    detail="audio changed during rekey",
                                    code="conflict",
                                )
                            audio_storage.enqueue_audio_delete(session, current, store=store)
                            current.storage_key = key
                            current.storage_locator = locator
                            current.size_bytes = len(reencrypted[0][1])
                            await session.delete(pending)
                            await session.commit()

                # --- finalize: revision bumps + journal retirement ----------
                # 2026-09-21 audit A-1 (kept): every entry blob rewritten
                # without advancing entries_revision let a client mid-
                # pagination across a rekey receive mixed old/new-key pages
                # with no collection_changed signal. The rekey is exactly
                # the collection-wide mutation the revision exists to mark;
                # measures get the same treatment (A-3). Item 11: the bumps
                # and the journal DELETE share one final short transaction,
                # so a live journal row always means "an interrupted
                # rotation is resumable" and never "rotation finished but
                # the marker never moved".
                async with sessionmaker() as session:
                    final_user = await _rekey_fresh_user(session, user.id, expected_epoch)
                    recovery_invalidated = final_user.recovery_verifier is not None
                    final_user.recovery_salt = None
                    final_user.recovery_verifier = None
                    final_user.recovery_wrapped_data_key = None
                    final_user.recovery_set_at = None
                    final_user.recovery_scheme = None
                    final_user.salt = base64.b64encode(salt).decode("ascii")
                    final_user.scrypt_salt = server_salt
                    final_user.verifier = verifier_hash
                    if wrapped_data_key is not None:
                        final_user.wrapped_data_key = wrapped_data_key
                        final_user.kdf_params = params_json
                    final_user.token_epoch += 1
                    # Therapist retirement can complete during the long,
                    # batched corpus rewrite. Rebuild and lock the bounded
                    # live relationship set at finalization; never recreate
                    # wrap state for a retired therapist, and never let that
                    # dead relationship block the patient's rotation.
                    final_active_rows = (
                        await session.execute(
                            select(Consent.id, Consent.therapist_id)
                            .join(User, Consent.therapist_id == User.id)
                            .where(
                                Consent.user_id == final_user.id,
                                Consent.id.in_(list(wraps)),
                                Consent.status == "active",
                                User.is_active.is_(True),
                            )
                            .with_for_update()
                        )
                    ).all()
                    final_active = {
                        str(consent_id): str(therapist_id)
                        for consent_id, therapist_id in final_active_rows
                    }
                    for consent_id, (item, blob) in wraps.items():
                        if consent_id not in final_active:
                            continue
                        await session.execute(
                            update(Consent)
                            .where(
                                Consent.id == consent_id,
                                Consent.user_id == final_user.id,
                                Consent.status == "active",
                            )
                            .values(ephemeral_pub=item.ephemeral_pub, wrapped_key=blob)
                        )
                    changed_therapists = list(final_active.values())
                    if changed_therapists:
                        await advance_sharing_revisions(
                            session,
                            patient_ids=[final_user.id],
                            therapist_ids=changed_therapists,
                        )
                    result = RekeyResponse(
                        entries=entries_done,
                        insights=insights_done,
                        measures=measures_done,
                        audio=audio_done,
                        recovery_invalidated=recovery_invalidated,
                        operation_id=body.operation_id,
                        consents_rewrapped=len(final_active),
                    )
                    final_user.rekey_operation_id = body.operation_id
                    final_user.rekey_operation_digest = digest
                    final_user.rekey_operation_epoch = final_user.token_epoch
                    final_user.rekey_operation_result = result.model_dump_json()
                    await append_access_log(
                        session,
                        actor_id=final_user.id,
                        actor_role=final_user.role,
                        user_id=final_user.id,
                        action="corpus_credential_rotated",
                    )
                    await _increment_entries_revision(session, final_user)
                    await _increment_measures_revision(session, final_user)
                    await session.execute(delete(RekeyJournal).where(RekeyJournal.id == journal_id))
                    try:
                        await session.commit()
                    except IntegrityError as exc:
                        if _is_fk_violation(exc):
                            raise ApiError(
                                status_code=410,
                                detail="account no longer exists",
                                code="account_deleted",
                            ) from None
                        raise
                    key_store.destroy_all_for_owner(final_user.id)
                    # This transaction uses a private session, so it never
                    # reaches get_session's post-commit journal hook. Anchor
                    # the committed security event outside the DB too; an
                    # exact response-loss retry must not append it again.
                    await flush_audit_journal(
                        session,
                        settings.audit_journal_path,
                        failure_observer=request.app.state.metrics.observe_audit_journal_failure,
                    )
        return result
    except _RekeyMismatch:
        raise ApiError(
            status_code=400,
            detail=(
                "old key did not authenticate every blob; already-completed "
                "batches remain rekeyed and the retry resumes from the journal. "
                "Verify the account's current data key and retry."
            ),
            code="rekey_key_mismatch",
        ) from None
    finally:
        zeroize(old_key)
        zeroize(new_key)
        await sharing_guards.aclose()
        if lifecycle_entered:
            await lifecycle_guard.__aexit__(None, None, None)


# The analysis cost of an entry scales with its *text bytes* (MinHash signs
# every shingle; the topic scan allocates per token). Blob/quota limits bound
# storage, not CPU — these bound what one recompute is ever asked to chew on.
MAX_ANALYSIS_TEXT_CHARS = 20_000  # per entry (journal entries are far smaller)
MAX_ANALYSIS_TOTAL_CHARS = 2_000_000  # per recompute; oldest text truncated first
# The brain runs on the SERVER-VALIDATED outer entry_date, never on the
# client-controlled created_at inside the encrypted payload. The inner date is
# only sanity-checked (parses, within a day of the outer date, so timezone
# skew between the client's clock and the server's cannot reject honest
# entries) — a year-3000 inner date used to reach the decay math and overflow
# every recompute from then on.
INNER_DATE_TOLERANCE_DAYS = 1

# P3 (2026-09-21): the entry payload's optional coarse writing-window
# bucket. A bucket, never a clock time — the contract stays date-granular
# for privacy; this is exactly enough for the "Sunday evening" temporal
# refinement.
_TOD_BUCKETS = frozenset({"morning", "afternoon", "evening", "night"})
# VOICE_PLAN (2026-09-29): transcript_lang is a bare ISO 639-1 code
# (optionally with a script/region subtag) — the same pattern the client
# schemas accept (imported at the top, not re-typed here, so the two
# cannot drift).
_LANG_CODE_RE = re.compile(LANGUAGE_CODE_PATTERN)

# Payload-shape failures: the ciphertext authenticated but the plaintext is
# semantically malformed (bad JSON, wrong types, impossible dates). Both the
# primary run and the amnesia retry translate these to the same 400 — the
# retry used to catch only TamperError, so a malformed entry surfaced as a
# 500 exactly when the state blob was ALSO tampered. OverflowError is a
# backstop behind the date validation above.
_ENTRY_MALFORMED = (
    json.JSONDecodeError,
    KeyError,
    UnicodeDecodeError,
    ValueError,
    TypeError,
    OverflowError,
)
# Flattened once: Python 3.14 rejects the nested except (TamperError,
# _ENTRY_MALFORMED) form.
_TAMPER_OR_MALFORMED = (TamperError, *_ENTRY_MALFORMED)


def _parse_inner_date(raw: object) -> date_type:
    """created_at arrives in two wire shapes: a date-only string (legacy
    clients and the test harness) and the FULL ISO timestamp every current
    client writes (mobile EntryScreen, web Entry — pinned as the canonical
    cross-platform payload in shared/interop_fixtures.json). Plain
    date.fromisoformat rejects the timestamp form, which made every
    recompute 400 entry_payload_malformed for accounts whose entries were
    saved from the real clients — invisible to the backend suite because
    its helpers build the date-only shape. The timestamp contributes only
    its calendar date; the ±1-day tolerance at the call site absorbs the
    client-vs-server timezone skew."""
    if not isinstance(raw, str):
        raise ValueError("created_at must be a string")
    try:
        return date_type.fromisoformat(raw)
    except ValueError:
        return datetime.fromisoformat(raw).date()


def _parse_entries(plains: list[bytearray], outer_dates: list[date_type]) -> list[JournalEntry]:
    entries: list[JournalEntry] = []
    for raw, outer in zip(plains, outer_dates):
        payload = json.loads(raw.decode("utf-8"))
        text = payload["text"]
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if len(text) > MAX_ANALYSIS_TEXT_CHARS:
            text = text[:MAX_ANALYSIS_TEXT_CHARS]
        sentiment = payload.get("sentiment")
        if sentiment is not None:
            # NaN/Infinity parse fine in Python's json and would poison
            # every average downstream — reject them here, clamp the rest
            # to the engine's [-1, 1] scale. bool is an int subclass in
            # Python but `true` is not a mood tag.
            if (
                isinstance(sentiment, bool)
                or not isinstance(sentiment, (int, float))
                or not math.isfinite(sentiment)
            ):
                raise ValueError("sentiment must be a finite number")
            sentiment = max(-1.0, min(1.0, float(sentiment)))
        inner = _parse_inner_date(payload["created_at"])
        if abs((inner - outer).days) > INNER_DATE_TOLERANCE_DAYS:
            raise ValueError("created_at does not match entry_date")
        # --- structured channels (payload v2, 2026-09-17). All optional;
        # every field is validated as hostile input exactly like sentiment:
        # malformed values are a 400 (entry_payload_malformed), never a
        # silent default that would quietly mislabel the analysis.
        energy = payload.get("energy")
        if energy is not None:
            if (
                isinstance(energy, bool)
                or not isinstance(energy, (int, float))
                or not math.isfinite(energy)
            ):
                raise ValueError("energy must be a finite number")
            energy = max(-1.0, min(1.0, float(energy)))
        sleep_raw = payload.get("sleep")
        if sleep_raw is not None:
            if (
                isinstance(sleep_raw, bool)
                or not isinstance(sleep_raw, int)
                or not 1 <= sleep_raw <= 5
            ):
                raise ValueError("sleep must be an integer 1..5")
        tags_raw = payload.get("tags")
        tags: tuple[str, ...] = ()
        if tags_raw is not None:
            if not isinstance(tags_raw, list) or len(tags_raw) > 8:
                raise ValueError("tags must be a list of at most 8 strings")
            cleaned = []
            for tag in tags_raw:
                if not isinstance(tag, str):
                    raise ValueError("tags must be strings")
                cleaned_tag = tag.strip().lower()[:24]
                if cleaned_tag and cleaned_tag not in cleaned:
                    cleaned.append(cleaned_tag)
            tags = tuple(cleaned)
        # P3 (2026-09-21): the coarse writing-window bucket. Strict like
        # every other channel — an unknown bucket is client drift, and the
        # honest answer is the same 400 the malformed-energy path gives.
        tod_raw = payload.get("tod")
        if tod_raw is not None:
            if not isinstance(tod_raw, str) or tod_raw not in _TOD_BUCKETS:
                raise ValueError("tod must be one of: " + ", ".join(sorted(_TOD_BUCKETS)))
        # --- voice channels (payload v3, VOICE_PLAN 2026-09-29). Validated
        # like every other channel: malformed values are a 400
        # (entry_payload_malformed), never a silent default.
        input_mode = payload.get("input_mode")
        if input_mode is not None and input_mode not in ("typed", "voice"):
            raise ValueError("input_mode must be 'typed' or 'voice'")
        transcript_lang = payload.get("transcript_lang")
        if transcript_lang is not None and _LANG_CODE_RE.fullmatch(transcript_lang) is None:
            raise ValueError("transcript_lang must be an ISO 639-1 code")
        english_text = payload.get("english_text")
        if english_text is not None:
            if not isinstance(english_text, str):
                raise ValueError("english_text must be a string or null")
            english_text = english_text[:MAX_ANALYSIS_TEXT_CHARS]
        # D-7 analysis-text routing: en/es analyze their native text (the
        # engine's own lexicons); every OTHER detected language analyzes the
        # English translation, so pattern quality never depends on
        # per-language lexicons. A missing/unavailable translation falls
        # back to the original text (the EN pipeline's best effort) — a
        # degraded analysis, never a failed one.
        if (
            transcript_lang is not None
            and transcript_lang not in ("en", "es")
            and isinstance(english_text, str)
            and english_text.strip()
        ):
            text = english_text
        entries.append(
            JournalEntry(
                text=text,
                entry_date=outer,
                sentiment=sentiment,
                energy=energy,
                sleep_quality=sleep_raw,
                tags=tags,
                tod=tod_raw,
            )
        )
    # Total-corpus budget: keep the most recent text (entries arrive in
    # date order) and truncate the oldest beyond the budget. JournalEntry
    # is frozen, so truncation swaps in a copy rather than mutating.
    total = sum(len(e.text) for e in entries)
    for i, entry in enumerate(entries):
        if total <= MAX_ANALYSIS_TOTAL_CHARS:
            break
        total -= len(entry.text)
        entries[i] = replace(entry, text="")
    return entries


def _chosen_pattern_pid(
    today: date_type, patterns: list, user_id: str, language: str = "en"
) -> str | None:
    """The pid of the pattern whose question was selected for today.

    Deterministic re-derivation of the same choice questions.question_for_today
    made (same pool, same rotation): build_pool's ordering is stable, so the
    pool index maps back to its pattern. Falls back to None when the day's
    question is generic. ``language`` must be the SAME language the served
    question was chosen in (2026-09-28 deep audit: the mirror used to build
    from the EN pool while the real question came from the ES pool — correct
    today only because the pools are positionally parallel).
    """
    from ..services import questions as question_engine

    pool_patterns = sorted(
        [
            p
            for p in patterns
            if not question_engine.pattern_is_sensitive(p)
            and not question_engine.pattern_is_muted(p)
        ],
        key=question_engine.feedback_rank,
    )[: question_engine.MAX_PATTERN_QUESTIONS]
    rendered: list[str] = []
    owners: list[str | None] = []
    for p in pool_patterns:
        for q in question_engine.render_pattern_questions(p, language):
            rendered.append(q)
            owners.append(p.detail.get("pattern_pid") if isinstance(p.detail, dict) else None)
    # The generic pool is language-selected exactly as build_pool does
    # (questions.py:560-572) — positionally parallel today, mirrored by
    # construction rather than by accident.
    generic = list(
        question_engine.GENERIC_QUESTIONS_ES
        if language == "es"
        else question_engine.GENERIC_QUESTIONS
    )
    rendered.extend(generic)
    owners.extend([None] * len(generic))
    # Mirror build_pool's dedupe + suppression filters.
    filtered: list[tuple[str | None, str]] = []
    seen: set[str] = set()
    for pid_owner, question_text in zip(owners, rendered):
        if question_text in seen or question_engine.crisis.matches_suppress(question_text):
            continue
        seen.add(question_text)
        filtered.append((pid_owner, question_text))
    pool = [q for _, q in filtered] or list(generic)
    index = (today.toordinal() + question_engine.user_rotation_offset(user_id)) % len(pool)
    chosen_owner = filtered[index][0] if index < len(filtered) else None
    return chosen_owner if isinstance(chosen_owner, str) else None


class FeedbackEvents(NamedTuple):
    """Decoded client feedback riding a recompute (all optional, all
    validated): question taps, pattern mutes, pattern unmutes."""

    taps: list[tuple[str, bool]]
    muted: list[str]
    unmuted: list[str]


def _parse_feedback(raw: bytes) -> FeedbackEvents:
    """Decoded question-feedback taps and pattern mutes:
    {"feedback": [{"pid": str, "resonated": bool}],
     "muted": [pid, ...], "unmuted": [pid, ...]}.
    Hostile-shape rules like every payload: malformed input is a 400
    (entry_payload_malformed), never a silent skip or a crash. That
    includes individual items (2026-09-20 audit fix L-11): a non-dict
    tap, a mistyped pid, or an out-of-range entry used to be dropped
    quietly, which drifted from this docstring's "never a silent skip"
    contract — a partially-corrupt feedback queue must be refused loudly
    (the client quarantines it) rather than half-applied invisibly. The
    [:100] bounds are volume caps, not validation: only the first 100
    items of each list are examined, and each examined item must be
    well-formed.

    The "feedback" key may be ABSENT when mutes/unmutes ride the blob
    (2026-09-21): the shipped client always emits all three keys, but a
    mute-only queue is a well-formed state — a blob carrying only
    muted/unmuted pids is accepted with zero taps. A missing key with NO
    mute lists at all ({} or a garbage shape) is still the loud 400:
    nothing would be applied, so nothing may be silently swallowed."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(
            status_code=400,
            detail="feedback blob is malformed",
            code="entry_payload_malformed",
        ) from exc
    if not isinstance(payload, dict):
        raise ApiError(
            status_code=400,
            detail="feedback blob is malformed",
            code="entry_payload_malformed",
        )
    events = payload.get("feedback")
    if events is None and ("muted" in payload or "unmuted" in payload):
        events = []  # mute/unmute-only blob: zero taps is a valid queue state
    if not isinstance(events, list):
        raise ApiError(
            status_code=400,
            detail="feedback blob is malformed",
            code="entry_payload_malformed",
        )
    taps: list[tuple[str, bool]] = []
    for item in events[:100]:
        if not isinstance(item, dict):
            raise ApiError(
                status_code=400,
                detail="feedback blob is malformed",
                code="entry_payload_malformed",
            )
        pid = item.get("pid")
        resonated = item.get("resonated")
        if not (isinstance(pid, str) and 1 <= len(pid) <= 128 and isinstance(resonated, bool)):
            raise ApiError(
                status_code=400,
                detail="feedback blob is malformed",
                code="entry_payload_malformed",
            )
        taps.append((pid, resonated))

    def _pid_list(key: str) -> list[str]:
        if key not in payload:
            return []
        raw_list = payload[key]
        if not isinstance(raw_list, list):
            raise ApiError(
                status_code=400,
                detail="feedback blob is malformed",
                code="entry_payload_malformed",
            )
        pids: list[str] = []
        for pid in raw_list[:100]:
            if not (isinstance(pid, str) and 1 <= len(pid) <= 128):
                raise ApiError(
                    status_code=400,
                    detail="feedback blob is malformed",
                    code="entry_payload_malformed",
                )
            pids.append(pid)
        return pids

    return FeedbackEvents(taps=taps, muted=_pid_list("muted"), unmuted=_pid_list("unmuted"))


async def _load_rows(
    session: AsyncSession, user_id: str, limit: int, blob_budget: int
) -> list[Entry]:
    """The most recent ``limit`` entries, in chronological order, within a
    cumulative ciphertext byte budget.

    Bounded in SQL — ORDER BY recency DESC, LIMIT, then reversed in Python
    — instead of fetching EVERY blob the account holds and slicing
    rows[-limit:]: at the 10k-entry / 256 MiB quota the old shape pulled
    hundreds of MiB over the wire to keep the newest 2000 rows.

    The byte budget (2026-09-17) is the second bound: rows are fetched in
    two phases — ids + sizes first, then only the NEWEST rows whose
    running ciphertext total stays within ``blob_budget`` — so peak
    recompute memory is bounded by the ANALYSIS budget, never by the
    account's storage quota. A quota-maxed account can no longer make one
    process transiently hold ~256 MiB ciphertext + plaintext + zeroized
    copies (x4 concurrent analyze slots) for the sake of a 2M-char
    analysis. Rows beyond the budget are dropped oldest-first, exactly
    like the per-recompute text truncation they sit beneath.
    """
    recency = (Entry.entry_date.desc(), Entry.received_at.desc(), Entry.id.desc())
    id_rows = (
        await session.execute(
            # The same dialect-aware byte-length expression the entries
            # quota uses — one definition of "how big is this blob".
            select(Entry.id, _entry_blob_length(session).label("size"))
            .where(Entry.user_id == user_id)
            .order_by(*recency)
            .limit(limit)
        )
    ).all()
    kept: list[str] = []
    budget = blob_budget
    for row_id, size in id_rows:
        if size is None or size > budget:
            break  # oldest rows are beyond the analysis budget: not fetched
        kept.append(row_id)
        budget -= size
    if not kept:
        return []
    rows = list(
        (
            await session.execute(
                select(Entry)
                .where(Entry.id.in_(kept))
                .order_by(Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc())
            )
        )
        .scalars()
        .all()
    )
    return rows


async def _entry_dates(session: AsyncSession, user_id: str) -> list[date_type]:
    """Distinct active dates for the threshold evaluation — an index-only
    scan over ix_entries_user_date (no row, and no ciphertext, is fetched)."""
    return list(
        (
            await session.execute(
                select(Entry.entry_date)
                .distinct()
                .where(Entry.user_id == user_id)
                .order_by(Entry.entry_date.asc())
            )
        )
        .scalars()
        .all()
    )


async def _latest_insight(session: AsyncSession, user_id: str, kind: str) -> Insight | None:
    return (
        (
            await session.execute(
                select(Insight)
                .where(Insight.user_id == user_id, Insight.kind == kind)
                .order_by(Insight.created_at.desc(), Insight.id.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )


@router.post(
    "/insights/recompute",
    response_model=RecomputeResponse,
    dependencies=[
        Depends(
            make_rate_limiter(
                "insights-recompute", "processing_rate_limit", "processing_rate_window"
            )
        )
    ],
)
async def recompute(
    request: Request,
    user: User = Depends(require_regular_user),
    x_processing_token: str | None = Header(default=None),
    feedback_blob: str | None = Body(default=None, embed=True),
):
    """``feedback_blob`` (2026-09-17): optional base64 AES-GCM blob holding
    the user's question-feedback taps ({"feedback": [{pid, resonated}]}),
    AAD-bound to ("feedback", user id) — opaque like every other payload,
    decrypted only inside the secure processing context, consumed by the
    brain's feedback-aware question ranking."""
    settings = request.app.state.settings
    key_store = request.app.state.key_store
    sessionmaker = request.app.state.sessionmaker
    # Capture the epoch this bearer authenticated under BEFORE any lock
    # wait (2026-09-20 audit fix M-2): a logout can commit while the
    # recompute is queued behind the lifecycle fence it must take, and the
    # in-fence re-authorization below compares against this value — a
    # pre-logout bearer must fail closed there, exactly like
    # _fresh_processing_session_user does for session minting.
    expected_epoch = user.token_epoch

    # Phase comes from plaintext DB dates — no decryption, no key needed.
    # Load ONLY the distinct dates here: a baseline-phase recompute must not
    # pull the account's whole ciphertext corpus (potentially hundreds of
    # MiB) into memory just to answer "still 12 days to go".
    async with sessionmaker() as session:
        date_rows = await _entry_dates(session, user.id)
    if not date_rows:
        raise ApiError(status_code=400, detail="no entries to analyze", code="bad_request")

    state = threshold.evaluate(date_rows, settings.unlock_threshold_days)
    today = _utc_today()

    if state.phase is not Phase.INSIGHT:
        # BASELINE: reveal nothing, decrypt nothing, analyze nothing. Any
        # session token the client opened is consumed (destroyed) so the
        # keystore does not hold an unused key for the rest of the TTL.
        if x_processing_token:
            # The token is account-bound just like the insight-phase pop.
            # A baseline caller may clean up only its own pending session.
            key_store.destroy(x_processing_token, owner=user.id)
        return RecomputeResponse(
            phase=state.phase.value,
            active_days=state.active_days,
            streak=state.streak,
            days_remaining=state.days_remaining,
            patterns_stored=0,
            question_stored=False,
            analyzer="none",
        )

    # ---- insight phase: key required, session single-use -------------------
    if not x_processing_token:
        raise ApiError(
            status_code=401,
            detail="missing processing session token",
            code="processing_session_required",
        )
    try:
        # The session is bound to the account that opened it: a token minted
        # for one user can never steer a recompute for another. pop() is an
        # ATOMIC consume — single-use by mechanism, not by the absence of an
        # await between get() and destroy().
        data_key = key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None

    # The popped key is a bytearray the keystore no longer references; it
    # is scrubbed in the finally below on EVERY exit from the recompute —
    # success, 400, 410, or an unexpected 500 alike. (str copies the parser
    # and analyzer make are immutable and still linger until GC — see the
    # enclave module docstring for what zeroization honestly covers.)
    # Metrics state is initialized here (not inside the lock) so the
    # finally below can observe a duration for ANY exit past this point —
    # a recompute that 400s after real analysis work is the operational
    # signal an operator most needs to see (2026-09-17 audit: only the
    # success path used to be counted).
    metrics = getattr(request.app.state, "metrics", None)
    started = time.monotonic()
    # Account changes take the same lifecycle lock. Re-authorize inside it
    # before decrypting the corpus or storing analysis results.
    lifecycle_guard = lifecycle_locks.hold(f"llm-lifecycle:{user.id}")
    lifecycle_entered = False
    try:
        # The zeroizing finally MUST cover lock acquisition too: cancellation
        # while this request waits behind consent withdrawal/account deletion
        # must not strand the popped bytearray until garbage collection.
        await lifecycle_guard.__aenter__()
        lifecycle_entered = True
        async with _recompute_locks.hold(f"insights:{user.id}"):
            # READ phase: one short transaction, closed by the context
            # manager BEFORE any analysis runs. Only plain values (blobs as
            # immutable bytes, dates, ids) leave the session.
            async with sessionmaker() as session:
                fresh_user = await session.get(User, user.id)
                if fresh_user is None or not fresh_user.is_active:
                    raise ApiError(
                        status_code=410,
                        detail="account no longer exists",
                        code="account_deleted",
                    )
                if fresh_user.token_epoch != expected_epoch:
                    # A token retired while this request waited cannot authorize analysis.
                    raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
                await ensure_no_rekey(session, user.id)
                # Re-read the threshold inputs and re-evaluate the phase
                # INSIDE the fence (2026-09-20 audit fix M-11): the phase
                # was fixed outside the lock, so entries deleted between
                # the pre-fence date read and here left a stale INSIGHT
                # verdict that decrypted and stored rows while the live
                # distinct-day count was below the threshold. The read-side
                # gates also evaluate live, so nothing was ever SERVED, but
                # the write side must not diverge from them either.
                date_rows = await _entry_dates(session, user.id)
                state = threshold.evaluate(date_rows, settings.unlock_threshold_days)
                if state.phase is not Phase.INSIGHT:
                    # Baseline re-established while this recompute waited:
                    # reveal nothing, store nothing. The popped session key
                    # is scrubbed by the finally like every other exit, and
                    # the response mirrors the pre-fence baseline path.
                    return RecomputeResponse(
                        phase=state.phase.value,
                        active_days=state.active_days,
                        streak=state.streak,
                        days_remaining=state.days_remaining,
                        patterns_stored=0,
                        question_stored=False,
                        analyzer="none",
                    )
                rows = await _load_rows(
                    session,
                    user.id,
                    settings.recompute_entry_limit,
                    settings.analysis_blob_budget,
                )
                # 2026-09-21 audit A-8: an account above the unlock
                # threshold by definition holds entries, so an EMPTY load
                # means the analysis blob budget could not fit even the
                # newest one. Proceeding would run the brain on an empty
                # corpus and silently overwrite the user's stored patterns
                # with that empty run — refuse instead; the config floor
                # (budget >= max_body_bytes) makes this unreachable except
                # through post-boot mutation.
                if not rows and date_rows:
                    raise ApiError(
                        status_code=413,
                        detail=(
                            "analysis blob budget is smaller than the newest "
                            "entry; refusing to analyze an empty corpus"
                        ),
                        code="payload_too_large",
                    )
                # The SERVER-validated outer dates drive the brain's calendar;
                # the client-controlled created_at inside each blob is only
                # sanity-checked.
                analysis_dates = [row.entry_date for row in rows]
                # The brain's memory from the previous recompute travels INTO
                # the secure context as one more encrypted item and comes back
                # out updated.
                prior = await _latest_insight(session, user.id, KIND_BRAIN)
                prior_seq = prior.state_seq if prior is not None else 0
                # Pin-on-first-write for the daily question (2026-09-20 audit
                # fix H-12): "one question per day, stable within the day" is
                # a product invariant, but the question row used to be
                # upserted from the CURRENT recompute's pool — a same-day
                # recompute after an evening entry (new pattern qualifying, a
                # fade, a mute, feedback taps) silently changed a question the
                # user may already have answered. When today's row exists it
                # is left untouched below; the recompute lock makes this
                # read the authoritative same-day check (recomputes for one
                # account serialize on it end to end).
                question_pinned = (
                    await session.execute(
                        select(Insight.id)
                        .where(
                            Insight.user_id == user.id,
                            Insight.kind == KIND_QUESTION,
                            Insight.for_date == today,
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none() is not None
                try:
                    entry_items = [
                        (guarded_entry_aads(row, settings), bytes(row.blob)) for row in rows
                    ]
                except TamperError:
                    raise ApiError(
                        status_code=400,
                        detail="entry blob failed authentication",
                        code="entry_blob_invalid",
                    ) from None
                state_item = (
                    (crypto.build_aad("insights", user.id, KIND_BRAIN), bytes(prior.blob))
                    if prior
                    else None
                )

            # Recompute uses deterministic findings only. Provider narration
            # has no validated semantic safety boundary.
            def make_analyze_fn(with_state: bool, with_feedback: bool):
                # A factory, not a plain closure: the tamper-retry below passes
                # different item TAILS (without the state blob, or without the
                # feedback blob), and a closure over the truthy originals would
                # strip the wrong plaintexts as "state"/"feedback" on those
                # paths.
                def analyze_fn(plains: list[bytearray]):
                    tail = (1 if with_state else 0) + (1 if with_feedback else 0)
                    entry_plains = plains[:-tail] if tail else plains
                    state_plain = bytes(plains[-tail]) if with_state and tail else None
                    fb_plain = bytes(plains[-1]) if with_feedback else None
                    entries = _parse_entries(entry_plains, analysis_dates)
                    events = _parse_feedback(fb_plain) if fb_plain is not None else None
                    result = brain.update(
                        brain.load_state(state_plain),
                        entries,
                        today,
                        feedback=events.taps if events else None,
                        muted=events.muted if events else None,
                        unmuted=events.unmuted if events else None,
                    )
                    return result, list(result.surfaced)

                return analyze_fn

            feedback_item = None
            if feedback_blob:
                # 2026-09-21 audit C-5: the AAD carries the seal DATE, so a
                # blob captured by a hostile server cannot be replayed
                # across recomputes — an old tap set can no longer re-rank
                # questions forever. The client seals the UTC day (its
                # toISOString date, not the device's local calendar); the
                # today-or-yesterday tolerance keeps an honest blob sealed
                # near UTC midnight from failing its recompute.
                #
                # 2026-09-26 audit item 12: the blob is decrypted exactly
                # ONCE and only inside the enclave discipline. The old flow
                # decrypted it TWICE outside SecureProcessingContext (an
                # AAD scan to pick the matching day, then a pre-flight
                # shape check). Instead the item carries the ordered
                # (today, yesterday) candidate LADDER the context already
                # understands for entry AAD generations: the context
                # authenticates under the first binding that fits, and the
                # shape check runs inside analyze_fn on the decrypted plain
                # (with_feedback branch, _parse_feedback below). A blob
                # that fits NEITHER day raises TamperError inside the run;
                # the retry ladder below already isolates that exact case
                # as 400 feedback_blob_invalid by re-running without the
                # feedback item.
                blob_bytes = _decode_b64(feedback_blob, "feedback_blob")
                feedback_item = (
                    (
                        crypto.build_aad("feedback", user.id, today.isoformat()),
                        crypto.build_aad(
                            "feedback", user.id, (today - timedelta(days=1)).isoformat()
                        ),
                    ),
                    blob_bytes,
                )
            encrypted = (
                entry_items
                + ([state_item] if state_item else [])
                + ([feedback_item] if feedback_item else [])
            )
            # Analysis runs on a DEDICATED capacity limiter, not the shared anyio
            # thread pool: recomputes are attacker-sized multi-second CPU work and
            # must never queue in front of login scrypt (or any other request's
            # worker) in the same FIFO pool. No DB session is open here.
            analyze_limiter = getattr(request.app.state, "analyze_limiter", None)

            observed_v2: set[str] = set()

            def run_encrypted(items, analyze_fn):
                # Construct the processing context INSIDE the worker callable
                # (2026-09-20 audit fix L-10): SecureProcessingContext.__init__
                # immediately copies the key, and the context's finally can
                # only zeroize that copy once run() has executed. Building it
                # here in the endpoint meant a cancellation while the request
                # sat QUEUED on the analyze limiter destroyed the endpoint's
                # own key scrub (the finally) without the context ever
                # running — stranding its copy until GC. As a worker-local
                # construction, a queued-then-cancelled request never mints
                # the copy at all.
                context = SecureProcessingContext(data_key)
                answer = context.run(items, analyze_fn)
                observed_v2.clear()
                observed_v2.update(
                    row.id
                    for row, aad in zip(rows, context.authenticated_aads)
                    if aad
                    == crypto.entry_aad_v2(row.user_id, row.client_entry_id, row.content_version)
                )
                return answer

            try:
                # Decryption + analysis is synchronous, potentially slow CPU (or an
                # LLM round-trip); run it in a worker thread so the event loop that
                # serves every other request never stalls behind a recompute.
                result, surfaced = await anyio.to_thread.run_sync(
                    run_encrypted,
                    encrypted,
                    make_analyze_fn(state_item is not None, feedback_item is not None),
                    limiter=analyze_limiter,
                )
            except TamperError:
                if state_item is None and feedback_item is None:
                    raise ApiError(
                        status_code=400,
                        detail="entry blob failed authentication",
                        code="entry_blob_invalid",
                    ) from None
                # Isolate the culprit before touching the brain state: retry
                # with entries + state but WITHOUT the feedback item. If that
                # succeeds, the (client-controlled) feedback blob was the
                # tampered one — a 400 with its own code, never a state wipe.
                # A tampered/corrupt brain state must not brick the account
                # forever: retry once with amnesia (fresh state, the same
                # capped entry corpus) — if an ENTRY blob is the culprit the
                # retry fails the same way and surfaces the real error.
                try:
                    result, surfaced = await anyio.to_thread.run_sync(
                        run_encrypted,
                        entry_items + ([state_item] if state_item else []),
                        make_analyze_fn(state_item is not None, False),
                        limiter=analyze_limiter,
                    )
                except _TAMPER_OR_MALFORMED:
                    # Still failing without the feedback item: either an entry
                    # blob or the state itself — the amnesia retry (entries
                    # only) distinguishes them exactly as before.
                    try:
                        result, surfaced = await anyio.to_thread.run_sync(
                            run_encrypted,
                            entry_items,
                            make_analyze_fn(False, False),
                            limiter=analyze_limiter,
                        )
                    except TamperError:
                        raise ApiError(
                            status_code=400,
                            detail="entry blob failed authentication",
                            code="entry_blob_invalid",
                        ) from None
                    except _ENTRY_MALFORMED:
                        # The state was tampered AND an entry payload is bad JSON
                        # (AEAD-valid): same 400 the primary path would give.
                        raise ApiError(
                            status_code=400,
                            detail="entry payload malformed",
                            code="entry_payload_malformed",
                        ) from None
                else:
                    # entries+state decrypted cleanly: the feedback blob was
                    # the tampered item. The client must quarantine its
                    # feedback queue (it can never authenticate), not wipe
                    # state and not silently drop the taps.
                    raise ApiError(
                        status_code=400,
                        detail="feedback blob failed authentication",
                        code="feedback_blob_invalid",
                    ) from None
            except _ENTRY_MALFORMED:
                # No exception-text echo: parser internals can quote payload content.
                raise ApiError(
                    status_code=400,
                    detail="entry payload malformed",
                    code="entry_payload_malformed",
                ) from None

            # Rollback visibility (2026-09-19): one monotonic generation per
            # recompute, embedded in the ENCRYPTED payload and echoed in the
            # plaintext response / row column. A replayed-older valid-GCM
            # blob now disagrees with its echo, and a client's pinned
            # high-water mark catches even a both-copies rollback.
            state_seq = prior_seq + 1
            insights_payload = {
                "v": 2,
                "phase": state.phase.value,
                "state_seq": state_seq,
                "stats": {**result.stats, "patterns": [p.to_dict() for p in surfaced]},
            }
            blob = crypto.encrypt(
                data_key,
                json.dumps(insights_payload).encode("utf-8"),
                crypto.build_aad("insights", user.id, KIND_PATTERNS),
            )
            state_blob = crypto.encrypt(
                data_key,
                brain.dump_state(result.new_state),
                crypto.build_aad("insights", user.id, KIND_BRAIN),
            )
            question_blob = None
            if surfaced and not question_pinned:
                # H-12 (2026-09-20): skip generation entirely when today's
                # row already exists — recomputing the rotation over a NEW
                # pool is exactly how an already-served (possibly already-
                # answered) question used to change mid-day.
                # 2026-09-26 audit M-B3: the stored question string is
                # rendered in the corpus's DETECTED language (the brain
                # reports it in stats) — Spanish users no longer receive
                # English templates around Spanish labels after the
                # threshold. "other" keeps the English pool (no template
                # set exists for unclassifiable languages).
                question_language = result.stats.get("language", "en")
                if question_language not in ("en", "es"):
                    question_language = "en"
                question = questions.question_for_today(
                    user.id, surfaced, today, language=question_language
                )
                question_payload = {
                    "for_date": today.isoformat(),
                    "question": question,
                    # The chosen pattern's stable id (when the question came
                    # from a pattern): routes the "did this land?" taps back
                    # to the right brain record. Absent for generic days.
                    "pattern_pid": _chosen_pattern_pid(
                        today, surfaced, user.id, language=question_language
                    ),
                }
                question_blob = crypto.encrypt(
                    data_key,
                    json.dumps(question_payload).encode("utf-8"),
                    crypto.build_aad("question", user.id, today.isoformat()),
                )

            # Caseload summaries (2026-09-19): while the surfaced patterns'
            # metadata exists in plaintext inside this processing scope,
            # wrap a small per-consent summary to each ACTIVE therapist's
            # public key (same ECIES construction as the data-key wrap,
            # context "caseload-summary") and persist it in the write
            # transaction below. The portal then triages with N small
            # decrypts instead of N full insight blobs, and a sensitive
            # card is discoverable without opening every chart. A malformed
            # or missing therapist key only skips that consent — it must
            # never fail the patient's recompute.
            summary_wraps: list[tuple[str, str, str, bytes]] = []
            summary_json = json.dumps(
                {
                    "v": 1,
                    "patterns": len(surfaced),
                    "sensitive": any(bool(p.detail.get("sensitive")) for p in surfaced),
                    "newest": max(
                        (
                            p.detail.get("last_seen")
                            for p in surfaced
                            if isinstance(p.detail.get("last_seen"), str)
                        ),
                        default=None,
                    ),
                    "for_date": today.isoformat(),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            async with sessionmaker() as session:
                # 2026-09-26 audit M-B2: the summary WRITE now applies the
                # same disclosure gate the measures READ has enforced since
                # H-14 — a v1-disclosure consent never named measures or
                # caseload summaries, so it must not receive one (even an
                # opaque, therapist-encrypted one). Persisting summaries for
                # legacy grants made the therapist LIST serve v2-shaped
                # triage data the patient never agreed to share; skip those
                # consents entirely (the status guard in the write below
                # still protects a revoke that raced since this read).
                consent_rows = (
                    await session.execute(
                        select(Consent.id, Consent.therapist_id, User.wrap_pub_key)
                        .join(User, Consent.therapist_id == User.id)
                        .where(
                            Consent.user_id == user.id,
                            Consent.status == "active",
                            Consent.disclosure == SHARING_DISCLOSURE_VERSION,
                            User.is_active.is_(True),
                        )
                        .limit(101)
                    )
                ).all()
                if len(consent_rows) > 100:
                    raise ApiError(
                        status_code=413,
                        detail="active sharing exceeds the supported summary size",
                        code="payload_too_large",
                    )
            for consent_id, therapist_id, wrap_pub in consent_rows:
                if not isinstance(wrap_pub, str) or not wrap_pub:
                    continue
                try:
                    eph_b64, wrapped_b64 = sharing.wrap_summary_payload(
                        summary_json, wrap_pub, user.id, therapist_id
                    )
                except sharing.SharingError:
                    continue
                summary_wraps.append(
                    (consent_id, therapist_id, eph_b64, base64.b64decode(wrapped_b64))
                )

            # WRITE phase: a second short transaction, opened only after the
            # analysis and encryption are done. Nothing here decrypts.
            async with sessionmaker() as session:
                try:
                    guard_writes = []
                    for row in rows:
                        if row.id in observed_v2:
                            seal_entry_guard(row, settings, v2_bound=True)
                            guard_writes.append({"id": row.id, **guard_values(row)})
                    if guard_writes:
                        await session.execute(update(Entry), guard_writes)
                    await _replace_insight(
                        session, user.id, "patterns", None, blob, state_seq=state_seq
                    )
                    await _replace_insight(
                        session, user.id, "brain", None, state_blob, state_seq=state_seq
                    )
                    question_stored = question_blob is not None or question_pinned
                    if question_blob is not None:
                        await _replace_insight(
                            session, user.id, "question", today, question_blob, state_seq=state_seq
                        )
                        # H-12: on the pinned path no write happens at all —
                        # the existing same-day row (question and rotation
                        # index chosen by the FIRST recompute of the day)
                        # is served unchanged for the rest of the day.
                    # Dated-question retention is handled by the bounded,
                    # cooperative maintenance sweep.  Request latency never
                    # scales with global or per-account historical rows.
                    # The status guard keeps a revoke that raced between the
                    # summary read above and this write from resurrecting a
                    # cleared row. 2026-09-26 audit item 14: the DISCLOSURE
                    # version is bound into the same WHERE clause. A
                    # revoke→re-grant between the read (which selected
                    # current-disclosure consents) and this write lands a consent
                    # that is active again but granted under whatever
                    # disclosure the patient answered THEN — writing the
                    # summary onto an older grant would resurrect triage
                    # data that grant never fully covered. Accepted
                    # residual, documented: a revoke→re-grant under the
                    # CURRENT disclosure version still receives this
                    # summary immediately — but that grant's terms are
                    # exactly the ones the summary was disclosed under, so
                    # the write is within the patient's standing consent;
                    # the next recompute refreshes it in order.
                    changed_therapists: list[str] = []
                    for consent_id, therapist_id, eph_b64, wrapped_bytes in summary_wraps:
                        changed = await session.execute(
                            update(Consent)
                            .where(
                                Consent.id == consent_id,
                                Consent.status == "active",
                                Consent.disclosure == SHARING_DISCLOSURE_VERSION,
                                Consent.therapist_id.in_(
                                    select(User.id).where(User.is_active.is_(True))
                                ),
                            )
                            .values(
                                summary_blob=wrapped_bytes,
                                summary_eph_pub=eph_b64,
                                summary_updated_at=utcnow(),
                            )
                            .returning(Consent.id)
                        )
                        if changed.scalar_one_or_none() is not None:
                            changed_therapists.append(therapist_id)
                    if changed_therapists:
                        await advance_sharing_revisions(
                            session,
                            therapist_ids=changed_therapists,
                        )
                    await session.commit()
                except IntegrityError as exc:
                    if _is_fk_violation(exc):
                        # DELETE /account committed while we were analyzing:
                        # the FK killed the insight insert. The account is
                        # gone — 410, not a bare 500.
                        raise ApiError(
                            status_code=410,
                            detail="account no longer exists",
                            code="account_deleted",
                        ) from None
                    raise
            return RecomputeResponse(
                phase=state.phase.value,
                active_days=state.active_days,
                streak=state.streak,
                days_remaining=state.days_remaining,
                patterns_stored=len(surfaced),
                question_stored=question_stored,
                state_seq=state_seq,
                analyzer="brain",
                # Derive lifecycle counters from the encrypted payload's cards.
                patterns_new=sum(1 for p in surfaced if p.detail.get("is_new")),
                patterns_fading=sum(
                    1 for p in surfaced if p.detail.get("pattern_state") == "fading"
                ),
            )
    finally:
        # Scrub before any awaited cleanup. A cancellation during context
        # manager exit must never skip the only deterministic data-key wipe.
        zeroize(data_key)
        # Record failed analyses as well as successful recomputations.
        if metrics is not None:
            metrics.observe_recompute(time.monotonic() - started)
        if lifecycle_entered:
            await lifecycle_guard.__aexit__(None, None, None)


@router.post(
    "/insights/local-recompute",
    response_model=RecomputeResponse,
    dependencies=[
        Depends(
            make_rate_limiter("local-recompute", "processing_rate_limit", "processing_rate_window")
        )
    ],
)
async def local_recompute(
    body: LocalRecomputeRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """Phase 3 (2026-09-21): the escrow-closing analysis upload.

    A client that ran the deterministic brain ON-DEVICE (the port tracked
    in mobile/src/brain/PORT.md) ships its two client-encrypted blobs —
    the new brain state and the patterns payload, under the SAME AAD
    contracts the app already uses to decrypt what GET /insights serves —
    and the server stores them with the ordinary state_seq discipline.
    NO processing session is opened and the data key never crosses the
    wire: the server stays blind end to end, which is the entire point.

    Trust posture, stated plainly: the patterns payload is patient-owned
    content exactly like entries (client-authored, server-opaque). The
    server-side engine's integrity work (FDR, replication gates) protects
    the patient from flukes; it cannot protect them from their own client
    any more than entry storage can — and the therapist only ever reads
    what this patient's app produced. What the server DOES ground: the
    threshold and phase in the response are evaluated over the account's
    REAL entry dates read from the database — ``analysis_dates`` is
    accepted, format-validated client metadata that influences neither
    (pentest I-1, 2026-09-29: an earlier docstring claimed an
    intersection that never ran; the real grounding is stronger, since a
    client's claims cannot ADD counted days) — the blob count stays
    bounded, and ``base_state_seq`` is checked against the latest brain
    row so a stale local run cannot silently clobber a newer one (409
    conflict; the client re-fetches and re-runs).
    """
    settings = request.app.state.settings
    if body.base_state_seq < 0:
        raise ApiError(
            status_code=422, detail="base_state_seq must be >= 0", code="validation_error"
        )
    if not 1 <= len(body.analysis_dates) <= 366:
        raise ApiError(
            status_code=422,
            detail="analysis_dates must carry between 1 and 366 dates",
            code="validation_error",
        )
    try:
        state_blob = base64.b64decode(body.state_blob, validate=True)
        patterns_blob = base64.b64decode(body.patterns_blob, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422,
            detail="state_blob and patterns_blob must be base64",
            code="validation_error",
        ) from None
    if not (
        crypto.MIN_BLOB_SIZE <= len(state_blob) <= settings.max_user_blob_bytes
        and crypto.MIN_BLOB_SIZE <= len(patterns_blob) <= settings.max_user_blob_bytes
    ):
        raise ApiError(
            status_code=422,
            detail="blobs must be within the storage size bounds",
            code="validation_error",
        )
    # I-1 (2026-09-29): validate each declared date's ISO format (rejecting
    # garbage early), but do not accumulate them — the threshold below is
    # evaluated exclusively over the account's real DB dates, so the
    # client's analysis_dates can neither add counted days nor influence
    # the phase. The old parsed_days set was built and never read.
    for raw in body.analysis_dates:
        try:
            date_type.fromisoformat(raw)
        except ValueError:
            raise ApiError(
                status_code=422, detail="analysis_dates must be ISO dates", code="validation_error"
            ) from None

    # M-2 fence (2026-09-26 audit, LOW batch item c): capture the epoch this
    # bearer authenticated under at ENTRY — the recompute sibling has
    # enforced exactly this inside its fence since 2026-09-20, and a logout
    # committed while this upload queued behind the recompute lock must
    # fail the write closed instead of letting a retired session overwrite
    # the stored brain state and patterns.
    expected_epoch = user.token_epoch
    async with (
        lifecycle_locks.hold(f"llm-lifecycle:{user.id}"),
        _recompute_locks.hold(f"insights:{user.id}"),
    ):
        fresh_user = (
            (
                await session.execute(
                    select(User).where(User.id == user.id).execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if fresh_user is None or not fresh_user.is_active:
            raise ApiError(status_code=404, detail="account not found", code="not_found")
        if fresh_user.token_epoch != expected_epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        if (
            await session.scalar(
                select(RekeyJournal.id).where(RekeyJournal.user_id == user.id).limit(1)
            )
            is not None
        ):
            raise ApiError(
                status_code=409,
                detail="complete the pending key rotation before analysis",
                code="rekey_in_progress",
            )
        prior = await _latest_insight(session, fresh_user.id, "brain")
        prior_seq = prior.state_seq if prior is not None else 0
        if prior_seq != body.base_state_seq:
            raise ApiError(
                status_code=409,
                detail="the stored brain state moved since this analysis ran",
                code="conflict",
            )
        # Ground the claimed scope: only dates the account actually has
        # (real_dates drives the honest threshold evaluation below — a
        # client cannot claim analysis of data that does not exist).
        real_dates = set(await _entry_dates(session, fresh_user.id))
        # 2026-09-26 audit item 13: evaluate the threshold HONESTLY over the
        # account's real distinct active dates (the same threshold.evaluate
        # every read path uses) instead of hardcoding phase="insight",
        # streak=0, days_remaining=0. The response must not claim the
        # account is in the insight phase while the threshold says baseline
        # — a client (or the portal) branching on phase would treat a
        # below-threshold upload as if revelation had been earned.
        state = threshold.evaluate(sorted(real_dates), settings.unlock_threshold_days)
        # patterns_stored honesty: the server CANNOT count the patterns in
        # the opaque client-encrypted payload (no key exists on this path
        # by design), so the only truthful counts are the client's declared
        # patterns_count or, absent a claim, 0 — never the count of analysis
        # DATES the old response invented (len(grounded)).
        patterns_stored = body.patterns_count if body.patterns_count is not None else 0
        state_seq = prior_seq + 1
        await _replace_insight(
            session, fresh_user.id, "patterns", None, patterns_blob, state_seq=state_seq
        )
        await _replace_insight(
            session, fresh_user.id, "brain", None, state_blob, state_seq=state_seq
        )
        try:
            await session.commit()
        except IntegrityError as exc:
            if _is_fk_violation(exc):
                raise ApiError(
                    status_code=410,
                    detail="account no longer exists",
                    code="account_deleted",
                ) from None
            raise
    return RecomputeResponse(
        phase=state.phase.value,
        active_days=state.active_days,
        streak=state.streak,
        days_remaining=state.days_remaining,
        patterns_stored=patterns_stored,
        question_stored=False,
        analyzer="local",
        state_seq=state_seq,
    )


@router.get(
    "/insights",
    response_model=InsightsResponse,
    dependencies=[
        Depends(make_rate_limiter("insights-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_insights(
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    # Same configured threshold as /insights/recompute, or the summary and
    # the stored blob disagree about the user's phase. Distinct dates only —
    # the index serves this without touching row data.
    rows = await _entry_dates(session, user.id)
    state = threshold.evaluate(rows, request.app.state.settings.unlock_threshold_days)
    latest = await _latest_insight(session, user.id, "patterns")
    # Phase-gated (2026-09-17 audit): deleting entries can drop the account
    # back below the threshold; a patterns blob stored while the account WAS
    # in the insight phase must not keep being served in baseline — nothing
    # is revealed before the threshold, including stored leftovers.
    blob = (
        base64.b64encode(bytes(latest.blob)).decode("ascii")
        if latest and state.phase is Phase.INSIGHT
        else None
    )
    return InsightsResponse(
        phase=state.phase.value,
        active_days=state.active_days,
        streak=state.streak,
        days_remaining=state.days_remaining,
        blob=blob,
        state_seq=latest.state_seq if latest is not None else 0,
    )


@router.get(
    "/questions/today",
    response_model=QuestionResponse,
    dependencies=[
        Depends(make_rate_limiter("questions-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_question_today(
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    today = _utc_today()
    # Phase-gated like GET /insights (2026-09-19 round): a question stored
    # while the account was in the insight phase is not served after entry
    # deletions drop it back to baseline — the threshold's "reveal nothing
    # early" discipline covers stored leftovers here too, not only the
    # patterns blob.
    dates = await _entry_dates(session, user.id)
    state = threshold.evaluate(dates, request.app.state.settings.unlock_threshold_days)
    if state.phase is not Phase.INSIGHT:
        raise ApiError(
            status_code=404,
            detail="no question for today; open a processing session and run /insights/recompute",
            code="not_found",
        )
    row = (
        (
            await session.execute(
                select(Insight)
                .where(
                    Insight.user_id == user.id,
                    Insight.kind == KIND_QUESTION,
                    Insight.for_date == today,
                )
                .order_by(Insight.created_at.desc(), Insight.id.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ApiError(
            status_code=404,
            detail="no question for today; open a processing session and run /insights/recompute",
            code="not_found",
        )
    return QuestionResponse(
        for_date=row.for_date or today,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
    )
