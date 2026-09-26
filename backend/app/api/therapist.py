"""Therapist portal endpoints: registration, pairing codes, patient reads,
and notes.

Role discipline: every route here requires a therapist token, and no
therapist token can reach the journal routes (deps.require_regular_user)
— a clinician account has NO path that writes a patient's entries, by
construction rather than by UI convention.

Read paths are consent-gated per request: an ACTIVE consent row for
(therapist, patient) is checked before any insight blob or entry row is
touched, and revoked/unknown patients answer the same 404. Notes are the
therapist's own record (they survive a revoke; account deletion on either
side cascades them away with the row). The measures read additionally
requires the consent to have been granted under the CURRENT sharing
disclosure (H-14, 2026-09-20): legacy v1 grants never named measures, so
they authorize entries/insights/notes but answer 409 disclosure_outdated
for measures until the patient re-consents under the v2 copy.

Auditing: grant/revoke (by the patient) and every patient-data read/write
(by the therapist) append access_log rows. The patient LIST is audited too
(H-14, 2026-09-20): since the caseload-summary columns landed on the list,
it moves patient-derived content, so every listed patient gets a
``list_patients`` row — one per patient whose metadata (and, while the
grant lives, summary) the therapist received.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
from datetime import date as date_type, timedelta

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import delete, distinct, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import check_keyed_limit_without_count, make_rate_limiter, record_keyed_failure
from ..db import rowcount as db_rowcount
from ..deps import ApiError, get_session, require_sharing_enabled, require_therapist
from ..locks import (
    UserLocks,
    sharing_locks,
    sharing_patient_lock_key,
    sharing_therapist_lock_key,
)
from ..models import (
    AccessLog,
    Consent,
    Entry,
    Measure,
    PairingCode,
    TherapistNote,
    TherapistNoteRevision,
    User,
    new_id,
    utcnow,
)
from ..schemas import (
    MeasureOut,
    InsightsResponse,
    NoteCreateRequest,
    NoteOut,
    NoteUpdateRequest,
    EntryOut,
    PatientOut,
    PairingCodeResponse,
    TherapistMeResponse,
    TherapistRegisterRequest,
    TokenResponse,
    TherapistAccessLogOut,
    NoteRevisionOut,
    WrapKeyRotateRequest,
    entry_out,
)
from ..security import sharing
from ..security.crypto import MIN_BLOB_SIZE
from ..security.tokens import issue_token
from ..services import threshold
from .account import _require_verifier
from .auth import SALT_BYTES, AUTH_KEY_SIZE, _auth_limiter, auth_work_slot, hash_verifier_off_loop
from .consents import MAX_PATIENTS_PER_THERAPIST, SHARING_DISCLOSURE_VERSION
from .measures import (
    MEASURE_PAGE_BLOB_BYTES,
    MEASURE_PAGE_LIMIT,
    MEASURES_REVISION_HEADER,
    _measure_blob_length,
    _measure_out,
    current_measures_revision,
)
from .entries import (
    ENTRIES_REVISION_HEADER,
    MAX_COLLECTION_REVISION,
    _blob_length as _entry_blob_length,
    assert_expected_revision,
    collection_changed_error,
    current_entries_revision,
    parse_expected_revision,
)
from .insights import _entry_dates, _latest_insight

router = APIRouter(
    prefix="/therapist",
    tags=["therapist"],
)

# How long a pairing code lives (single-use). Generated fresh per attempt;
# the portal displays it, the patient types it.
PAIRING_TTL_SECONDS = sharing.PAIRING_TTL_SECONDS

# Housekeeping horizon for dead pairing-code rows: consumed/expired codes
# are deleted lazily once they are past this age (the digest row itself is
# worthless, but rows should not accumulate forever).
PAIRING_RETENTION = timedelta(days=1)
# 2026-09-17: audit rows age out after two years (time-based; account
# deletion still never touches them — they simply live out their window).
ACCESS_LOG_RETENTION = timedelta(days=730)

# Notes are encrypted but still attacker-controlled storage. Keep one
# therapist/patient chart bounded independently of the journal quota so a
# compromised clinician session cannot turn a patient relationship into an
# unbounded database/response allocation. These values deliberately leave
# ample room for ordinary longitudinal notes (~32 MiB / 1,000 records).
MAX_NOTES_PER_PATIENT = 1_000
MAX_NOTE_BYTES_PER_PATIENT = 32 * 1024 * 1024
NOTES_PAGE_SIZE = 100
# 2026-09-26 audit H-6: the same attacker-controlled-storage reasoning now
# covers the EDIT HISTORY. Every changing update preserves the superseded
# blob as an immutable TherapistNoteRevision row (up to MAX_BLOB_64 ≈ 1.07
# MiB each) that the chart quota never counted and nothing ever pruned —
# an unbounded byte faucet on the notes table. Two bounds close it:
#   * a per-NOTE revision cap with oldest-eviction on insert (below), so
#     one note's history is a bounded ring, and
#   * the chart quota itself counting revision rows+bytes (see
#     _assert_note_quota), so history can never crowd past the same
#     32 MiB / row budget live notes obey.
# 50 keeps a genuinely useful longitudinal edit trail (the revisions read
# serves 50 per page) while bounding one note's history far below the
# chart's byte budget.
MAX_NOTE_REVISIONS_PER_NOTE = 50
# Count pagination alone still permits a page of 100 near-maximum encrypted
# notes (over 100 MiB of raw ciphertext).  Bound a response independently of
# the chart-storage quota.  This is deliberately above one accepted note, so
# a valid single note can always be retrieved rather than making a chart
# unrecoverable after a limit change.
NOTES_PAGE_BLOB_BYTES = 2 * 1024 * 1024

_note_locks = UserLocks()
MAX_PAIRING_CODE_ATTEMPTS = 5

# Therapist evidence is decrypted in a browser tab.  Unlike the patient's
# sync client, a portal drill-down must never materialize the account's full
# journal in one JSON response.  The byte budget applies to stored ciphertext
# before base64/JSON expansion, and the endpoint fetches blob values only
# after a small metadata page has passed both limits.
THERAPIST_ENTRY_PAGE_SIZE = 25
THERAPIST_ENTRY_RESPONSE_BLOB_BYTES = 2 * 1024 * 1024
NOTES_REVISION_HEADER = "X-Notes-Revision"


async def _current_notes_revision(session: AsyncSession, therapist_id: str) -> int:
    """Load the therapist-global note snapshot marker.

    A global marker intentionally invalidates a continuation when the same
    therapist changes a different chart: it is conservative, but it avoids
    lost increments across independently locked patient charts.
    """
    revision = await session.scalar(select(User.notes_revision).where(User.id == therapist_id))
    if revision is None:
        raise collection_changed_error("notes", NOTES_REVISION_HEADER)
    return int(revision)


async def _increment_notes_revision(session: AsyncSession, therapist: User) -> int:
    """Atomically advance the therapist-global note marker with a write."""
    result = await session.execute(
        update(User)
        .where(User.id == therapist.id, User.notes_revision < MAX_COLLECTION_REVISION)
        .values(notes_revision=User.notes_revision + 1)
    )
    if db_rowcount(result) != 1:
        # Keep a note mutation and its marker indivisible: an unmarked write
        # would allow an offset continuation to silently drift.
        raise ApiError(
            status_code=503,
            detail="unable to advance notes revision; retry shortly",
            code="service_unavailable",
            headers={"Retry-After": "1"},
        )
    await session.refresh(therapist, attribute_names=["notes_revision"])
    return therapist.notes_revision


def access_log_prune_statement(now, retention_days: int = ACCESS_LOG_RETENTION.days):
    """DELETE for audit rows past the retention window. THE one statement
    for both call sites — the opportunistic prune in POST /therapist/
    pairing-codes below and the lifespan's daily sweep (main.py): a
    steady-state deployment creates no pairing codes, so the endpoint
    alone never prunes and the table grows unbounded."""
    return delete(AccessLog).where(AccessLog.at < now - timedelta(days=retention_days))


MAX_WRAP_KEY_BLOB_BYTES = 1024  # b64 cap mirrors schemas; decoded bound

_b64_error = (binascii.Error, ValueError)


def _decode_b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except _b64_error:
        raise ApiError(
            status_code=422, detail=f"{what} must be base64", code="validation_error"
        ) from None


def _is_unique_violation(exc: IntegrityError) -> bool:
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    if getattr(orig, "pgcode", None) == "23505" or getattr(orig, "sqlstate", None) == "23505":
        return True
    return "unique" in str(orig).lower()


def _is_fk_violation(exc: IntegrityError) -> bool:
    """The write lost a parent row: the patient (or therapist) account was
    hard-deleted while this request was between its consent read and its
    commit — account deletion cascades the consent and every chart row, so
    the insert dies on the foreign key. 23503 foreign_key_violation; the
    SQLite fallback matches the driver's wording. Distinguished from a
    duplicate by create_note (2026-09-20 audit fix L-12): a concurrent
    deletion masquerading as "already exists" would hide the real outcome."""
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    if getattr(orig, "pgcode", None) == "23503" or getattr(orig, "sqlstate", None) == "23503":
        return True
    return "foreign key" in str(orig).lower()


def _audit(session: AsyncSession, actor: User, user_id: str, action: str) -> None:
    session.add(AccessLog(actor_id=actor.id, actor_role=actor.role, user_id=user_id, action=action))


def _disclosure_outdated_response() -> JSONResponse:
    """409 envelope for a measures read under a legacy sharing disclosure
    (H-14, 2026-09-20).

    Returned directly rather than raised: the shared API error envelope
    carries only detail+code, and the mobile client needs to branch on
    ``meta.sharing_disclosure_version`` to offer the re-consent flow
    instead of a dead end — so this one payload embeds the meta block the
    decision needs. Same shape discipline as the envelope otherwise."""
    return JSONResponse(
        status_code=409,
        content={
            "detail": (
                "sharing disclosure is outdated; this consent does not cover "
                "measures. The patient must review the updated disclosure and "
                "re-consent."
            ),
            "code": "disclosure_outdated",
            "meta": {"sharing_disclosure_version": SHARING_DISCLOSURE_VERSION},
        },
    )


# --- registration & self ------------------------------------------------------


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=201,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-register", "auth_rate_limit", "auth_rate_window")),
    ],
)
async def register_therapist(
    body: TherapistRegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    x_therapist_enrollment_token: str | None = Header(default=None),
):
    """Therapist account creation. Same key schedule and enumeration
    posture as patient registration (hash first, per-username failure
    bucket, 409 only for real conflicts) plus the sharing key material:
    a P-256 public wrap key (validated: it must actually be a P-256 SPKI
    key — a grant against a garbage key would be a grant nothing can ever
    unwrap) and the PRIVATE key as a password-encrypted blob the server
    stores but cannot open."""
    settings = request.app.state.settings
    # In non-development deployments, sharing can only be explicitly enabled
    # with a controlled enrollment secret (Settings rejects an enabled
    # production feature without one). This is an operator provisioning gate,
    # not a claim that a free-form display name proves clinical credentials.
    expected_enrollment = settings.therapist_enrollment_token.strip()
    if expected_enrollment:
        provided_enrollment = (
            x_therapist_enrollment_token if isinstance(x_therapist_enrollment_token, str) else ""
        )
        if not hmac.compare_digest(provided_enrollment.encode(), expected_enrollment.encode()):
            raise ApiError(status_code=404, detail="not found", code="not_found")
    username_key = f"register-name:{body.username}"
    check_keyed_limit_without_count(
        request, username_key, settings.auth_rate_limit, settings.auth_rate_window
    )
    try:
        salt_bytes = base64.b64decode(body.salt, validate=True)
        verifier_bytes = base64.b64decode(body.verifier, validate=True)
    except _b64_error:
        raise ApiError(
            status_code=422, detail="salt and verifier must be base64", code="validation_error"
        ) from None
    if len(salt_bytes) != SALT_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"salt must be exactly {SALT_BYTES} bytes",
            code="validation_error",
        )
    if len(verifier_bytes) != AUTH_KEY_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"verifier must be {AUTH_KEY_SIZE} bytes",
            code="validation_error",
        )
    try:
        sharing.validate_public_key_b64(body.wrap_pub_key)
    except sharing.SharingError as exc:
        raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
    key_blob = _decode_b64(body.wrap_key_blob, "wrap_key_blob")
    if not MIN_BLOB_SIZE <= len(key_blob) <= MAX_WRAP_KEY_BLOB_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrap_key_blob must be {MIN_BLOB_SIZE}-{MAX_WRAP_KEY_BLOB_BYTES} bytes",
            code="validation_error",
        )

    scrypt_server_salt = os.urandom(16)
    async with auth_work_slot(request):
        verifier_hash = await hash_verifier_off_loop(
            verifier_bytes, scrypt_server_salt, limiter=_auth_limiter(request)
        )
    existing = await session.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none() is not None:
        record_keyed_failure(request, username_key, settings.auth_rate_window)
        raise ApiError(status_code=409, detail="username already taken", code="conflict")

    user = User(
        username=body.username,
        salt=body.salt,
        verifier=verifier_hash,
        scrypt_salt=scrypt_server_salt,
        role="therapist",
        display_name=body.display_name,
        wrap_pub_key=body.wrap_pub_key,
        wrap_key_blob=key_blob,
    )
    session.add(user)
    try:
        await session.flush()
        response = TokenResponse(
            token=issue_token(
                user.id, settings.token_secret, settings.token_ttl_seconds, epoch=user.token_epoch
            ),
            user_id=user.id,
            expires_in=settings.token_ttl_seconds,
            role="therapist",
        )
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        record_keyed_failure(request, username_key, settings.auth_rate_window)
        raise ApiError(status_code=409, detail="username already taken", code="conflict") from exc
    return response


@router.get(
    "/me",
    response_model=TherapistMeResponse,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-me", "read_rate_limit", "read_rate_window")),
    ],
)
async def therapist_me(
    user: User = Depends(require_therapist),
) -> TherapistMeResponse:
    """Everything the portal needs to unlock its wrap key locally (the
    blob is decryptable only with the therapist's password-derived KEK)."""
    return TherapistMeResponse(
        username=user.username,
        display_name=user.display_name or user.username,
        wrap_pub_key=user.wrap_pub_key or "",
        wrap_key_blob=base64.b64encode(bytes(user.wrap_key_blob or b"")).decode("ascii"),
        totp_enabled=user.totp_enabled is True,
    )


@router.put(
    "/wrap-key",
    status_code=204,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(
            make_rate_limiter("therapist-wrap-rotate", "auth_rate_limit", "auth_rate_window")
        ),
    ],
)
async def rotate_wrap_key(
    body: WrapKeyRotateRequest,
    request: Request,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    """Rotate the therapist's sharing (wrap) keypair (2026-09-21, audit
    C-2: wrap keys were write-once at registration — a compromised wrap
    private key was unrecoverable without deleting the account).

    Verifier-gated like every key-material swap: a stolen bearer must not
    be able to publish its OWN public half and receive every future
    patient re-wrap. The new blob is typically the same private key
    re-wrapped under a NEW password-derived KEK (password-change
    ordering: this FIRST, then PUT /account/credential), or a genuinely
    fresh keypair after wrap-key compromise.

    Compromise-rotation trade-off, stated plainly: existing grants hold
    data keys wrapped to the OLD public half. Patients see the new
    therapist_wrap_pub_key in ConsentOut and re-wrap via the existing
    PUT /consents/{id}/rewrap — no re-pairing needed. Until a patient
    re-wraps, their grant is openable only with the OLD private key, so
    the client keeps the previous key material locally until every
    active grant has rotated (grants that never re-wrap after a
    compromise rotation are intentionally lost to the therapist — that
    is the point of retiring the compromised key).
    """
    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    # M-B1 (2026-09-26): epoch captured at entry; the fence below re-reads
    # the row and refuses a session retired by a concurrent logout or
    # credential rotation (the M-2 pattern), and the verifier proof runs
    # against the freshly re-read row.
    expected_epoch = user.token_epoch
    await _require_verifier(user, verifier, request, session)
    try:
        sharing.validate_public_key_b64(body.wrap_pub_key)
    except sharing.SharingError as exc:
        raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
    key_blob = _decode_b64(body.wrap_key_blob, "wrap_key_blob")
    if not MIN_BLOB_SIZE <= len(key_blob) <= MAX_WRAP_KEY_BLOB_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrap_key_blob must be {MIN_BLOB_SIZE}-{MAX_WRAP_KEY_BLOB_BYTES} bytes",
            code="validation_error",
        )
    # Grants and content reads take this lock first, so no patient flow
    # can read the old public half mid-swap.
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        fresh = (
            (
                await session.execute(
                    select(User).where(User.id == user.id).execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if fresh is None or not fresh.is_active:
            raise ApiError(status_code=404, detail="account not found", code="not_found")
        if fresh.token_epoch != expected_epoch:
            # M-B1 (2026-09-26): a logout/credential rotation committed
            # while this request queued on the therapist fence — the
            # bearer+verifier pair predates the epoch bump and must not
            # publish replacement wrap key material.
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        fresh.wrap_pub_key = body.wrap_pub_key
        fresh.wrap_key_blob = key_blob
        _audit(session, fresh, fresh.id, "wrap_key_rotate")
        await session.commit()


@router.get(
    "/access-log",
    response_model=list[TherapistAccessLogOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-access-log", "read_rate_limit", "read_rate_window")),
    ],
)
async def read_own_access_log(
    response: Response,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
):
    """The therapist's own action history (2026-09-21 audit B-4): every
    portal read and write they performed, newest first — the
    accountability counterpart of the patient's who-accessed-my-data
    view. `patient_name` is the acted-on account's display name; None on
    self-lifecycle rows (wrap_key_rotate). Cursor-paginated like the
    patient view (X-Next-Cursor while older rows remain)."""
    from datetime import datetime as _dt

    from sqlalchemy import or_

    query = (
        select(AccessLog, User)
        .join(User, AccessLog.user_id == User.id, isouter=True)
        .where(AccessLog.actor_id == user.id)
        .order_by(AccessLog.at.desc(), AccessLog.id.desc())
    )
    if cursor:
        parts = cursor.split("|", 1)
        if len(parts) != 2:
            raise ApiError(status_code=422, detail="malformed cursor", code="validation_error")
        try:
            cursor_at = _dt.fromisoformat(parts[0])
        except ValueError:
            raise ApiError(
                status_code=422, detail="malformed cursor", code="validation_error"
            ) from None
        query = query.where(
            or_(
                AccessLog.at < cursor_at,
                (AccessLog.at == cursor_at) & (AccessLog.id < parts[1]),
            )
        )
    rows = (await session.execute(query.limit(limit + 1))).all()
    if len(rows) > limit:
        response.headers["X-Next-Cursor"] = (
            f"{rows[limit - 1][0].at.isoformat()}|{rows[limit - 1][0].id}"
        )
        rows = rows[:limit]
    return [
        TherapistAccessLogOut(
            at=row.AccessLog.at,
            action=row.AccessLog.action,
            patient_name=(
                None
                if row.User is None or row.AccessLog.user_id == user.id
                else (row.User.display_name or row.User.username)
            ),
        )
        for row in rows
    ]


@router.delete(
    "/account",
    status_code=204,
    dependencies=[
        # 2026-09-26 audit (LOW, batch item e): sharing-disabled
        # deployments must not expose the therapist delete route either —
        # the same fail-closed posture deps.py documents for every other
        # sharing surface (flat 404 when the feature is administratively
        # off, consistent with register/me/wrap-key/pairing).
        Depends(require_sharing_enabled),
        Depends(
            make_rate_limiter("therapist-account-delete", "auth_rate_limit", "auth_rate_window")
        ),
    ],
)
async def delete_therapist_account(
    request: Request,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    """Therapist account deletion (verifier-gated, like the patient's).
    Cascades: consents (patients' shares die), notes, pairing codes."""
    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    # M-B1 (2026-09-26): epoch captured at entry; enforced inside the
    # therapist fence below (the M-2 pattern — see rotate_wrap_key).
    expected_epoch = user.token_epoch
    await _require_verifier(user, verifier, request, session)
    # Therapist content reads and grants take this lock first, so a deletion
    # cannot commit between their consent decision and response assembly.
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        # M-B1 (2026-09-26): liveness AND epoch on a freshly re-read row
        # before the destructive commit — a pre-rotation bearer+verifier
        # pair queued behind the fence must not complete the deletion.
        fresh = (
            (
                await session.execute(
                    select(User).where(User.id == user.id).execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if fresh is None or not fresh.is_active:
            raise ApiError(status_code=404, detail="account not found", code="not_found")
        if fresh.token_epoch != expected_epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()


# --- pairing ------------------------------------------------------------------


@router.post(
    "/pairing-codes",
    response_model=PairingCodeResponse,
    status_code=201,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("pairing-create", "auth_rate_limit", "auth_rate_window")),
    ],
)
async def create_pairing_code(
    request: Request,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    # Opportunistic housekeeping in the same transaction: dead code rows
    # (consumed or long expired) cannot accumulate unboundedly.
    now = utcnow()
    await session.execute(
        delete(PairingCode).where(PairingCode.expires_at < now - PAIRING_RETENTION)
    )
    # access_log retention (2026-09-17): every therapist read appends a row
    # forever before this — the table grew unbounded. Two years is the
    # records-process window; time-based only (account deletion NEVER
    # cascade-deletes audit rows — that property is what lets a trail
    # outlive the account for its full retention period).
    await session.execute(
        access_log_prune_statement(now, request.app.state.settings.access_log_retention_days)
    )
    for _ in range(MAX_PAIRING_CODE_ATTEMPTS):
        code = sharing.generate_pairing_code()
        row = PairingCode(
            therapist_id=user.id,
            code_hash=sharing.pairing_code_digest(code, request.app.state.settings.token_secret),
            created_at=now,
            expires_at=now + timedelta(seconds=PAIRING_TTL_SECONDS),
        )
        session.add(row)
        try:
            await session.commit()
            return PairingCodeResponse(code=code, expires_in=PAIRING_TTL_SECONDS)
        except IntegrityError as exc:
            await session.rollback()
            if not _is_unique_violation(exc):
                raise
            # The database constraint is the authority across sessions and
            # hosts. Draw again; this is bounded so a broken RNG/mock cannot
            # turn a request into an endless DB retry loop.
    raise ApiError(
        status_code=503,
        detail="unable to allocate a unique pairing code; retry shortly",
        code="service_unavailable",
        headers={"Retry-After": "1"},
    )


# --- patient reads ------------------------------------------------------------


async def _active_consent(session: AsyncSession, therapist: User, user_id: str) -> Consent:
    """The ACTIVE consent for this pair, or a flat 404. Unknown patient,
    non-patient account, no consent, and revoked consent are
    indistinguishable on purpose."""
    if len(user_id) > 32:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    consent = (
        (
            await session.execute(
                select(Consent).where(
                    Consent.therapist_id == therapist.id, Consent.user_id == user_id
                )
            )
        )
        .scalars()
        .first()
    )
    if consent is None or consent.status != "active":
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    return consent


@router.get(
    "/patients",
    response_model=list[PatientOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-patients", "read_rate_limit", "read_rate_window")),
    ],
)
async def list_patients(
    request: Request,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    out: list[PatientOut] = []
    # A list includes each active grant's wrapped data key.  Take the same
    # therapist->patient order as content reads and re-read each pair under
    # its patient fence; otherwise a revoke could clear the key just after a
    # bulk SELECT but before this endpoint returns it.
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        # 2026-09-26 audit H-7: the CAP counts ACTIVE consents only — the
        # therapist-side twin of the patient list's F-9 rule. Consent rows
        # are never deleted (they carry disclosure history and note
        # continuity), so counting revoked rows against
        # MAX_PATIENTS_PER_THERAPIST permanently 413'd the caseload of a
        # clinician with >100 LIFETIME patients even at a small active
        # load. The retained HISTORY below is still returned in full;
        # like the patient side it is bounded by DISTINCT patients via
        # the unique (patient, therapist) pair, each an account that had
        # to exist — not manufacturable by grant/revoke churn.
        active_count = int(
            (
                await session.execute(
                    select(func.count(Consent.id)).where(
                        Consent.therapist_id == user.id,
                        Consent.status == "active",
                    )
                )
            ).scalar_one()
        )
        if active_count > MAX_PATIENTS_PER_THERAPIST:
            raise ApiError(
                status_code=413,
                detail="patient list exceeds the supported caseload size",
                code="payload_too_large",
            )
        patient_ids = (
            (
                await session.execute(
                    select(Consent.user_id)
                    .where(Consent.therapist_id == user.id)
                    .order_by(Consent.granted_at.desc(), Consent.id.desc())
                )
            )
            .scalars()
            .all()
        )
        await session.commit()
        for patient_id in patient_ids:
            async with sharing_locks.hold(sharing_patient_lock_key(patient_id)):
                row = (
                    await session.execute(
                        select(Consent, User)
                        .join(User, Consent.user_id == User.id)
                        .where(Consent.therapist_id == user.id, Consent.user_id == patient_id)
                        .execution_options(populate_existing=True)
                    )
                ).first()
                if row is None:
                    # A concurrent account deletion can remove the pair
                    # between the ID list and its per-patient fence.
                    await session.commit()
                    continue
                consent, patient = row
                active = consent.status == "active"
                # H-16 (2026-09-20): gate the caseload summary on the
                # patient being CURRENTLY insight-phase, not merely on the
                # consent status. Every sibling patterns read is phase-gated
                # ("nothing is revealed before the threshold, including
                # stored leftovers"); the list used to keep serving the last
                # insight-phase summary after entry deletions dropped the
                # account back to baseline — until revoke or a future
                # insight-phase recompute. Same _entry_dates +
                # threshold.evaluate live check those reads use.
                insight_phase = False
                if active:
                    dates = await _entry_dates(session, patient_id)
                    insight_phase = (
                        threshold.evaluate(
                            dates, request.app.state.settings.unlock_threshold_days
                        ).phase
                        is threshold.Phase.INSIGHT
                    )
                # 2026-09-26 audit M-B2: the summary SERVE now applies the
                # same disclosure gate as the WRITE side (insights.py) and
                # the measures read (H-14): a v1-disclosure grant never
                # named caseload summaries, so a summary that predates the
                # gate (written while the recompute persisted it for every
                # active consent) is treated as no-summary rather than
                # served. Re-consenting under the current disclosure makes
                # the next recompute write — and this list serve — it.
                serve_summary = (
                    active
                    and insight_phase
                    and consent.disclosure == SHARING_DISCLOSURE_VERSION
                )
                out.append(
                    PatientOut(
                        user_id=patient.id,
                        username=patient.username,
                        status=consent.status,
                        granted_at=consent.granted_at,
                        revoked_at=consent.revoked_at,
                        # Key material only while the grant lives.
                        ephemeral_pub=consent.ephemeral_pub if active else None,
                        wrapped_key=(
                            base64.b64encode(bytes(consent.wrapped_key)).decode("ascii")
                            if active and consent.wrapped_key is not None
                            else None
                        ),
                        # Same rule for the caseload summary — plus the live
                        # phase gate above: encrypted to this therapist, gone
                        # the moment the grant does OR the account leaves the
                        # insight phase.
                        summary_blob=(
                            base64.b64encode(bytes(consent.summary_blob)).decode("ascii")
                            if serve_summary and consent.summary_blob is not None
                            else None
                        ),
                        summary_eph_pub=consent.summary_eph_pub if serve_summary else None,
                        summary_updated_at=consent.summary_updated_at if serve_summary else None,
                    )
                )
                # H-14 (2026-09-20): the list moves patient-derived caseload
                # summaries, so it is audited like every other patient-data
                # read — one row per listed patient (the exposure is
                # per-patient), action ``list_patients``. Committed with the
                # same per-patient transaction as the row above.
                _audit(session, user, patient_id, "list_patients")
                await session.commit()
    return out


@router.get(
    "/patients/{user_id}/insights",
    response_model=InsightsResponse,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-insights", "read_rate_limit", "read_rate_window")),
    ],
)
async def read_patient_insights(
    request: Request,
    user_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    """The patient's pattern view — byte-identical shape to the patient's
    own GET /insights (threshold summary + encrypted patterns blob), so
    the portal decrypts with the same AAD path the mobile app uses."""
    if len(user_id) > 32:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    # Consent revocation must serialize with the entire read decision and
    # response construction, not merely with the initial SELECT.  The
    # therapist key also fences therapist-account deletion.  Every path that
    # takes both sharing locks uses this fixed order to avoid lock cycles.
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        async with sharing_locks.hold(sharing_patient_lock_key(user_id)):
            consent = await _active_consent(session, user, user_id)
            _audit(session, user, consent.user_id, "read_insights")
            rows = await _entry_dates(session, consent.user_id)
            state = threshold.evaluate(rows, request.app.state.settings.unlock_threshold_days)
            latest = await _latest_insight(session, consent.user_id, "patterns")
            # Phase-gated like the patient's own GET /insights (2026-09-17
            # audit): a stored blob from the account's insight phase must not
            # keep being served if entry deletions dropped it back into
            # baseline.
            blob = (
                base64.b64encode(bytes(latest.blob)).decode("ascii")
                if latest and state.phase is threshold.Phase.INSIGHT
                else None
            )
            response = InsightsResponse(
                phase=state.phase.value,
                active_days=state.active_days,
                streak=state.streak,
                days_remaining=state.days_remaining,
                blob=blob,
                # H-16 (2026-09-20): the rollback-replay detection contract
                # applies on the therapist path too — the response used to
                # hardcode 0 while the decrypted payload embeds N >= 1. The
                # state_seq enforcement contract itself: the PATIENT web
                # app's stateSeqGuard is the shipped client-side check;
                # the portal's own guard ships in this release's portal
                # workstream (2026-09-26 — the server has echoed the
                # marker since H-16; who verifies it is client-side).
                state_seq=latest.state_seq if latest is not None else 0,
            )
            await session.commit()  # the audit row
    return response


@router.get(
    "/patients/{user_id}/measures",
    response_model=list[MeasureOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-measures", "read_rate_limit", "read_rate_window")),
    ],
)
async def read_patient_measures(
    user_id: str,
    response: Response,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=200, ge=1, le=MEASURE_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=100_000),
    page_bytes: int | None = Query(default=None, ge=1, le=MEASURE_PAGE_BLOB_BYTES),
    expected_revision: str | None = None,
):
    """The patient's recorded wellbeing measures (MBC, 2026-09-19): opaque
    blobs under the SAME active-consent rule as entries — the portal
    decrypts with the per-consent unwrapped data key and interprets;
    this server never learns a score. Read is audit-logged like every
    other patient-data access.

    H-14 (2026-09-20): the consent must ALSO have been granted under the
    CURRENT sharing disclosure — the v1 copy named only entries and
    patterns, so it cannot authorize measures. Legacy grants answer 409
    disclosure_outdated (meta carries the current version) instead of
    serving data the patient never agreed to share in those terms.

    A-3 (2026-09-21): the entries pagination contract, ported. Byte-bounded
    pages (``page_bytes`` opt-in with ``X-Next-Offset``; legacy requests
    over the 2 MiB ciphertext budget get an explicit 413) and the
    ``X-Measures-Revision`` snapshot marker — a concurrent patient create
    answers 409 collection_changed instead of letting offset paging on the
    DESC list duplicate or skip rows. ``id`` breaks
    (measure_date, received_at) ties for one stable order across pages.
    """
    expected = parse_expected_revision(expected_revision)
    if len(user_id) > 32:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    out: list[MeasureOut] = []
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        async with sharing_locks.hold(sharing_patient_lock_key(user_id)):
            consent = await _active_consent(session, user, user_id)
            if consent.disclosure != SHARING_DISCLOSURE_VERSION:
                # Nothing was served: return the re-consent signal before
                # touching any ciphertext (and before any audit row — the
                # refusal exposed no patient data).
                return _disclosure_outdated_response()
            revision = await current_measures_revision(session, consent.user_id)
            assert_expected_revision(
                expected,
                revision,
                collection="measures",
                header_name=MEASURES_REVISION_HEADER,
            )
            _audit(session, user, consent.user_id, "read_measures")
            # Ids + byte lengths first; full blobs are fetched only for the
            # rows that fit the response budget.
            metadata = (
                await session.execute(
                    select(Measure.id, _measure_blob_length(session).label("blob_bytes"))
                    .where(Measure.user_id == consent.user_id)
                    .order_by(
                        Measure.measure_date.desc(),
                        Measure.received_at.desc(),
                        Measure.id.desc(),
                    )
                    .offset(offset)
                    # One extra metadata row tells the portal whether it
                    # must follow a cursor without inferring from page
                    # length.
                    .limit(limit + 1)
                )
            ).all()
            requested = [(str(row[0]), int(row[1])) for row in metadata[:limit]]
            selected: list[tuple[str, int]]
            if page_bytes is None:
                selected = requested
                if sum(size for _, size in selected) > MEASURE_PAGE_BLOB_BYTES:
                    raise ApiError(
                        status_code=413,
                        detail=(
                            "requested measure page exceeds the 2 MiB ciphertext budget; "
                            "upgrade to a byte-paginating portal"
                        ),
                        code="payload_too_large",
                    )
            else:
                selected = []
                used_bytes = 0
                for row_id, size in requested:
                    if size > page_bytes:
                        if not selected:
                            raise ApiError(
                                status_code=413,
                                detail=("a measure exceeds the requested page byte budget"),
                                code="payload_too_large",
                            )
                        break
                    if used_bytes + size > page_bytes:
                        break
                    selected.append((row_id, size))
                    used_bytes += size

            selected_ids = [row_id for row_id, _ in selected]
            rows: list[Measure] = []
            if selected_ids:
                rows = list(
                    (
                        await session.execute(
                            select(Measure).where(
                                Measure.user_id == consent.user_id,
                                Measure.id.in_(selected_ids),
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                # Audit durability (M-30 pattern): measure ciphertext is now
                # in memory, so the audit row added above must survive any
                # later failure — commit it in its own short transaction
                # before the consistency checks that can refuse the page.
                await session.commit()
                rows_by_id = {row.id: row for row in rows}
                if len(rows_by_id) != len(selected_ids):
                    raise collection_changed_error("measures", MEASURES_REVISION_HEADER, revision)
                rows = [rows_by_id[row_id] for row_id in selected_ids]
                byte_limit = page_bytes if page_bytes is not None else MEASURE_PAGE_BLOB_BYTES
                if sum(len(bytes(row.blob)) for row in rows) > byte_limit:
                    raise collection_changed_error("measures", MEASURES_REVISION_HEADER, revision)

            has_more = len(selected) < len(requested) or len(metadata) > limit
            if has_more and rows:
                response.headers["X-Next-Offset"] = str(offset + len(rows))
            out = [_measure_out(row) for row in rows]
            final_revision = await current_measures_revision(session, consent.user_id)
            if final_revision != revision:
                raise collection_changed_error("measures", MEASURES_REVISION_HEADER, final_revision)
            response.headers[MEASURES_REVISION_HEADER] = str(revision)
            # Audit bookkeeping, corrected 2026-09-21 (audit A-7): the
            # after-fetch commit above only ran for pages that selected
            # rows. An EMPTY page skips it entirely, so the audit row —
            # written unconditionally before the metadata query — is
            # persisted HERE: empty reads ARE audited, which is the right
            # posture (the consented scope was exercised even when no
            # rows matched). Oversized-refused 413 pages raise before any
            # commit and stay unaudited: no ciphertext was served. This
            # trailing commit closes the read transaction symmetrically.
            await session.commit()
    return out


@router.get(
    "/patients/{user_id}/entries",
    response_model=list[EntryOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-entries", "read_rate_limit", "read_rate_window")),
    ],
)
async def read_patient_entries(
    user_id: str,
    response: Response,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    since: date_type | None = Query(default=None),
    until: date_type | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=THERAPIST_ENTRY_PAGE_SIZE, ge=1, le=THERAPIST_ENTRY_PAGE_SIZE),
    page_bytes: int | None = Query(
        default=None,
        ge=1,
        le=THERAPIST_ENTRY_RESPONSE_BLOB_BYTES,
    ),
    expected_revision: str | None = None,
):
    """The patient's entries, paginated, with an ``until`` bound the
    patient endpoint never needed (the drill-down fetches a pattern's
    evidence window, not the whole journal).

    ``page_bytes`` is explicit modern-client opt-in to byte-truncated pages
    and ``X-Next-Offset``. Without it an older portal gets a clear 413 if its
    (already 25-row-capped) request would exceed the hard budget rather than
    silently ignoring a short page and losing later evidence.
    """
    expected = parse_expected_revision(expected_revision)
    if len(user_id) > 32:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    result: list[EntryOut] = []
    async with sharing_locks.hold(sharing_therapist_lock_key(user.id)):
        async with sharing_locks.hold(sharing_patient_lock_key(user_id)):
            consent = await _active_consent(session, user, user_id)
            revision = await current_entries_revision(session, consent.user_id)
            assert_expected_revision(
                expected,
                revision,
                collection="entries",
                header_name=ENTRIES_REVISION_HEADER,
            )
            _audit(session, user, consent.user_id, "read_entries")
            # Fetch ids + byte lengths first. This stays bounded at 26 tiny
            # metadata rows rather than loading the former 500 full blobs;
            # only entries that fit the response budget are fetched below.
            query = select(Entry.id, _entry_blob_length(session).label("size")).where(
                Entry.user_id == consent.user_id
            )
            if since is not None:
                query = query.where(Entry.entry_date >= since)
            if until is not None:
                query = query.where(Entry.entry_date <= until)
            metadata = (
                await session.execute(
                    query.order_by(Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc())
                    .offset(offset)
                    # One extra metadata row tells the portal whether it
                    # must follow a cursor without inferring from page
                    # length.
                    .limit(limit + 1)
                )
            ).all()
            requested = [(str(row_id), int(raw_size)) for row_id, raw_size in metadata[:limit]]
            selected: list[tuple[str, int]]
            if page_bytes is None:
                selected = requested
                if sum(size for _, size in selected) > THERAPIST_ENTRY_RESPONSE_BLOB_BYTES:
                    raise ApiError(
                        status_code=413,
                        detail=(
                            "requested evidence page exceeds the 2 MiB ciphertext budget; "
                            "upgrade to a byte-paginating portal"
                        ),
                        code="payload_too_large",
                    )
            else:
                selected = []
                used_bytes = 0
                for row_id, size in requested:
                    if size > page_bytes:
                        # Never make an oversized/corrupt first row look like
                        # an empty completed page. A real portal retries with
                        # its fixed 2 MiB budget, so this is only possible for
                        # an explicit smaller request or legacy bad data.
                        if not selected:
                            raise ApiError(
                                status_code=413,
                                detail="an evidence entry exceeds the requested page byte budget",
                                code="payload_too_large",
                            )
                        break
                    if used_bytes + size > page_bytes:
                        break
                    selected.append((row_id, size))
                    used_bytes += size

            selected_ids = [row_id for row_id, _ in selected]
            rows: list[Entry] = []
            if selected_ids:
                rows = list(
                    (
                        await session.execute(
                            select(Entry).where(
                                Entry.user_id == consent.user_id,
                                Entry.id.in_(selected_ids),
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                # Audit durability (2026-09-20 audit fix M-30): journal
                # ciphertext for this therapist is now in memory, so the
                # audit row added above must survive ANY later failure. The
                # consistency checks below deliberately raise 409 AFTER this
                # fetch — a rolled-back audit row would mean the server
                # fetched a chart with no surviving access record. Committing
                # here in its own short transaction (nothing else is pending)
                # pins the access fact before the checks that can refuse the
                # page.
                await session.commit()
                rows_by_id = {row.id: row for row in rows}
                if len(rows_by_id) != len(selected_ids):
                    # A second worker changed the page after its metadata
                    # sizing pass. Do not manufacture a cursor that skips or
                    # repeats evidence; a retry receives a fresh page.
                    raise ApiError(
                        status_code=409,
                        detail="entries changed while paging; retry the request",
                        code="conflict",
                    )
                rows = [rows_by_id[row_id] for row_id in selected_ids]
                # The normal deployment is single-process and entry writes
                # are serialized there. This is still a defensive backstop
                # for a misconfigured multi-worker deployment: never emit a
                # page that grew after metadata selection.
                byte_limit = (
                    page_bytes if page_bytes is not None else THERAPIST_ENTRY_RESPONSE_BLOB_BYTES
                )
                if sum(len(bytes(row.blob)) for row in rows) > byte_limit:
                    raise ApiError(
                        status_code=409,
                        detail="entries changed while paging; retry the request",
                        code="conflict",
                    )

            has_more = len(selected) < len(requested) or len(metadata) > limit
            if has_more and rows:
                # Contract consumed by the portal: a decimal, strictly
                # progressing offset equal to rows actually returned. An
                # absent header is the sole end-of-results signal.
                response.headers["X-Next-Offset"] = str(offset + len(rows))
            # Base64 conversion is response construction too. Keep it inside
            # the consent fence; once the lock opens a revoke may return, and
            # this request must not newly materialize journal bytes from an
            # already-loaded ORM row after that linearization point.
            result = [entry_out(row) for row in rows]
            final_revision = await current_entries_revision(session, consent.user_id)
            if final_revision != revision:
                raise collection_changed_error("entries", ENTRIES_REVISION_HEADER, final_revision)
            # Successful pages always expose their snapshot, including empty
            # and terminal pages, so a caller never needs to infer it from a
            # continuation header.
            response.headers[ENTRIES_REVISION_HEADER] = str(revision)
            # Audit bookkeeping, corrected 2026-09-21 (audit A-7): the
            # after-fetch commit above only ran for pages that selected
            # rows. An EMPTY page skips it entirely, so the audit row —
            # written unconditionally before the metadata query — is
            # persisted HERE: empty reads ARE audited, which is the right
            # posture (the consented scope was exercised even when no
            # rows matched). Oversized-refused 413 pages raise before any
            # commit and stay unaudited: no ciphertext was served. This
            # trailing commit closes the read transaction symmetrically.
            await session.commit()
    return result


# --- notes --------------------------------------------------------------------


async def _note_target(session: AsyncSession, therapist: User, user_id: str) -> str:
    """The patient id a note may attach to: the (therapist, patient) pair
    must have a consent row — ANY status. Notes are the therapist's own
    record and outlive a revoke; the row is the proof this patient was
    ever legitimately connected to this therapist."""
    if len(user_id) > 32:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    consent = (
        (
            await session.execute(
                select(Consent).where(
                    Consent.therapist_id == therapist.id, Consent.user_id == user_id
                )
            )
        )
        .scalars()
        .first()
    )
    if consent is None:
        raise ApiError(status_code=404, detail="patient not found", code="not_found")
    return consent.user_id


def _note_out(row: TherapistNote) -> NoteOut:
    return NoteOut(
        id=row.id,
        client_note_id=row.client_note_id,
        pattern_pid=row.pattern_pid,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _note_blob_length(session: AsyncSession):
    if session.bind.dialect.name == "postgresql":
        return func.octet_length(TherapistNote.blob)
    return func.length(TherapistNote.blob)


def _revision_blob_length(session: AsyncSession):
    if session.bind.dialect.name == "postgresql":
        return func.octet_length(TherapistNoteRevision.blob)
    return func.length(TherapistNoteRevision.blob)


async def _enforce_note_revision_cap(session: AsyncSession, note_id: str) -> None:
    """2026-09-26 audit H-6: keep at most MAX_NOTE_REVISIONS_PER_NOTE
    revisions per note, deleting the OLDEST beyond the cap.

    Runs inside the caller's chart-lock transaction AFTER the new revision
    row was added (autoflush makes it visible to the keep-set SELECT), so
    the eviction and the edit that triggered it commit or roll back
    together. Oldest-first is (created_at, id) ascending — the exact
    ordering key the revisions read uses, reversed — so eviction is
    deterministic regardless of insert timing."""
    keep_ids = (
        select(TherapistNoteRevision.id)
        .where(TherapistNoteRevision.note_id == note_id)
        .order_by(
            TherapistNoteRevision.created_at.desc(), TherapistNoteRevision.id.desc()
        )
        .limit(MAX_NOTE_REVISIONS_PER_NOTE)
    )
    await session.execute(
        delete(TherapistNoteRevision).where(
            TherapistNoteRevision.note_id == note_id,
            TherapistNoteRevision.id.not_in(keep_ids),
        )
    )


async def _assert_note_quota(
    session: AsyncSession,
    therapist_id: str,
    patient_id: str,
    incoming: int,
    *,
    previous_size: int = 0,
    is_new: bool,
) -> None:
    """Check a per-chart count + ciphertext budget under the chart lock.

    2026-09-26 audit H-6: the budget now counts the note EDIT HISTORY too.
    Every changing edit used to insert a full TherapistNoteRevision row
    (blobs up to MAX_BLOB_64 ≈ 1.07 MiB) with zero accounting and no
    pruning — the chart quota bounded only live notes, so history grew
    without limit. Revision rows join the row budget and revision bytes
    join the byte budget (one outer-joined aggregate query; the revision
    table carries no patient column, so it joins through the note)."""
    note_count, note_bytes, revision_count, revision_bytes = (
        await session.execute(
            select(
                func.count(distinct(TherapistNote.id)),
                func.coalesce(func.sum(_note_blob_length(session)), 0),
                func.count(TherapistNoteRevision.id),
                func.coalesce(func.sum(_revision_blob_length(session)), 0),
            )
            .outerjoin(
                TherapistNoteRevision, TherapistNoteRevision.note_id == TherapistNote.id
            )
            .where(
                TherapistNote.therapist_id == therapist_id,
                TherapistNote.user_id == patient_id,
            )
        )
    ).one()
    if is_new and int(note_count) + int(revision_count) >= MAX_NOTES_PER_PATIENT:
        raise ApiError(
            status_code=413,
            detail=f"note storage quota reached ({MAX_NOTES_PER_PATIENT} notes)",
            code="quota_exceeded",
        )
    if (
        int(note_bytes) - previous_size + incoming + int(revision_bytes)
        > MAX_NOTE_BYTES_PER_PATIENT
    ):
        raise ApiError(
            status_code=413,
            detail="note storage quota reached (total size)",
            code="blob_quota_exceeded",
        )


def _decode_note_blob(value: str) -> bytes:
    blob = _decode_b64(value, "blob")
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"blob must be at least {MIN_BLOB_SIZE} bytes",
            code="validation_error",
        )
    return blob


@router.get(
    "/patients/{user_id}/notes",
    response_model=list[NoteOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-notes-read", "read_rate_limit", "read_rate_window")),
    ],
)
async def list_notes(
    user_id: str,
    response: Response,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=NOTES_PAGE_SIZE, ge=1, le=NOTES_PAGE_SIZE),
    page_bytes: int | None = Query(default=None, ge=1, le=NOTES_PAGE_BLOB_BYTES),
    expected_revision: str | None = None,
):
    expected = parse_expected_revision(expected_revision)
    # Resolve the chart before waiting for its lock, then release the pooled
    # connection.  Re-check under that lock below: account/consent state may
    # have changed while this request was queued.
    patient_id = await _note_target(session, user, user_id)
    await session.commit()

    # Existing deployed portals use ``len(rows) < limit`` as their end
    # signal.  Byte-truncating every request would make one of those clients
    # silently omit later notes.  A modern client explicitly opts in with
    # page_bytes; legacy requests instead fail loudly if their full requested
    # page would exceed the safe response budget.
    byte_limit = page_bytes if page_bytes is not None else NOTES_PAGE_BLOB_BYTES
    async with _note_locks.hold(f"notes:{user.id}:{patient_id}"):
        patient_id = await _note_target(session, user, user_id)
        revision = await _current_notes_revision(session, user.id)
        assert_expected_revision(
            expected,
            revision,
            collection="notes",
            header_name=NOTES_REVISION_HEADER,
        )
        _audit(session, user, patient_id, "read_notes")
        # Do the first, bounded query without materializing ciphertext.  The
        # previous ``limit + 1`` query fetched up to 101 note blobs before it
        # could paginate; a chart within its 32 MiB storage quota could
        # therefore make one ordinary read allocate and serialize roughly
        # 43 MiB of base64 JSON.  Select ids and sizes first, then fetch only
        # rows the caller can safely receive.
        candidate_rows = (
            await session.execute(
                select(TherapistNote.id, _note_blob_length(session).label("size"))
                .where(
                    TherapistNote.therapist_id == user.id,
                    TherapistNote.user_id == patient_id,
                )
                .order_by(TherapistNote.created_at.asc(), TherapistNote.id.asc())
                # One extra *metadata* row tells the caller whether the
                # count bound has more data without materializing a whole
                # encrypted chart.
                .offset(offset)
                .limit(limit + 1)
            )
        ).all()

        # The extra metadata row is continuation evidence only.  Never let it
        # become a 101st returned row when all blobs happen to fit the byte
        # cap.
        requested_rows = candidate_rows[:limit]
        selected_ids: list[str] = []
        used_blob_bytes = 0
        more = len(candidate_rows) > limit
        for note_id, size in requested_rows:
            # Application writes always have a non-null blob.  Treat a
            # malformed legacy row conservatively as empty for pagination
            # rather than raising a 500 while rendering a therapist's own
            # record.
            blob_bytes = int(size or 0)
            if blob_bytes > byte_limit:
                raise ApiError(
                    status_code=413,
                    detail="stored note exceeds the response size limit",
                    code="payload_too_large",
                )
            if used_blob_bytes + blob_bytes > byte_limit:
                if page_bytes is None:
                    raise ApiError(
                        status_code=413,
                        detail="note page exceeds the response size limit; update the portal",
                        code="payload_too_large",
                    )
                more = True
                break
            selected_ids.append(note_id)
            used_blob_bytes += blob_bytes

        rows: list[TherapistNote] = []
        if selected_ids:
            rows = list(
                (
                    await session.execute(
                        select(TherapistNote)
                        .where(
                            TherapistNote.therapist_id == user.id,
                            TherapistNote.id.in_(selected_ids),
                        )
                        .order_by(TherapistNote.created_at.asc(), TherapistNote.id.asc())
                    )
                )
                .scalars()
                .all()
            )
            # Audit durability (2026-09-20 audit fix M-30, same fix as the
            # entries read): note ciphertext is now in memory, and the
            # mismatch/size checks below can raise 409 AFTER this point. The
            # audit row added above must survive those refusals — the server
            # fetched the chart either way.
            await session.commit()
            # Normal writes hold this same chart lock.  A missing/changed row
            # therefore signals a bypassed deployment invariant rather than a
            # reason to return a short page that an old client mistakes for
            # complete history.
            if {row.id for row in rows} != set(selected_ids) or sum(
                len(bytes(row.blob)) for row in rows
            ) > byte_limit:
                raise ApiError(
                    status_code=409,
                    detail="notes changed while paging; retry the request",
                    code="conflict",
                )
        # Serialize the opaque blob while the chart fence is still held.
        # Returning ORM rows and letting FastAPI/model conversion access
        # ``row.blob`` after this scope would reopen the same mutation window
        # that the metadata/blob consistency check above deliberately closes.
        out = [_note_out(row) for row in rows]
        final_revision = await _current_notes_revision(session, user.id)
        if final_revision != revision:
            raise collection_changed_error("notes", NOTES_REVISION_HEADER, final_revision)
        response.headers[NOTES_REVISION_HEADER] = str(revision)
        # Audit bookkeeping, corrected 2026-09-21 (audit A-7): the
        # after-fetch commit above only ran for pages that fetched note
        # ciphertext. An EMPTY page skips it entirely, so the audit row —
        # written unconditionally above — is persisted HERE: empty reads
        # ARE audited (the consent scope was exercised even when no rows
        # matched). Refused pages raise before any commit and stay
        # unaudited. This closes the read transaction symmetrically.
        await session.commit()
    # Modern byte-bounded pages always advance exactly by materialized rows.
    # The chart lock/mismatch check above turns a bypassed write invariant
    # into a retryable conflict instead of an ambiguous end-of-history signal.
    if more and rows:
        response.headers["X-Next-Offset"] = str(offset + len(rows))
    return out


@router.post(
    "/patients/{user_id}/notes",
    response_model=NoteOut,
    status_code=201,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(
            make_rate_limiter("therapist-notes-write", "entries_rate_limit", "entries_rate_window")
        ),
    ],
)
async def create_note(
    body: NoteCreateRequest,
    user_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    patient_id = await _note_target(session, user, user_id)
    blob = _decode_note_blob(body.blob)
    # 2026-09-26 audit (LOW, batch item b): close the read transaction the
    # pre-lock _note_target opened BEFORE queueing on the chart lock — the
    # same pooling discipline list_notes/update_note already apply; the row
    # is re-resolved under the lock below.
    await session.commit()
    async with _note_locks.hold(f"notes:{user.id}:{patient_id}"):
        existing = (
            (
                await session.execute(
                    select(TherapistNote).where(
                        TherapistNote.therapist_id == user.id,
                        TherapistNote.client_note_id == body.client_note_id,
                    )
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            # Idempotent retry of an offline queue: rewrite in place (the
            # patient's entries do the same on client_entry_id conflicts).
            # Patient-scoped (2026-09-17 audit): the idempotency key is
            # (therapist, client_note_id) — reusing an id for a DIFFERENT
            # patient must not silently rewrite the first patient's note; that
            # is a client bug and answers a conflict, loudly.
            if existing.user_id != patient_id:
                raise ApiError(
                    status_code=409,
                    detail="note id already used for another patient",
                    code="conflict",
                )
            changed = bytes(existing.blob) != blob or existing.pattern_pid != body.pattern_pid
            if changed:
                if bytes(existing.blob) != blob:
                    # Note-history parity (independent audit V-4,
                    # 2026-09-21): an idempotent RETRY arriving with
                    # different content is still a CHANGING update — the
                    # superseded blob is preserved as an immutable revision
                    # exactly like PATCH, or a retried create silently
                    # replaces history. Same AAD (client_note_id is stable).
                    session.add(
                        TherapistNoteRevision(
                            note_id=existing.id,
                            therapist_id=user.id,
                            blob=bytes(existing.blob),
                            created_at=utcnow(),
                        )
                    )
                    # 2026-09-26 audit H-6: evict beyond the per-note cap
                    # BEFORE the quota math so the chart budget sees the
                    # post-eviction history (same rule as PATCH below).
                    await _enforce_note_revision_cap(session, existing.id)
                # H-6: the quota check runs AFTER the pending revision is
                # visible, so the preserved superseded blob is counted.
                await _assert_note_quota(
                    session,
                    user.id,
                    patient_id,
                    len(blob),
                    previous_size=len(bytes(existing.blob)),
                    is_new=False,
                )
                existing.blob = blob
                existing.pattern_pid = body.pattern_pid
                existing.updated_at = utcnow()
            else:
                await _assert_note_quota(
                    session,
                    user.id,
                    patient_id,
                    len(blob),
                    previous_size=len(bytes(existing.blob)),
                    is_new=False,
                )
            row = existing
        else:
            await _assert_note_quota(session, user.id, patient_id, len(blob), is_new=True)
            row = TherapistNote(
                id=new_id(),
                therapist_id=user.id,
                user_id=patient_id,
                client_note_id=body.client_note_id,
                pattern_pid=body.pattern_pid,
                blob=blob,
            )
            session.add(row)
            changed = True
        _audit(session, user, patient_id, "write_note")
        try:
            if changed:
                # The note and global therapist marker commit together. Note
                # charts use different locks, so this must be a database-side
                # increment rather than ``user.notes_revision += 1``.
                await _increment_notes_revision(session, user)
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _is_unique_violation(exc):
                # The duplicate is the genuine idempotent-retry/conflict case
                # (the pre-check above is the fast path; the unique index on
                # (therapist, client_note_id) decides races).
                raise ApiError(
                    status_code=409, detail="note already exists", code="conflict"
                ) from exc
            if _is_fk_violation(exc):
                # L-12 (2026-09-20): the patient account was hard-deleted
                # between _note_target's consent read and this commit (the
                # deletion cascades the consent and the whole chart). The
                # note was NOT created and nothing "already exists" — 404,
                # the same flat answer an unknown pair gets, never a
                # masquerading conflict.
                raise ApiError(
                    status_code=404, detail="patient not found", code="not_found"
                ) from exc
            raise
        # A concurrent update/delete uses this same chart fence.  Refresh and
        # construct the response before opening it, so a successful write
        # cannot turn into a stale-row error (or serialize changed data) in
        # the small gap after its commit.
        await session.refresh(row)
        response = _note_out(row)
        await session.commit()
    return response


@router.patch(
    "/notes/{note_id}",
    response_model=NoteOut,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(
            make_rate_limiter("therapist-notes-update", "entries_rate_limit", "entries_rate_window")
        ),
    ],
)
async def update_note(
    body: NoteUpdateRequest,
    note_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    row = (
        (
            await session.execute(
                select(TherapistNote).where(
                    TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
                )
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ApiError(status_code=404, detail="note not found", code="not_found")
    blob = _decode_note_blob(body.blob)
    # This read establishes the chart key used for serialization; close its
    # transaction before potentially waiting behind another note update.
    await session.commit()
    async with _note_locks.hold(f"notes:{user.id}:{row.user_id}"):
        # Re-fetch under the same chart lock: another request may have
        # deleted the row while this endpoint was waiting to update it.
        row = (
            (
                await session.execute(
                    select(TherapistNote).where(
                        TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            raise ApiError(status_code=404, detail="note not found", code="not_found")
        changed = bytes(row.blob) != blob
        if changed:
            # P3 (2026-09-21): the edit history — the SUPERSEDED blob is
            # preserved as an immutable revision before the live row
            # takes the new text. Same AAD (client_note_id is stable), so
            # the portal decrypts revisions exactly like live notes.
            session.add(
                TherapistNoteRevision(
                    note_id=row.id,
                    therapist_id=user.id,
                    blob=bytes(row.blob),
                    created_at=utcnow(),
                )
            )
            # 2026-09-26 audit H-6: per-note revision cap with OLDEST
            # eviction, applied before the quota math so the chart budget
            # sees the post-eviction history (the eviction, the preserved
            # revision and the edit share this chart-lock transaction —
            # a refused quota rolls the eviction back with everything
            # else).
            await _enforce_note_revision_cap(session, row.id)
        # H-6: the quota check now counts revision rows+bytes; running it
        # after the (pending, autoflushed) revision insert means the
        # preserved superseded blob is inside the budget it must fit.
        await _assert_note_quota(
            session,
            user.id,
            row.user_id,
            len(blob),
            previous_size=len(bytes(row.blob)),
            is_new=False,
        )
        if changed:
            row.blob = blob
            row.updated_at = utcnow()
        _audit(session, user, row.user_id, "update_note")
        if changed:
            await _increment_notes_revision(session, user)
        await session.commit()
        # Keep the post-commit refresh and base64 conversion inside the same
        # chart fence as the mutation; delete_note takes this key too.
        await session.refresh(row)
        response = _note_out(row)
        await session.commit()
    return response


@router.get(
    "/notes/{note_id}/revisions",
    response_model=list[NoteRevisionOut],
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(
            make_rate_limiter("therapist-note-revisions", "read_rate_limit", "read_rate_window")
        ),
    ],
)
async def read_note_revisions(
    note_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=200),
):
    """The edit history of one of the therapist's OWN notes (P3,
    2026-09-21 — clinic readiness). Revisions are the superseded blobs,
    newest first, under the same note AAD the portal already uses for
    live notes. Ownership-scoped: another therapist's note id is the
    flat 404, and the read is audit-logged."""
    row = (
        (
            await session.execute(
                select(TherapistNote).where(
                    TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
                )
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ApiError(status_code=404, detail="note not found", code="not_found")
    revisions = (
        (
            await session.execute(
                select(TherapistNoteRevision)
                .where(
                    TherapistNoteRevision.note_id == note_id,
                    TherapistNoteRevision.therapist_id == user.id,
                )
                .order_by(TherapistNoteRevision.created_at.desc(), TherapistNoteRevision.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    _audit(session, user, row.user_id, "read_note_revisions")
    await session.commit()
    return [
        NoteRevisionOut(
            id=rev.id,
            blob=base64.b64encode(bytes(rev.blob)).decode("ascii"),
            created_at=rev.created_at,
        )
        for rev in revisions
    ]


@router.delete(
    "/notes/{note_id}",
    status_code=204,
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-notes-delete", "read_rate_limit", "read_rate_window")),
    ],
)
async def delete_note(
    note_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    # Read the chart identity first, then release the short read transaction
    # before waiting. Update/delete for one therapist+patient must use the
    # same serialization key; otherwise a delete can race an updater between
    # its locked re-fetch and commit and turn a normal stale row into a 500.
    row = (
        (
            await session.execute(
                select(TherapistNote).where(
                    TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
                )
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ApiError(status_code=404, detail="note not found", code="not_found")
    await session.commit()
    async with _note_locks.hold(f"notes:{user.id}:{row.user_id}"):
        # The row may have been removed while this delete waited behind an
        # update/delete already holding the same chart lock.
        row = (
            (
                await session.execute(
                    select(TherapistNote).where(
                        TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            raise ApiError(status_code=404, detail="note not found", code="not_found")
        patient_id = row.user_id
        await session.delete(row)
        _audit(session, user, patient_id, "delete_note")
        await _increment_notes_revision(session, user)
        await session.commit()
