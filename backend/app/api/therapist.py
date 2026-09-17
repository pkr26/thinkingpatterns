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
side cascades them away with the row).

Auditing: grant/revoke (by the patient) and every patient-data read/write
(by the therapist) append access_log rows. The patient LIST is not audited
row-by-row — it exposes only the therapist's own consent metadata — while
insights/entries/notes reads are, because those move patient content.
"""

from __future__ import annotations

import base64
import binascii
import os
from datetime import date as date_type, timedelta

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import check_keyed_limit_without_count, make_rate_limiter, record_keyed_failure
from ..deps import ApiError, get_session, require_therapist
from ..models import AccessLog, Consent, Entry, PairingCode, TherapistNote, User, new_id, utcnow
from ..schemas import (
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
    entry_out,
)
from ..security import sharing
from ..security.crypto import MIN_BLOB_SIZE
from ..security.tokens import issue_token
from ..services import threshold
from .account import _require_verifier
from .auth import SALT_BYTES, AUTH_KEY_SIZE, _auth_limiter, hash_verifier_off_loop
from .insights import _entry_dates, _latest_insight

router = APIRouter(prefix="/therapist", tags=["therapist"])

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


def access_log_prune_statement(now):
    """DELETE for audit rows past the retention window. THE one statement
    for both call sites — the opportunistic prune in POST /therapist/
    pairing-codes below and the lifespan's daily sweep (main.py): a
    steady-state deployment creates no pairing codes, so the endpoint
    alone never prunes and the table grows unbounded."""
    return delete(AccessLog).where(AccessLog.at < now - ACCESS_LOG_RETENTION)

MAX_WRAP_KEY_BLOB_BYTES = 1024  # b64 cap mirrors schemas; decoded bound

_b64_error = (binascii.Error, ValueError)


def _decode_b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except _b64_error:
        raise ApiError(
            status_code=422, detail=f"{what} must be base64", code="validation_error"
        ) from None


def _audit(session: AsyncSession, actor: User, user_id: str, action: str) -> None:
    session.add(AccessLog(actor_id=actor.id, actor_role=actor.role, user_id=user_id, action=action))


# --- registration & self ------------------------------------------------------


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("therapist-register", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def register_therapist(
    body: TherapistRegisterRequest, request: Request, session: AsyncSession = Depends(get_session)
):
    """Therapist account creation. Same key schedule and enumeration
    posture as patient registration (hash first, per-username failure
    bucket, 409 only for real conflicts) plus the sharing key material:
    a P-256 public wrap key (validated: it must actually be a P-256 SPKI
    key — a grant against a garbage key would be a grant nothing can ever
    unwrap) and the PRIVATE key as a password-encrypted blob the server
    stores but cannot open."""
    settings = request.app.state.settings
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
        Depends(make_rate_limiter("therapist-me", "read_rate_limit", "read_rate_window"))
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
    )


@router.delete(
    "/account",
    status_code=204,
    dependencies=[
        Depends(
            make_rate_limiter("therapist-account-delete", "auth_rate_limit", "auth_rate_window")
        )
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
    await _require_verifier(user, verifier, request)
    await session.execute(delete(User).where(User.id == user.id))
    await session.commit()


# --- pairing ------------------------------------------------------------------


@router.post(
    "/pairing-codes",
    response_model=PairingCodeResponse,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("pairing-create", "auth_rate_limit", "auth_rate_window"))
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
    await session.execute(access_log_prune_statement(now))
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
    except IntegrityError as exc:
        # Astronomically unlikely (fixed-window counter makes sustained
        # generation cheap to throttle); still refuse rather than retry-loop.
        await session.rollback()
        raise ApiError(
            status_code=409, detail="pairing code collision, try again", code="conflict"
        ) from exc
    return PairingCodeResponse(code=code, expires_in=PAIRING_TTL_SECONDS)


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
        Depends(make_rate_limiter("therapist-patients", "read_rate_limit", "read_rate_window"))
    ],
)
async def list_patients(
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(
            select(Consent, User)
            .join(User, Consent.user_id == User.id)
            .where(Consent.therapist_id == user.id)
            .order_by(Consent.granted_at.desc())
        )
    ).all()
    out: list[PatientOut] = []
    for consent, patient in rows:
        active = consent.status == "active"
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
            )
        )
    return out


@router.get(
    "/patients/{user_id}/insights",
    response_model=InsightsResponse,
    dependencies=[
        Depends(make_rate_limiter("therapist-insights", "read_rate_limit", "read_rate_window"))
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
    consent = await _active_consent(session, user, user_id)
    _audit(session, user, consent.user_id, "read_insights")
    rows = await _entry_dates(session, consent.user_id)
    state = threshold.evaluate(rows, request.app.state.settings.unlock_threshold_days)
    latest = await _latest_insight(session, consent.user_id, "patterns")
    await session.commit()  # the audit row
    return InsightsResponse(
        phase=state.phase.value,
        active_days=state.active_days,
        streak=state.streak,
        days_remaining=state.days_remaining,
        blob=base64.b64encode(bytes(latest.blob)).decode("ascii") if latest else None,
    )


@router.get(
    "/patients/{user_id}/entries",
    response_model=list[EntryOut],
    dependencies=[
        Depends(make_rate_limiter("therapist-entries", "read_rate_limit", "read_rate_window"))
    ],
)
async def read_patient_entries(
    user_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
    since: date_type | None = Query(default=None),
    until: date_type | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=100, ge=1, le=500),
):
    """The patient's entries, paginated, with an ``until`` bound the
    patient endpoint never needed (the drill-down fetches a pattern's
    evidence window, not the whole journal). Same wire shape and ordering
    as the patient's own list."""
    consent = await _active_consent(session, user, user_id)
    _audit(session, user, consent.user_id, "read_entries")
    query = select(Entry).where(Entry.user_id == consent.user_id)
    if since is not None:
        query = query.where(Entry.entry_date >= since)
    if until is not None:
        query = query.where(Entry.entry_date <= until)
    query = (
        query.order_by(Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await session.execute(query)).scalars().all()
    await session.commit()  # the audit row
    return [entry_out(row) for row in rows]


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


@router.get(
    "/patients/{user_id}/notes",
    response_model=list[NoteOut],
    dependencies=[
        Depends(make_rate_limiter("therapist-notes-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def list_notes(
    user_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    patient_id = await _note_target(session, user, user_id)
    _audit(session, user, patient_id, "read_notes")
    rows = (
        (
            await session.execute(
                select(TherapistNote)
                .where(TherapistNote.therapist_id == user.id, TherapistNote.user_id == patient_id)
                .order_by(TherapistNote.created_at.asc(), TherapistNote.id.asc())
            )
        )
        .scalars()
        .all()
    )
    await session.commit()  # the audit row
    return [_note_out(row) for row in rows]


@router.post(
    "/patients/{user_id}/notes",
    response_model=NoteOut,
    status_code=201,
    dependencies=[
        Depends(
            make_rate_limiter("therapist-notes-write", "entries_rate_limit", "entries_rate_window")
        )
    ],
)
async def create_note(
    body: NoteCreateRequest,
    user_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    patient_id = await _note_target(session, user, user_id)
    blob = _decode_b64(body.blob, "blob")
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
        existing.blob = blob
        existing.pattern_pid = body.pattern_pid
        existing.updated_at = utcnow()
        row = existing
    else:
        row = TherapistNote(
            id=new_id(),
            therapist_id=user.id,
            user_id=patient_id,
            client_note_id=body.client_note_id,
            pattern_pid=body.pattern_pid,
            blob=blob,
        )
        session.add(row)
    _audit(session, user, patient_id, "write_note")
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ApiError(status_code=409, detail="note already exists", code="conflict") from exc
    await session.refresh(row)
    return _note_out(row)


@router.patch(
    "/notes/{note_id}",
    response_model=NoteOut,
    dependencies=[
        Depends(
            make_rate_limiter("therapist-notes-update", "entries_rate_limit", "entries_rate_window")
        )
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
    row.blob = _decode_b64(body.blob, "blob")
    row.updated_at = utcnow()
    _audit(session, user, row.user_id, "update_note")
    await session.commit()
    await session.refresh(row)
    return _note_out(row)


@router.delete(
    "/notes/{note_id}",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("therapist-notes-delete", "read_rate_limit", "read_rate_window"))
    ],
)
async def delete_note(
    note_id: str,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        delete(TherapistNote).where(
            TherapistNote.id == note_id, TherapistNote.therapist_id == user.id
        )
    )
    if result.rowcount == 0:
        raise ApiError(status_code=404, detail="note not found", code="not_found")
    await session.commit()
