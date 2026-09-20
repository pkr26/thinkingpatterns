"""Patient-side sharing: pairing lookup, consent grant/list/revoke.

The sharing model is zero-knowledge end to end:

  * The therapist's portal shows a short-lived pairing code.
  * The patient types it; lookup answers with the therapist's display name
    and P-256 public wrap key WITHOUT burning the code (the patient sees
    exactly who they are about to share with before deciding).
  * On confirm, the app wraps its data key to that public key
    (ECDH + HKDF + AES-GCM — see security/sharing.py) and the grant call
    burns the code and stores the wrap. The verifier (password proof) is
    required: a stolen bearer token must not be able to hand a journal to
    a third party, exactly like account deletion.
  * Revoke clears the wrapped key. The server cannot claw back bytes a
    browser already decrypted — the disclosure copy says so plainly — but
    every read path dies with the consent.

Enumeration posture: pairing lookup and grant answer 404 for any unknown,
expired, or consumed code — indistinguishable — and share the auth rate
bucket, so code guessing is throttled with credential guessing.
"""

from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..db import rowcount as db_rowcount
from ..deps import ApiError, get_session, require_regular_user, require_sharing_enabled
from ..locks import (
    sharing_locks,
    sharing_patient_lock_key,
    sharing_therapist_lock_key,
)
from ..models import (
    ROLE_THERAPIST,
    AccessLog,
    Consent,
    PairingCode,
    User,
    utcnow,
)
from ..schemas import (
    ConsentGrantRequest,
    ConsentOut,
    PairingLookupRequest,
    PairingLookupResponse,
)
from ..security import sharing
from ..security.crypto import MIN_BLOB_SIZE
from .account import _require_verifier

router = APIRouter(
    prefix="/consents",
    tags=["consents"],
    dependencies=[Depends(require_sharing_enabled)],
)

# Version of the sharing disclosure copy the mobile app shows before a
# grant (Art. 7 record parity with the LLM consent flow).
SHARING_DISCLOSURE_VERSION = "v1"

# The wrap of a 32-byte data key is 12 + 32 + 16 = 60 bytes; a little
# headroom for format evolution, still far below anything worth storing.
MAX_WRAPPED_KEY_BYTES = 256

# Consent metadata is deliberately available as a complete list to the
# current mobile and portal clients.  Bound both sides of the relationship so
# a compromised account cannot manufacture an unbounded list/DB scan, while a
# normal clinician still has room for a practical caseload.  Revoked rows are
# included: they carry disclosure history and therapist-note continuity, so
# counting only active rows would leave the retained-list response unbounded.
MAX_CONSENTS_PER_PATIENT = 100
MAX_PATIENTS_PER_THERAPIST = 100

_b64_error = (binascii.Error, ValueError)


def _decode_b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except _b64_error:
        raise ApiError(
            status_code=422, detail=f"{what} must be base64", code="validation_error"
        ) from None


async def _live_code(session: AsyncSession, code: str, secret: str) -> PairingCode | None:
    """The unconsumed, unexpired pairing-code row for this code, or None.
    Lookup and grant share this: both must treat unknown/expired/consumed
    identically."""
    digest = sharing.pairing_code_digest(code, secret)
    row = (
        (
            await session.execute(
                select(PairingCode)
                .where(PairingCode.code_hash == digest, PairingCode.consumed_at.is_(None))
                .order_by(PairingCode.expires_at.desc())
                .limit(1)
                # A grant can first inspect a code, wait for a sharing lock,
                # then inspect it again. Never let the identity map turn the
                # second check into a stale consumed/expired row.
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .first()
    )
    if row is None or row.expires_at <= utcnow():
        return None
    return row


async def _therapist_for_code(session: AsyncSession, code_row: PairingCode) -> User | None:
    """The live therapist account behind a pairing code. A deactivated or
    degraded therapist row answers None (404) — an expired code from a
    closed account must not route a grant at a dead target."""
    therapist = await session.get(User, code_row.therapist_id, populate_existing=True)
    if (
        therapist is None
        or not therapist.is_active
        or therapist.role != ROLE_THERAPIST
        or not therapist.wrap_pub_key
    ):
        return None
    return therapist


@router.post(
    "/pairing/lookup",
    response_model=PairingLookupResponse,
    dependencies=[
        Depends(make_rate_limiter("pairing-lookup", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def lookup_pairing(
    body: PairingLookupRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    code = sharing.normalize_pairing_code(body.code)
    code_row = await _live_code(session, code, request.app.state.settings.token_secret)
    if code_row is None:
        raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
    therapist = await _therapist_for_code(session, code_row)
    if therapist is None:
        raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
    return PairingLookupResponse(
        therapist_id=therapist.id,
        display_name=therapist.display_name or therapist.username,
        wrap_pub_key=therapist.wrap_pub_key or "",
    )


def _consent_out(consent: Consent, therapist: User) -> ConsentOut:
    return ConsentOut(
        id=consent.id,
        therapist_id=therapist.id,
        display_name=therapist.display_name or therapist.username,
        username=therapist.username,
        status=consent.status,
        granted_at=consent.granted_at,
        revoked_at=consent.revoked_at,
    )


@router.get(
    "",
    response_model=list[ConsentOut],
    dependencies=[
        Depends(make_rate_limiter("consents-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def list_consents(
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(
            select(Consent, User)
            .join(User, Consent.therapist_id == User.id)
            .where(Consent.user_id == user.id)
            .order_by(Consent.granted_at.desc())
            # Preserve the established complete-list contract.  An imported
            # or manually-created legacy account beyond the durable cap gets
            # a loud error rather than a truncated list a mobile client would
            # mistake for complete sharing state.
            .limit(MAX_CONSENTS_PER_PATIENT + 1)
        )
    ).all()
    if len(rows) > MAX_CONSENTS_PER_PATIENT:
        raise ApiError(
            status_code=413,
            detail="sharing history exceeds the supported list size",
            code="payload_too_large",
        )
    return [_consent_out(consent, therapist) for consent, therapist in rows]


@router.post(
    "",
    response_model=ConsentOut,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("consents-grant", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def grant_consent(
    body: ConsentGrantRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    # The grant widens who can read the journal — password proof required,
    # header transport preferred (same contract as DELETE /account).
    # The server, not a mutable client build, is authoritative about which
    # disclosure was current. Storing an arbitrary caller-provided string
    # made the Art. 7 record unable to prove what the patient saw.
    if body.disclosure != SHARING_DISCLOSURE_VERSION:
        raise ApiError(
            status_code=409,
            detail="sharing disclosure is outdated; refresh and review it again",
            code="disclosure_outdated",
        )
    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    await _require_verifier(user, verifier, request)

    try:
        sharing.validate_public_key_b64(body.ephemeral_pub)
    except sharing.SharingError:
        raise ApiError(
            status_code=422,
            detail="ephemeral_pub must be a P-256 SPKI key",
            code="validation_error",
        ) from None
    wrapped = _decode_b64(body.wrapped_key, "wrapped_key")
    if not MIN_BLOB_SIZE <= len(wrapped) <= MAX_WRAPPED_KEY_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrapped_key must be {MIN_BLOB_SIZE}-{MAX_WRAPPED_KEY_BYTES} bytes",
            code="validation_error",
        )

    code = sharing.normalize_pairing_code(body.code)
    code_row = await _live_code(session, code, request.app.state.settings.token_secret)
    if code_row is None:
        raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
    therapist = await _therapist_for_code(session, code_row)
    if therapist is None:
        raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
    therapist_id = therapist.id
    # Do not hold a pooled database connection while queued behind a sharing
    # fence. The row is re-read below while both relevant locks are held.
    await session.commit()

    # A grant can race a revocation or either account deletion. The fixed
    # therapist->patient order is shared with therapist reads/listing; once
    # entered, all state that authorizes this new share is freshly read.
    async with sharing_locks.hold(sharing_therapist_lock_key(therapist_id)):
        async with sharing_locks.hold(sharing_patient_lock_key(user.id)):
            code_row = await _live_code(session, code, request.app.state.settings.token_secret)
            if code_row is None:
                raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
            therapist = await _therapist_for_code(session, code_row)
            # A pruned, very old code could theoretically be re-issued after
            # the preflight query. Refuse rather than use the wrong therapist
            # lock for that new row; the flat 404 keeps code enumeration safe.
            if therapist is None or therapist.id != therapist_id:
                raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
            fresh_user = await session.get(User, user.id, populate_existing=True)
            if fresh_user is None or not fresh_user.is_active:
                raise ApiError(status_code=404, detail="account not found", code="not_found")

            existing = (
                (
                    await session.execute(
                        select(Consent)
                        .where(
                            Consent.user_id == fresh_user.id,
                            Consent.therapist_id == therapist.id,
                        )
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .first()
            )
            if existing is None:
                # These counts are inside the therapist->patient lock order,
                # so concurrent standard grants cannot race past either cap.
                # Check before consuming the single-use code: after revoking
                # an old relationship, the patient can retry the same still-
                # live code rather than asking the clinician for a new one.
                patient_count = int(
                    (
                        await session.execute(
                            select(func.count(Consent.id)).where(Consent.user_id == fresh_user.id)
                        )
                    ).scalar_one()
                )
                if patient_count >= MAX_CONSENTS_PER_PATIENT:
                    raise ApiError(
                        status_code=413,
                        detail="sharing history has reached the supported limit",
                        code="payload_too_large",
                    )
                therapist_count = int(
                    (
                        await session.execute(
                            select(func.count(Consent.id)).where(
                                Consent.therapist_id == therapist.id
                            )
                        )
                    ).scalar_one()
                )
                if therapist_count >= MAX_PATIENTS_PER_THERAPIST:
                    raise ApiError(
                        status_code=413,
                        detail="therapist caseload has reached the supported limit",
                        code="payload_too_large",
                    )

            # Burn the code atomically (2026-09-17 audit): the SELECT above
            # is a fast-path pre-check only — two concurrent grants of the
            # same code both see consumed_at IS NULL there. The conditional
            # UPDATE is the authority: exactly one redeemer's WHERE matches,
            # the loser gets the same 404 as an unknown code. Single
            # transaction with the grant below = both or neither.
            now = utcnow()
            claim = await session.execute(
                update(PairingCode)
                .where(
                    PairingCode.id == code_row.id,
                    PairingCode.consumed_at.is_(None),
                    PairingCode.expires_at > now,
                )
                .values(consumed_at=now)
            )
            if db_rowcount(claim) == 0:
                raise ApiError(status_code=404, detail="pairing code not found", code="not_found")
            if existing is not None:
                # Re-grant (after revoke, or to refresh the wrap): same pair,
                # same row — the therapist's note history survives.
                existing.status = "active"
                existing.granted_at = now
                existing.revoked_at = None
                existing.ephemeral_pub = body.ephemeral_pub
                existing.wrapped_key = wrapped
                existing.disclosure = SHARING_DISCLOSURE_VERSION
                consent = existing
            else:
                consent = Consent(
                    user_id=fresh_user.id,
                    therapist_id=therapist.id,
                    status="active",
                    granted_at=now,
                    ephemeral_pub=body.ephemeral_pub,
                    wrapped_key=wrapped,
                    disclosure=SHARING_DISCLOSURE_VERSION,
                )
                session.add(consent)
            session.add(
                AccessLog(
                    actor_id=fresh_user.id,
                    actor_role=fresh_user.role,
                    user_id=fresh_user.id,
                    action="grant",
                )
            )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                # Concurrent grants of the same pair (two tabs, same code
                # redeemed twice concurrently — the code row was selected
                # FOR-burn by both).
                raise ApiError(
                    status_code=409, detail="consent already being granted", code="conflict"
                ) from exc
            await session.refresh(consent)
            response = _consent_out(consent, therapist)
    return response


@router.delete(
    "/{consent_id}",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("consents-revoke", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def revoke_consent(
    consent_id: str,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    await _require_verifier(user, verifier, request)
    # This is the counterpart to the therapist content-read fence. It owns
    # the patient key until the cleared key material and revoked status are
    # committed, so no new read can see active consent after this returns.
    async with sharing_locks.hold(sharing_patient_lock_key(user.id)):
        fresh_user = await session.get(User, user.id, populate_existing=True)
        if fresh_user is None or not fresh_user.is_active:
            raise ApiError(status_code=404, detail="account not found", code="not_found")
        consent = (
            (
                await session.execute(
                    select(Consent)
                    .where(Consent.id == consent_id, Consent.user_id == fresh_user.id)
                    .execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if consent is None:
            raise ApiError(status_code=404, detail="consent not found", code="not_found")
        if consent.status != "revoked":
            consent.status = "revoked"
            consent.revoked_at = utcnow()
            # Nothing left to unwrap: the wrapped key and the ephemeral
            # public key are the grant's key material — cleared, not
            # archived. The caseload summary rides the same rule.
            consent.wrapped_key = None
            consent.ephemeral_pub = None
            consent.summary_blob = None
            consent.summary_eph_pub = None
            consent.summary_updated_at = None
            session.add(
                AccessLog(
                    actor_id=fresh_user.id,
                    actor_role=fresh_user.role,
                    user_id=fresh_user.id,
                    action="revoke",
                )
            )
            await session.commit()
