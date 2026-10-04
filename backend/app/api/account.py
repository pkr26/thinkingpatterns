"""Account management: ciphertext export, consent, and hard deletion.

Destructive and privacy-relevant operations re-authenticate: deleting the
account or enabling third-party LLM analysis requires the password-derived
verifier, so a stolen bearer token alone can neither erase a journal nor
widen its disclosure. Deletion also purges any in-memory processing-session
keys for the account.

DELETE /account takes the verifier in the X-Account-Verifier header
(preferred — a request BODY on DELETE is undefined behavior for many
clients and proxies); a JSON body is still accepted as a deprecated
fallback for older clients.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import os
from datetime import date as date_type, datetime, timezone

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import check_keyed_limit_without_count, make_rate_limiter, record_keyed_failure
from ..db import rowcount as db_rowcount
from ..deps import (
    ApiError,
    ensure_no_rekey,
    get_session,
    require_regular_user,
    require_therapist_account,
    require_user,
)
from ..locks import lifecycle_locks, sharing_locks, sharing_patient_lock_key
from ..models import (
    KEY_SCHEME_V1,
    KEY_SCHEME_V2,
    AccessLog,
    AudioAttachment,
    AuditChainState,
    Consent,
    ConsentEvent,
    Entry,
    Insight,
    Measure,
    RekeyJournal,
    TotpBackupCode,
    User,
    utcnow,
)
from ..schemas import (
    AccessLogExportRow,
    AccountDeleteRequest,
    ConsentEventOut,
    CredentialRotateRequest,
    ExportBundle,
    InsightOut,
    KeyEnvelopeUpgradeRequest,
    LlmConsentRequest,
    LlmConsentResponse,
    PasswordChangeRequest,
    PatientAccessLogOut,
    RecoveryPasswordResetRequest,
    RecoverySetupRequest,
    RecoveryStatusResponse,
    ShareRecord,
    StepUpRequest,
    StepUpResponse,
    TotpConfirmRequest,
    TotpEnableResponse,
    TotpSetupRequest,
    TotpSetupResponse,
    VoiceConsentRequest,
    VoiceConsentResponse,
    entry_out,
)
from ..security import crypto, envelope, kdf
from ..security.deletion_tombstone import new_deletion_tombstone
from ..security.enclave import zeroize
from ..security.kdf import (
    KDF_PARAMS_MIN_PBKDF2_ITERATIONS,
    KdfParamsError,
    canonical_kdf_params_json,
    parse_kdf_params_json,
    validate_kdf_params,
)
from ..security.sharing import backup_code_digest
from ..security.totp import (
    BACKUP_CODE_COUNT,
    generate_backup_code,
    generate_secret,
    otpauth_uri,
    unwrap_secret,
    verify_code,
    wrap_secret,
)
from ..services import llm, stt
from ..services.audio_store import AudioStoreError, get_audio_store_cached
from ._audit import append_access_log, parse_access_log_cursor
from ._sharing_state import (
    MAX_RETAINED_RELATIONSHIPS_PER_ACCOUNT,
    add_consent_event,
)
from .auth import (
    AUTH_KEY_SIZE,
    SALT_BYTES,
    _auth_limiter,
    auth_work_slot,
    hash_verifier_off_loop,
)
from .measures import _measure_out

logger = logging.getLogger("mindpattern.account")

router = APIRouter(prefix="/account", tags=["account"])

# Canonical home is services/llm.py (it feeds the consent-policy
# fingerprint). Re-exported here for the established account-API import
# path used by tests and any older callers.
LLM_DISCLOSURE_VERSION = llm.LLM_DISCLOSURE_VERSION
# Same standing for the voice-transcription disclosure (services/stt.py).
VOICE_DISCLOSURE_VERSION = stt.STT_DISCLOSURE_VERSION

# Export is intentionally complete rather than paginated for the user, but
# each short-lived database page must remain small.  Metadata pages permit a
# stable cursor without first loading a hundred opaque blobs; selected blob
# pages stay bounded even when an account approaches its storage quota.
EXPORT_METADATA_PAGE_SIZE = 100
EXPORT_PAGE_BLOB_BYTES = 2 * 1024 * 1024


def _export_blob_length(session: AsyncSession, column):
    """Return binary byte length using the active database dialect."""
    if session.bind.dialect.name == "postgresql":
        return func.octet_length(column)
    return func.length(column)


def _take_export_metadata_page(rows):
    """Take a byte-bounded prefix of metadata rows.

    The final element of every row is the database-measured blob size.  One
    oversized first row is still emitted: an export must never silently omit
    a valid stored item after an input limit is raised.  Current entry writes
    are below this budget, so normal pages never exercise that escape hatch.
    """
    selected: list[object] = []
    used_blob_bytes = 0
    for row in rows:
        blob_bytes = int(row[-1] or 0)
        if selected and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
            break
        selected.append(row)
        used_blob_bytes += blob_bytes
    return selected


async def _require_verifier(
    user: User,
    body_verifier: str,
    request: Request,
    session: AsyncSession | None = None,
) -> User:
    """Password-equivalent proof: scrypt(verifier) must match the stored hash.

    403, not 401: the bearer token authenticated fine — it is the
    re-authentication that failed. Clients treat 401 as "session expired,
    re-login", which would loop forever on a wrong-password answer.

    2026-09-26 audit M-B1: when the caller supplies its request session,
    the comparison runs against a FRESHLY re-read row
    (``populate_existing``), not the auth-time ORM snapshot — the app's
    sessionmaker is ``expire_on_commit=False``, so that snapshot keeps
    PRE-ROTATION salt/verifier bytes for the whole request. A credential
    rotation (or logout) that commits while this request is in flight must
    make the old verifier fail HERE instead of re-authenticating a
    mid-flight request against retired key material; the caller's own
    lifecycle fence additionally re-checks the token epoch (see each
    verifier-gated endpoint). A vanished row falls back to the snapshot
    only so the endpoint's in-fence re-read (which refuses missing
    accounts with its own flat 404) still decides the outcome — nothing
    can commit from a deleted account either way. Returns the row the
    proof was checked against so callers can reuse the fresh object.

    Pentest I-2 (2026-09-29): every verifier-gated endpoint has its OWN
    per-IP bucket, but thirteen endpoints accept this proof — a stolen
    bearer used to buy ~13 x auth_rate_limit wrong-verifier scrypt runs
    per minute from one IP by rotating endpoints. This aggregate
    per-USERNAME bucket spans them all at once. It is keyed on the
    authenticated user id (reachable only PAST a valid bearer — no
    anonymous lockout oracle, the same standing as the TOTP D-4 bucket)
    and counts only ACTUAL failures, so honest re-auth never spends it.
    The preflight check runs before the scrypt so an exhausted budget
    costs no further verifier hashing."""
    settings = request.app.state.settings
    # getattr with the documented defaults: direct-call test doubles may
    # carry partial settings objects (the require_sharing_enabled idiom).
    verifier_limit = getattr(settings, "verifier_failure_limit", 30)
    verifier_window = getattr(settings, "auth_rate_window", 60)
    verifier_fail_key = f"verifier-fail:{user.id}"
    check_keyed_limit_without_count(
        request,
        verifier_fail_key,
        verifier_limit,
        verifier_window,
    )
    target = user
    if session is not None:
        fresh = (
            (
                await session.execute(
                    select(User).where(User.id == user.id).execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if fresh is not None:
            target = fresh
    try:
        verifier_bytes = base64.b64decode(body_verifier, validate=True)
    except (binascii.Error, ValueError):
        record_keyed_failure(request, verifier_fail_key, verifier_window)
        raise ApiError(
            status_code=403, detail="invalid credentials", code="verification_failed"
        ) from None
    async with auth_work_slot(request):
        candidate = await hash_verifier_off_loop(
            verifier_bytes,
            target.scrypt_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )
    if not hmac.compare_digest(candidate, bytes(target.verifier)):
        record_keyed_failure(request, verifier_fail_key, verifier_window)
        raise ApiError(status_code=403, detail="invalid credentials", code="verification_failed")
    return target


async def _require_step_up_or_verifier(
    user: User,
    *,
    action: str,
    proof: str | None,
    verifier: str | None,
    request: Request,
    session: AsyncSession,
) -> User:
    """Authorize a sensitive action with a one-use proof or mobile fallback."""
    if isinstance(proof, str):
        request_state = getattr(request, "state", None)
        valid = await request.app.state.step_up_store.consume(
            proof,
            user_id=user.id,
            action=action,
            token_jti=getattr(request_state, "mindpattern_token_jti", None),
            token_epoch=getattr(request_state, "mindpattern_token_epoch", user.token_epoch),
        )
        if not valid:
            raise ApiError(
                status_code=403,
                detail="step-up proof is invalid, expired, or already used",
                code="step_up_invalid",
            )
        return user
    if isinstance(verifier, str):
        # Compatibility path for native clients that derive this value from
        # a password typed immediately before the action.
        return await _require_verifier(user, verifier, request, session)
    raise ApiError(
        status_code=403,
        detail="fresh authentication is required for this action",
        code="step_up_required",
    )


@router.post(
    "/step-up",
    response_model=StepUpResponse,
    dependencies=[
        Depends(make_rate_limiter("account-step-up", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def create_step_up_proof(
    body: StepUpRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
) -> StepUpResponse:
    """Exchange a fresh password proof for one action-bound, one-use proof."""
    fresh = await _require_verifier(user, body.verifier, request, session)
    request_state = getattr(request, "state", None)
    try:
        proof, expires_in = await request.app.state.step_up_store.issue(
            user_id=fresh.id,
            action=body.action,
            token_jti=getattr(request_state, "mindpattern_token_jti", None),
            token_epoch=getattr(request_state, "mindpattern_token_epoch", fresh.token_epoch),
        )
    except RuntimeError:
        raise ApiError(
            status_code=503,
            detail="step-up service is temporarily at capacity",
            code="service_unavailable",
            headers={"Retry-After": "1"},
        ) from None
    return StepUpResponse(proof=proof, action=body.action, expires_in=expires_in)


def _epoch_fence_failed(fresh: User, expected_epoch: int) -> bool:
    """2026-09-26 audit M-B1: the in-fence epoch half of the M-2 pattern.

    Every verifier-gated lifecycle endpoint captures ``user.token_epoch``
    at entry (the epoch its bearer authenticated under) and re-reads the
    row inside its fence; this predicate is the shared 401 decision. A
    logout or credential rotation that committed while the request was
    queued behind the fence must fail the request closed — a pre-rotation
    bearer+verifier pair may not finish widening disclosure or destroying
    the account, exactly like the M-2 recompute/rekey fences."""
    return fresh.token_epoch != expected_epoch


@router.get(
    "/export",
    # Dedicated tight bucket (default 5/min): one export streams up to the
    # whole per-account blob quota — far heavier than the ordinary reads
    # whose bucket it used to share.
    dependencies=[
        Depends(make_rate_limiter("account-export", "export_rate_limit", "export_rate_window"))
    ],
)
async def export_account(
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """Stream the subject's portable account data and consent/access history.

    Credential verifiers, TOTP secrets/codes, token revocations, rate-limit
    state and audit-chain integrity anchors are security/operational records,
    not portable content, and are intentionally excluded.

    The response is assembled incrementally (one entry per chunk) so a
    long journal cannot be materialized in memory as a single response
    object. The document shape IS the ExportBundle schema: the head is
    dumped from a validated ExportBundle (minus its lists) and every item
    is its EntryOut/InsightOut member model, serialized in JSON mode so
    datetimes are ISO-8601 strings ("2026-09-07T12:00:00+00:00"), never
    the str() of a datetime. The client decrypts locally with its derived
    data key — the server cannot produce plaintext exports because it
    never holds the key.
    """

    # populate_existing refreshes the identity-map object supplied by the
    # authentication dependency too. Capture authorization before any read,
    # otherwise comparing fresh.token_epoch with user.token_epoch compares
    # the refreshed value with itself after a concurrent credential change.
    expected_export_epoch = user.token_epoch
    export_jti = getattr(getattr(request, "state", None), "mindpattern_token_jti", None)

    # A slow client must never pin this request's database cursor/transaction
    # for the full download. Admission caps active exports, and each page
    # below owns a short-lived session that closes BEFORE any bytes are
    # yielded to the network.
    export_limiter: anyio.CapacityLimiter | None = getattr(
        request.app.state, "export_limiter", None
    )
    acquired_export_slot = False
    # Starlette runs a StreamingResponse's generator in a different task from
    # the endpoint.  Use an explicit borrower instead of the implicit current
    # task so the generator can reliably release the admission slot on normal
    # completion, cancellation, or a disconnected client.
    export_borrower = object()
    if export_limiter is not None:
        try:
            export_limiter.acquire_on_behalf_of_nowait(export_borrower)
            acquired_export_slot = True
        except anyio.WouldBlock:
            raise ApiError(
                status_code=503,
                detail="export service busy; retry shortly",
                code="service_unavailable",
                headers={"Retry-After": "1"},
            ) from None

    try:
        # Capture metadata and an export cutoff in one SHORT transaction.
        # Pages use received/created-at <= cutoff so newly-created rows do
        # not drift into a download that began earlier.
        cutoff = datetime.now(timezone.utc)
        fresh = (
            (
                await session.execute(
                    select(User).where(User.id == user.id).execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )
        if fresh is None or not fresh.is_active or fresh.token_epoch != expected_export_epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        if isinstance(
            export_jti, str
        ) and await request.app.state.token_revocations.is_revoked_checked(session, export_jti):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        await ensure_no_rekey(session, fresh.id)
        if (
            await session.scalar(
                select(Consent.id)
                .where(Consent.user_id == fresh.id)
                .order_by(Consent.id)
                .offset(MAX_RETAINED_RELATIONSHIPS_PER_ACCOUNT)
                .limit(1)
            )
            is not None
        ):
            raise ApiError(
                status_code=413,
                detail="retained sharing history exceeds the supported export size",
                code="payload_too_large",
            )
        # L-8 (2026-09-20): the insights section is SNAPSHOT-paginated, and
        # the snapshot of row IDS (ordered by created-at-at-cutoff for a
        # deterministic bundle) is captured here, in the same short head
        # transaction as the cutoff. A row's ``id`` never changes (recompute
        # upserts dated rows in place), but ``created_at`` DOES mutate — a
        # same-day recompute rewrites the question row's created_at past the
        # cutoff — so the old (created_at, id) keyset could move an
        # un-emitted row across/beyond the cursor and silently drop it from
        # the bundle. The snapshot membership is frozen instead: ids absent
        # from a later page (an undated row replaced by a recompute between
        # pages) abort the download, so a complete bundle never silently
        # omits that analysis. The set is small and bounded by
        # construction (2 undated rows + the 90-day dated-question window).
        insight_snapshot = list(
            (
                await session.execute(
                    select(Insight.id)
                    .where(Insight.user_id == fresh.id, Insight.created_at <= cutoff)
                    .order_by(Insight.created_at.asc(), Insight.id.asc())
                )
            )
            .scalars()
            .all()
        )
        # Sharing membership is fenced by ``consents_revision`` and walked
        # with an immutable id keyset below.  This avoids materializing a
        # patient's lifetime relationship history before the first byte.
        # Freeze the append-only audit sequence with indexed point reads.
        # The chain-state row is the append/prune lock authority, so this
        # short transaction cannot observe a torn head.  Export pages below
        # keyset each sequence exactly once and reject any un-emitted gap.
        audit_state = await session.scalar(
            select(AuditChainState)
            .where(AuditChainState.user_id == fresh.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        audit_first_seq = await session.scalar(
            select(AccessLog.chain_seq)
            .where(AccessLog.user_id == fresh.id)
            .order_by(AccessLog.chain_seq)
            .limit(1)
        )
        audit_last_seq = (
            int(audit_state.head_seq)
            if audit_state is not None and audit_first_seq is not None
            else None
        )
        if audit_first_seq is not None and (
            audit_state is None
            or audit_state.first_retained_seq is None
            or int(audit_state.first_retained_seq) != int(audit_first_seq)
        ):
            raise ApiError(
                status_code=409,
                detail="access history changed during export; retry",
                code="collection_changed",
            )
        export_settings = request.app.state.settings
        if (
            get_audio_store_cached(export_settings) is None
            and await session.scalar(
                select(AudioAttachment.id)
                .where(AudioAttachment.user_id == fresh.id, AudioAttachment.expires_at > cutoff)
                .limit(1)
            )
            is not None
        ):
            raise ApiError(
                status_code=503,
                detail="audio export storage unavailable",
                code="audio_storage_unconfigured",
            )
        head = ExportBundle(
            version=3,
            username=fresh.username,
            exported_at=cutoff,
            user_id=fresh.id,
            salt=fresh.salt,
            age_attestation_version=fresh.age_attestation_version,
            age_attested_at=fresh.age_attested_at,
            recovery_enabled=fresh.recovery_verifier is not None,
            recovery_set_at=fresh.recovery_set_at,
            recovery_scheme=(
                "v2"
                if fresh.recovery_verifier is not None and (fresh.recovery_scheme or 1) == 2
                else ("v1" if fresh.recovery_verifier is not None else None)
            ),
            # v2 key scheme (2026-09-26): the envelope travels with the
            # user's own document — export-then-delete on a v2 account
            # without it would destroy the only copy of the data key's
            # locker (the salt alone re-derives nothing under v2).
            key_scheme=fresh.key_scheme or KEY_SCHEME_V1,
            wrapped_data_key=(
                base64.b64encode(bytes(fresh.wrapped_data_key)).decode("ascii")
                if fresh.key_scheme == KEY_SCHEME_V2 and fresh.wrapped_data_key is not None
                else None
            ),
            kdf_params=parse_kdf_params_json(fresh.kdf_params),
            llm_consent=bool(fresh.llm_consent),
            llm_consent_at=fresh.llm_consent_at,
            llm_consent_disclosure=fresh.llm_consent_disclosure,
            llm_consent_policy=fresh.llm_consent_policy,
            voice_consent=bool(fresh.voice_consent),
            voice_consent_at=fresh.voice_consent_at,
            voice_consent_disclosure=fresh.voice_consent_disclosure,
            voice_consent_policy=fresh.voice_consent_policy,
            # Shares are streamed in bounded metadata pages below, just like
            # ciphertext rows.  Keeping all consent records in this header
            # used an unbounded ``.all()`` before the first response byte.
            shares=[],
            consent_events=[],
            access_log=[],
            audio=[],
            entries=[],
            insights=[],
            measures=[],
        )
        await session.commit()
    except BaseException:
        if acquired_export_slot and export_limiter is not None:
            export_limiter.release_on_behalf_of(export_borrower)
        raise

    sessionmaker = request.app.state.sessionmaker
    head_json = json.dumps(
        head.model_dump(
            mode="json",
            exclude={
                "shares",
                "consent_events",
                "access_log",
                "entries",
                "insights",
                "measures",
                "audio",
            },
        )
    )[1:-1]

    expected_export_revisions = (
        fresh.entries_revision,
        fresh.measures_revision,
        fresh.consents_revision,
    )

    async def check_export_snapshot(page_session):
        # Hold the revision authority row for this short page transaction.
        # Every collection mutation advances a column on this row, so no
        # writer can change membership between the revision check and the
        # bounded page query.
        current = (
            await page_session.execute(
                select(User)
                .where(User.id == fresh.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if current is None or not current.is_active or current.token_epoch != expected_export_epoch:
            raise ApiError(status_code=401, detail="export session retired", code="unauthorized")
        if isinstance(
            export_jti, str
        ) and await request.app.state.token_revocations.is_revoked_checked(
            page_session, export_jti
        ):
            raise ApiError(status_code=401, detail="export session retired", code="unauthorized")
        # Partial rekey batches commit before the final epoch/revision bump.
        # A journal is therefore a snapshot change even if those counters
        # still equal the header's values. Never complete a mixed-key export.
        await ensure_no_rekey(page_session, fresh.id)
        if (
            current.entries_revision,
            current.measures_revision,
            current.consents_revision,
        ) != expected_export_revisions:
            raise ApiError(
                status_code=409,
                detail="account changed during export; retry",
                code="collection_changed",
            )

    async def bundle():
        try:
            yield "{"
            yield head_json
            yield ',"shares":['
            first = True
            share_cursor = ""
            while True:
                async with sessionmaker() as page_session:
                    await check_export_snapshot(page_session)
                    share_rows = (
                        await page_session.execute(
                            select(
                                Consent.id,
                                Consent.status,
                                Consent.granted_at,
                                Consent.revoked_at,
                                Consent.therapist_id,
                                Consent.scope,
                                Consent.disclosure,
                                Consent.share_voice,
                                User.username,
                                User.display_name,
                            )
                            .join(User, Consent.therapist_id == User.id)
                            .where(
                                Consent.user_id == fresh.id,
                                Consent.id > share_cursor,
                                User.is_active.is_(True),
                            )
                            .order_by(Consent.id.asc())
                            .limit(EXPORT_METADATA_PAGE_SIZE)
                        )
                    ).all()
                    # Export policy is the same as the live sharing views:
                    # a retired therapist is no longer an exportable
                    # counterpart. Refuse the snapshot while a bounded
                    # physical purge is pending rather than silently omit a
                    # row under an unchanged patient revision. The patient
                    # row lock held by check_export_snapshot keeps purge's
                    # revision bump from crossing this final liveness probe.
                    inactive_relationship = await page_session.scalar(
                        select(Consent.id)
                        .join(User, Consent.therapist_id == User.id)
                        .where(
                            Consent.user_id == fresh.id,
                            User.is_active.is_(False),
                        )
                        .limit(1)
                    )
                    if inactive_relationship is not None:
                        raise ApiError(
                            status_code=409,
                            detail="account changed during export; retry",
                            code="collection_changed",
                        )
                    rendered = [
                        ShareRecord(
                            id=consent_id,
                            therapist_id=therapist_id,
                            therapist_username=username,
                            therapist_display_name=display_name or username,
                            status=status,
                            granted_at=granted_at,
                            revoked_at=revoked_at,
                            scope=scope,
                            disclosure=disclosure,
                            share_voice=bool(share_voice),
                        ).model_dump(mode="json")
                        for consent_id, status, granted_at, revoked_at, therapist_id, scope, disclosure, share_voice, username, display_name in share_rows
                    ]
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False
                if len(share_rows) < EXPORT_METADATA_PAGE_SIZE:
                    break
                share_cursor = share_rows[-1][0]

            yield '],"consent_events":['
            first = True
            consent_cursor: tuple | None = None
            while True:
                async with sessionmaker() as page_session:
                    await check_export_snapshot(page_session)
                    consent_query = (
                        select(ConsentEvent)
                        .where(
                            ConsentEvent.user_id == fresh.id,
                            ConsentEvent.occurred_at <= cutoff,
                        )
                        .order_by(ConsentEvent.occurred_at, ConsentEvent.id)
                        .limit(EXPORT_METADATA_PAGE_SIZE)
                    )
                    if consent_cursor is not None:
                        last_at, last_id = consent_cursor
                        consent_query = consent_query.where(
                            or_(
                                ConsentEvent.occurred_at > last_at,
                                and_(
                                    ConsentEvent.occurred_at == last_at,
                                    ConsentEvent.id > last_id,
                                ),
                            )
                        )
                    rows = (await page_session.execute(consent_query)).scalars().all()
                    rendered = [
                        ConsentEventOut(
                            id=row.id,
                            kind=row.kind,
                            action=row.action,
                            disclosure=row.disclosure,
                            policy=row.policy,
                            consent_id=row.consent_id,
                            share_voice=row.share_voice,
                            event_version=row.event_version,
                            occurred_at=row.occurred_at,
                        ).model_dump(mode="json")
                        for row in rows
                    ]
                    if rows:
                        consent_cursor = (rows[-1].occurred_at, rows[-1].id)
                if not rendered:
                    break
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False

            yield '],"access_log":['
            first = True
            audit_next_seq = int(audit_first_seq) if audit_first_seq is not None else None
            while (
                audit_next_seq is not None
                and audit_last_seq is not None
                and audit_next_seq <= audit_last_seq
            ):
                async with sessionmaker() as page_session:
                    await check_export_snapshot(page_session)
                    page_state = await page_session.scalar(
                        select(AuditChainState)
                        .where(AuditChainState.user_id == fresh.id)
                        .with_for_update()
                    )
                    if page_state is None or page_state.head_seq < audit_last_seq:
                        raise ApiError(
                            status_code=409,
                            detail="access history changed during export; retry",
                            code="collection_changed",
                        )
                    rows = (
                        (
                            await page_session.execute(
                                select(AccessLog)
                                .where(
                                    AccessLog.user_id == fresh.id,
                                    AccessLog.chain_seq >= audit_next_seq,
                                    AccessLog.chain_seq <= audit_last_seq,
                                )
                                .order_by(AccessLog.chain_seq)
                                .limit(EXPORT_METADATA_PAGE_SIZE)
                            )
                        )
                        .scalars()
                        .all()
                    )
                    expected_sequences = list(range(audit_next_seq, audit_next_seq + len(rows)))
                    if not rows or [int(row.chain_seq) for row in rows] != expected_sequences:
                        raise ApiError(
                            status_code=409,
                            detail="access history changed during export; retry",
                            code="collection_changed",
                        )
                    rendered = [
                        AccessLogExportRow(
                            id=row.id,
                            actor_id=row.actor_id,
                            actor_role=row.actor_role,
                            action=row.action,
                            at=row.at,
                            chain_seq=row.chain_seq,
                        ).model_dump(mode="json")
                        for row in rows
                    ]
                    audit_next_seq = int(rows[-1].chain_seq) + 1
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False

            yield '],"entries":['
            first = True
            # ``entry_date`` is intentionally editable.  Never keyset an
            # internal multi-page export on it: an edit between pages could
            # move one row across the cursor and make the bundle omit or
            # duplicate that entry. received_at and id are immutable.
            entry_cursor: tuple[datetime, str] | None = None
            while True:
                # Entry mutations and account deletion take this same fence.
                # Keep it only across the metadata/blob reads, never network
                # output, so a concurrent write cannot grow a selected page
                # after its size check on the supported single-process
                # topology.
                async with lifecycle_locks.hold(f"llm-lifecycle:{fresh.id}"):
                    async with sessionmaker() as page_session:
                        await check_export_snapshot(page_session)
                        # Fetch only ids, order keys, and DB-measured byte
                        # sizes first.  A 100-row page of 1 MiB entries used
                        # to load ~100 MiB into memory before streaming
                        # started.
                        query = (
                            select(
                                Entry.id,
                                Entry.entry_date,
                                Entry.received_at,
                                _export_blob_length(page_session, Entry.blob).label("size"),
                            )
                            .where(Entry.user_id == fresh.id, Entry.received_at <= cutoff)
                            .order_by(Entry.received_at.asc(), Entry.id.asc())
                            .limit(EXPORT_METADATA_PAGE_SIZE)
                        )
                        if entry_cursor is not None:
                            last_received, last_id = entry_cursor
                            query = query.where(
                                or_(
                                    Entry.received_at > last_received,
                                    and_(
                                        Entry.received_at == last_received,
                                        Entry.id > last_id,
                                    ),
                                )
                            )
                        metadata_rows = (await page_session.execute(query)).all()
                        selected = _take_export_metadata_page(metadata_rows)
                        rendered = []
                        used_blob_bytes = 0
                        last_processed = None
                        # Wave 4 (2026-09-30): fetch selected blobs in ONE
                        # batched IN query per metadata page (the per-row
                        # SELECT made a 10k-entry export 10k round trips).
                        # The byte budget still admits rows one at a time in
                        # the server's stable (received_at, id) order; rows
                        # beyond the page budget stay for the next page.
                        by_id: dict = {}
                        if selected:
                            rows_page = (
                                (
                                    await page_session.execute(
                                        select(Entry).where(
                                            Entry.user_id == fresh.id,
                                            Entry.id.in_([m[0] for m in selected]),
                                        )
                                    )
                                )
                                .scalars()
                                .all()
                            )
                            for row in rows_page:
                                by_id[row.id] = row
                        for metadata in selected:
                            row = by_id.get(metadata[0])
                            if row is None:
                                raise ApiError(
                                    status_code=409,
                                    detail="record disappeared during export; retry",
                                    code="collection_changed",
                                )
                            blob_bytes = len(bytes(row.blob))
                            if rendered and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
                                break
                            rendered.append(entry_out(row).model_dump(mode="json"))
                            used_blob_bytes += blob_bytes
                            last_processed = metadata
                        for row in by_id.values():
                            page_session.expunge(row)
                        if last_processed is not None:
                            entry_cursor = (last_processed[2], last_processed[0])
                if not rendered:
                    if metadata_rows:
                        continue
                    break
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False

            yield '],"insights":['
            first = True
            # Snapshot-driven pages (L-8, see the head): walk the frozen id
            # list with a pending-tail cursor instead of a (created_at, id)
            # keyset, so a recompute between pages can never move an
            # un-emitted row past the cursor and drop it from the bundle.
            pending_ids = list(insight_snapshot)
            while pending_ids:
                chunk_ids = pending_ids[:EXPORT_METADATA_PAGE_SIZE]
                rendered = []
                # Recompute holds the lifecycle fence while it replaces
                # insights.  Taking it here provides the same size stability
                # as entries without pinning it across a slow download.
                async with lifecycle_locks.hold(f"llm-lifecycle:{fresh.id}"):
                    async with sessionmaker() as page_session:
                        await check_export_snapshot(page_session)
                        sizes = {
                            row_id: int(size or 0)
                            for row_id, size in (
                                await page_session.execute(
                                    select(
                                        Insight.id,
                                        _export_blob_length(page_session, Insight.blob).label(
                                            "size"
                                        ),
                                    ).where(Insight.user_id == fresh.id, Insight.id.in_(chunk_ids))
                                )
                            ).all()
                        }
                        if set(sizes) != set(chunk_ids):
                            raise ApiError(
                                status_code=409,
                                detail="analysis changed during export; retry",
                                code="collection_changed",
                            )
                        # SQL IN has no order guarantee: restore the frozen
                        # snapshot order so the byte bound consumes rows in
                        # the bundle's deterministic sequence and the
                        # pending-tail cursor below advances over the SAME
                        # sequence.
                        ordered_meta = [(row_id, sizes[row_id]) for row_id in chunk_ids]
                        selected = _take_export_metadata_page(ordered_meta)
                        used_blob_bytes = 0
                        position_by_id = {row_id: pos for pos, row_id in enumerate(chunk_ids)}
                        processed_pos = -1
                        # Wave 4 (2026-09-30): ONE batched IN fetch for the
                        # selected rows (was a per-row SELECT round trip);
                        # the ordered consumption below is unchanged.
                        selected_rows: dict = {}
                        if selected:
                            for row in (
                                (
                                    await page_session.execute(
                                        select(Insight).where(
                                            Insight.user_id == fresh.id,
                                            Insight.id.in_([m[0] for m in selected]),
                                        )
                                    )
                                )
                                .scalars()
                                .all()
                            ):
                                selected_rows[row.id] = row
                        for metadata in selected:
                            row = selected_rows.get(metadata[0])
                            if row is None or row.created_at > cutoff:
                                raise ApiError(
                                    status_code=409,
                                    detail="analysis changed during export; retry",
                                    code="collection_changed",
                                )
                            blob_bytes = len(bytes(row.blob))
                            if rendered and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
                                break
                            rendered.append(
                                InsightOut(
                                    kind=row.kind,
                                    for_date=row.for_date,
                                    blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
                                    created_at=row.created_at,
                                    # Legacy rows pre-date the column;
                                    # the additive contract defaults them.
                                    state_seq=row.state_seq or 0,
                                ).model_dump(mode="json")
                            )
                            used_blob_bytes += blob_bytes
                            processed_pos = position_by_id[metadata[0]]
                        for row in selected_rows.values():
                            page_session.expunge(row)
                        # Consume the chunk through the last row the blob
                        # loop actually emitted — a row the byte bound stopped BEFORE
                        # stays pending and is re-fetched on the next short
                        # page, exactly like the entries cursor's
                        # last_processed.
                        # 2026-09-21 audit A-2: the processed branch used to
                        # replace pending_ids with the chunk tail ALONE,
                        # silently discarding every id queued past the first
                        # EXPORT_METADATA_PAGE_SIZE rows — latent at ~93
                        # insight rows max today, a live GDPR truncation the
                        # moment retention or page size grows past one chunk.
                        if processed_pos >= 0:
                            pending_ids = (
                                chunk_ids[processed_pos + 1 :] + pending_ids[len(chunk_ids) :]
                            )
                        else:
                            pending_ids = pending_ids[len(chunk_ids) :]
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False

            yield '],"measures":['
            first = True
            # H-3 (2026-09-20): stream every Measure row — the export used to
            # omit them entirely, so export-then-delete permanently lost the
            # account's whole PHQ-9 history. Same byte-bounded keyset pattern
            # as entries; the cursor rides (measure_date, id) because both are
            # IMMUTABLE (measures have no update path; only account deletion
            # — which holds this same lifecycle fence — removes rows), and
            # the pair walks the ix_measures_user_date index.
            measure_cursor: tuple[date_type, str] | None = None
            while True:
                async with lifecycle_locks.hold(f"llm-lifecycle:{fresh.id}"):
                    async with sessionmaker() as page_session:
                        await check_export_snapshot(page_session)
                        query = (
                            select(
                                Measure.id,
                                Measure.measure_date,
                                Measure.received_at,
                                _export_blob_length(page_session, Measure.blob).label("size"),
                            )
                            .where(Measure.user_id == fresh.id, Measure.received_at <= cutoff)
                            .order_by(Measure.measure_date.asc(), Measure.id.asc())
                            .limit(EXPORT_METADATA_PAGE_SIZE)
                        )
                        if measure_cursor is not None:
                            last_date, last_id = measure_cursor
                            query = query.where(
                                or_(
                                    Measure.measure_date > last_date,
                                    and_(Measure.measure_date == last_date, Measure.id > last_id),
                                )
                            )
                        metadata_rows = (await page_session.execute(query)).all()
                        selected = _take_export_metadata_page(metadata_rows)
                        rendered = []
                        used_blob_bytes = 0
                        last_processed = None
                        # Wave 4: ONE batched IN fetch per metadata page.
                        measure_rows: dict = {}
                        if selected:
                            for row in (
                                (
                                    await page_session.execute(
                                        select(Measure).where(
                                            Measure.user_id == fresh.id,
                                            Measure.id.in_([m[0] for m in selected]),
                                        )
                                    )
                                )
                                .scalars()
                                .all()
                            ):
                                measure_rows[row.id] = row
                        for metadata in selected:
                            row = measure_rows.get(metadata[0])
                            if row is None:
                                raise ApiError(
                                    status_code=409,
                                    detail="record disappeared during export; retry",
                                    code="collection_changed",
                                )
                            blob_bytes = len(bytes(row.blob))
                            if rendered and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
                                break
                            rendered.append(_measure_out(row).model_dump(mode="json"))
                            used_blob_bytes += blob_bytes
                            last_processed = metadata
                        for row in measure_rows.values():
                            page_session.expunge(row)
                        if last_processed is not None:
                            measure_cursor = (last_processed[1], last_processed[0])
                if not rendered:
                    if metadata_rows:
                        continue
                    break
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False
            # Kept voice recordings (2026-09-29 deep audit, LOW→fixed):
            # the export used to omit every kept AudioAttachment — the
            # recordings were destroyed with the account with no
            # self-service way to take them along (GDPR Art. 20 gap).
            # Metadata pages read under the lifecycle fence; the OBJECT
            # fetches happen OUTSIDE it (never hold the fence across
            # network I/O — same rule as F2): an object erased between
            # listing and fetch is skipped, honestly.
            yield '],"audio":['
            first = True
            # getattr: the export's own test doubles carry partial app
            # state (the require_sharing_enabled idiom, line ~184) — no
            # settings means no audio store, and the section is empty.
            export_settings = getattr(request.app.state, "settings", None)
            audio_store = (
                get_audio_store_cached(export_settings) if export_settings is not None else None
            )
            audio_cursor: tuple | None = None
            if audio_store is not None and export_settings is not None:
                while True:
                    page_meta: list[dict] = []
                    async with lifecycle_locks.hold(f"llm-lifecycle:{fresh.id}"):
                        async with sessionmaker() as page_session:
                            await check_export_snapshot(page_session)
                            query = (
                                select(
                                    AudioAttachment.id,
                                    AudioAttachment.client_entry_id,
                                    AudioAttachment.mime_type,
                                    AudioAttachment.duration_seconds,
                                    AudioAttachment.size_bytes,
                                    AudioAttachment.expires_at,
                                    AudioAttachment.created_at,
                                    AudioAttachment.storage_key,
                                    AudioAttachment.backend,
                                    AudioAttachment.storage_locator,
                                    AudioAttachment.content_version,
                                )
                                .where(
                                    AudioAttachment.user_id == fresh.id,
                                    AudioAttachment.created_at <= cutoff,
                                    AudioAttachment.expires_at > cutoff,
                                )
                                .order_by(
                                    AudioAttachment.created_at.asc(),
                                    AudioAttachment.id.asc(),
                                )
                                .limit(EXPORT_METADATA_PAGE_SIZE)
                            )
                            if audio_cursor is not None:
                                last_created, last_id = audio_cursor
                                query = query.where(
                                    or_(
                                        AudioAttachment.created_at > last_created,
                                        and_(
                                            AudioAttachment.created_at == last_created,
                                            AudioAttachment.id > last_id,
                                        ),
                                    )
                                )
                            meta_rows = (await page_session.execute(query)).all()
                            page_meta = [row._asdict() for row in meta_rows]
                            if page_meta:
                                last = page_meta[-1]
                                audio_cursor = (last["created_at"], last["id"])
                    if not page_meta:
                        break
                    for meta in page_meta:
                        key = meta.pop("storage_key")
                        try:
                            from types import SimpleNamespace

                            from ..services.audio_store import store_for_object

                            source_store = store_for_object(
                                export_settings, SimpleNamespace(**meta)
                            )
                            blob = await source_store.get(
                                key, max_bytes=export_settings.audio_max_body_bytes
                            )
                        except AudioStoreError:
                            raise ApiError(
                                status_code=503,
                                detail="audio export is incomplete; retry",
                                code="audio_storage_failed",
                            ) from None
                        yield ("" if first else ",") + json.dumps(
                            {
                                **{
                                    k: v
                                    for k, v in meta.items()
                                    if k not in {"backend", "storage_locator"}
                                },
                                "blob": base64.b64encode(blob).decode("ascii"),
                            },
                            default=str,
                        )
                        first = False
            async with sessionmaker() as final_session:
                await check_export_snapshot(final_session)
            yield "]}"
        finally:
            if acquired_export_slot and export_limiter is not None:
                export_limiter.release_on_behalf_of(export_borrower)

    return StreamingResponse(bundle(), media_type="application/json")


def _consent_response(user: User, settings) -> LlmConsentResponse:
    """Consent record plus whether it authorizes the live provider policy."""
    return LlmConsentResponse(
        enabled=bool(user.llm_consent),
        active_for_current_policy=llm.consent_is_current(user, settings),
        llm_consent_at=user.llm_consent_at,
        llm_consent_disclosure=user.llm_consent_disclosure,
        llm_consent_policy=user.llm_consent_policy,
    )


@router.put(
    "/credential",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-credential", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def rotate_credential(
    body: CredentialRotateRequest,
    request: Request,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Legacy credential-only swaps are unsafe for both encrypted account roles."""
    if user.key_scheme == KEY_SCHEME_V2:
        raise ApiError(
            status_code=409,
            detail="use the atomic envelope password endpoint",
            code="key_scheme_conflict",
        )
    raise ApiError(
        status_code=409,
        detail="upgrade the client to atomically rotate keys and credentials",
        code="upgrade_required",
    )


# --- key-recovery envelope (wave 3, 2026-09-30) -----------------------------------
#
# A forgotten password destroys a zero-knowledge journal by design; the
# opt-in recovery envelope is the honest escape hatch: a random user-held
# 32-byte key whose scrypt verifier lives here, beside a CLIENT-SEALED
# copy of the data key only that key opens. The server can neither open
# the data-key copy nor reconstruct the recovery key.


@router.get(
    "/recovery",
    response_model=RecoveryStatusResponse,
    dependencies=[
        Depends(make_rate_limiter("account-recovery-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_recovery_status(
    user: User = Depends(require_regular_user),
) -> RecoveryStatusResponse:
    """Whether a recovery kit exists (never any secret material)."""
    return RecoveryStatusResponse(
        enabled=user.recovery_verifier is not None,
        set_at=user.recovery_set_at,
        scheme="v2" if (user.recovery_scheme or 1) == 2 else "v1",
    )


@router.put(
    "/recovery",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-recovery", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def set_recovery_envelope(
    body: RecoverySetupRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """Create or replace the recovery envelope (password re-auth required).

    The scrypt verifier is computed server-side from the transmitted
    verifier and never stored in the clear. 2026-10-01 audit C1: with
    scheme="v2" the verifier is domain-separated HKDF material — unlike a
    login verifier (which decrypts nothing), the legacy v1 recovery key
    WAS also the seal KEK input, so a server that observed it could open
    the sealed data key; v2 kits close that hole (the server can neither
    open the data-key copy nor derive anything that can). A replacement
    rotates the previous kit off: the OLD recovery key stops working the
    moment this returns.
    """
    if body.scheme != "v2":
        raise ApiError(
            status_code=409,
            detail="legacy recovery setup is retired; create a v2 recovery kit",
            code="upgrade_required",
        )
    expected_epoch = user.token_epoch
    await _require_verifier(user, body.password_verifier, request, session)
    try:
        recovery_key = base64.b64decode(body.verifier, validate=True)
        wrapped_key = base64.b64decode(body.wrapped_key, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422,
            detail="verifier and wrapped_key must be base64",
            code="validation_error",
        ) from None
    if len(recovery_key) != 32:
        raise ApiError(
            status_code=422, detail="verifier must be exactly 32 bytes", code="validation_error"
        )
    if len(wrapped_key) != envelope.WRAPPED_DATA_KEY_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrapped_key must be exactly {envelope.WRAPPED_DATA_KEY_BYTES} bytes",
            code="validation_error",
        )
    scrypt_salt = os.urandom(16)
    async with auth_work_slot(request):
        recovery_hash = await hash_verifier_off_loop(
            recovery_key,
            scrypt_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        fresh.recovery_salt = scrypt_salt
        fresh.recovery_verifier = recovery_hash
        fresh.recovery_wrapped_data_key = wrapped_key
        fresh.recovery_set_at = utcnow()
        # 2026-10-01 audit C1: record the verifier/seal scheme. v2 = the
        # transmitted verifier is domain-separated HKDF material that can
        # open nothing; v1 = the legacy raw-key kit (kept verifiable).
        fresh.recovery_scheme = 2 if body.scheme == "v2" else 1
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="recovery_kit_created",
        )
        await session.commit()


@router.delete(
    "/recovery",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-recovery", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def clear_recovery_envelope(
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    verifier: str = Header(default=None),
):
    """Disable the recovery kit (password re-auth required).

    From this moment the account is again recoverable ONLY by password —
    the honest trade-off the confirmation copy states.
    """

    # Header-shaped proof (mirrors DELETE /account): require the verifier.
    if not verifier:
        raise ApiError(status_code=422, detail="verifier header required", code="validation_error")
    expected_epoch = user.token_epoch
    await _require_verifier(user, verifier, request, session)
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        fresh.recovery_salt = None
        fresh.recovery_verifier = None
        fresh.recovery_wrapped_data_key = None
        fresh.recovery_set_at = None
        fresh.recovery_scheme = None
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="recovery_kit_removed",
        )
        await session.commit()


@router.put(
    "/recovery/password",
    status_code=204,
    dependencies=[
        Depends(
            make_rate_limiter("account-recovery-password", "auth_rate_limit", "auth_rate_window")
        )
    ],
)
async def reset_password_with_recovery_key(
    body: RecoveryPasswordResetRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_processing_token: str | None = Header(default=None),
):
    """Set a brand-new password, proven by the RECOVERY key (wave 3).

    The user forgot the password — the old-password verifier proof of
    PUT /account/password is impossible by definition, so the proof here
    is knowledge of the recovery key (scrypt against the stored recovery
    verifier). Everything else is the SAME contract as the password
    change: one atomic swap of salt + scrypt verifier + data-key envelope,
    the X-Processing-Token possession probe (the popped key must
    authenticate stored ciphertext, so a stolen recovery session can
    never replace the envelope with garbage), the lifecycle fence with
    the in-fence epoch re-read, a token-epoch bump, and a processing-key
    purge. The recovery kit itself stays valid (the data key it seals did
    not change).
    """
    try:
        recovery_key = base64.b64decode(body.proof, validate=True)
        new_salt_bytes = base64.b64decode(body.new_salt, validate=True)
        new_verifier_bytes = base64.b64decode(body.new_verifier, validate=True)
        wrapped_key_bytes = base64.b64decode(body.wrapped_data_key, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422,
            detail="proof, new_salt, new_verifier and wrapped_data_key must be base64",
            code="validation_error",
        ) from None
    if len(recovery_key) != 32:
        raise ApiError(
            status_code=422, detail="proof must be exactly 32 bytes", code="validation_error"
        )
    if len(new_salt_bytes) != SALT_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"new_salt must be exactly {SALT_BYTES} bytes",
            code="validation_error",
        )
    if len(new_verifier_bytes) != AUTH_KEY_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"new_verifier must be {AUTH_KEY_SIZE} bytes",
            code="validation_error",
        )
    if len(wrapped_key_bytes) != envelope.WRAPPED_DATA_KEY_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrapped_data_key must be exactly {envelope.WRAPPED_DATA_KEY_BYTES} bytes",
            code="validation_error",
        )
    if user.recovery_verifier is None or user.recovery_salt is None:
        raise ApiError(
            status_code=409,
            detail="no recovery kit on this account",
            code="recovery_not_configured",
        )
    expected_epoch = user.token_epoch
    expected_recovery_verifier = bytes(user.recovery_verifier)
    expected_recovery_scheme = user.recovery_scheme
    # Recovery-key proof (off the event loop, same limiter as login).
    recovery_salt = bytes(user.recovery_salt)
    async with auth_work_slot(request):
        candidate = await hash_verifier_off_loop(
            recovery_key,
            recovery_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )
    if not hmac.compare_digest(candidate, expected_recovery_verifier):
        raise ApiError(status_code=401, detail="invalid credentials", code="invalid_credentials")
    # kdf_params: same canonicalization contract as the password change.
    if body.new_kdf_params is not None:
        try:
            canonical_params = validate_kdf_params(
                body.new_kdf_params, min_pbkdf2_iterations=KDF_PARAMS_MIN_PBKDF2_ITERATIONS
            )
        except KdfParamsError as exc:
            raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
        params_json = canonical_kdf_params_json(canonical_params)
    elif user.kdf_params:
        stored_params = parse_kdf_params_json(user.kdf_params)
        if stored_params is None:
            raise ApiError(
                status_code=409,
                detail="stored kdf_params are invalid; contact the operator",
                code="envelope_key_mismatch",
            )
        params_json = canonical_kdf_params_json(stored_params)
    else:
        params_json = canonical_kdf_params_json(kdf.KDF_PARAMS_DEFAULT)
    scrypt_server_salt = os.urandom(16)
    async with auth_work_slot(request):
        new_verifier_hash = await hash_verifier_off_loop(
            new_verifier_bytes,
            scrypt_server_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )
    if not x_processing_token:
        raise ApiError(
            status_code=422,
            detail="processing session token required (X-Processing-Token)",
            code="processing_session_required",
        )
    from .insights import KeyNotFound

    try:
        candidate_key = request.app.state.key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None
    try:
        async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
            fresh = (
                (
                    await session.execute(
                        select(User)
                        .where(User.id == user.id)
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .first()
            )
            if fresh is None or not fresh.is_active:
                raise ApiError(status_code=404, detail="account not found", code="not_found")
            if fresh.token_epoch != expected_epoch:
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            if (
                fresh.recovery_verifier is None
                or fresh.recovery_salt is None
                or bytes(fresh.recovery_verifier) != expected_recovery_verifier
                or bytes(fresh.recovery_salt) != recovery_salt
                or fresh.recovery_scheme != expected_recovery_scheme
            ):
                raise ApiError(
                    status_code=401, detail="invalid credentials", code="invalid_credentials"
                )
            # Possession probe — the SAME contract as PUT /account/password
            # (entry AAD first, insight fallback, vacuous on an empty
            # corpus), run off the loop via the shared helper.
            proved = await _prove_current_data_key(
                session, fresh, candidate_key, request.app.state.settings
            )
            if not proved:
                raise ApiError(
                    status_code=403,
                    detail=(
                        "the processing session's key did not authenticate stored "
                        "ciphertext; open a session with the account's current data key"
                    ),
                    code="envelope_key_mismatch",
                )
            await session.execute(
                update(User)
                .where(User.id == fresh.id)
                .values(
                    salt=base64.b64encode(new_salt_bytes).decode("ascii"),
                    verifier=new_verifier_hash,
                    scrypt_salt=scrypt_server_salt,
                    token_epoch=User.token_epoch + 1,
                    key_scheme=KEY_SCHEME_V2,
                    wrapped_data_key=wrapped_key_bytes,
                    kdf_params=params_json,
                )
            )
            await append_access_log(
                session,
                actor_id=fresh.id,
                actor_role=fresh.role,
                user_id=fresh.id,
                action="password_reset_via_recovery",
            )
            await session.commit()
            request.app.state.key_store.destroy_all_for_owner(fresh.id)
    finally:
        zeroize(candidate_key)


@router.put(
    "/password",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-password", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def change_password(
    body: PasswordChangeRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_processing_token: str | None = Header(default=None),
):
    """Change the password WITHOUT re-encrypting anything (v2, 2026-09-26).

    The client unwraps its random data key locally with the OLD password,
    derives a fresh salt (and optionally fresh kdf_params) from the NEW
    password, re-wraps the SAME data key, and uploads one payload; this
    endpoint swaps salt + scrypt verifier + envelope in ONE transaction.
    NO rekey of the corpus happens and none is needed — every stored blob
    and every therapist consent wrap keeps opening under the same random
    data key, which is the entire point of the v2 envelope (a v1 password
    change is O(corpus): rekey first, then PUT /account/credential).

    Same guards as the credential rotation it supersedes for v2 accounts:
    old-password verifier proof (a stolen bearer must not lock the real
    user out), the lifecycle fence with an in-fence epoch re-read (M-B1),
    a token-epoch bump on success (every bearer dies — the LOGIN
    credential changed), and a processing-key purge.

    v1→v2 migration via this endpoint (re-audit, 2026-09-27): the uploaded
    envelope MUST wrap the account's CURRENT data key, and the server
    cannot tell that from any 32 bytes — a buggy client uploading an
    envelope over the wrong key would brick every future unlock. Every
    caller therefore MUST send X-Processing-Token (a live owner-bound
    processing session opened with the current data key) and the popped
    key must AUTHENTICATE stored ciphertext — the same possession probe
    as /account/key-envelope/upgrade — before the swap. Wrong key: 403
    envelope_key_mismatch, and the account keeps its previous envelope.
    An empty corpus proves nothing by decrypting, so possession is vacuous
    and the change proceeds (the client holds the only key that will ever
    have wrapped anything).

    2026-09-28 audit (M-1): the probe is required for v2→v2 changes too.
    The old exemption argued the client "proved it holds the key by
    unwrapping under the old password" — but the unwrap is client-side
    and invisible to the server; the verifier proves the AUTH credential,
    not the data key. That is exactly why /key-envelope/upgrade demands
    the probe on every envelope replacement, and why this channel must
    not disagree: with only a stolen bearer + phished verifier, an
    attacker could PUT a random 60-byte blob and permanently destroy the
    only copy of the data key's locker. The client already holds the
    unwrapped key (it just opened it to re-wrap), so the honest flow pays
    one extra POST /processing/sessions — no corpus walk is implied.
    """
    expected_epoch = user.token_epoch
    await _require_verifier(user, body.verifier, request, session)
    try:
        new_salt_bytes = base64.b64decode(body.new_salt, validate=True)
        new_verifier_bytes = base64.b64decode(body.new_verifier, validate=True)
        wrapped_key_bytes = base64.b64decode(body.wrapped_data_key, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422,
            detail="new_salt, new_verifier and wrapped_data_key must be base64",
            code="validation_error",
        ) from None
    if len(new_salt_bytes) != SALT_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"new_salt must be exactly {SALT_BYTES} bytes",
            code="validation_error",
        )
    if len(new_verifier_bytes) != AUTH_KEY_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"new_verifier must be {AUTH_KEY_SIZE} bytes",
            code="validation_error",
        )
    if len(wrapped_key_bytes) != envelope.WRAPPED_DATA_KEY_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrapped_data_key must be exactly {envelope.WRAPPED_DATA_KEY_BYTES} bytes",
            code="validation_error",
        )
    # kdf_params: explicit blob (validated + canonicalized) or keep the
    # account's current one. A v1 account upgrading here without a blob
    # gets the documented default (the v1 contract's pbkdf2-600k).
    if body.new_kdf_params is not None:
        try:
            # Pentest T-2 (2026-09-29): a blob NEWLY PERSISTED by this
            # credential rotation must meet the shipped 600k contract (the
            # read floor stays lower for pre-constraint accounts).
            canonical_params = validate_kdf_params(
                body.new_kdf_params, min_pbkdf2_iterations=KDF_PARAMS_MIN_PBKDF2_ITERATIONS
            )
        except KdfParamsError as exc:
            raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
        params_json = canonical_kdf_params_json(canonical_params)
    elif user.kdf_params:
        # Independent audit 2026-09-27: re-storing the account's current
        # blob verbatim used to propagate a hand-edited or legacy-garbage
        # column into the fresh envelope row. Re-validate + canonicalize
        # first; a corrupt column fails CLOSED here (the row stays as-is,
        # the operator investigates) instead of bricking a later unlock.
        stored_params = parse_kdf_params_json(user.kdf_params)
        if stored_params is None:
            raise ApiError(
                status_code=409,
                detail="stored kdf_params are invalid; contact the operator",
                code="envelope_key_mismatch",
            )
        params_json = canonical_kdf_params_json(stored_params)
    else:
        params_json = canonical_kdf_params_json(kdf.KDF_PARAMS_DEFAULT)

    scrypt_server_salt = os.urandom(16)
    async with auth_work_slot(request):
        new_verifier_hash = await hash_verifier_off_loop(
            new_verifier_bytes,
            scrypt_server_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )

    # The client's session key is consumed ONLY after the verifier proof
    # passed — a failed proof must not burn it (the rekey endpoint's
    # discipline). pop (not peek): single-use, like every
    # processing-token consumer. Required from EVERY caller (2026-09-28
    # audit M-1): the probe below is what authorizes replacing
    # wrapped_data_key, v2→v2 included.
    candidate_key: bytearray | None = None
    if not x_processing_token:
        raise ApiError(
            status_code=422,
            detail="processing session token required (X-Processing-Token)",
            code="processing_session_required",
        )
    from .insights import KeyNotFound

    try:
        candidate_key = request.app.state.key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None
    try:
        async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
            fresh = (
                (
                    await session.execute(
                        select(User)
                        .where(User.id == user.id)
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .first()
            )
            if fresh is None or not fresh.is_active:
                raise ApiError(status_code=404, detail="account not found", code="not_found")
            if fresh.token_epoch != expected_epoch:
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            if candidate_key is not None:
                # Possession probe, identical to /key-envelope/upgrade's: one
                # stored blob must authenticate under the popped key (inside
                # the fence — entry writes and recomputes hold the same lock,
                # so the sampled row cannot be re-keyed mid-probe). Run off
                # the loop: AES-GCM is CPU work sized by the blob cap.
                proved = await _prove_current_data_key(
                    session, fresh, candidate_key, request.app.state.settings
                )
                if not proved:
                    raise ApiError(
                        status_code=403,
                        detail=(
                            "the processing session's key did not authenticate stored "
                            "ciphertext; open a session with the account's current data key"
                        ),
                        code="envelope_key_mismatch",
                    )
            await session.execute(
                update(User)
                .where(User.id == fresh.id)
                .values(
                    salt=body.new_salt,
                    verifier=new_verifier_hash,
                    scrypt_salt=scrypt_server_salt,
                    token_epoch=User.token_epoch + 1,
                    key_scheme=KEY_SCHEME_V2,
                    wrapped_data_key=wrapped_key_bytes,
                    kdf_params=params_json,
                )
            )
            await append_access_log(
                session,
                actor_id=user.id,
                actor_role=user.role,
                user_id=user.id,
                action="credential_rotated",
            )
            await session.commit()
            # The credential every live bearer authenticated under is gone: kill
            # the sessions and any resident processing keys in the same lifecycle
            # event, exactly like the v1 credential rotation.
            request.app.state.key_store.destroy_all_for_owner(fresh.id)
    finally:
        if candidate_key is not None:
            zeroize(candidate_key)


def _authenticate_blob_only(key: bytearray, blob: bytes, aad) -> bool:
    """Does this key open this blob? GCM-authenticate WITHOUT keeping the
    plaintext: the decrypted bytes are discarded into a zeroized buffer the
    moment the authentication answer exists. The possession proof for the
    envelope upgrade needs the YES/NO, never the content. (The transient
    immutable ``bytes`` AESGCM returns is the same documented GC residual
    every decrypt in this package carries; the owned buffer is scrubbed.)

    ``aad`` may be a single binding or the ordered candidate tuple the
    entry ladder uses (v2 AAD first, v1 legacy fallback) — mirrored from
    the rekey path's decrypt helper, which lives behind a deferred import
    (module-level would cycle)."""
    from ..security.enclave import SecureBuffer

    candidates = aad if isinstance(aad, tuple) else (aad,)
    for candidate in candidates:
        try:
            buf = SecureBuffer(crypto.decrypt(key, blob, candidate))
        except crypto.TamperError:
            continue
        buf.zeroize()
        return True
    return False


async def _prove_current_data_key(
    session: AsyncSession, user: User, key: bytearray, settings
) -> bool:
    """Empty means every encrypted store is empty; measures are not optional."""
    if (
        await session.scalar(
            select(RekeyJournal.id).where(RekeyJournal.user_id == user.id).limit(1)
        )
        is not None
    ):
        raise ApiError(
            status_code=409,
            detail="complete the pending key rotation first",
            code="rekey_in_progress",
        )
    entry = (
        await session.execute(
            select(Entry.client_entry_id, Entry.content_version, Entry.blob)
            .where(Entry.user_id == user.id)
            .order_by(Entry.received_at.desc(), Entry.id.desc())
            .limit(1)
        )
    ).first()
    if entry is not None:
        return await anyio.to_thread.run_sync(
            _authenticate_blob_only,
            key,
            bytes(entry[2]),
            crypto.entry_aad_candidates(user.id, entry[0], int(entry[1])),
        )
    insight = (
        await session.execute(
            select(Insight.kind, Insight.for_date, Insight.blob)
            .where(Insight.user_id == user.id)
            .limit(1)
        )
    ).first()
    if insight is not None:
        kind, for_date, blob = insight
        aad = (
            crypto.build_aad("question", user.id, for_date.isoformat())
            if kind == "question" and for_date is not None
            else crypto.build_aad("insights", user.id, kind)
        )
        return await anyio.to_thread.run_sync(_authenticate_blob_only, key, bytes(blob), aad)
    measure = (
        await session.execute(
            select(Measure.client_measure_id, Measure.blob)
            .where(Measure.user_id == user.id)
            .limit(1)
        )
    ).first()
    if measure is not None:
        return await anyio.to_thread.run_sync(
            _authenticate_blob_only,
            key,
            bytes(measure[1]),
            crypto.build_aad("measure", user.id, measure[0]),
        )
    audio = await session.scalar(
        select(AudioAttachment)
        .where(AudioAttachment.user_id == user.id, AudioAttachment.expires_at > utcnow())
        .limit(1)
    )
    if audio is not None:
        from ..services.audio_store import AudioStoreError, store_for_object

        try:
            store = store_for_object(settings, audio)
            if store is None:
                raise AudioStoreError("unconfigured")
            blob = await store.get(audio.storage_key, max_bytes=settings.audio_max_body_bytes)
        except AudioStoreError:
            raise ApiError(
                status_code=503,
                detail="audio key proof storage unavailable",
                code="audio_store_error",
            ) from None
        return await anyio.to_thread.run_sync(
            _authenticate_blob_only,
            key,
            blob,
            crypto.build_aad("audio", user.id, audio.client_entry_id, str(audio.content_version)),
        )
    return True


@router.post(
    "/key-envelope/upgrade",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-envelope", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def upgrade_key_envelope(
    body: KeyEnvelopeUpgradeRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_processing_token: str | None = Header(default=None),
    x_account_verifier: str | None = Header(default=None),
):
    """Migrate a v1 account to the v2 key envelope (self-service, 2026-09-26).

    After unlocking locally, a v1 client — which by definition holds the
    account's password-derived data key — wraps THAT key under the
    password-derived KEK and uploads the envelope. The account flips to
    key_scheme=KEY_SCHEME_V2 and future password changes become O(1); the corpus
    keeps decrypting under the same key (now random-or-derived behind an
    envelope, transparent to every read path).

    Two independent proofs, both required:
      * password re-authentication (X-Account-Verifier) — the same gate as
        every credential-adjacent lifecycle action;
      * possession of the CURRENT data key (X-Processing-Token): a live,
        owner-bound processing session whose key AUTHENTICATES stored
        ciphertext. The server otherwise cannot tell the real data key
        from any 32 bytes, and storing an envelope over the wrong key
        would brick every future unlock. An account with no stored
        ciphertext yet proves nothing by decrypting — possession is
        vacuous and the upgrade proceeds (the client is migrating before
        its first write; it still holds the same key it will use).

    Already-v2 accounts may re-upload (an envelope refresh, e.g. after a
    kdf_params change) under the same two proofs.
    """
    from .insights import KeyNotFound

    verifier = _account_verifier_from_header(x_account_verifier)
    expected_epoch = user.token_epoch
    await _require_verifier(user, verifier, request, session)
    try:
        wrapped_key_bytes = base64.b64decode(body.wrapped_data_key, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422, detail="wrapped_data_key must be base64", code="validation_error"
        ) from None
    if len(wrapped_key_bytes) != envelope.WRAPPED_DATA_KEY_BYTES:
        raise ApiError(
            status_code=422,
            detail=f"wrapped_data_key must be exactly {envelope.WRAPPED_DATA_KEY_BYTES} bytes",
            code="validation_error",
        )
    if body.kdf_params is not None:
        try:
            # Pentest T-2 (2026-09-29): same write floor as registration —
            # an upgrade may not grandfather a sub-contract cost profile.
            canonical_params = validate_kdf_params(
                body.kdf_params, min_pbkdf2_iterations=KDF_PARAMS_MIN_PBKDF2_ITERATIONS
            )
        except KdfParamsError as exc:
            raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
        params_json = canonical_kdf_params_json(canonical_params)
    elif user.kdf_params:
        # Independent audit 2026-09-27: re-storing the account's current
        # blob verbatim used to propagate a hand-edited or legacy-garbage
        # column into the fresh envelope row. Re-validate + canonicalize
        # first; a corrupt column fails CLOSED here (the row stays as-is,
        # the operator investigates) instead of bricking a later unlock.
        stored_params = parse_kdf_params_json(user.kdf_params)
        if stored_params is None:
            raise ApiError(
                status_code=409,
                detail="stored kdf_params are invalid; contact the operator",
                code="envelope_key_mismatch",
            )
        params_json = canonical_kdf_params_json(stored_params)
    else:
        params_json = canonical_kdf_params_json(kdf.KDF_PARAMS_DEFAULT)

    if not x_processing_token:
        raise ApiError(
            status_code=422,
            detail="processing session token required (X-Processing-Token)",
            code="processing_session_required",
        )
    # Verifier proof PASSED before consuming the client's uploaded key —
    # a failed proof must not burn it (the rekey endpoint's discipline).
    try:
        candidate_key = request.app.state.key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None
    try:
        async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
            fresh = (
                (
                    await session.execute(
                        select(User)
                        .where(User.id == user.id)
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .first()
            )
            if fresh is None or not fresh.is_active:
                raise ApiError(status_code=404, detail="account not found", code="not_found")
            if _epoch_fence_failed(fresh, expected_epoch):
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            # Possession probe: one stored blob must authenticate under the
            # popped key (inside the fence — entry writes and recomputes hold
            # the same lock, so the sampled row cannot be re-keyed mid-probe).
            proved = await _prove_current_data_key(
                session, fresh, candidate_key, request.app.state.settings
            )
            if not proved:
                raise ApiError(
                    status_code=403,
                    detail=(
                        "the processing session's key did not authenticate stored "
                        "ciphertext; open a session with the account's current data key"
                    ),
                    code="envelope_key_mismatch",
                )
            await session.execute(
                update(User)
                .where(User.id == fresh.id)
                .values(
                    key_scheme=KEY_SCHEME_V2,
                    wrapped_data_key=wrapped_key_bytes,
                    kdf_params=params_json,
                )
            )
            await append_access_log(
                session,
                actor_id=user.id,
                actor_role=user.role,
                user_id=user.id,
                action="key_envelope_upgrade",
            )
            await session.commit()
    finally:
        zeroize(candidate_key)


def _account_verifier_from_header(header_value: str | None) -> str:
    """X-Account-Verifier extraction with the same transport rules as the
    other verifier-gated routes (isinstance, not ``is not None``: direct
    test calls pass the Header() sentinel, not a string)."""
    verifier = header_value if isinstance(header_value, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    return verifier


@router.get(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[
        Depends(make_rate_limiter("account-consent-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_llm_consent(
    request: Request,
    user: User = Depends(require_regular_user),
) -> LlmConsentResponse:
    """Current consent state, so the client toggle reflects the account."""
    return _consent_response(user, request.app.state.settings)


ACCESS_LOG_PAGE_MAX = 200


@router.get(
    "/access-log",
    response_model=list[PatientAccessLogOut],
    dependencies=[
        Depends(make_rate_limiter("account-access-log", "read_rate_limit", "read_rate_window"))
    ],
)
async def read_own_access_log(
    request: Request,
    response: Response,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=ACCESS_LOG_PAGE_MAX),
    cursor: str | None = Query(default=None),
):
    """WHO ACCESSED MY DATA (2026-09-21 audit B-4): the patient's view of
    every audit row against their account — their own lifecycle actions
    (grant/revoke/rewrap) and every therapist read/write, newest first.

    GDPR Art. 15 parity: the access trail used to be write-only, readable
    only by manual SQL. Rows survive account deletion for the full
    retention window (that property is the trail's compliance value), so
    a deleted account's trail answers "who had access before erasure" to
    the operator, while a live account answers it to the SUBJECT here.

    Cursor-paginated (append-only DESC list): each response carries
    X-Next-Cursor while older rows remain.
    """
    from sqlalchemy import or_

    query = (
        select(AccessLog, User)
        .join(User, AccessLog.actor_id == User.id, isouter=True)
        .where(AccessLog.user_id == user.id)
        .order_by(AccessLog.at.desc(), AccessLog.id.desc())
    )
    if cursor:
        # 2026-09-26 audit item 18: tz-aware ISO-8601 + 32-hex id, or 422 —
        # a naive/date-only instant silently compared as host-local time
        # and shifted the continuation page by the host's UTC offset.
        cursor_at, cursor_id = parse_access_log_cursor(cursor)
        query = query.where(
            or_(
                AccessLog.at < cursor_at,
                (AccessLog.at == cursor_at) & (AccessLog.id < cursor_id),
            )
        )
    rows = (await session.execute(query.limit(limit + 1))).all()
    if len(rows) > limit:
        response.headers["X-Next-Cursor"] = (
            f"{rows[limit - 1][0].at.isoformat()}|{rows[limit - 1][0].id}"
        )
        rows = rows[:limit]
    return [
        PatientAccessLogOut(
            at=row.AccessLog.at,
            action=row.AccessLog.action,
            actor="self" if row.AccessLog.actor_id == user.id else "therapist",
            actor_name=(
                None
                if row.User is None or row.AccessLog.actor_id == user.id
                else (row.User.display_name or row.User.username)
            ),
        )
        for row in rows
    ]


@router.put(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[
        Depends(make_rate_limiter("account-consent", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def set_llm_consent(
    body: LlmConsentRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_step_up_proof: str | None = Header(default=None),
):
    """Explicit, re-authenticated per-user opt-in for LLM analysis.

    When the operator has configured MINDPATTERN_LLM_URL, journal text is
    only sent to that third-party endpoint for accounts with consent=True.

    Enabling also writes the Art. 7 record (timestamp + disclosure
    version); disabling clears both, so the row never claims a consent it
    no longer holds.
    """
    # Epoch BEFORE the proof (2026-09-26 audit follow-up N-2): the proof's
    # populate_existing re-read refreshes this same ORM object in place.
    expected_epoch = user.token_epoch
    await _require_step_up_or_verifier(
        user,
        action="llm_consent",
        proof=x_step_up_proof,
        verifier=body.verifier,
        request=request,
        session=session,
    )
    # M-B1 (2026-09-26): the epoch this bearer authenticated under, for the
    # in-fence re-authorization below.
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # Authentication loaded this row before re-authentication/KDF work.
        # Re-load under the same fence so a concurrent withdrawal/deletion or
        # provider-policy change cannot be decided from a stale ORM object.
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        policy = llm.processing_policy_fingerprint(request.app.state.settings)
        if body.enabled and policy is None:
            raise ApiError(
                status_code=409,
                detail="third-party analysis is not configured on this server",
                code="llm_unavailable",
            )
        if bool(fresh.llm_consent) == body.enabled and (
            not body.enabled
            or (
                fresh.llm_consent_disclosure == LLM_DISCLOSURE_VERSION
                and fresh.llm_consent_policy == policy
            )
        ):
            return _consent_response(fresh, request.app.state.settings)
        fresh.llm_consent = body.enabled
        consent_at = utcnow()
        event_disclosure = LLM_DISCLOSURE_VERSION if body.enabled else fresh.llm_consent_disclosure
        event_policy = policy if body.enabled else fresh.llm_consent_policy
        if body.enabled:
            fresh.llm_consent_at = consent_at
            fresh.llm_consent_disclosure = LLM_DISCLOSURE_VERSION
            fresh.llm_consent_policy = policy
        else:
            fresh.llm_consent_at = None
            fresh.llm_consent_disclosure = None
            fresh.llm_consent_policy = None
        session.add(fresh)
        await add_consent_event(
            session,
            ConsentEvent(
                user_id=fresh.id,
                kind="llm",
                action="granted" if body.enabled else "withdrawn",
                disclosure=event_disclosure,
                policy=event_policy,
                occurred_at=consent_at,
            ),
            permission_increasing=body.enabled,
        )
        # 2026-09-29 deep-audit MEDIUM: the most consequential privacy
        # decision in the product — journal text flowing to a third-party
        # endpoint — now leaves a tamper-evident trail row. The columns
        # above are silently REWRITTEN on every toggle, so without this
        # row a disputed withdrawal has no retained evidence at all.
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="llm_consent_on" if body.enabled else "llm_consent_off",
        )
        await session.commit()
    return _consent_response(fresh, request.app.state.settings)


def _voice_consent_response(user: User, settings) -> VoiceConsentResponse:
    """Voice consent record plus live-policy currency (same honesty as the
    LLM consent response: a stale yes must never look active)."""
    return VoiceConsentResponse(
        enabled=bool(user.voice_consent),
        active_for_current_policy=stt.consent_is_current(user, settings),
        voice_consent_at=user.voice_consent_at,
        voice_consent_disclosure=user.voice_consent_disclosure,
        voice_consent_policy=user.voice_consent_policy,
    )


@router.get(
    "/voice-consent",
    response_model=VoiceConsentResponse,
    dependencies=[
        Depends(make_rate_limiter("account-consent-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_voice_consent(
    request: Request,
    user: User = Depends(require_regular_user),
) -> VoiceConsentResponse:
    """Current voice-transcription consent state, for the client toggle."""
    return _voice_consent_response(user, request.app.state.settings)


@router.put(
    "/voice-consent",
    response_model=VoiceConsentResponse,
    dependencies=[
        Depends(make_rate_limiter("account-consent", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def set_voice_consent(
    body: VoiceConsentRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_step_up_proof: str | None = Header(default=None),
):
    """Explicit, re-authenticated per-user opt-in for voice transcription.

    When the operator has configured MINDPATTERN_STT_URL, recorded audio is
    only sent to that third-party endpoint for accounts with consent=True,
    and the audio is deleted immediately after transcription. Enabling
    writes the Art. 7 record (timestamp + disclosure version); disabling
    clears it, so the row never claims a consent it no longer holds.
    Mirrors set_llm_consent exactly (verifier proof, lifecycle fence,
    fresh re-read, policy fingerprint).
    """
    expected_epoch = user.token_epoch
    await _require_step_up_or_verifier(
        user,
        action="voice_consent",
        proof=x_step_up_proof,
        verifier=body.verifier,
        request=request,
        session=session,
    )
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        policy = stt.processing_policy_fingerprint(request.app.state.settings)
        if body.enabled and policy is None:
            raise ApiError(
                status_code=409,
                detail="voice transcription is not configured on this server",
                code="stt_unavailable",
            )
        if bool(fresh.voice_consent) == body.enabled and (
            not body.enabled
            or (
                fresh.voice_consent_disclosure == VOICE_DISCLOSURE_VERSION
                and fresh.voice_consent_policy == policy
            )
        ):
            return _voice_consent_response(fresh, request.app.state.settings)
        fresh.voice_consent = body.enabled
        consent_at = utcnow()
        event_disclosure = (
            VOICE_DISCLOSURE_VERSION if body.enabled else fresh.voice_consent_disclosure
        )
        event_policy = policy if body.enabled else fresh.voice_consent_policy
        if body.enabled:
            fresh.voice_consent_at = consent_at
            fresh.voice_consent_disclosure = VOICE_DISCLOSURE_VERSION
            fresh.voice_consent_policy = policy
        else:
            fresh.voice_consent_at = None
            fresh.voice_consent_disclosure = None
            fresh.voice_consent_policy = None
        session.add(fresh)
        await add_consent_event(
            session,
            ConsentEvent(
                user_id=fresh.id,
                kind="voice",
                action="granted" if body.enabled else "withdrawn",
                disclosure=event_disclosure,
                policy=event_policy,
                occurred_at=consent_at,
            ),
            permission_increasing=body.enabled,
        )
        # 2026-09-29 deep-audit MEDIUM: same trail-completeness fix as the
        # LLM toggle — recorded audio flowing off-server must be visible in
        # the chained, MAC-sealed history, not just in a mutable column.
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="voice_consent_on" if body.enabled else "voice_consent_off",
        )
        await session.commit()
    return _voice_consent_response(fresh, request.app.state.settings)


@router.delete(
    "",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-delete", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def delete_account(
    request: Request,
    body: AccountDeleteRequest | None = None,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
    x_step_up_proof: str | None = Header(default=None),
):
    """Immediately retire the account and enqueue bounded physical erasure.

    Requires the verifier (password proof) — a bearer token alone must not
    be able to permanently destroy a journal. In-memory processing-session
    keys for this account are wiped alongside the rows.
    """
    # Preferred transport is the header (a body on DELETE is undefined
    # behavior for many clients/proxies); the JSON body is the deprecated
    # fallback kept for older clients. (isinstance, not "is not None": called
    # directly in tests the header parameter's default is the Header()
    # sentinel, not a string.)
    header_verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    verifier = header_verifier if header_verifier is not None else (body.verifier if body else None)
    # Epoch BEFORE the proof (2026-09-26 audit follow-up N-2): the proof's
    # populate_existing re-read refreshes this same ORM object in place.
    expected_epoch = user.token_epoch
    await _require_step_up_or_verifier(
        user,
        action="account_delete",
        proof=x_step_up_proof,
        verifier=verifier,
        request=request,
        session=session,
    )
    if not user.is_active:
        raise ApiError(status_code=404, detail="account not found", code="not_found")
    # M-B1 (2026-09-26): capture the token's epoch at entry; the fences
    # below re-read the row and refuse a request whose credential was
    # rotated (or session logged out) while it waited on the locks.
    # Recompute holds the same lifecycle fence across its fresh consent read
    # and possible external dispatch. Once deletion returns, no queued or
    # in-flight recompute may newly send this account's plaintext off-server.
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # Patient-sharing reads/grants use this fence while deciding whether
        # an active consent can expose journal ciphertext. Deleting the user
        # inside it makes the account lifecycle linearize with those reads.
        async with sharing_locks.hold(sharing_patient_lock_key(user.id)):
            # M-B1 (2026-09-26): liveness AND epoch on a freshly re-read row
            # before the destructive commit — a pre-rotation bearer+verifier
            # pair queued behind these fences must not complete the deletion.
            fresh = (
                (
                    await session.execute(
                        select(User)
                        .where(User.id == user.id)
                        .execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .first()
            )
            if fresh is None or not fresh.is_active:
                raise ApiError(status_code=404, detail="account not found", code="not_found")
            if _epoch_fence_failed(fresh, expected_epoch):
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            request.app.state.key_store.destroy_all_for_owner(user.id)
            # 2026-09-26 audit item 17: a terminal audit row INSIDE the
            # deletion transaction. actor_id/user_id are deliberately
            # non-FK on AccessLog, so the row survives the cascade that
            # removes everything else — without it, hard deletion left NO
            # record that the patient (the data subject of every other row
            # in their chain) exercised the right to erasure, and the
            # retained trail ended ambiguously at the last therapist read.
            # Chained (item 16) like every audit append: it becomes the
            # patient's chain head forever after.
            await append_access_log(
                session,
                actor_id=user.id,
                actor_role=user.role,
                user_id=user.id,
                action="account_deleted",
            )
            session.add(
                new_deletion_tombstone(
                    fresh,
                    secret=request.app.state.settings.auth_token_secret,
                    auth_secret_version=request.app.state.settings.auth_secret_version,
                    now=utcnow(),
                )
            )
            from ..services.account_deletion import (
                purge_one_account_page,
                stage_account_deletion,
            )

            stage_account_deletion(session, fresh)
            await session.commit()
            # Preserve prompt hard-erasure semantics for ordinary small
            # accounts while keeping request work strictly capped. Oversized
            # accounts leave the same durable job for the background worker.
            # This uses a fresh session: rolling back the request session
            # after its terminal audit commit would suppress that committed
            # row's post-response journal flush.
            try:
                async with request.app.state.sessionmaker() as purge_session:
                    progress = await purge_one_account_page(
                        purge_session,
                        request.app.state.settings,
                        owner_id=user.id,
                    )
                    await purge_session.commit()
                request.app.state.account_deletion_backlog = progress.backlog
            except Exception:  # noqa: BLE001 - logical erasure already committed
                request.app.state.account_deletion_backlog = True
                logger.error("bounded account purge deferred to background worker")
            request.app.state.account_deletion_wakeup.set()


# --- Required therapist TOTP before patient-data access -----------------------
#
# Therapist accounts read PHI-adjacent data with a password + scrypt
# verifier and previously no second factor. Enrollment is a three-step
# contract mirroring the credential-rotation flow: (1) verifier-
# re-authenticated setup stores a PENDING wrapped secret and shows it to
# the therapist exactly once; (2) enable proves the authenticator holds it
# and arms the login check; (3) disable re-proves both halves and clears
# everything. The returned one-time backup codes are the self-service
# authenticator-loss recovery path. Patients stay password-only by design — the mobile client
# has no TOTP surface, so setup is therapist-gated and a patient token
# answers 403.


@router.post(
    "/totp/setup",
    response_model=TotpSetupResponse,
    dependencies=[
        Depends(make_rate_limiter("account-totp", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def totp_setup(
    body: TotpSetupRequest,
    request: Request,
    user: User = Depends(require_therapist_account),
    session: AsyncSession = Depends(get_session),
):
    """Arm a PENDING TOTP secret (nothing is enforced at login yet).

    The secret is returned in the clear exactly once, wrapped at rest
    immediately, and re-shown never. While an enrollment is ENABLED this
    answers 409: re-arming must go through disable, which requires a live
    code — otherwise an attacker holding only the password half could
    strip the factor by re-running setup and logging in password-only
    (the exact threat the factor exists for). A lost authenticator uses one
    of the one-time backup codes minted at enablement.
    """
    if user.totp_enabled:
        raise ApiError(
            status_code=409,
            detail="totp already enabled — disable it (code required) before re-arming",
            code="version_conflict",
        )
    # Epoch BEFORE the proof (2026-09-26 audit follow-up N-2):
    # _require_verifier's populate_existing re-read refreshes this same ORM
    # object in place, so capturing afterwards would compare the
    # post-refresh epoch against itself and fence nothing.
    expected_epoch = user.token_epoch
    await _require_verifier(user, body.verifier, request, session)
    raw_secret, secret_b32 = generate_secret()
    wrapped = wrap_secret(raw_secret, request.app.state.settings.totp_wrap_secret)
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # M-B1 (2026-09-26): re-read inside the fence; a session retired by
        # logout/rotation while this request queued must not arm a factor.
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        # One transaction: pending secret recorded, enrollment disarmed
        # until confirm, replay fence reset, audit row persisted.
        await session.execute(
            update(User)
            .where(User.id == user.id)
            .values(totp_secret=wrapped, totp_enabled=None, totp_last_counter=None)
        )
        await append_access_log(
            session,
            actor_id=user.id,
            actor_role=user.role,
            user_id=user.id,
            action="totp_setup",
        )
        await session.commit()
    return TotpSetupResponse(
        secret_base32=secret_b32,
        otpauth_uri=otpauth_uri(secret_b32, user.username),
    )


@router.post(
    "/totp/enable",
    response_model=TotpEnableResponse,
    status_code=200,
    dependencies=[
        Depends(make_rate_limiter("account-totp", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def totp_enable(
    body: TotpConfirmRequest,
    request: Request,
    user: User = Depends(require_therapist_account),
    session: AsyncSession = Depends(get_session),
):
    """Confirm enrollment by presenting a code from the PENDING secret.

    2026-09-26 pentest S-3: enabling also mints the one-time recovery-code
    set and returns it in this response — the ONLY time the codes exist in
    plaintext anywhere. The 204 this endpoint used to answer became this
    body; clients that treated 204 as success keep working (200 is also a
    success status) and simply gain the codes.
    """
    # Epoch BEFORE the proof (2026-09-26 audit follow-up N-2):
    # _require_verifier's populate_existing re-read refreshes this same ORM
    # object in place, so capturing afterwards would compare the
    # post-refresh epoch against itself and fence nothing.
    expected_epoch = user.token_epoch
    await _require_verifier(user, body.verifier, request, session)
    settings = request.app.state.settings
    secret = unwrap_secret(user.totp_secret, settings.totp_wrap_secret)
    matched = verify_code(secret, code=body.code) if secret is not None else None
    # 2026-09-28 deep audit: capture the WRAPPED secret the proof ran
    # against, BEFORE the in-fence populate_existing re-read can refresh
    # user.totp_secret in place — the guarded UPDATE's WHERE used the
    # re-bound (post-refresh) attribute, comparing the column to its own
    # current value: the guard could never fire and a concurrent re-setup
    # committed between proof and arm armed the NEW secret on a code
    # verified against the OLD one.
    verified_wrapped_secret = user.totp_secret
    if matched is None:
        raise ApiError(status_code=403, detail="invalid totp code", code="totp_code_invalid")
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # M-B1 (2026-09-26): liveness+epoch on a freshly re-read row inside
        # the fence before the guarded arm below.
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        # Guarded update: only arms when the stored secret is still the one
        # this code was checked against (a concurrent re-setup wins and
        # leaves enrollment pending for a fresh confirm).
        # 2026-09-26: db_rowcount — the established typed helper for DML
        # rowcounts (the Result stubs carry no rowcount; see app/db.py);
        # this was the one remaining raw .rowcount read and it tripped the
        # mypy gate.
        result = await session.execute(
            update(User)
            .where(User.id == user.id, User.totp_secret == verified_wrapped_secret)
            .values(totp_enabled=True, totp_last_counter=matched)
        )
        if db_rowcount(result) != 1:
            raise ApiError(
                status_code=409,
                detail="totp setup changed, confirm again",
                code="version_conflict",
            )
        # Recovery-code set (2026-09-26 pentest S-3): minted inside the
        # same fence and transaction as the arm itself, so an enabled
        # account ALWAYS has exactly one intact set. Any stale rows (a
        # disable→re-enable cycle already purges, this is belt-and-braces
        # against operator-restored snapshots) die before the insert.
        backup_codes = [generate_backup_code() for _ in range(BACKUP_CODE_COUNT)]
        await session.execute(delete(TotpBackupCode).where(TotpBackupCode.user_id == user.id))
        for code in backup_codes:
            session.add(
                TotpBackupCode(
                    user_id=user.id,
                    digest=backup_code_digest(code, settings.totp_wrap_secret),
                )
            )
        await append_access_log(
            session,
            actor_id=user.id,
            actor_role=user.role,
            user_id=user.id,
            action="totp_enable",
        )
        await session.commit()
    return TotpEnableResponse(backup_codes=backup_codes)


@router.post(
    "/totp/disable",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("account-totp", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def totp_disable(
    body: TotpConfirmRequest,
    request: Request,
    user: User = Depends(require_therapist_account),
    session: AsyncSession = Depends(get_session),
):
    """Turn TOTP off: verifier (password half) + code (authenticator half).

    Both halves on purpose: with only the verifier, a phished password
    strips the factor it exists to gate; with only the code, a stolen
    bearer plus shoulder-surfed code disarms it. A LOST authenticator is
    an operator action (clear users.totp_* by hand) — this system has no
    account recovery by design, and the registration screen says so.
    """
    if not user.totp_enabled:
        raise ApiError(status_code=404, detail="totp not enabled", code="not_found")
    # Epoch BEFORE the proof (2026-09-26 audit follow-up N-2):
    # _require_verifier's populate_existing re-read refreshes this same ORM
    # object in place, so capturing afterwards would compare the
    # post-refresh epoch against itself and fence nothing.
    expected_epoch = user.token_epoch
    await _require_verifier(user, body.verifier, request, session)
    settings = request.app.state.settings
    secret = unwrap_secret(user.totp_secret, settings.totp_wrap_secret)
    matched = verify_code(secret, code=body.code) if secret is not None else None
    # 2026-09-28 deep audit: capture the WRAPPED secret the proof ran
    # against, BEFORE the in-fence populate_existing re-read can refresh
    # user.totp_secret in place — the guarded UPDATE's WHERE used the
    # re-bound (post-refresh) attribute, comparing the column to its own
    # current value: the guard could never fire and a concurrent re-setup
    # committed between proof and arm armed the NEW secret on a code
    # verified against the OLD one.
    verified_wrapped_secret = user.totp_secret
    replayed = (
        user.totp_last_counter is not None
        and matched is not None
        and matched <= user.totp_last_counter
    )
    if matched is None or replayed:
        raise ApiError(status_code=403, detail="invalid totp code", code="totp_code_invalid")
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # M-B1 (2026-09-26): liveness+epoch on a freshly re-read row inside
        # the fence before the factor is stripped below.
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
        if _epoch_fence_failed(fresh, expected_epoch):
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        await session.execute(
            update(User)
            # 2026-09-28 deep audit: only strips the factor the code was
            # verified against — a concurrent re-setup between proof and
            # strip survives for its own fresh confirm, instead of being
            # silently wiped by this request.
            .where(User.id == user.id, User.totp_secret == verified_wrapped_secret)
            .values(totp_secret=None, totp_enabled=None, totp_last_counter=None)
        )
        # The recovery-code set dies with the factor (2026-09-26 pentest
        # S-3): leaving live single-use codes behind a disabled factor
        # would make re-enrollment's fresh set ambiguous. Same transaction.
        await session.execute(delete(TotpBackupCode).where(TotpBackupCode.user_id == user.id))
        await append_access_log(
            session,
            actor_id=user.id,
            actor_role=user.role,
            user_id=user.id,
            action="totp_disable",
        )
        await session.commit()
