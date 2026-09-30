"""Voice journaling endpoints (VOICE_PLAN.md, 2026-09-29, P1).

Transcription + text translation only — attachments arrive in P2. The
privacy contract of this router, enforced here and pinned by tests:

  * The whole router is behind the fail-closed MINDPATTERN_AUDIO_ENABLED
    flag (flat 404 when off, the deps.require_sharing_enabled posture —
    a disabled deployment must not advertise that the feature exists).
  * Journal-owner accounts only: a therapist token is a 403 (the role
    gate is require_regular_user, same as /entries).
  * Every route requires a CURRENT voice-transcription consent record
    (the Art. 7 fingerprint check in services/stt.py). Consent is judged
    per-request from the live settings, so an operator policy change
    makes stale consent inert immediately.
  * Audio bytes exist in this process for the duration of one upstream
    call and are then dropped. They are never persisted, logged (only
    their decoded LENGTH is ever compared against the cap), or echoed.
  * Provider output is bounded and control-stripped in services/stt.py
    before it reaches a response.
"""

from __future__ import annotations

import base64
import binascii
import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_regular_user
from ..locks import UserLocks, lifecycle_locks
from ..models import AudioAttachment, Entry, User, utcnow
from ..schemas import (
    AudioAttachmentCreate,
    AudioAttachmentCreated,
    AudioAttachmentOut,
    AudioTranslationRequest,
    AudioTranslationResponse,
    AudioTranscriptionRequest,
    AudioTranscriptionResponse,
)
from ..security.crypto import MIN_BLOB_SIZE
from ..services import audio_store as audio_store_service
from ..services import stt
from ..services.audio_store import AudioStoreError, get_audio_store_cached
from ..services.stt import ALLOWED_AUDIO_MIMES, normalize_mime

logger = logging.getLogger("mindpattern.audio")

router = APIRouter(prefix="/audio", tags=["audio"])

# Same per-user write serialization the entries router uses: the quota
# check + upsert must not interleave with a concurrent upload for the
# same account.
_audio_locks = UserLocks()


async def require_audio_enabled(request: Request) -> None:
    """Fail closed when the voice feature is administratively off.

    Flat 404 (not a dedicated code): same reasoning as
    deps.require_sharing_enabled — do not advertise whether a sensitive
    feature is merely disabled. Clients learn availability from
    GET /meta (audio_available), never from this error.

    Wired as a SIGNATURE dependency placed after require_regular_user, so
    the wall order is authenticate → role → flag: an anonymous probe gets
    the same 401 as every other walled route (the exhaustive role-wall
    contract), and a therapist token the same 403.
    """
    if not bool(getattr(request.app.state.settings, "audio_enabled", False)):
        raise ApiError(status_code=404, detail="not found", code="not_found")


def _require_voice_consent(user: User, settings) -> None:
    if not stt.consent_is_current(user, settings):
        raise ApiError(
            status_code=403,
            detail="voice transcription consent required",
            code="voice_consent_required",
        )


def _decode_audio(value: str, settings) -> bytes:
    """base64 → bytes with the route's own decoded-size cap.

    The middleware caps the whole JSON body at
    settings.audio_max_body_bytes; this re-check on the DECODED bytes
    keeps the route honest even if a deployment ever widens the edge cap
    past what a recording may claim.
    """
    try:
        audio = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422, detail="audio must be base64", code="validation_error"
        ) from None
    if len(audio) > settings.audio_max_body_bytes:
        raise ApiError(
            status_code=413,
            detail="recording too large",
            code="audio_too_large",
        )
    return audio


@router.post(
    "/transcriptions",
    response_model=AudioTranscriptionResponse,
    dependencies=[
        Depends(
            make_rate_limiter(
                "audio-transcribe", "audio_transcribe_rate_limit", "audio_transcribe_rate_window"
            )
        ),
    ],
)
async def transcribe_recording(
    body: AudioTranscriptionRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    _flag: None = Depends(require_audio_enabled),
    session: AsyncSession = Depends(get_session),
):
    """Transcribe one recording in its spoken language, then translate.

    The response carries the original transcript, the detected language
    (ISO 639-1 when recognized, plus the raw provider string), and an
    English translation produced from the TEXT via the existing LLM
    client (null when translation is unavailable — degraded, not
    failed). Audio bytes never outlive this request.

    2026-09-29 deep-audit MEDIUM (voice dispatched outside the lifecycle
    fence): consent withdrawal and account deletion take the same
    ``llm-lifecycle`` lock, so holding it across BOTH provider round
    trips makes "withdrawal returned" linearize BEFORE any dispatch that
    starts after it — the same property the recompute path and account
    deletion docstring already promise. The consent check re-reads the
    user fresh INSIDE the fence (the dependency-loaded object can be
    stale by the time the slow call starts).
    """
    settings = request.app.state.settings
    engine = stt.get_stt(settings)
    if engine is None:
        raise ApiError(
            status_code=503,
            detail="speech-to-text is not configured on this server",
            code="stt_unconfigured",
        )
    # Fail fast on the dependency-loaded row (status-code precedence:
    # 403 before any 422); the fenced re-read below is the race closure.
    _require_voice_consent(user, settings)
    mime = normalize_mime(body.mime)
    if mime not in ALLOWED_AUDIO_MIMES:
        raise ApiError(
            status_code=422,
            detail="unsupported audio format",
            code="validation_error",
        )
    if not 0 < body.duration_seconds <= settings.audio_max_duration_seconds:
        raise ApiError(
            status_code=422,
            detail="recording duration exceeds the allowed maximum",
            code="validation_error",
        )
    audio = _decode_audio(body.audio_b64, settings)
    if not audio:
        raise ApiError(
            status_code=422,
            detail="recording is empty",
            code="validation_error",
        )
    expected_epoch = user.token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        fresh = await session.get(User, user.id, populate_existing=True)
        if fresh is None or not fresh.is_active:
            raise ApiError(
                status_code=410,
                detail="account no longer exists",
                code="account_deleted",
            )
        if fresh.token_epoch != expected_epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        _require_voice_consent(fresh, settings)
        try:
            result = await engine.transcribe(audio, mime)
        except Exception as exc:  # noqa: BLE001 — every upstream failure is one outcome
            logger.warning("stt upstream failed for user %s (%s)", user.id, type(exc).__name__)
            raise ApiError(
                status_code=502,
                detail="speech-to-text provider failed; try again",
                code="stt_upstream",
            ) from None
        english_text = None
        if result.text and stt.translation_dispatch_allowed(fresh, settings):
            english_text = await stt.translate_to_english(
                settings, result.text, result.language_iso
            )
    return AudioTranscriptionResponse(
        original_text=result.text,
        language=result.language_iso,
        language_raw=result.language_raw,
        english_text=english_text,
        provider_name=settings.stt_provider_name.strip(),
        policy_version=settings.stt_policy_version.strip(),
    )


@router.post(
    "/translations",
    response_model=AudioTranslationResponse,
    dependencies=[
        Depends(
            make_rate_limiter(
                "audio-transcribe", "audio_transcribe_rate_limit", "audio_transcribe_rate_window"
            )
        ),
    ],
)
async def translate_text(
    body: AudioTranslationRequest,
    request: Request,
    user: User = Depends(require_regular_user),
    _flag: None = Depends(require_audio_enabled),
    session: AsyncSession = Depends(get_session),
):
    """Re-translate an edited transcript before saving (payload v3).

    The stored entry's ``english_text`` must always correspond to the
    SAVED text, so a patient who edits their transcript calls this once
    before encryption. Shares the transcription rate bucket: it is the
    same user action (one recording → one transcription + at most a few
    re-translations while editing).

    H4 (audit 2026-09-29): the LLM endpoint is a consent surface of its
    own — an account that has not accepted the CURRENT LLM policy gets
    a null translation (degraded mode), never a dispatch of journal
    text to a provider they declined.

    2026-09-29 deep-audit MEDIUM: the dispatch runs INSIDE the same
    ``llm-lifecycle`` fence as transcription, with the consent re-read
    on a fresh user row — withdrawal/deletion that returned before this
    request started can never race a dispatch out the door.
    """
    settings = request.app.state.settings
    # Fail fast (same precedence as before the fence); re-checked under it.
    _require_voice_consent(user, settings)
    expected_epoch = user.token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        fresh = await session.get(User, user.id, populate_existing=True)
        if fresh is None or not fresh.is_active:
            raise ApiError(
                status_code=410,
                detail="account no longer exists",
                code="account_deleted",
            )
        if fresh.token_epoch != expected_epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        _require_voice_consent(fresh, settings)
        if not stt.translation_dispatch_allowed(fresh, settings):
            return AudioTranslationResponse(english_text=None)
        english_text = await stt.translate_to_english(settings, body.text, body.source_lang)
    return AudioTranslationResponse(english_text=english_text)


# --- attachments (P2) -----------------------------------------------------------


def _decode_blob(value: str, settings) -> bytes:
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422, detail="blob must be base64", code="validation_error"
        ) from None
    if len(blob) > settings.audio_max_body_bytes:
        raise ApiError(status_code=413, detail="recording too large", code="audio_too_large")
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"blob must be at least {MIN_BLOB_SIZE} bytes",
            code="validation_error",
        )
    return blob


async def _owner_attachment(
    session: AsyncSession, store, user_id: str, attachment_id: str
) -> AudioAttachment:
    """Owner-scoped fetch with lazy expiry enforcement.

    Another user's id is a flat 404 (an existence oracle for someone
    else's attachment metadata is still a leak). An expired row is
    deleted HERE — object first, then row — and answers 410, so a dead
    deployment's missed sweep cycles cannot extend retention.
    """
    row = await session.get(AudioAttachment, attachment_id)
    if row is None or row.user_id != user_id:
        raise ApiError(status_code=404, detail="attachment not found", code="not_found")
    if row.expires_at <= utcnow():
        try:
            await store.delete(row.storage_key)
        except AudioStoreError:
            logger.warning("lazy expiry could not delete object for %s; row kept", row.id)
            raise ApiError(
                status_code=410, detail="recording expired", code="audio_expired"
            ) from None
        await session.delete(row)
        await session.commit()
        raise ApiError(status_code=410, detail="recording expired", code="audio_expired")
    return row


def _attachment_out(row: AudioAttachment, blob: bytes) -> AudioAttachmentOut:
    return AudioAttachmentOut(
        id=row.id,
        client_entry_id=row.client_entry_id,
        blob=base64.b64encode(blob).decode("ascii"),
        mime_type=row.mime_type,
        duration_seconds=row.duration_seconds,
        size_bytes=row.size_bytes,
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


@router.post(
    "/attachments",
    response_model=AudioAttachmentCreated,
    status_code=201,
    dependencies=[
        Depends(
            make_rate_limiter("audio-upload", "audio_upload_rate_limit", "audio_upload_rate_window")
        ),
    ],
)
async def upload_attachment(
    body: AudioAttachmentCreate,
    request: Request,
    user: User = Depends(require_regular_user),
    _flag: None = Depends(require_audio_enabled),
    session: AsyncSession = Depends(get_session),
):
    """Store (or replace) the kept recording for one entry.

    The blob is opaque client-side ciphertext; the server puts it in
    object storage and records metadata only. One attachment per entry:
    a re-upload replaces the previous object first. Retention starts at
    upload (expires_at = now + audio_retention_days, default 30).
    """
    settings = request.app.state.settings
    _require_voice_consent(user, settings)
    store = get_audio_store_cached(settings)
    if store is None:
        raise ApiError(
            status_code=503,
            detail="audio storage is not configured on this server",
            code="audio_storage_unconfigured",
        )
    mime = normalize_mime(body.mime)
    if mime not in ALLOWED_AUDIO_MIMES:
        raise ApiError(status_code=422, detail="unsupported audio format", code="validation_error")
    if not 0 < body.duration_seconds <= settings.audio_max_duration_seconds:
        raise ApiError(
            status_code=422,
            detail="recording duration exceeds the allowed maximum",
            code="validation_error",
        )
    blob = _decode_blob(body.blob, settings)

    expected_epoch = user.token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _audio_locks.hold(f"audio:{user.id}"):
            fresh = await session.get(User, user.id, populate_existing=True)
            if fresh is None or not fresh.is_active or fresh.token_epoch != expected_epoch:
                raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
            entry_exists = await session.execute(
                select(Entry.id).where(
                    Entry.user_id == fresh.id, Entry.client_entry_id == body.client_entry_id
                )
            )
            if entry_exists.scalar_one_or_none() is None:
                raise ApiError(
                    status_code=404,
                    detail="no entry with that client_entry_id",
                    code="unknown_entry",
                )
            existing = (
                (
                    await session.execute(
                        select(AudioAttachment).where(
                            AudioAttachment.user_id == fresh.id,
                            AudioAttachment.client_entry_id == body.client_entry_id,
                        )
                    )
                )
                .scalars()
                .first()
            )
            now = utcnow()
            live_total = int(
                (
                    await session.execute(
                        select(func.coalesce(func.sum(AudioAttachment.size_bytes), 0)).where(
                            AudioAttachment.user_id == fresh.id,
                            AudioAttachment.expires_at > now,
                        )
                    )
                ).scalar_one()
            )
            replaced_bytes = existing.size_bytes if existing is not None else 0
            if live_total - replaced_bytes + len(blob) > settings.audio_max_user_bytes:
                raise ApiError(
                    status_code=413,
                    detail="audio storage quota reached",
                    code="audio_quota_exceeded",
                )
            key = audio_store_service.new_storage_key(fresh.id)
            try:
                await store.put(key, blob)
            except AudioStoreError:
                logger.warning("audio put failed for user %s", fresh.id)
                raise ApiError(
                    status_code=502,
                    detail="audio storage failed; try again",
                    code="audio_storage_failed",
                ) from None
            if existing is not None:
                # Replace semantics: the OLD object dies before the row is
                # repointed (an orphaned new object is the lifecycle
                # backstop's problem; a row without its object must never
                # happen).
                try:
                    await store.delete(existing.storage_key)
                except AudioStoreError:
                    logger.warning(
                        "orphaned old audio object %s (replace path)", existing.storage_key
                    )
                row = existing
                row.backend = store.backend
                row.storage_key = key
                row.size_bytes = len(blob)
                row.mime_type = mime
                row.duration_seconds = body.duration_seconds
                row.content_version = 1
                row.created_at = now
                row.expires_at = audio_store_service.attachment_expiry(settings)
            else:
                row = AudioAttachment(
                    user_id=fresh.id,
                    client_entry_id=body.client_entry_id,
                    backend=store.backend,
                    storage_key=key,
                    size_bytes=len(blob),
                    mime_type=mime,
                    duration_seconds=body.duration_seconds,
                    content_version=1,
                    created_at=now,
                    expires_at=audio_store_service.attachment_expiry(settings),
                )
                session.add(row)
            await session.commit()
    return AudioAttachmentCreated(
        attachment_id=row.id, expires_at=row.expires_at, size_bytes=row.size_bytes
    )


@router.get(
    "/attachments/{attachment_id}",
    response_model=AudioAttachmentOut,
    dependencies=[Depends(make_rate_limiter("audio-read", "read_rate_limit", "read_rate_window"))],
)
async def fetch_attachment(
    attachment_id: str,
    request: Request,
    user: User = Depends(require_regular_user),
    _flag: None = Depends(require_audio_enabled),
    session: AsyncSession = Depends(get_session),
):
    """Fetch one kept recording (owner-only) for playback."""
    settings = request.app.state.settings
    store = get_audio_store_cached(settings)
    if store is None:
        raise ApiError(
            status_code=503,
            detail="audio storage is not configured on this server",
            code="audio_storage_unconfigured",
        )
    row = await _owner_attachment(session, store, user.id, attachment_id)
    try:
        blob = await store.get(row.storage_key, max_bytes=settings.audio_max_body_bytes)
    except AudioStoreError:
        logger.warning("audio get failed for attachment %s", row.id)
        raise ApiError(
            status_code=502, detail="audio storage failed", code="audio_storage_failed"
        ) from None
    return _attachment_out(row, blob)


@router.delete(
    "/attachments/{attachment_id}",
    status_code=204,
    dependencies=[
        Depends(make_rate_limiter("audio-delete", "read_rate_limit", "read_rate_window"))
    ],
)
async def delete_attachment(
    attachment_id: str,
    request: Request,
    user: User = Depends(require_regular_user),
    _flag: None = Depends(require_audio_enabled),
    session: AsyncSession = Depends(get_session),
):
    """Delete the recording (the ENTRY survives — this is the patient's
    'remove audio but keep the entry' control; deleting the entry itself
    cleans its attachment through the entries route)."""
    settings = request.app.state.settings
    store = get_audio_store_cached(settings)
    if store is None:
        raise ApiError(
            status_code=503,
            detail="audio storage is not configured on this server",
            code="audio_storage_unconfigured",
        )
    row = await session.get(AudioAttachment, attachment_id)
    if row is None or row.user_id != user.id:
        raise ApiError(status_code=404, detail="attachment not found", code="not_found")
    try:
        await store.delete(row.storage_key)
    except AudioStoreError:
        logger.warning("audio delete failed for attachment %s", row.id)
        raise ApiError(
            status_code=502, detail="audio storage failed", code="audio_storage_failed"
        ) from None
    await session.execute(sa_delete(AudioAttachment).where(AudioAttachment.id == row.id))
    await session.commit()
    return Response(status_code=204)
