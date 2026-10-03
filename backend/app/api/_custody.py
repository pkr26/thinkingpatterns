"""Atomic opaque clinician custody transactions, including exact lost-response retries."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_sharing_enabled, require_therapist
from ..locks import lifecycle_locks, sharing_locks, sharing_therapist_lock_key
from ..models import ROLE_THERAPIST, User
from ..schemas import TherapistCustodyRequest, TherapistPasswordRequest
from ..security import tokens
from ..security.crypto import MIN_BLOB_SIZE
from .account import _require_verifier
from .auth import AUTH_KEY_SIZE, SALT_BYTES, _auth_limiter, auth_work_slot, hash_verifier_off_loop
from ._audit import append_access_log

router = APIRouter(
    dependencies=[
        Depends(require_sharing_enabled),
        Depends(make_rate_limiter("therapist-custody-auth", "auth_rate_limit", "auth_rate_window")),
    ]
)


def _decode(value: str, minimum: int, maximum: int) -> bytes:
    try:
        result = base64.b64decode(value, validate=True)
        if not minimum <= len(result) <= maximum:
            raise ValueError("size")
        return result
    except ValueError:
        raise ApiError(
            status_code=422, detail="invalid key material", code="validation_error"
        ) from None


def _digest(body: TherapistCustodyRequest, action: str) -> str:
    encoded = json.dumps(body.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(action.encode() + b"\0" + encoded).hexdigest()


def _check_version(user: User, body: TherapistCustodyRequest) -> None:
    if body.custody_version != body.expected_custody_version + 1:
        raise ApiError(
            status_code=422, detail="custody version must advance by one", code="validation_error"
        )
    if user.custody_version != body.expected_custody_version:
        raise ApiError(status_code=409, detail="custody changed; reload account", code="conflict")


def _advance_notes_snapshot(user: User) -> None:
    if user.notes_revision >= 2**63 - 1:
        raise ApiError(
            status_code=503, detail="unable to advance notes revision", code="service_unavailable"
        )
    user.notes_revision += 1


async def _fresh(session: AsyncSession, user_id: str) -> User:
    user = await session.scalar(
        select(User).where(User.id == user_id).execution_options(populate_existing=True)
    )
    if user is None or not user.is_active or user.role != ROLE_THERAPIST:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    return user


@router.put("/custody", status_code=204)
async def install_custody(
    body: TherapistCustodyRequest,
    request: Request,
    user: User = Depends(require_therapist),
    session: AsyncSession = Depends(get_session),
) -> None:
    epoch = user.token_epoch
    digest = _digest(body, "custody")
    blob = _decode(body.notes_keyring_blob, MIN_BLOB_SIZE, 65536)
    async with (
        lifecycle_locks.hold(f"llm-lifecycle:{user.id}"),
        sharing_locks.hold(sharing_therapist_lock_key(user.id)),
    ):
        fresh = await _fresh(session, user.id)
        if fresh.token_epoch != epoch:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        if fresh.custody_operation_id == body.operation_id:
            if fresh.custody_operation_epoch == epoch and hmac.compare_digest(
                fresh.custody_operation_digest or "", digest
            ):
                return
            raise ApiError(
                status_code=409, detail="operation identifier already used", code="conflict"
            )
        _check_version(fresh, body)
        await _require_verifier(fresh, body.verifier, request, session)
        _advance_notes_snapshot(fresh)
        fresh.notes_keyring_blob = blob
        fresh.custody_version = body.custody_version
        fresh.custody_operation_id = body.operation_id
        fresh.custody_operation_digest = digest
        fresh.custody_operation_epoch = epoch
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="notes_custody_install",
        )
        await session.commit()


async def require_password_retry_therapist(
    request: Request,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    # This endpoint alone admits an immediately preceding epoch for an EXACT
    # already-committed retry. It never authenticates a new mutation that way.
    failure = ApiError(status_code=401, detail="invalid token", code="unauthorized")
    if not authorization or not authorization.startswith("Bearer "):
        raise failure
    try:
        payload = tokens.verify_token(
            authorization[7:].strip(), request.app.state.settings.auth_token_secret
        )
    except tokens.TokenError:
        raise failure from None
    settings = request.app.state.settings
    if payload.get("ksv", 1) != settings.auth_secret_version:
        raise failure
    jti = payload.get("jti")
    if isinstance(jti, str) and await request.app.state.token_revocations.is_revoked_checked(
        session, jti
    ):
        raise failure
    user = (
        await _fresh(session, payload["uid"])
        if payload.get("purpose") == tokens.PURPOSE_THERAPIST
        else await session.get(User, payload["uid"])
    )
    if user is None or not user.is_active:
        raise failure
    expected_purpose = (
        tokens.PURPOSE_THERAPIST if user.role == ROLE_THERAPIST else tokens.PURPOSE_PATIENT
    )
    if payload.get("purpose") not in (None, expected_purpose):
        raise failure
    if user.role != ROLE_THERAPIST:
        raise ApiError(status_code=403, detail="not a therapist account", code="forbidden")
    epoch = payload.get("ep", 1)
    if epoch not in (user.token_epoch, user.token_epoch - 1):
        raise failure
    request.state.custody_token_epoch = epoch
    request.state.custody_token_jti = jti
    await session.commit()
    return user


@router.put("/password", status_code=204)
async def change_password(
    body: TherapistPasswordRequest,
    request: Request,
    user: User = Depends(require_password_retry_therapist),
    session: AsyncSession = Depends(get_session),
) -> None:
    failure = ApiError(status_code=401, detail="invalid token", code="unauthorized")
    settings = request.app.state.settings
    digest = _digest(body, "password")
    user_id = user.id
    await session.commit()
    async with (
        lifecycle_locks.hold(f"llm-lifecycle:{user_id}"),
        sharing_locks.hold(sharing_therapist_lock_key(user_id)),
    ):
        fresh = await _fresh(session, user_id)
        epoch = request.state.custody_token_epoch
        jti = request.state.custody_token_jti
        if isinstance(jti, str) and await request.app.state.token_revocations.is_revoked_checked(
            session, jti
        ):
            raise failure
        if fresh.custody_operation_id == body.operation_id:
            if (
                fresh.custody_operation_epoch == fresh.token_epoch
                and epoch in (fresh.token_epoch, fresh.token_epoch - 1)
                and hmac.compare_digest(fresh.custody_operation_digest or "", digest)
            ):
                return
            raise ApiError(
                status_code=409, detail="operation identifier already used", code="conflict"
            )
        if epoch != fresh.token_epoch:
            raise failure
        _check_version(fresh, body)
        if body.wrap_pub_key != fresh.wrap_pub_key:
            raise ApiError(
                status_code=422,
                detail="password changes must preserve the sharing public key",
                code="validation_error",
            )
        salt = _decode(body.new_salt, SALT_BYTES, SALT_BYTES)
        verifier = _decode(body.new_verifier, AUTH_KEY_SIZE, AUTH_KEY_SIZE)
        wrap = _decode(body.wrap_key_blob, MIN_BLOB_SIZE, 1024)
        keyring = _decode(body.notes_keyring_blob, MIN_BLOB_SIZE, 65536)
        await _require_verifier(fresh, body.verifier, request, session)
        server_salt = os.urandom(16)
        async with auth_work_slot(request):
            verifier_hash = await hash_verifier_off_loop(
                verifier, server_salt, limiter=_auth_limiter(request), n=settings.scrypt_n
            )
        _advance_notes_snapshot(fresh)
        fresh.salt = base64.b64encode(salt).decode("ascii")
        fresh.scrypt_salt = server_salt
        fresh.verifier = verifier_hash
        fresh.wrap_key_blob = wrap
        fresh.notes_keyring_blob = keyring
        fresh.custody_version = body.custody_version
        fresh.token_epoch += 1
        fresh.custody_operation_id = body.operation_id
        fresh.custody_operation_digest = digest
        fresh.custody_operation_epoch = fresh.token_epoch
        await append_access_log(
            session,
            actor_id=fresh.id,
            actor_role=fresh.role,
            user_id=fresh.id,
            action="therapist_password_change",
        )
        await session.commit()
        request.app.state.key_store.destroy_all_for_owner(fresh.id)
