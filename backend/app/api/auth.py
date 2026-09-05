"""Registration and login.

The client derives auth_key = HKDF(master_key) on-device and sends only
auth_key; the server stores scrypt(auth_key) with a server-side salt, so a
database leak reveals neither the password nor any key that decrypts data.

Enumeration posture, stated honestly:
  * Salt lookup (POST /auth/salt) never reveals account existence — unknown
    AND deactivated accounts get a deterministic decoy salt, and the
    response shape/size/timing is identical.
  * Registration must, like every name-based system without an identity
    channel (email etc.), answer whether a name is available — the 409 is
    real. What we can do (and do): burn identical CPU on both outcomes so
    timing adds nothing, and rate-limit per-IP AND per-username so mass
    enumeration is throttled to a crawl.

Login/logout: logout bumps the account's token epoch, instantly revoking
every bearer token issued so far (stateless tokens, server-side kill
switch). scrypt runs in a worker thread — a ~35ms KDF on the event loop
would let a single IP stall every concurrent request.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import (
    check_keyed_limit,
    check_keyed_limit_without_count,
    make_rate_limiter,
    record_keyed_failure,
)
from ..deps import get_session, require_user
from ..models import User
from ..schemas import LoginRequest, RegisterRequest, SaltLookupRequest, SaltResponse, TokenResponse
from ..security.tokens import issue_token

router = APIRouter(prefix="/auth", tags=["auth"])

# N=2^16 (64 MiB) — above OWASP's absolute floor and defensible here: the
# input is a 256-bit key already stretched by client-side PBKDF2-600k, so
# offline cracking pays both costs per guess.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024
AUTH_KEY_SIZE = 32
SALT_BYTES = 16  # exactly — the decoy is 16 bytes too, so lengths cannot differ

_b64_decode_error = (binascii.Error, ValueError)


def hash_verifier(auth_key: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        auth_key, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM
    )


async def hash_verifier_off_loop(auth_key: bytes, salt: bytes) -> bytes:
    """scrypt is ~35ms of CPU: never run it on the event loop thread."""
    return await anyio.to_thread.run_sync(hash_verifier, auth_key, salt)


def decoy_salt(username: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), b"decoy:" + username.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest[:SALT_BYTES]).decode("ascii")


def _issue(request: Request, user: User) -> TokenResponse:
    settings = request.app.state.settings
    return TokenResponse(
        token=issue_token(
            user.id, settings.token_secret, settings.token_ttl_seconds, epoch=user.token_epoch
        ),
        user_id=user.id,
        expires_in=settings.token_ttl_seconds,
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=201,
    dependencies=[Depends(make_rate_limiter("auth-register", "auth_rate_limit", "auth_rate_window"))],
)
async def register(body: RegisterRequest, request: Request, session: AsyncSession = Depends(get_session)):
    settings = request.app.state.settings
    # Per-username bucket: rotating source IPs must not allow unbounded
    # probing of one name (the 409 availability answer is the one oracle a
    # name-based system cannot fully close).
    check_keyed_limit(request, f"register-name:{body.username}",
                      settings.auth_rate_limit, settings.auth_rate_window)
    try:
        salt_bytes = base64.b64decode(body.salt, validate=True)
        verifier_bytes = base64.b64decode(body.verifier, validate=True)
    except _b64_decode_error:
        raise HTTPException(status_code=422, detail="salt and verifier must be base64")
    if len(salt_bytes) != SALT_BYTES:
        raise HTTPException(status_code=422, detail=f"salt must be exactly {SALT_BYTES} bytes")
    if len(verifier_bytes) != AUTH_KEY_SIZE:
        raise HTTPException(status_code=422, detail=f"verifier must be {AUTH_KEY_SIZE} bytes")

    # Hash FIRST, before the existence check, so the taken/free paths are
    # computationally identical (no timing oracle on top of the status code).
    scrypt_server_salt = os.urandom(16)
    verifier_hash = await hash_verifier_off_loop(verifier_bytes, scrypt_server_salt)

    existing = await session.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="username already taken")

    user = User(
        username=body.username,
        salt=body.salt,
        verifier=verifier_hash,
        scrypt_salt=scrypt_server_salt,
    )
    session.add(user)
    try:
        # Issue the token BEFORE committing: if issuance ever fails the row
        # must not persist, or the username is silently consumed (first
        # request 500, every retry 409 "taken").
        await session.flush()
        response = _issue(request, user)
        await session.commit()
    except IntegrityError as exc:
        # Two concurrent registrations of the same username: the unique
        # index is the authority, the pre-check above is just fast-path UX.
        await session.rollback()
        raise HTTPException(status_code=409, detail="username already taken") from exc
    return response


@router.post(
    "/salt",
    response_model=SaltResponse,
    dependencies=[Depends(make_rate_limiter("auth-salt", "auth_rate_limit", "auth_rate_window"))],
)
async def get_salt(body: SaltLookupRequest, request: Request, session: AsyncSession = Depends(get_session)):
    # POST, not GET /salt/{username}: usernames must never ride the URL path,
    # where default proxy/uvicorn access logs would inventory every queried
    # name. The body is not logged by standard servers.
    result = await session.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if user is not None and user.is_active:
        return SaltResponse(salt=user.salt)
    # Unknown OR deactivated account: deterministic decoy (never reveal
    # account existence, never hand out a real salt for a suspended account).
    return SaltResponse(salt=decoy_salt(body.username, request.app.state.settings.token_secret))


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(make_rate_limiter("auth-login", "auth_rate_limit", "auth_rate_window"))],
)
async def login(body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)):
    settings = request.app.state.settings
    # Per-username bucket (slows targeted credential stuffing that rotates
    # IPs), but only FAILED VERIFICATIONS consume it: checking-and-counting
    # up front let anyone anonymously lock a victim out of their own account
    # by spraying garbage logins at their name.
    username_key = f"login-name:{body.username}"
    check_keyed_limit_without_count(
        request, username_key, settings.auth_rate_limit, settings.auth_rate_window
    )
    result = await session.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    try:
        verifier_bytes = base64.b64decode(body.verifier, validate=True)
    except _b64_decode_error:
        verifier_bytes = b""
    if user is None or not user.is_active:
        # Burn equivalent CPU so response timing does not reveal existence.
        await hash_verifier_off_loop(b"\x00" * AUTH_KEY_SIZE, b"\x00" * 16)
        raise HTTPException(status_code=401, detail="invalid credentials")
    candidate = await hash_verifier_off_loop(verifier_bytes, user.scrypt_salt)
    if not hmac.compare_digest(candidate, bytes(user.verifier)):
        record_keyed_failure(request, username_key, settings.auth_rate_window)
        raise HTTPException(status_code=401, detail="invalid credentials")
    return _issue(request, user)


@router.post(
    "/logout",
    status_code=204,
    dependencies=[Depends(make_rate_limiter("auth-logout", "auth_rate_limit", "auth_rate_window"))],
)
async def logout(user: User = Depends(require_user), session: AsyncSession = Depends(get_session)):
    """Revoke every bearer token for this account (all devices) at once.

    Sign-out on one device cannot selectively kill its own token without
    per-token state; the epoch bump retires them all — the user re-logs-in
    elsewhere, which is the safe direction to err for journal data.
    """
    user.token_epoch = user.token_epoch + 1
    await session.commit()
