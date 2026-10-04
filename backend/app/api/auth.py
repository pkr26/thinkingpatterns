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
switch). scrypt runs in a worker thread behind a dedicated CapacityLimiter
(app.state.auth_limiter) — a ~35ms/64-MiB KDF on the event loop, or
unbounded concurrent KDFs on the shared pool, would let a single IP stall
every concurrent request.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
import anyio.to_thread
from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import (
    check_keyed_limit_without_count,
    make_rate_limiter,
    record_keyed_failure,
)
from ..db import rowcount as db_rowcount
from ..deps import ApiError, get_session, require_user
from ..locks import lifecycle_locks
from ..models import KEY_SCHEME_V1, KEY_SCHEME_V2, ROLE_THERAPIST, TotpBackupCode, User, utcnow
from ..schemas import (
    KeyEnvelopeResponse,
    LoginRequest,
    RegisterRequest,
    SaltLookupRequest,
    SaltResponse,
    TokenResponse,
    RecoveryLoginRequest,
    RecoveryLoginResponse,
)
from ..security import tokens
from ..security.kdf import (
    KDF_PARAMS_MIN_PBKDF2_ITERATIONS,
    KdfParamsError,
    canonical_kdf_params_json,
    hkdf_sha256,
    parse_kdf_params_json,
    validate_kdf_params,
)
from ..security.sharing import backup_code_digest
from ..security.tokens import issue_token
from ..security.totp import unwrap_secret, verify_code
from ._audit import append_access_log

router = APIRouter(prefix="/auth", tags=["auth"])

# Server-side verifier hashing. N=2^17 (128 MiB, ~70ms) is the config
# default (MINDPATTERN_SCRYPT_N; Settings.scrypt_n) — raised from 2^16 in
# the 2026-09-26 remediation. Rationale: the input is a 256-bit key
# already stretched by client-side PBKDF2-600k (an offline cracker pays
# BOTH costs per guess), the ~70ms sits comfortably inside the auth
# admission limiter's latency budget (4 concurrent slots ≈ no visible
# queue at human login rates), and doubling the memory re-priced GPU
# attacks that had begun to treat 64 MiB as cheap. MIGRATION: scrypt
# output depends on N and the schema records no per-account factor, so
# accounts hashed under the old 2^16 default fail login after an upgrade
# until re-registered, or the operator pins MINDPATTERN_SCRYPT_N=65536
# (see config.py).
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
# 2^17 × r=8 × 128 bytes/Block = 128 MiB per hash; maxmem must exceed the
# peak or hashlib refuses the parameters. 512 MiB leaves room for a future
# default bump without a second knob.
SCRYPT_MAXMEM = 512 * 1024 * 1024
AUTH_KEY_SIZE = 32
SALT_BYTES = 16  # exactly — the decoy is 16 bytes too, so lengths cannot differ

_b64_decode_error = (binascii.Error, ValueError)

# 2026-09-28 deep audit: import the pinned constant — the value used to be
# redeclared here while account.py imported envelope's, so a future format
# change would silently diverge the register path from the upgrade paths.
from ..security.envelope import WRAPPED_DATA_KEY_BYTES as WRAPPED_DATA_KEY_SIZE  # noqa: E402


def hash_verifier(auth_key: bytes, salt: bytes, n: int = SCRYPT_N) -> bytes:
    return hashlib.scrypt(auth_key, salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM)


async def hash_verifier_off_loop(
    auth_key: bytes, salt: bytes, limiter=None, n: int = SCRYPT_N
) -> bytes:
    """scrypt is ~70ms of CPU and 128 MiB of RAM: never run it on the event
    loop thread, and cap concurrency through the app's dedicated auth
    limiter so a login flood cannot queue unbounded scrypt allocations on
    the shared anyio pool."""
    return await anyio.to_thread.run_sync(hash_verifier, auth_key, salt, n, limiter=limiter)


def _auth_limiter(request: Request):
    # Same pattern as the recompute path: a dedicated CapacityLimiter wired
    # in main.py; getattr keeps direct-router unit tests without app state
    # working (anyio falls back to the default pool limiter on None).
    return getattr(request.app.state, "auth_limiter", None)


@asynccontextmanager
async def auth_work_slot(request: Request) -> AsyncIterator[None]:
    """Admit password-KDF work without queueing a DB-owning request.

    ``CapacityLimiter`` is also passed to ``run_sync`` so only its worker
    slots execute scrypt.  This companion, non-blocking limiter is acquired
    *before* login opens a DB transaction. Its capacity matches the worker
    limiter, so every admitted request has a worker slot available after its
    short database read; excess requests receive a retryable overload error
    instead of piling up while holding pooled connections.
    """
    limiter = getattr(request.app.state, "auth_admission_limiter", None)
    if limiter is None:
        # Direct router tests construct minimal request doubles. Production
        # apps always wire the admission limiter in main.create_app().
        yield
        return
    try:
        limiter.acquire_nowait()
    except anyio.WouldBlock:
        raise ApiError(
            status_code=503,
            detail="authentication service busy; retry shortly",
            code="service_unavailable",
            headers={"Retry-After": "1"},
        ) from None
    try:
        yield
    finally:
        limiter.release()


async def _close_read_transaction(session: AsyncSession) -> None:
    """Return the pool connection after an auth SELECT and before scrypt."""
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        raise


DECOY_SALT_INFO = b"mindpattern/decoy-salt/v1"
RECOVERY_LIMIT_INFO = b"mindpattern/recovery-rate-limit/v1"


def decoy_salt(username: str, secret: str) -> str:
    # Key separation: the decoy HMAC runs under an HKDF subkey derived from
    # the token secret, not the raw secret itself — token signing and decoy
    # salts must never be two uses of one HMAC key.
    decoy_key = hkdf_sha256(secret.encode("utf-8"), None, DECOY_SALT_INFO)
    digest = hmac.new(decoy_key, b"decoy:" + username.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest[:SALT_BYTES]).decode("ascii")


def recovery_failure_key(username: str, secret: str) -> str:
    """Opaque bucket id using the database lookup's exact username semantics.

    Registration and lookup are case-sensitive and do not trim. Collapsing
    case or whitespace here would let an unknown spelling spend a real
    account's recovery budget even though it can never select that row.
    """
    key = hkdf_sha256(secret.encode("utf-8"), None, RECOVERY_LIMIT_INFO)
    digest = hmac.new(key, username.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"recovery-fail:{digest}"


def _issue(request: Request, user: User) -> TokenResponse:
    """Mint a bearer for an authenticated account.

    Signed under the AUTH-token secret (Settings.auth_token_secret — the
    purpose-split resolution: explicit MINDPATTERN_AUTH_TOKEN_SECRET, else
    the legacy MINDPATTERN_TOKEN_SECRET), stamped with the secret's
    key-scheme version (ksv) so a future rotation to a split secret
    invalidates cleanly, carrying a fresh 128-bit jti for single-token
    logout, and pinned to the account's role so the wire token names its
    purpose. The DB role remains the authorization authority downstream.
    """
    settings = request.app.state.settings
    return TokenResponse(
        token=issue_token(
            user.id,
            settings.auth_token_secret,
            settings.token_ttl_seconds,
            epoch=user.token_epoch,
            purpose=tokens.PURPOSE_THERAPIST
            if user.role == ROLE_THERAPIST
            else tokens.PURPOSE_PATIENT,
            ksv=settings.auth_secret_version,
        ),
        user_id=user.id,
        expires_in=settings.token_ttl_seconds,
        role=user.role,
        key_scheme=user.key_scheme if user.key_scheme else KEY_SCHEME_V1,
        mfa_enrollment_required=user.role == ROLE_THERAPIST and user.totp_enabled is not True,
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("auth-register", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def register(
    body: RegisterRequest, request: Request, session: AsyncSession = Depends(get_session)
):
    settings = request.app.state.settings
    # Per-username bucket: rotating source IPs must not allow unbounded
    # probing of one name (the 409 availability answer is the one oracle a
    # name-based system cannot fully close). Like the login path, the probe
    # itself does NOT consume the bucket — only ACTUAL conflicts (409s) are
    # counted, so spraying garbage or taken-name probes cannot 429 the
    # legitimate first registrant of a free name.
    username_key = f"register-name:{body.username}"
    check_keyed_limit_without_count(
        request, username_key, settings.auth_rate_limit, settings.auth_rate_window
    )
    try:
        salt_bytes = base64.b64decode(body.salt, validate=True)
        verifier_bytes = base64.b64decode(body.verifier, validate=True)
    except _b64_decode_error:
        raise ApiError(
            status_code=422, detail="salt and verifier must be base64", code="validation_error"
        )
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
    # v2 key scheme (2026-09-26): kdf_params and wrapped_data_key arrive
    # together or not at all. The params blob is validated + canonicalized
    # (structure AND cost bounds — security.kdf); the wrapped key is stored
    # OPAQUELY: the server never sees the KEK input, so the 60-byte blob is
    # as unreadable to it as any entry ciphertext. A v1 registration (both
    # fields absent) keeps the exact historical behavior.
    kdf_params_json: str | None = None
    wrapped_key_bytes: bytes | None = None
    if body.kdf_params is not None or body.wrapped_data_key is not None:
        if body.kdf_params is None or body.wrapped_data_key is None:
            raise ApiError(
                status_code=422,
                detail="v2 registration requires kdf_params and wrapped_data_key together",
                code="validation_error",
            )
        try:
            # Pentest T-2 (2026-09-29): NEWLY REGISTERED params must meet the
            # shipped 600k contract — the read floor stays lower so
            # pre-constraint blobs keep validating.
            canonical = validate_kdf_params(
                body.kdf_params, min_pbkdf2_iterations=KDF_PARAMS_MIN_PBKDF2_ITERATIONS
            )
        except KdfParamsError as exc:
            raise ApiError(status_code=422, detail=str(exc), code="validation_error") from None
        kdf_params_json = canonical_kdf_params_json(canonical)
        try:
            wrapped_key_bytes = base64.b64decode(body.wrapped_data_key, validate=True)
        except _b64_decode_error:
            raise ApiError(
                status_code=422,
                detail="wrapped_data_key must be base64",
                code="validation_error",
            ) from None
        if len(wrapped_key_bytes) != WRAPPED_DATA_KEY_SIZE:
            raise ApiError(
                status_code=422,
                detail=f"wrapped_data_key must be exactly {WRAPPED_DATA_KEY_SIZE} bytes",
                code="validation_error",
            )

    # Hash FIRST, before the existence check, so the taken/free paths are
    # computationally identical (no timing oracle on top of the status code).
    scrypt_server_salt = os.urandom(16)
    async with auth_work_slot(request):
        verifier_hash = await hash_verifier_off_loop(
            verifier_bytes,
            scrypt_server_salt,
            limiter=_auth_limiter(request),
            n=settings.scrypt_n,
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
        key_scheme=KEY_SCHEME_V2 if wrapped_key_bytes is not None else "v1",
        wrapped_data_key=wrapped_key_bytes,
        kdf_params=kdf_params_json,
        age_attestation_version=body.age_attestation,
        age_attested_at=utcnow(),
    )
    session.add(user)
    try:
        # Issue the token BEFORE committing: if issuance ever fails the row
        # must not persist, or the username is silently consumed (first
        # request 500, every retry 409 "taken").
        await session.flush()
        await append_access_log(
            session,
            actor_id=user.id,
            actor_role="patient",
            user_id=user.id,
            action="account_created",
            allow_new_chain=True,
        )
        response = _issue(request, user)
        await session.commit()
    except IntegrityError as exc:
        # Two concurrent registrations of the same username: the unique
        # index is the authority, the pre-check above is just fast-path UX.
        await session.rollback()
        record_keyed_failure(request, username_key, settings.auth_rate_window)
        raise ApiError(status_code=409, detail="username already taken", code="conflict") from exc
    return response


@router.get(
    "/key-envelope",
    response_model=KeyEnvelopeResponse,
    dependencies=[
        Depends(make_rate_limiter("auth-envelope", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_key_envelope(
    request: Request,
    user: User = Depends(require_user),
):
    """The v2 unlock material: salt + kdf_params + wrapped data key.

    After login, a v2 client fetches this and unwraps its random data key
    LOCALLY (KEK = HKDF of the password-derived key per kdf_params — see
    security/envelope.py; the server holds no input that can perform the
    unwrap, so serving the blob to the authenticated account leaks
    nothing an attacker with the bearer + the database does not already
    have). v1 accounts answer key_scheme=KEY_SCHEME_V1 with null envelope fields —
    the legacy password-derived flow, and a hint that the client MAY
    offer the self-service upgrade (POST /account/key-envelope/upgrade).

    Fresh-device residual, stated honestly: kdf_params are echoed only to
    AUTHENTICATED callers (returning them with the pre-login salt lookup
    would turn a non-default cost profile into an account-existence
    oracle). The shipped client derives with the constant default params
    (pbkdf2-sha256-600k), so fresh-device login is unambiguous; a future
    client that adopts non-default params must remember them on-device —
    a 401 on a known-good password then means "params mismatch", not
    "wrong password".
    """
    params = parse_kdf_params_json(user.kdf_params)
    if user.key_scheme == KEY_SCHEME_V2 and (params is None or user.wrapped_data_key is None):
        # Unreachable through the API (every v2 write path validates the
        # pair atomically); a hand-mangled row fails CLOSED with the flat
        # 404 instead of coaching an attacker about the account's state.
        raise ApiError(status_code=404, detail="account not found", code="not_found")
    return KeyEnvelopeResponse(
        key_scheme=user.key_scheme or KEY_SCHEME_V1,
        salt=user.salt,
        kdf_params=params,
        wrapped_data_key=(
            base64.b64encode(bytes(user.wrapped_data_key)).decode("ascii")
            if user.key_scheme == KEY_SCHEME_V2 and user.wrapped_data_key is not None
            else None
        ),
    )


@router.post(
    "/salt",
    response_model=SaltResponse,
    dependencies=[Depends(make_rate_limiter("auth-salt", "auth_rate_limit", "auth_rate_window"))],
)
async def get_salt(
    body: SaltLookupRequest, request: Request, session: AsyncSession = Depends(get_session)
):
    # POST, not GET /salt/{username}: usernames must never ride the URL path,
    # where default proxy/uvicorn access logs would inventory every queried
    # name. The body is not logged by standard servers.
    result = await session.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if user is not None and user.is_active:
        return SaltResponse(salt=user.salt)
    # Unknown OR deactivated account: deterministic decoy (never reveal
    # account existence, never hand out a real salt for a suspended account).
    # C-6 (2026-09-21): a dedicated MINDPATTERN_DECOY_SECRET, when set,
    # decouples decoy-salt stability from token-secret rotation.
    settings = request.app.state.settings
    return SaltResponse(
        salt=decoy_salt(body.username, settings.decoy_secret.strip() or settings.token_secret)
    )


@router.post(
    "/recover",
    response_model=RecoveryLoginResponse,
    dependencies=[
        Depends(make_rate_limiter("auth-recover", "auth_rate_limit", "auth_rate_window"))
    ],
)
async def recover_login(
    body: RecoveryLoginRequest, request: Request, session: AsyncSession = Depends(get_session)
):
    """Log in with the RECOVERY KEY instead of the password (wave 3).

    For accounts that created a recovery kit: the key verifies against its
    scrypt hash (decoy CPU burn for unknown/inactive/no-kit accounts, so
    timing never reveals existence or enrollment), the response carries a
    session AND the client-sealed data-key copy only the recovery key
    opens. The token epoch bumps (every existing bearer dies — a recovery
    event implies the password may be lost or compromised).

    PATIENT accounts only: therapist second-factor accounts recover
    through their TOTP recovery codes; a recovery kit here would bypass
    that factor entirely.
    """
    settings = request.app.state.settings
    recovery_fail_key = recovery_failure_key(
        body.username, settings.decoy_secret.strip() or settings.token_secret
    )
    # Apply the same opaque keyed budget before account lookup for known,
    # unknown, inactive, unenrolled, and wrong-scheme inputs alike.
    check_keyed_limit_without_count(
        request,
        recovery_fail_key,
        settings.verifier_failure_limit,
        settings.auth_rate_window,
    )
    async with auth_work_slot(request):
        result = await session.execute(select(User).where(User.username == body.username))
        user = result.scalar_one_or_none()
        await _close_read_transaction(session)
        try:
            recovery_key = base64.b64decode(body.verifier, validate=True)
        except _b64_decode_error:
            recovery_key = b""
        expected_epoch = user.token_epoch if user is not None else None
        verifier_hash = user.recovery_verifier if user is not None else None
        recovery_salt = user.recovery_salt if user is not None else None
        sealed_key = user.recovery_wrapped_data_key if user is not None else None
        if (
            user is None
            or not user.is_active
            or verifier_hash is None
            or recovery_salt is None
            or sealed_key is None
            or user.role != "user"
            or len(recovery_key) != 32
        ):
            # Same burn as an unknown-account login; the branch conditions
            # are deliberately one expression so none of them is readable
            # from timing.
            await hash_verifier_off_loop(
                b"\x00" * 32,
                b"\x00" * 16,
                limiter=_auth_limiter(request),
                n=request.app.state.settings.scrypt_n,
            )
            record_keyed_failure(request, recovery_fail_key, settings.auth_rate_window)
            raise ApiError(
                status_code=401, detail="invalid credentials", code="invalid_credentials"
            )
        # The scheme is an explicit part of the credential.  It must not be
        # an enrollment oracle: wrong scheme, wrong proof and no kit all
        # perform a scrypt burn and return the same flat failure.
        stored_scheme = 2 if (user.recovery_scheme or 1) == 2 else 1
        hint_scheme = 2 if body.scheme == "v2" else 1
        candidate = await hash_verifier_off_loop(
            recovery_key,
            recovery_salt,
            limiter=_auth_limiter(request),
            n=settings.scrypt_n,
        )
        if hint_scheme != stored_scheme or not hmac.compare_digest(candidate, bytes(verifier_hash)):
            record_keyed_failure(request, recovery_fail_key, settings.auth_rate_window)
            raise ApiError(
                status_code=401, detail="invalid credentials", code="invalid_credentials"
            )
        # A kit withdrawal/replacement or another recovery while hashing retires
        # this proof. Re-read every enrolled field under the lifecycle fence.
        async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
            fresh = await session.scalar(
                select(User).where(User.id == user.id).execution_options(populate_existing=True)
            )
            if (
                fresh is None
                or not fresh.is_active
                or fresh.role != "user"
                or fresh.token_epoch != expected_epoch
                or fresh.recovery_verifier != verifier_hash
                or fresh.recovery_salt != recovery_salt
                or fresh.recovery_wrapped_data_key != sealed_key
                or (2 if (fresh.recovery_scheme or 1) == 2 else 1) != stored_scheme
            ):
                record_keyed_failure(request, recovery_fail_key, settings.auth_rate_window)
                raise ApiError(
                    status_code=401, detail="invalid credentials", code="invalid_credentials"
                )
            fresh.token_epoch += 1
            await session.commit()
            request.app.state.key_store.destroy_all_for_owner(fresh.id)
            user = fresh
        token = issue_token(
            user.id,
            settings.auth_token_secret,
            settings.token_ttl_seconds,
            epoch=user.token_epoch,
            purpose=tokens.PURPOSE_PATIENT,
            ksv=settings.auth_secret_version,
        )
        # key_scheme travels via the response model's default contract;
        # the sealed copy is non-None on this branch (the guard above
        # rejected accounts without a kit).
        response = RecoveryLoginResponse(
            username=user.username,
            token=token,
            user_id=user.id,
            expires_in=settings.token_ttl_seconds,
            role=user.role,
            recovery_wrapped_data_key=base64.b64encode(bytes(sealed_key)).decode("ascii"),
            recovery_scheme="v2" if stored_scheme == 2 else "v1",
        )
        response.key_scheme = user.key_scheme if user.key_scheme else "v1"
        return response


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(make_rate_limiter("auth-login", "auth_rate_limit", "auth_rate_window"))],
)
async def login(body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)):
    # Login throttling is intentionally IP/device-facing only. A hard
    # per-username deny bucket turns a distributed attacker into a trivial
    # account-lockout oracle: they can spend the victim's failure budget and
    # make a correct password return 429. The normal auth bucket still
    # throttles each source, while real deployments should add trusted
    # device/risk signals or a challenge rather than anonymously denying the
    # account holder.
    async with auth_work_slot(request):
        result = await session.execute(select(User).where(User.username == body.username))
        user = result.scalar_one_or_none()
        # Critical ordering: do not retain a pool connection while the KDF is
        # queued/running. expire_on_commit=False keeps these ORM attributes
        # usable after the read transaction releases its connection.
        await _close_read_transaction(session)
        try:
            verifier_bytes = base64.b64decode(body.verifier, validate=True)
        except _b64_decode_error:
            verifier_bytes = b""
        if user is None or not user.is_active:
            # Burn equivalent CPU so response timing does not reveal existence.
            await hash_verifier_off_loop(
                b"\x00" * AUTH_KEY_SIZE,
                b"\x00" * 16,
                limiter=_auth_limiter(request),
                n=request.app.state.settings.scrypt_n,
            )
            raise ApiError(
                status_code=401, detail="invalid credentials", code="invalid_credentials"
            )
        candidate = await hash_verifier_off_loop(
            verifier_bytes,
            user.scrypt_salt,
            limiter=_auth_limiter(request),
            n=request.app.state.settings.scrypt_n,
        )
        if not hmac.compare_digest(candidate, bytes(user.verifier)):
            raise ApiError(
                status_code=401, detail="invalid credentials", code="invalid_credentials"
            )
        # Optional therapist second factor (2026-09-21 audit C-2/F-4,
        # delivered 2026-09-22). Checked only AFTER the password verifier,
        # so a TOTP-enabled account never reveals whether the password was
        # the wrong half. A missing code is a distinct, machine-readable
        # answer (totp_required) so the portal can render the code field
        # without knowing the account type up front.
        if user.totp_enabled:
            code = (body.totp_code or "").strip()
            if not code:
                raise ApiError(
                    status_code=401,
                    detail="totp code required",
                    code="totp_required",
                )
            settings = request.app.state.settings
            # Per-username second-factor failure throttle (2026-09-26
            # pentest D-4). Safe where a per-username PASSWORD deny bucket
            # is not: this branch is reachable only with a VALID verifier,
            # so a username-only attacker can never spend this budget —
            # there is no lockout oracle for unauthenticated spray. It
            # caps distributed code guessing (10/min/IP × N IPs) that the
            # per-IP bucket cannot see.
            totp_fail_key = f"totp-fail:{user.username}"
            check_keyed_limit_without_count(
                request,
                totp_fail_key,
                settings.totp_failure_limit,
                settings.auth_rate_window,
            )
            # Purpose-split secret (2026-09-26): TOTP secrets at rest unwrap
            # under MINDPATTERN_TOTP_WRAP_SECRET (else the legacy token
            # secret — identity derivation, so existing blobs stay valid).
            secret = unwrap_secret(user.totp_secret, settings.totp_wrap_secret)
            matched = (
                verify_code(secret, code) if secret is not None else None
            )  # unwrap failure = fail closed: no second factor, no token
            # 2026-09-26 audit item 10: the snapshot replay pre-check
            # (``matched <= user.totp_last_counter`` against the auth-time
            # ORM row) is GONE. A concurrent login that advanced the counter
            # to the SAME timestep made a FRESH code look "replayed" here
            # and 401'd it, even though the atomic fence below would have
            # rejected only the true loser. Every authenticator-code success
            # now flows through the conditional UPDATE — it is the sole
            # replay authority. Timing equivalence is preserved: both
            # failure paths still pay one keyed verification plus one
            # committed database write before the same 401 envelope.
            if matched is None:
                # Recovery codes (2026-09-26 pentest S-3): a 10-char
                # single-use code redeems in place of the authenticator
                # code. Atomic redemption (conditional UPDATE authority),
                # so concurrent presentations of one code resolve to
                # exactly one success.
                redeemed = False
                digest_candidate = backup_code_digest(code, settings.totp_wrap_secret)
                live_codes = (
                    (
                        await session.execute(
                            select(TotpBackupCode).where(
                                TotpBackupCode.user_id == user.id,
                                TotpBackupCode.used_at.is_(None),
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in live_codes:
                    if hmac.compare_digest(row.digest, digest_candidate):
                        burn = await session.execute(
                            update(TotpBackupCode)
                            .where(
                                TotpBackupCode.id == row.id,
                                TotpBackupCode.used_at.is_(None),
                            )
                            .values(used_at=utcnow())
                        )
                        await session.commit()
                        redeemed = db_rowcount(burn) == 1
                        break
                if not redeemed:
                    record_keyed_failure(request, totp_fail_key, settings.auth_rate_window)
                    raise ApiError(
                        status_code=401,
                        detail="invalid totp code",
                        code="totp_code_invalid",
                    )
            else:
                # Replay fence, ATOMIC (2026-09-26 pentest D-3): the
                # conditional UPDATE is the authority — two logins racing
                # the same code serialize on the row and exactly one wins
                # (the loser's WHERE clause no longer matches after the
                # winner's commit). Audit item 10 removed the snapshot
                # fast-path: the fence alone decides, so a concurrent
                # same-timestep login can never 401 a genuinely fresh code.
                fence = await session.execute(
                    update(User)
                    .where(
                        User.id == user.id,
                        User.totp_enabled.is_(True),
                        or_(
                            User.totp_last_counter.is_(None),
                            User.totp_last_counter < matched,
                        ),
                    )
                    .values(totp_last_counter=matched)
                )
                await session.commit()
                if db_rowcount(fence) != 1:
                    record_keyed_failure(request, totp_fail_key, settings.auth_rate_window)
                    raise ApiError(
                        status_code=401,
                        detail="invalid totp code",
                        code="totp_code_invalid",
                    )
        return _issue(request, user)


@router.post(
    "/logout",
    status_code=204,
    dependencies=[Depends(make_rate_limiter("auth-logout", "auth_rate_limit", "auth_rate_window"))],
)
async def logout(
    request: Request,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    """Sign out THIS device's session (2026-09-26 remediation wave).

    Every bearer now carries a 128-bit jti; logout records it in the
    in-process revocation store with a ttl equal to the token's own
    expiry, and deps.require_user refuses any bearer whose jti is
    resident. Other devices' tokens for the same account stay valid —
    the previous behavior (an unconditional epoch bump killing every
    session at once) remains available as the GLOBAL revocation
    primitive and is still exercised by credential rotation and account
    deletion, where invalidating everything is exactly the point.

    Legacy tokens minted before the jti claim existed cannot be revoked
    individually; for them (and only them) this path falls back to the
    epoch bump, preserving the historical all-devices semantics instead
    of silently accepting an unrevocable logout.

    The lifecycle fence and processing-key purge are unchanged: after
    sign-out returns, nothing may still hold THIS account's data key from
    a session this logout raced (the account-deletion path does the same
    purge).
    """
    bearer = authorization[len("Bearer ") :].strip() if authorization else ""
    try:
        payload = tokens.verify_token(bearer, request.app.state.settings.auth_token_secret)
    except tokens.TokenError:
        # require_user just accepted this token; a failure here means the
        # header was mangled between the two reads. Fail CLOSED — refuse
        # the logout rather than revoking nothing and answering 204.
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized") from None
    if payload.get("ksv", 1) != request.app.state.settings.auth_secret_version:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    # Session creation takes the same fence from its fresh epoch/revocation
    # check through key_store.create(). That makes this commit-plus-purge one
    # lifecycle event: a pre-logout bearer cannot create a new key after the
    # purge has returned.
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        jti = payload.get("jti")
        if isinstance(jti, str) and jti:
            # Independent audit 2026-09-27: the revocation is written to
            # the durable table in the same fenced lifecycle event (the
            # in-memory cache alone died with the process — a deploy or
            # crash resurrected every logged-out bearer until its exp).
            # The commit failure path raises: a logout that cannot make
            # its revocation durable must not answer 204.
            await request.app.state.token_revocations.revoke_durable(
                session, jti, float(payload["exp"])
            )
            await session.commit()
        else:
            # Legacy jti-less bearer: the only honest revocation left is the
            # account-wide epoch bump (single atomic UPDATE, never a
            # read-modify-write — overlapping logouts both bump).
            await session.execute(
                update(User).where(User.id == user.id).values(token_epoch=User.token_epoch + 1)
            )
            await session.commit()
        request.app.state.key_store.destroy_all_for_owner(user.id)
