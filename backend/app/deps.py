"""Shared FastAPI dependencies and the error-envelope contract.

Every error response the API emits (endpoint-raised or default) is::

    {"detail": <human string, never echoing input>, "code": <machine string>}

Endpoints raise :class:`ApiError` with an explicit code; the exception
handler in main.py renders the envelope, falling back to the per-status
defaults below for exceptions raised by the framework itself (404 on
unknown routes, 405, ...). Mobile clients branch on ``code`` and display
``detail`` — both must stay stable, and ``detail`` must stay a STRING
(never the old FastAPI list-of-objects validation shape).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ROLE_THERAPIST, ROLE_USER, User
from .security import tokens

# Codes assigned when the raised exception carries no explicit one.
DEFAULT_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    409: "conflict",
    410: "gone",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


class ApiError(HTTPException):
    """HTTPException carrying the machine-readable `code` of the envelope."""

    def __init__(
        self, status_code: int, detail: str, code: str, headers: dict | None = None
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


async def require_user(
    request: Request,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    # Every failure is the same flat 401: distinguishing expired / bad
    # signature / unknown user / revoked-token only helps token-lifecycle
    # probing.
    failure = ApiError(status_code=401, detail="invalid token", code="unauthorized")
    if not authorization or not authorization.startswith("Bearer "):
        raise failure
    token = authorization[len("Bearer ") :].strip()
    try:
        payload = tokens.verify_token(token, request.app.state.settings.auth_token_secret)
    except tokens.TokenError:
        raise failure from None
    # ksv (2026-09-26 purpose-split secrets): the signing-secret scheme the
    # token was minted under must equal the live one. A token issued under
    # scheme 1 is dead the moment an operator sets MINDPATTERN_AUTH_TOKEN_SECRET
    # — even when its bytes equal the legacy secret, the rotation is
    # EXPLICIT. Tokens without a ksv claim are legacy and count as scheme 1.
    if payload.get("ksv", 1) != request.app.state.settings.auth_secret_version:
        raise failure
    # Single-token revocation (2026-09-26): a logout records the token's
    # jti until its own exp. Legacy jti-less tokens cannot be individually
    # revoked — they remain covered by the account-wide epoch below.
    jti = payload.get("jti")
    if isinstance(jti, str) and request.app.state.token_revocations.is_revoked(jti):
        raise failure
    user = await session.get(User, payload["uid"])
    if user is None or not user.is_active:
        raise failure
    # Epoch check: logout bumped the account's epoch, retiring every token
    # issued before it — stateless tokens still get a server-side kill switch.
    if payload.get("ep", 1) != user.token_epoch:
        raise failure
    # Expose the authenticated jti for in-fence re-checks (the processing-
    # session mint re-verifies revocation inside the lifecycle fence, the
    # same M-2 staleness rule it applies to the epoch). Real requests
    # always carry Starlette state; direct-call test doubles may not —
    # skip the stash rather than fail an otherwise-authenticated call.
    request_state = getattr(request, "state", None)
    if request_state is not None:
        request_state.mindpattern_token_jti = jti if isinstance(jti, str) else None
    # End the auth read transaction immediately: the session stays usable
    # (the next query auto-begins), but the pooled connection is NOT pinned
    # open for the rest of the request — a recompute holds no transaction
    # across its seconds of analysis (Postgres pool pressure). Commit, not
    # rollback: rollback would EXPIRE the user object's attributes, and the
    # first later access would hit the DB synchronously (MissingGreenlet
    # under asyncio). Committing a read-only transaction cannot legitimately
    # fail; if it ever does, re-load so callers still get a usable object.
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        user = await session.get(User, payload["uid"]) or user
    return user


async def require_regular_user(
    user: User = Depends(require_user),
) -> User:
    """Journal-owner endpoints: a therapist token must not reach them. The
    token authenticated fine — the ROLE is wrong — so this is 403
    (forbidden), not 401; a client that treats 401 as "re-login" would
    otherwise loop a logged-in therapist forever."""
    if user.role != ROLE_USER:
        raise ApiError(
            status_code=403,
            detail="therapist accounts cannot access journal endpoints",
            code="forbidden",
        )
    return user


async def require_therapist(
    user: User = Depends(require_user),
) -> User:
    """Sharing endpoints: only therapist accounts. Same 403-not-401 logic,
    mirrored — a patient token is a valid session with the wrong role."""
    if user.role != ROLE_THERAPIST:
        raise ApiError(
            status_code=403,
            detail="not a therapist account",
            code="forbidden",
        )
    return user


async def require_sharing_enabled(request: Request) -> None:
    """Fail closed when the controlled therapist-sharing feature is off.

    A disabled deployment must not expose either public therapist elevation
    or patient pairing/grant routes. Use a flat 404 rather than advertising
    whether a sensitive feature is merely administratively disabled.
    """
    if not bool(getattr(request.app.state.settings, "therapist_sharing_enabled", False)):
        raise ApiError(status_code=404, detail="not found", code="not_found")
