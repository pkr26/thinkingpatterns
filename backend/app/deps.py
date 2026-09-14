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

from .models import User
from .security import tokens

# Codes assigned when the raised exception carries no explicit one.
DEFAULT_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
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

    def __init__(self, status_code: int, detail: str, code: str, headers: dict | None = None) -> None:
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
    # signature / unknown user only helps token-lifecycle probing.
    failure = ApiError(status_code=401, detail="invalid token", code="unauthorized")
    if not authorization or not authorization.startswith("Bearer "):
        raise failure
    token = authorization[len("Bearer "):].strip()
    try:
        payload = tokens.verify_token(token, request.app.state.settings.token_secret)
    except tokens.TokenError:
        raise failure from None
    user = await session.get(User, payload["uid"])
    if user is None or not user.is_active:
        raise failure
    # Epoch check: logout bumped the account's epoch, retiring every token
    # issued before it — stateless tokens still get a server-side kill switch.
    if payload.get("ep", 1) != user.token_epoch:
        raise failure
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
