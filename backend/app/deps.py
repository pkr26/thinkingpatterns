"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User
from .security import tokens


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
    failure = HTTPException(status_code=401, detail="invalid token")
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
    return user
