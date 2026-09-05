"""Account management: ciphertext export, consent, and hard deletion.

Destructive and privacy-relevant operations re-authenticate: deleting the
account or enabling third-party LLM analysis requires the password-derived
verifier, so a stolen bearer token alone can neither erase a journal nor
widen its disclosure. Deletion also purges any in-memory processing-session
keys for the account.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import get_session, require_user
from ..models import Entry, Insight, User
from ..schemas import AccountDeleteRequest, EntryOut, InsightOut, LlmConsentRequest, LlmConsentResponse
from .auth import hash_verifier_off_loop

router = APIRouter(prefix="/account", tags=["account"])


async def _require_verifier(user: User, body_verifier: str) -> None:
    """Password-equivalent proof: scrypt(verifier) must match the stored hash."""
    try:
        verifier_bytes = base64.b64decode(body_verifier, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=401, detail="invalid credentials") from None
    candidate = await hash_verifier_off_loop(verifier_bytes, user.scrypt_salt)
    if not hmac.compare_digest(candidate, bytes(user.verifier)):
        raise HTTPException(status_code=401, detail="invalid credentials")


@router.get(
    "/export",
    dependencies=[Depends(make_rate_limiter("account-read", "read_rate_limit", "read_rate_window"))],
)
async def export_account(
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Stream everything the server holds: ciphertext only.

    The response is assembled incrementally (one entry per chunk) so a
    long journal cannot be materialized in memory as a single response
    object. The client decrypts locally with its derived data key — the
    server cannot produce plaintext exports because it never holds the key.
    """

    async def bundle():
        # stream(): rows are fetched lazily so a long journal is never fully
        # materialized in memory while the response is assembled.
        entry_rows = (
            await session.stream(
                select(Entry).where(Entry.user_id == user.id).order_by(Entry.entry_date.asc())
            )
        ).scalars()
        insight_rows = (
            await session.stream(
                select(Insight).where(Insight.user_id == user.id).order_by(Insight.created_at.asc())
            )
        ).scalars()
        head = {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "username": user.username,
            "user_id": user.id,
            "salt": user.salt,
            "llm_consent": bool(user.llm_consent),
        }
        yield "{"
        yield json.dumps(head, default=str)[1:-1]  # inner fields, no braces
        yield ',"entries":['
        first = True
        async for row in entry_rows:
            out = EntryOut(
                id=row.id,
                client_entry_id=row.client_entry_id,
                blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
                entry_date=row.entry_date,
                received_at=row.received_at,
            )
            yield ("" if first else ",") + json.dumps(out.model_dump(), default=str)
            first = False
        yield '],"insights":['
        first = True
        async for row in insight_rows:
            out = InsightOut(
                kind=row.kind,
                for_date=row.for_date,
                blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
                created_at=row.created_at,
            )
            yield ("" if first else ",") + json.dumps(out.model_dump(), default=str)
            first = False
        yield "]}"

    return StreamingResponse(bundle(), media_type="application/json")


@router.get(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[Depends(make_rate_limiter("account-consent-read", "read_rate_limit", "read_rate_window"))],
)
async def get_llm_consent(
    user: User = Depends(require_user),
) -> LlmConsentResponse:
    """Current consent state, so the client toggle reflects the account."""
    return LlmConsentResponse(enabled=bool(user.llm_consent))


@router.put(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[Depends(make_rate_limiter("account-consent", "auth_rate_limit", "auth_rate_window"))],
)
async def set_llm_consent(
    body: LlmConsentRequest,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Explicit, re-authenticated per-user opt-in for LLM analysis.

    When the operator has configured MINDPATTERN_LLM_URL, journal text is
    only sent to that third-party endpoint for accounts with consent=True.
    """
    await _require_verifier(user, body.verifier)
    user.llm_consent = body.enabled
    session.add(user)
    await session.commit()
    return LlmConsentResponse(enabled=user.llm_consent)


@router.delete(
    "",
    status_code=204,
    dependencies=[Depends(make_rate_limiter("account-delete", "auth_rate_limit", "auth_rate_window"))],
)
async def delete_account(
    body: AccountDeleteRequest,
    request: Request,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Hard delete: user row, all entries, all insights. No tombstones.

    Requires the verifier (password proof) — a bearer token alone must not
    be able to permanently destroy a journal. In-memory processing-session
    keys for this account are wiped alongside the rows.
    """
    await _require_verifier(user, body.verifier)
    if not user.is_active:
        raise HTTPException(status_code=404, detail="account not found")
    request.app.state.key_store.destroy_all_for_owner(user.id)
    await session.execute(delete(Insight).where(Insight.user_id == user.id))
    await session.execute(delete(Entry).where(Entry.user_id == user.id))
    await session.execute(delete(User).where(User.id == user.id))
    await session.commit()
