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
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_user
from ..models import Entry, Insight, User, utcnow
from ..schemas import (
    AccountDeleteRequest,
    ExportBundle,
    InsightOut,
    LlmConsentRequest,
    LlmConsentResponse,
    entry_out,
)
from .auth import _auth_limiter, hash_verifier_off_loop

router = APIRouter(prefix="/account", tags=["account"])

# Version of the disclosure copy the client shows in the consent flow.
# Recorded on every enable so the account can demonstrate WHICH text it
# agreed to (GDPR Art. 7); bump it whenever that copy changes — a consent
# recorded against an older version is the honest answer, not a bug.
LLM_DISCLOSURE_VERSION = "v1"


async def _require_verifier(user: User, body_verifier: str, request: Request) -> None:
    """Password-equivalent proof: scrypt(verifier) must match the stored hash.

    403, not 401: the bearer token authenticated fine — it is the
    re-authentication that failed. Clients treat 401 as "session expired,
    re-login", which would loop forever on a wrong-password answer.
    """
    try:
        verifier_bytes = base64.b64decode(body_verifier, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(status_code=403, detail="invalid credentials", code="verification_failed") from None
    candidate = await hash_verifier_off_loop(
        verifier_bytes, user.scrypt_salt, limiter=_auth_limiter(request)
    )
    if not hmac.compare_digest(candidate, bytes(user.verifier)):
        raise ApiError(status_code=403, detail="invalid credentials", code="verification_failed")


@router.get(
    "/export",
    # Dedicated tight bucket (default 5/min): one export streams up to the
    # whole per-account blob quota — far heavier than the ordinary reads
    # whose bucket it used to share.
    dependencies=[Depends(make_rate_limiter("account-export", "export_rate_limit", "export_rate_window"))],
)
async def export_account(
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Stream everything the server holds: ciphertext only.

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
        head = ExportBundle(
            version=1,
            exported_at=datetime.now(timezone.utc),
            username=user.username,
            user_id=user.id,
            salt=user.salt,
            llm_consent=bool(user.llm_consent),
            llm_consent_at=user.llm_consent_at,
            llm_consent_disclosure=user.llm_consent_disclosure,
            entries=[],
            insights=[],
        )
        yield "{"
        # The head fields only (entries/insights stream below), no braces.
        yield json.dumps(head.model_dump(mode="json", exclude={"entries", "insights"}))[1:-1]
        yield ',"entries":['
        first = True
        async for row in entry_rows:
            yield ("" if first else ",") + json.dumps(entry_out(row).model_dump(mode="json"))
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
            yield ("" if first else ",") + json.dumps(out.model_dump(mode="json"))
            first = False
        yield "]}"

    return StreamingResponse(bundle(), media_type="application/json")


def _consent_response(user: User) -> LlmConsentResponse:
    """Consent flag + its Art. 7 record, shared by the read and write paths."""
    return LlmConsentResponse(
        enabled=bool(user.llm_consent),
        llm_consent_at=user.llm_consent_at,
        llm_consent_disclosure=user.llm_consent_disclosure,
    )


@router.get(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[Depends(make_rate_limiter("account-consent-read", "read_rate_limit", "read_rate_window"))],
)
async def get_llm_consent(
    user: User = Depends(require_user),
) -> LlmConsentResponse:
    """Current consent state, so the client toggle reflects the account."""
    return _consent_response(user)


@router.put(
    "/llm-consent",
    response_model=LlmConsentResponse,
    dependencies=[Depends(make_rate_limiter("account-consent", "auth_rate_limit", "auth_rate_window"))],
)
async def set_llm_consent(
    body: LlmConsentRequest,
    request: Request,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    """Explicit, re-authenticated per-user opt-in for LLM analysis.

    When the operator has configured MINDPATTERN_LLM_URL, journal text is
    only sent to that third-party endpoint for accounts with consent=True.

    Enabling also writes the Art. 7 record (timestamp + disclosure
    version); disabling clears both, so the row never claims a consent it
    no longer holds.
    """
    await _require_verifier(user, body.verifier, request)
    user.llm_consent = body.enabled
    if body.enabled:
        user.llm_consent_at = utcnow()
        user.llm_consent_disclosure = LLM_DISCLOSURE_VERSION
    else:
        user.llm_consent_at = None
        user.llm_consent_disclosure = None
    session.add(user)
    await session.commit()
    return _consent_response(user)


@router.delete(
    "",
    status_code=204,
    dependencies=[Depends(make_rate_limiter("account-delete", "auth_rate_limit", "auth_rate_window"))],
)
async def delete_account(
    request: Request,
    body: AccountDeleteRequest | None = None,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    """Hard delete: user row, all entries, all insights. No tombstones.

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
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    await _require_verifier(user, verifier, request)
    if not user.is_active:
        raise ApiError(status_code=404, detail="account not found", code="not_found")
    request.app.state.key_store.destroy_all_for_owner(user.id)
    await session.execute(delete(Insight).where(Insight.user_id == user.id))
    await session.execute(delete(Entry).where(Entry.user_id == user.id))
    await session.execute(delete(User).where(User.id == user.id))
    await session.commit()
