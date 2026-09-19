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

import anyio
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_regular_user
from ..locks import lifecycle_locks, sharing_locks, sharing_patient_lock_key
from ..models import Consent, Entry, Insight, User, utcnow
from ..schemas import (
    AccountDeleteRequest,
    ExportBundle,
    InsightOut,
    LlmConsentRequest,
    LlmConsentResponse,
    ShareRecord,
    entry_out,
)
from .auth import _auth_limiter, auth_work_slot, hash_verifier_off_loop
from ..services import llm

router = APIRouter(prefix="/account", tags=["account"])

# Canonical home is services/llm.py (it feeds the consent-policy
# fingerprint). Re-exported here for the established account-API import
# path used by tests and any older callers.
LLM_DISCLOSURE_VERSION = llm.LLM_DISCLOSURE_VERSION

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


async def _require_verifier(user: User, body_verifier: str, request: Request) -> None:
    """Password-equivalent proof: scrypt(verifier) must match the stored hash.

    403, not 401: the bearer token authenticated fine — it is the
    re-authentication that failed. Clients treat 401 as "session expired,
    re-login", which would loop forever on a wrong-password answer.
    """
    try:
        verifier_bytes = base64.b64decode(body_verifier, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=403, detail="invalid credentials", code="verification_failed"
        ) from None
    async with auth_work_slot(request):
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
    dependencies=[
        Depends(make_rate_limiter("account-export", "export_rate_limit", "export_rate_window"))
    ],
)
async def export_account(
    request: Request,
    user: User = Depends(require_regular_user),
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
        if fresh is None:
            raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
        head = ExportBundle(
            version=1,
            exported_at=cutoff,
            user_id=fresh.id,
            salt=fresh.salt,
            llm_consent=bool(fresh.llm_consent),
            llm_consent_at=fresh.llm_consent_at,
            llm_consent_disclosure=fresh.llm_consent_disclosure,
            llm_consent_policy=fresh.llm_consent_policy,
            # Shares are streamed in bounded metadata pages below, just like
            # ciphertext rows.  Keeping all consent records in this header
            # used an unbounded ``.all()`` before the first response byte.
            shares=[],
            entries=[],
            insights=[],
        )
        await session.commit()
    except Exception:
        if acquired_export_slot and export_limiter is not None:
            export_limiter.release_on_behalf_of(export_borrower)
        raise

    sessionmaker = request.app.state.sessionmaker
    head_json = json.dumps(head.model_dump(mode="json", exclude={"shares", "entries", "insights"}))[
        1:-1
    ]

    async def bundle():
        try:
            yield "{"
            yield head_json
            yield ',"shares":['
            first = True
            share_cursor: tuple | None = None
            while True:
                async with sessionmaker() as page_session:
                    query = (
                        select(Consent, User)
                        .join(User, Consent.therapist_id == User.id)
                        .where(Consent.user_id == fresh.id, Consent.granted_at <= cutoff)
                        .order_by(Consent.granted_at.asc(), Consent.id.asc())
                        .limit(EXPORT_METADATA_PAGE_SIZE)
                    )
                    if share_cursor is not None:
                        last_granted, last_id = share_cursor
                        query = query.where(
                            or_(
                                Consent.granted_at > last_granted,
                                and_(
                                    Consent.granted_at == last_granted,
                                    Consent.id > last_id,
                                ),
                            )
                        )
                    share_rows = (await page_session.execute(query)).all()
                    rendered = [
                        ShareRecord(
                            therapist_username=therapist.username,
                            therapist_display_name=therapist.display_name or therapist.username,
                            status=consent.status,
                            granted_at=consent.granted_at,
                            revoked_at=consent.revoked_at,
                        ).model_dump(mode="json")
                        for consent, therapist in share_rows
                    ]
                    if share_rows:
                        last_consent, _ = share_rows[-1]
                        share_cursor = (last_consent.granted_at, last_consent.id)
                if not rendered:
                    break
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
                        # Fetch selected blobs one at a time.  The lifecycle
                        # fence prevents normal writers from changing their
                        # size; one-at-a-time is also a defensive cap if a
                        # deployment ever bypasses that in-process invariant.
                        for metadata in selected:
                            row = (
                                (
                                    await page_session.execute(
                                        select(Entry).where(
                                            Entry.user_id == fresh.id,
                                            Entry.id == metadata[0],
                                        )
                                    )
                                )
                                .scalars()
                                .first()
                            )
                            if row is None:
                                last_processed = metadata
                                continue
                            blob_bytes = len(bytes(row.blob))
                            if rendered and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
                                page_session.expunge(row)
                                break
                            rendered.append(entry_out(row).model_dump(mode="json"))
                            used_blob_bytes += blob_bytes
                            last_processed = metadata
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
            insight_cursor: tuple | None = None
            while True:
                # Recompute holds the lifecycle fence while it replaces
                # insights.  Taking it here provides the same size stability
                # as entries without pinning it across a slow download.
                async with lifecycle_locks.hold(f"llm-lifecycle:{fresh.id}"):
                    async with sessionmaker() as page_session:
                        query = (
                            select(
                                Insight.id,
                                Insight.created_at,
                                _export_blob_length(page_session, Insight.blob).label("size"),
                            )
                            .where(Insight.user_id == fresh.id, Insight.created_at <= cutoff)
                            .order_by(Insight.created_at.asc(), Insight.id.asc())
                            .limit(EXPORT_METADATA_PAGE_SIZE)
                        )
                        if insight_cursor is not None:
                            last_created, last_id = insight_cursor
                            query = query.where(
                                or_(
                                    Insight.created_at > last_created,
                                    and_(Insight.created_at == last_created, Insight.id > last_id),
                                )
                            )
                        metadata_rows = (await page_session.execute(query)).all()
                        selected = _take_export_metadata_page(metadata_rows)
                        rendered = []
                        used_blob_bytes = 0
                        last_processed = None
                        for metadata in selected:
                            row = (
                                (
                                    await page_session.execute(
                                        select(Insight).where(
                                            Insight.user_id == fresh.id,
                                            Insight.id == metadata[0],
                                        )
                                    )
                                )
                                .scalars()
                                .first()
                            )
                            if row is None:
                                last_processed = metadata
                                continue
                            blob_bytes = len(bytes(row.blob))
                            if rendered and used_blob_bytes + blob_bytes > EXPORT_PAGE_BLOB_BYTES:
                                page_session.expunge(row)
                                break
                            rendered.append(
                                InsightOut(
                                    kind=row.kind,
                                    for_date=row.for_date,
                                    blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
                                    created_at=row.created_at,
                                ).model_dump(mode="json")
                            )
                            used_blob_bytes += blob_bytes
                            last_processed = metadata
                            page_session.expunge(row)
                        if last_processed is not None:
                            insight_cursor = (last_processed[1], last_processed[0])
                if not rendered:
                    # The selected rows may have been deleted between the
                    # metadata and blob queries.  Their cursor was still
                    # advanced, so continue toward later rows instead of
                    # truncating the export at that concurrent mutation.
                    if metadata_rows:
                        continue
                    break
                for item in rendered:
                    yield ("" if first else ",") + json.dumps(item)
                    first = False
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
):
    """Explicit, re-authenticated per-user opt-in for LLM analysis.

    When the operator has configured MINDPATTERN_LLM_URL, journal text is
    only sent to that third-party endpoint for accounts with consent=True.

    Enabling also writes the Art. 7 record (timestamp + disclosure
    version); disabling clears both, so the row never claims a consent it
    no longer holds.
    """
    await _require_verifier(user, body.verifier, request)
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
        policy = llm.processing_policy_fingerprint(request.app.state.settings)
        if body.enabled and policy is None:
            raise ApiError(
                status_code=409,
                detail="third-party analysis is not configured on this server",
                code="llm_unavailable",
            )
        fresh.llm_consent = body.enabled
        if body.enabled:
            fresh.llm_consent_at = utcnow()
            fresh.llm_consent_disclosure = LLM_DISCLOSURE_VERSION
            fresh.llm_consent_policy = policy
        else:
            fresh.llm_consent_at = None
            fresh.llm_consent_disclosure = None
            fresh.llm_consent_policy = None
        session.add(fresh)
        await session.commit()
    return _consent_response(fresh, request.app.state.settings)


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
    # Recompute holds the same lifecycle fence across its fresh consent read
    # and possible external dispatch. Once deletion returns, no queued or
    # in-flight recompute may newly send this account's plaintext off-server.
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        # Patient-sharing reads/grants use this fence while deciding whether
        # an active consent can expose journal ciphertext. Deleting the user
        # inside it makes the account lifecycle linearize with those reads.
        async with sharing_locks.hold(sharing_patient_lock_key(user.id)):
            request.app.state.key_store.destroy_all_for_owner(user.id)
            await session.execute(delete(Insight).where(Insight.user_id == user.id))
            await session.execute(delete(Entry).where(Entry.user_id == user.id))
            await session.execute(delete(User).where(User.id == user.id))
            await session.commit()
