"""Patient-recorded wellbeing measures (measurement-based care, 2026-09-19).

One opaque blob per completed questionnaire (e.g. an in-app PHQ-9). The
server's role is storage and consent-gated relay, exactly like entries:
it cannot decrypt (no key), never parses the payload, and learns only the
calendar date, the ciphertext, and its size. The PATIENT decides to share
by the same therapist-consent machinery as patterns and entries — the
therapist portal decrypts with the per-consent unwrapped data key.

Why the app never interprets a score: MindPattern's charter is
observations, not diagnosis. A patient-entered measure shared with THEIR
clinician keeps interpretation where it belongs — the clinician's — while
giving them trend data between sessions. The sharing disclosure copy
(SHARING_DISCLOSURE_VERSION "v2", 2026-09-20 audit fix H-14) names
measures explicitly; grants recorded under the legacy v1 disclosure do
NOT cover measures — the therapist measures read refuses them with 409
disclosure_outdated rather than serving data the patient never agreed to
share in those terms.

Enforced here beyond blob opacity: the same date bounds as entries (no
pre-account backdating, ≤ server-today+1), a per-account measure count
quota, duplicate-client-id idempotency (409), and per-user serialization
so concurrent creates cannot over-consume the quota.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import date as date_type, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..db import rowcount as db_rowcount
from ..deps import ApiError, get_session, require_regular_user
from ..locks import UserLocks, lifecycle_locks
from ..models import Measure, User
from ..schemas import MeasureCreate, MeasureDeleteResponse, MeasureOut
from ..security.crypto import MIN_BLOB_SIZE
from ._audit import append_access_log
from ._paging import (
    MAX_COLLECTION_REVISION,
    assert_expected_revision,
    collection_changed_error,
    emit_page_headers,
    parse_expected_revision,
    select_byte_page,
    verify_fetched_page,
)

router = APIRouter(prefix="/measures", tags=["measures"])

# Same grace semantics as entries (see entries.py for the reasoning):
# one day back absorbs timezone skew without enabling a backfill, one day
# forward absorbs every real timezone east of UTC.
BACKDATE_GRACE_DAYS = 1
FORWARD_GRACE_DAYS = 1

# A weekly measure over four decades; generous for the use, bounded for the
# database. Measures are tiny (scores, not prose).
MAX_MEASURES_PER_USER = 2000

# Page ceiling for BOTH measure read paths (patient + therapist mirror,
# 2026-09-20 audit fix M-4). The old 100/200-row cliffs made measure
# #201+ stored-and-quota-charged but invisible on every read path while
# the write quota is 2000; the deterministic (measure_date, received_at,
# id) ordering plus offset paging lets clients walk the whole history.
MEASURE_PAGE_LIMIT = 500

# 2026-09-21 audit A-3: measures join the entries pagination contract.
# A hard per-response ciphertext budget (a legacy 500-row page of 8 KiB
# blobs was ~4 MB of base64 on the wire), an explicit page_bytes opt-in
# with X-Next-Offset continuation, and an optimistic revision marker so
# a concurrent create can never let an offset continuation duplicate or
# skip rows silently.
MEASURE_PAGE_BLOB_BYTES = 2 * 1024 * 1024
MEASURES_REVISION_HEADER = "X-Measures-Revision"

_user_locks = UserLocks()


def _measure_blob_length(session: AsyncSession):
    """Byte length of the measure blob, per dialect (same shape as entries'
    _blob_length: octet_length on Postgres, length on SQLite)."""
    if session.bind.dialect.name == "postgresql":
        return func.octet_length(Measure.blob)
    return func.length(Measure.blob)


async def current_measures_revision(session: AsyncSession, user_id: str) -> int:
    """Return a freshly selected measure collection marker (entries'
    current_entries_revision contract: a missing owner is a lifecycle
    fence violation and must force a retry, never a bare offset page)."""
    revision = await session.scalar(select(User.measures_revision).where(User.id == user_id))
    if revision is None:
        raise collection_changed_error("measures", MEASURES_REVISION_HEADER)
    return int(revision)


async def _increment_measures_revision(session: AsyncSession, user: User) -> int:
    """Atomically advance the owner's measure marker in the write
    transaction (mirror of entries' _increment_entries_revision)."""
    result = await session.execute(
        update(User)
        .where(User.id == user.id, User.measures_revision < MAX_COLLECTION_REVISION)
        .values(measures_revision=User.measures_revision + 1)
    )
    if db_rowcount(result) != 1:
        # Do not commit the paired measure write if the marker cannot
        # advance: an unmarked mutation could otherwise make a
        # continuation drift.
        raise ApiError(
            status_code=503,
            detail="unable to advance measures revision; retry shortly",
            code="service_unavailable",
            headers={"Retry-After": "1"},
        )
    await session.refresh(user, attribute_names=["measures_revision"])
    return user.measures_revision


def _utc_today() -> date_type:
    """Server-UTC calendar day (2026-09-20 audit fix L-5).

    ``date.today()`` answers in the HOST's local timezone; the grace-day
    contract ("≤ server-UTC today + 1") and the threshold math both
    assume UTC. On any non-UTC host the local answer drifts by hours and
    rejects/accepts the wrong edge entries near midnight.
    """
    return datetime.now(timezone.utc).date()


def _decode_measure_blob(value: str) -> bytes:
    """b64 → bytes with the same 4xx discipline as entries: bad base64 is
    a client bug (422/validation_error — aligned with entries' envelope
    by 2026-09-20 audit fix L-7; clients branch on `code` and the two
    modules must not diverge for identical client errors), never a 500,
    and never echoes the payload."""
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(
            status_code=422, detail="blob must be base64", code="validation_error"
        ) from exc
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"blob must be at least {MIN_BLOB_SIZE} bytes",
            code="validation_error",
        )
    return blob


def _validate_measure_date(measure_date: date_type, user: User) -> None:
    today = _utc_today()
    if measure_date > today + timedelta(days=FORWARD_GRACE_DAYS):
        raise ApiError(
            status_code=422,
            detail="measure_date cannot be in the future",
            code="validation_error",
        )
    # entries.py's twin guards a NULL created_at (defensive parity — the
    # column is NOT NULL with an ORM default, but the two modules
    # implementing the same grace semantics must not disagree).
    created_day = user.created_at.date() if user.created_at else today
    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)
    if measure_date < earliest:
        raise ApiError(
            status_code=422,
            detail="measure_date cannot predate the account",
            code="validation_error",
        )


async def _fresh_active_measure_user(
    session: AsyncSession, user_id: str, expected_epoch: int
) -> User:
    """Re-check a measure mutation's authorization inside the lifecycle
    fence (2026-09-20 audit fix M-3, mirroring entries
    ``_fresh_active_entry_user``): a bearer that authenticated before a
    logout but acquires the fence afterwards must fail closed — including
    on ``token_epoch``, so a retired token can never complete a measure
    insert after the logout commit. 401/unauthorized, the same envelope
    entries uses (L-7 alignment; the old 410/account_deleted drifted)."""
    fresh = await session.get(User, user_id, populate_existing=True)
    if fresh is None or not fresh.is_active or fresh.token_epoch != expected_epoch:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    return fresh


def _measure_out(row: Measure) -> MeasureOut:
    return MeasureOut(
        id=row.id,
        client_measure_id=row.client_measure_id,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        measure_date=row.measure_date,
        received_at=row.received_at,
    )


@router.post(
    "",
    response_model=MeasureOut,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("measures", "entries_rate_limit", "entries_rate_window"))
    ],
)
async def create_measure(
    body: MeasureCreate,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    blob = _decode_measure_blob(body.blob)
    # Capture the epoch this request authenticated under BEFORE waiting on
    # the fences (2026-09-20 audit fix M-3): a logout/deletion can commit
    # while we are queued, and the in-fence re-check below must see it.
    expected_epoch = user.token_epoch

    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"measures:{user.id}"):
            fresh_user = await _fresh_active_measure_user(session, user.id, expected_epoch)
            _validate_measure_date(body.measure_date, fresh_user)

            # Duplicate BEFORE quota (2026-09-20 audit fix L-6, same fix as
            # entries): an idempotent retry of an already-stored
            # client_measure_id at the quota boundary used to answer 413,
            # so an offline queue could not tell "already applied" from
            # "genuinely full" and would wedge. The duplicate answer (409)
            # must win — it is the terminal, correct verdict for a retry.
            existing = await session.execute(
                select(Measure.id).where(
                    Measure.user_id == fresh_user.id,
                    Measure.client_measure_id == body.client_measure_id,
                )
            )
            if existing.scalar_one_or_none() is not None:
                raise ApiError(status_code=409, detail="measure already exists", code="conflict")

            count = (
                await session.execute(
                    select(func.count())
                    .select_from(Measure)
                    .where(Measure.user_id == fresh_user.id)
                )
            ).scalar_one()
            if count >= MAX_MEASURES_PER_USER:
                raise ApiError(
                    status_code=413,
                    detail="measure quota exceeded",
                    code="quota_exceeded",
                )

            row = Measure(
                user_id=fresh_user.id,
                client_measure_id=body.client_measure_id,
                blob=blob,
                measure_date=body.measure_date,
            )
            session.add(row)
            # 2026-09-21 audit A-3: the create advances the measure marker
            # in the same transaction, so a mid-pagination client sees
            # collection_changed instead of silently shifted offsets.
            await _increment_measures_revision(session, fresh_user)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                orig = getattr(exc, "orig", None)
                duplicate = (
                    (
                        getattr(orig, "pgcode", None) == "23505"
                        or getattr(orig, "sqlstate", None) == "23505"
                        or "unique" in str(orig).lower()
                    )
                    if orig is not None
                    else False
                )
                if duplicate:
                    # Concurrent sync of the same client_measure_id: the
                    # unique index decides, the pre-check is the fast path.
                    raise ApiError(
                        status_code=409, detail="measure already exists", code="conflict"
                    ) from exc
                raise
            await session.refresh(row)
            response = _measure_out(row)
            await session.commit()
    return response


@router.get(
    "",
    response_model=list[MeasureOut],
    dependencies=[
        Depends(make_rate_limiter("measures-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def list_measures(
    response: Response,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=100, ge=1, le=MEASURE_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=100_000),
    page_bytes: int | None = Query(default=None, ge=1, le=MEASURE_PAGE_BLOB_BYTES),
    expected_revision: str | None = None,
):
    """The patient's own measures, newest completion first.

    The entries pagination contract, ported 2026-09-21 (audit A-3).
    ``page_bytes`` is the explicit modern-client opt-in to a short page and
    ``X-Next-Offset`` continuation; a legacy client never receives a
    silently truncated page — a page over the hard ciphertext budget is an
    explicit 413. ``X-Measures-Revision`` carries the snapshot marker;
    passing it back as ``expected_revision`` makes any concurrent create
    answer 409 collection_changed instead of letting offset paging
    duplicate or skip rows on the DESC list. Metadata (id + byte length)
    is selected first; the database never materializes full blobs just to
    discover a response would be too large. ``id`` breaks
    (measure_date, received_at) ties for one stable order across pages.
    """
    expected = parse_expected_revision(expected_revision)
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        revision = await current_measures_revision(session, user.id)
        assert_expected_revision(
            expected,
            revision,
            collection="measures",
            header_name=MEASURES_REVISION_HEADER,
        )
        metadata = (
            await session.execute(
                select(Measure.id, _measure_blob_length(session).label("blob_bytes"))
                .where(Measure.user_id == user.id)
                .order_by(
                    Measure.measure_date.desc(),
                    Measure.received_at.desc(),
                    Measure.id.desc(),
                )
                .offset(offset)
                # The extra metadata-only row says whether a full
                # item-count page has more history without loading
                # another ciphertext.
                .limit(limit + 1)
            )
        ).all()
        requested = [(str(row[0]), int(row[1])) for row in metadata[:limit]]

        page = select_byte_page(
            requested,
            more_after_request=len(metadata) > limit,
            page_bytes=page_bytes,
            hard_budget=MEASURE_PAGE_BLOB_BYTES,
            collection="measure",
        )

        selected_ids = [measure_id for measure_id, _ in page.selected]
        ordered_rows: list[Measure] = []
        if selected_ids:
            rows = (
                (
                    await session.execute(
                        select(Measure).where(
                            Measure.user_id == user.id, Measure.id.in_(selected_ids)
                        )
                    )
                )
                .scalars()
                .all()
            )
            ordered_rows = verify_fetched_page(
                selected_ids,
                rows,
                byte_limit=page_bytes if page_bytes is not None else MEASURE_PAGE_BLOB_BYTES,
                collection="measures",
                header_name=MEASURES_REVISION_HEADER,
                revision=revision,
            )

        result = [_measure_out(row) for row in ordered_rows]
        final_revision = await current_measures_revision(session, user.id)
        if final_revision != revision:
            raise collection_changed_error("measures", MEASURES_REVISION_HEADER, final_revision)
        emit_page_headers(
            response,
            revision=revision,
            header_name=MEASURES_REVISION_HEADER,
            has_more=page.has_more,
            rows_returned=len(result),
            offset=offset,
        )
    return result


@router.delete(
    "/{client_measure_id}",
    response_model=MeasureDeleteResponse,
    # 2026-09-26 audit item 21: a wrongly-recorded measure previously had NO
    # correction path — the patient's only recourse was deleting the whole
    # account. Deletes hit the database like any other write and join the
    # same bucket family the entry delete uses.
    dependencies=[
        Depends(make_rate_limiter("measures-delete", "read_rate_limit", "read_rate_window"))
    ],
)
async def delete_measure(
    client_measure_id: str,
    request: Request,
    response: Response,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    x_account_verifier: str | None = Header(default=None),
):
    """Hard-delete one recorded measure (verifier-gated correction path).

    2026-09-26 audit item 21. A measure is patient-authored content; a
    mis-recorded questionnaire row is the patient's error to correct, but
    the correction is DESTRUCTIVE and re-authenticated with the password
    verifier exactly like every other destructive action (account deletion,
    credential rotation, rekey): a stolen bearer must not be able to erase
    a wellbeing history. The same lifecycle/epoch fence as every measure
    mutation applies, the delete and the measures_revision advance commit
    atomically (a paged client sees collection_changed instead of silent
    offset drift), and the deletion is audit-logged through the chained
    append (action ``delete_measure``) so the trail records the correction.
    """
    # Deferred import: account.py imports this module's helpers at module
    # level, so a module-level back-import would cycle.
    from .account import _require_verifier

    verifier = x_account_verifier if isinstance(x_account_verifier, str) else None
    if verifier is None:
        raise ApiError(
            status_code=422,
            detail="account verifier required (X-Account-Verifier header)",
            code="validation_error",
        )
    # Same malformed-id guard the entries paths enforce (2026-09-28 deep
    # audit symmetry fix — identical verdict, one shared shape).
    from ..schemas import CLIENT_ID_PATTERN as _MEASURE_ID_PATTERN

    if re.fullmatch(_MEASURE_ID_PATTERN, client_measure_id) is None:
        raise ApiError(status_code=404, detail="measure not found", code="not_found")
    expected_epoch = user.token_epoch
    await _require_verifier(user, verifier, request, session)
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"measures:{user.id}"):
            fresh_user = await _fresh_active_measure_user(session, user.id, expected_epoch)
            result = await session.execute(
                delete(Measure).where(
                    Measure.user_id == fresh_user.id,
                    Measure.client_measure_id == client_measure_id,
                )
            )
            if db_rowcount(result) == 0:
                raise ApiError(status_code=404, detail="measure not found", code="not_found")
            await append_access_log(
                session,
                actor_id=fresh_user.id,
                actor_role=fresh_user.role,
                user_id=fresh_user.id,
                action="delete_measure",
            )
            new_revision = await _increment_measures_revision(session, fresh_user)
            response.headers[MEASURES_REVISION_HEADER] = str(new_revision)
            await session.commit()
            return MeasureDeleteResponse(measures_revision=new_revision)
