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
giving them trend data between sessions. The sharing disclosure copy (v2)
names measures explicitly.

Enforced here beyond blob opacity: the same date bounds as entries (no
pre-account backdating, ≤ server-today+1), a per-account measure count
quota, duplicate-client-id idempotency (409), and per-user serialization
so concurrent creates cannot over-consume the quota.
"""

from __future__ import annotations

import base64
import binascii
from datetime import date as date_type, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_regular_user
from ..locks import UserLocks, lifecycle_locks
from ..models import Measure, User
from ..schemas import MeasureCreate, MeasureOut
from ..security.crypto import MIN_BLOB_SIZE

router = APIRouter(prefix="/measures", tags=["measures"])

# Same grace semantics as entries (see entries.py for the reasoning):
# one day back absorbs timezone skew without enabling a backfill, one day
# forward absorbs every real timezone east of UTC.
BACKDATE_GRACE_DAYS = 1
FORWARD_GRACE_DAYS = 1

# A weekly measure over four decades; generous for the use, bounded for
# the database. Measures are tiny (scores, not prose).
MAX_MEASURES_PER_USER = 2000

MEASURE_PAGE_LIMIT = 200

_user_locks = UserLocks()


def _decode_measure_blob(value: str) -> bytes:
    """b64 → bytes with the same 4xx discipline as entries: bad base64 is
    a client bug (422 via schema length is not possible here, so 400),
    never a 500, and never echoes the payload."""
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(
            status_code=400, detail="measure blob is not valid base64", code="bad_request"
        ) from exc
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(status_code=400, detail="measure blob is too small", code="bad_request")
    return blob


def _validate_measure_date(measure_date: date_type, user: User) -> None:
    today = date_type.today()
    if measure_date > today + timedelta(days=FORWARD_GRACE_DAYS):
        raise ApiError(
            status_code=422,
            detail="measure_date cannot be in the future",
            code="validation_error",
        )
    earliest = min(user.created_at.date(), today) - timedelta(days=BACKDATE_GRACE_DAYS)
    if measure_date < earliest:
        raise ApiError(
            status_code=422,
            detail="measure_date cannot predate the account",
            code="validation_error",
        )


async def _fresh_active_user(session: AsyncSession, user_id: str) -> User:
    fresh = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if fresh is None or not fresh.is_active:
        raise ApiError(status_code=410, detail="account no longer exists", code="account_deleted")
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

    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"measures:{user.id}"):
            fresh_user = await _fresh_active_user(session, user.id)
            _validate_measure_date(body.measure_date, fresh_user)

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

            existing = await session.execute(
                select(Measure.id).where(
                    Measure.user_id == fresh_user.id,
                    Measure.client_measure_id == body.client_measure_id,
                )
            )
            if existing.scalar_one_or_none() is not None:
                raise ApiError(status_code=409, detail="measure already exists", code="conflict")

            row = Measure(
                user_id=fresh_user.id,
                client_measure_id=body.client_measure_id,
                blob=blob,
                measure_date=body.measure_date,
            )
            session.add(row)
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
    limit: int = 100,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """The patient's own measures, newest completion first. Pagination is
    deliberately simple: measures are few and small; the limit is capped."""
    bounded = max(1, min(limit, MEASURE_PAGE_LIMIT))
    rows = (
        (
            await session.execute(
                select(Measure)
                .where(Measure.user_id == user.id)
                .order_by(Measure.measure_date.desc(), Measure.received_at.desc())
                .limit(bounded)
            )
        )
        .scalars()
        .all()
    )
    return [_measure_out(row) for row in rows]
