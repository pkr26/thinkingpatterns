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
from datetime import date as date_type, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
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

# Page ceiling for BOTH measure read paths (patient + therapist mirror,
# 2026-09-20 audit fix M-4). The old 100/200-row cliffs made measure
# #201+ stored-and-quota-charged but invisible on every read path while
# the write quota is 2000; the deterministic (measure_date, received_at,
# id) ordering plus offset paging lets clients walk the whole history.
MEASURE_PAGE_LIMIT = 500

_user_locks = UserLocks()


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
    earliest = min(user.created_at.date(), today) - timedelta(days=BACKDATE_GRACE_DAYS)
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
    limit: int = Query(default=100, ge=1, le=MEASURE_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=100_000),
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """The patient's own measures, newest completion first.

    Offset paging (2026-09-20 audit fix M-4): the write quota is 2000 but
    reads used to hard-cap at 100-200 rows with no continuation, so
    measure #201+ was stored and quota-charged yet invisible to the
    patient, the therapist, and the export. ``id`` breaks
    (measure_date, received_at) ties — without a deterministic total order
    an offset page can skip or repeat a row across pages. Clients page by
    offset until a short page.
    """
    rows = (
        (
            await session.execute(
                select(Measure)
                .where(Measure.user_id == user.id)
                .order_by(
                    Measure.measure_date.desc(),
                    Measure.received_at.desc(),
                    Measure.id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [_measure_out(row) for row in rows]
