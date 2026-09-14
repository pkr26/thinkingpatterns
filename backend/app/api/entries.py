"""Entry sync: the server receives, stores, and returns opaque blobs.

It cannot decrypt them (no key) and it never learns their length-bounded
content beyond what the client chose to put in the encrypted payload.

Enforced here beyond blob opacity:
  * entry_date is client-supplied, so it is bounded to "not before the
    account existed (minus one day of timezone grace)" — backdating 30
    distinct days in an afternoon must not fast-forward the 30-day
    progressive-revelation threshold — and to "not after server-UTC today
    plus one day of forward grace" (clients send their DEVICE-LOCAL date:
    a UTC+14 user's morning entry is already tomorrow in UTC, and must not
    be rejected all morning; wider future-dating would let a client write
    entries the threshold counts but the calendar hasn't reached).
  * a per-account storage quota (entry count + total ciphertext bytes)
    bounds recompute/export memory and database growth.
"""

from __future__ import annotations

import base64
import binascii
from datetime import date as date_type, timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_user
from ..locks import UserLocks
from ..models import Entry, User
from ..schemas import EntryCreate, EntryOut, entry_out
from ..security.crypto import MIN_BLOB_SIZE

router = APIRouter(prefix="/entries", tags=["entries"])

# How far before account creation an entry may claim to have been written.
# One day of grace absorbs timezone skew between the client's "today" and
# the server's UTC created_at — and still makes a 30-day backfill impossible.
BACKDATE_GRACE_DAYS = 1

# How far past server-UTC today an entry may claim. The client sends its
# device-local date; east of UTC that date is already tomorrow while the
# user's morning is still ongoing. One day absorbs every real timezone
# (UTC+14 max) without opening meaningful future-dating.
FORWARD_GRACE_DAYS = 1

_user_locks = UserLocks()


def _is_unique_violation(exc: IntegrityError) -> bool:
    """Only a duplicate (user_id, client_entry_id) is a 409; every other
    integrity error (e.g. a FK failure against a just-deleted account on
    SQLite-with-FKs-on or Postgres) must surface as itself, not masquerade
    as 'entry already exists'."""
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    # 23505 unique_violation: psycopg-style drivers call it pgcode, asyncpg
    # calls it sqlstate.
    if getattr(orig, "pgcode", None) == "23505" or getattr(orig, "sqlstate", None) == "23505":
        return True
    return "unique" in str(orig).lower()


def _blob_length(session: AsyncSession):
    """Byte length of a LargeBinary column, per dialect: SQLite's length()
    counts blob bytes; PostgreSQL's length() is text-only, so bytea needs
    octet_length."""
    if session.bind.dialect.name == "postgresql":
        return func.octet_length(Entry.blob)
    return func.length(Entry.blob)


async def _assert_within_quota(session: AsyncSession, user: User, incoming: int, settings) -> None:
    stats = (
        await session.execute(
            select(func.count(Entry.id), func.coalesce(func.sum(_blob_length(session)), 0)).where(
                Entry.user_id == user.id
            )
        )
    ).one()
    count, total_bytes = stats[0], int(stats[1])
    if count >= settings.max_entries_per_user:
        raise ApiError(
            status_code=413,
            detail=f"storage quota reached ({settings.max_entries_per_user} entries)",
            code="quota_exceeded",
        )
    if total_bytes + incoming > settings.max_user_blob_bytes:
        raise ApiError(
            status_code=413,
            detail="storage quota reached (total size)",
            code="blob_quota_exceeded",
        )


@router.post(
    "",
    response_model=EntryOut,
    status_code=201,
    dependencies=[Depends(make_rate_limiter("entries-create", "entries_rate_limit", "entries_rate_window"))],
)
async def create_entry(
    body: EntryCreate,
    request: Request,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        blob = base64.b64decode(body.blob, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(status_code=422, detail="blob must be base64", code="validation_error")
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"blob must be at least {MIN_BLOB_SIZE} bytes",
            code="validation_error",
        )
    today = date_type.today()
    if body.entry_date > today + timedelta(days=FORWARD_GRACE_DAYS):
        raise ApiError(
            status_code=422, detail="entry_date cannot be in the future", code="validation_error"
        )
    # Earliest believable entry: the account's creation day, or the server's
    # today if UTC ran ahead of the client's local calendar — whichever is
    # earlier — minus one day of timezone grace. Bulk backdating (the 30-day
    # threshold fast-forward) stays impossible either way.
    created_day = user.created_at.date() if user.created_at else today
    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)
    if body.entry_date < earliest:
        raise ApiError(
            status_code=422,
            detail="entry_date is before this account existed",
            code="validation_error",
        )

    # Serialize quota-check + insert per user: without the lock, N concurrent
    # creates each see the quota as un-consumed and all commit.
    async with _user_locks.hold(f"entries:{user.id}"):
        await _assert_within_quota(session, user, len(blob), request.app.state.settings)

        existing = await session.execute(
            select(Entry.id).where(Entry.user_id == user.id, Entry.client_entry_id == body.client_entry_id)
        )
        if existing.scalar_one_or_none() is not None:
            raise ApiError(status_code=409, detail="entry already exists", code="conflict")

        row = Entry(
            user_id=user.id,
            client_entry_id=body.client_entry_id,
            blob=blob,
            entry_date=body.entry_date,
        )
        session.add(row)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if _is_unique_violation(exc):
                # Concurrent sync of the same client_entry_id (e.g. an offline
                # queue flushed twice): the unique index decides, the pre-check
                # is fast-path.
                raise ApiError(
                    status_code=409, detail="entry already exists", code="conflict"
                ) from exc
            raise
    await session.refresh(row)
    return entry_out(row)


@router.get(
    "",
    response_model=list[EntryOut],
    dependencies=[Depends(make_rate_limiter("entries-read", "read_rate_limit", "read_rate_window"))],
)
async def list_entries(
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
    since: date_type | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=100, ge=1, le=500),
):
    query = select(Entry).where(Entry.user_id == user.id)
    if since is not None:
        query = query.where(Entry.entry_date >= since)
    query = (
        # id breaks (entry_date, received_at) ties so paginated clients see
        # one stable order across pages.
        query.order_by(Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await session.execute(query)).scalars().all()
    return [entry_out(row) for row in rows]


@router.delete(
    "/{client_entry_id}",
    status_code=204,
    # Deletes hit the database like any other write; leaving them unlimited
    # let a valid token bypass every other bucket with raw DB load.
    dependencies=[Depends(make_rate_limiter("entries-delete", "read_rate_limit", "read_rate_window"))],
)
async def delete_entry(
    client_entry_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        delete(Entry).where(Entry.user_id == user.id, Entry.client_entry_id == client_entry_id)
    )
    if result.rowcount == 0:
        raise ApiError(status_code=404, detail="entry not found", code="not_found")
    await session.commit()
