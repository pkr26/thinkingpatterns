"""Entry sync: the server receives, stores, and returns opaque blobs.

It cannot decrypt them (no key) and it never learns their length-bounded
content beyond what the client chose to put in the encrypted payload.

Enforced here beyond blob opacity:
  * entry_date is client-supplied, so it is bounded to "not before the
    account existed (minus one day of timezone grace)" — backdating 30
    distinct days in an afternoon must not fast-forward the 30-day
    progressive-revelation threshold.
  * a per-account storage quota (entry count + total ciphertext bytes)
    bounds recompute/export memory and database growth.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date as date_type, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import get_session, require_user
from ..models import Entry, User
from ..schemas import EntryCreate, EntryOut
from ..security.crypto import MIN_BLOB_SIZE

router = APIRouter(prefix="/entries", tags=["entries"])

# How far before account creation an entry may claim to have been written.
# One day of grace absorbs timezone skew between the client's "today" and
# the server's UTC created_at — and still makes a 30-day backfill impossible.
BACKDATE_GRACE_DAYS = 1


class _UserLocks:
    """Per-user asyncio locks serializing quota-check + insert.

    The quota is otherwise a check-then-insert race: N concurrent creates
    each observe quota-N free and all commit, overshooting both the entry
    count and the byte total. The deployment is single-process per instance
    (documented in the README), so an in-process lock is the authority; the
    registry is bounded and only idle entries are recycled.

    "Idle" is tracked by a refcount, not by lock.locked(): between a
    release() and a waiter's re-acquire a lock reports locked() == False,
    so evicting on locked() alone could drop a lock a waiter is parked on
    — orphaning that waiter while the next get() mints a second lock for
    the same key. The refcount is incremented synchronously (no await)
    before the caller blocks on acquire, closing that window.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        # key -> [lock, live holders+waiters]
        self._locks: dict[str, list] = {}
        self._max_keys = max_keys

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[asyncio.Lock]:
        entry = self._locks.get(key)
        if entry is None:
            if len(self._locks) >= self._max_keys:
                for stale in [
                    k for k, v in self._locks.items() if v[1] == 0
                ][: len(self._locks) - self._max_keys + 1]:
                    del self._locks[stale]
            entry = [asyncio.Lock(), 0]
            self._locks[key] = entry
        entry[1] += 1
        try:
            async with entry[0]:
                yield entry[0]
        finally:
            entry[1] -= 1


_user_locks = _UserLocks()


def _is_unique_violation(exc: IntegrityError) -> bool:
    """Only a duplicate (user_id, client_entry_id) is a 409; every other
    integrity error (e.g. a FK failure against a just-deleted account on
    SQLite-with-FKs-on or Postgres) must surface as itself, not masquerade
    as 'entry already exists'."""
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    pgcode = getattr(orig, "pgcode", None)
    if pgcode == "23505":
        return True
    return "unique" in str(orig).lower()


def _to_out(row: Entry) -> EntryOut:
    return EntryOut(
        id=row.id,
        client_entry_id=row.client_entry_id,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        entry_date=row.entry_date,
        received_at=row.received_at,
    )


async def _assert_within_quota(session: AsyncSession, user: User, incoming: int, settings) -> None:
    stats = (
        await session.execute(
            select(func.count(Entry.id), func.coalesce(func.sum(func.length(Entry.blob)), 0)).where(
                Entry.user_id == user.id
            )
        )
    ).one()
    count, total_bytes = stats[0], int(stats[1])
    if count >= settings.max_entries_per_user:
        raise HTTPException(
            status_code=413,
            detail=f"storage quota reached ({settings.max_entries_per_user} entries)",
        )
    if total_bytes + incoming > settings.max_user_blob_bytes:
        raise HTTPException(status_code=413, detail="storage quota reached (total size)")


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
        raise HTTPException(status_code=422, detail="blob must be base64")
    if len(blob) < MIN_BLOB_SIZE:
        raise HTTPException(status_code=422, detail=f"blob must be at least {MIN_BLOB_SIZE} bytes")
    if body.entry_date > date_type.today():
        raise HTTPException(status_code=422, detail="entry_date cannot be in the future")
    # Earliest believable entry: the account's creation day, or the server's
    # today if UTC ran ahead of the client's local calendar — whichever is
    # earlier — minus one day of timezone grace. Bulk backdating (the 30-day
    # threshold fast-forward) stays impossible either way.
    created_day = user.created_at.date() if user.created_at else date_type.today()
    earliest = min(created_day, date_type.today()) - timedelta(days=BACKDATE_GRACE_DAYS)
    if body.entry_date < earliest:
        raise HTTPException(
            status_code=422, detail="entry_date is before this account existed"
        )

    # Serialize quota-check + insert per user: without the lock, N concurrent
    # creates each see the quota as un-consumed and all commit.
    async with _user_locks.hold(f"entries:{user.id}"):
        await _assert_within_quota(session, user, len(blob), request.app.state.settings)

        existing = await session.execute(
            select(Entry.id).where(Entry.user_id == user.id, Entry.client_entry_id == body.client_entry_id)
        )
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(status_code=409, detail="entry already exists")

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
                raise HTTPException(status_code=409, detail="entry already exists") from exc
            raise
    await session.refresh(row)
    return _to_out(row)


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
    return [_to_out(row) for row in rows]


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
        raise HTTPException(status_code=404, detail="entry not found")
    await session.commit()
