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
import re
from datetime import date as date_type, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..db import rowcount as db_rowcount
from ..deps import ApiError, get_session, require_regular_user
from ..locks import UserLocks, lifecycle_locks
from ..models import Entry, User
from ..schemas import CLIENT_ID_PATTERN, EntryCreate, EntryOut, EntryReplace, entry_out
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

# A journal entry may legitimately carry about 1.1 MiB of ciphertext, but a
# 500-row response used to turn one ordinary history request into hundreds of
# MiB of base64 JSON.  Bound a page by *raw* ciphertext bytes; base64/JSON
# overhead means the wire response is larger, but still remains a deliberately
# small, mobile-manageable unit.  The schema's single-entry ceiling is below
# this value, so a valid entry can always fit in one page.
ENTRY_PAGE_BLOB_BYTES = 2 * 1024 * 1024

# Revision values travel in an HTTP header and optional query parameter.  Keep
# their grammar canonical and bounded to the signed 64-bit database column:
# this rejects parser-friendly but framing-ambiguous forms such as ``+1``,
# ``01``, whitespace, and Unicode digits.
MAX_COLLECTION_REVISION = 2**63 - 1
ENTRIES_REVISION_HEADER = "X-Entries-Revision"
_EXPECTED_REVISION_RE = re.compile(r"(?:0|[1-9][0-9]{0,18})")

_user_locks = UserLocks()
_CLIENT_ENTRY_ID_RE = re.compile(CLIENT_ID_PATTERN)


def parse_expected_revision(value: str | None) -> int | None:
    """Parse a client snapshot marker without accepting permissive int forms."""
    if value is None:
        return None
    if not isinstance(value, str) or _EXPECTED_REVISION_RE.fullmatch(value) is None:
        raise ApiError(
            status_code=422,
            detail="expected_revision must be a canonical non-negative decimal",
            code="validation_error",
        )
    revision = int(value)
    if revision > MAX_COLLECTION_REVISION:
        raise ApiError(
            status_code=422,
            detail="expected_revision must be a canonical non-negative decimal",
            code="validation_error",
        )
    return revision


def collection_changed_error(
    collection: str, header_name: str, current_revision: int | None = None
) -> ApiError:
    """Retryable conflict for a collection that moved between page requests."""
    headers = {header_name: str(current_revision)} if current_revision is not None else None
    return ApiError(
        status_code=409,
        detail=f"{collection} changed while paging; retry the request",
        code="collection_changed",
        headers=headers,
    )


def assert_expected_revision(
    expected_revision: int | None,
    current_revision: int,
    *,
    collection: str,
    header_name: str,
) -> None:
    if expected_revision is not None and expected_revision != current_revision:
        raise collection_changed_error(collection, header_name, current_revision)


async def current_entries_revision(session: AsyncSession, user_id: str) -> int:
    """Return a freshly selected entry collection marker.

    A missing owner can only arise when a deployment violates the normal
    lifecycle fence across processes.  It is still safer to make a caller
    retry than to emit an offset page without a valid snapshot marker.
    """
    revision = await session.scalar(select(User.entries_revision).where(User.id == user_id))
    if revision is None:
        raise collection_changed_error("entries", ENTRIES_REVISION_HEADER)
    return int(revision)


async def _increment_entries_revision(session: AsyncSession, user: User) -> int:
    """Atomically advance an owner's entry marker in the write transaction."""
    result = await session.execute(
        update(User)
        .where(User.id == user.id, User.entries_revision < MAX_COLLECTION_REVISION)
        .values(entries_revision=User.entries_revision + 1)
    )
    if db_rowcount(result) != 1:
        # Do not commit the paired entry write if the marker cannot advance:
        # an unmarked mutation could otherwise make a continuation drift.
        raise ApiError(
            status_code=503,
            detail="unable to advance entries revision; retry shortly",
            code="service_unavailable",
            headers={"Retry-After": "1"},
        )
    # UPDATE synchronization differs by driver/session configuration; an
    # explicit refresh keeps a subsequently reused ORM user authoritative.
    await session.refresh(user, attribute_names=["entries_revision"])
    return user.entries_revision


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
    """Byte length of a LargeBinary column, per dialect. Postgres's
    octet_length is the unambiguous bytea size function (length() DOES
    accept bytea there, but naming it explicitly keeps the intent obvious
    and dialect-symmetric); SQLite's length() counts blob bytes. Shared by
    the entries quota check and the recompute corpus loader (insights.py)
    so the two can never drift apart."""
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


async def _assert_replacement_within_quota(
    session: AsyncSession, user: User, old_size: int, incoming: int, settings
) -> None:
    """The entry count is unchanged by PUT; enforce only the adjusted bytes."""
    total = int(
        (
            await session.execute(
                select(func.coalesce(func.sum(_blob_length(session)), 0)).where(
                    Entry.user_id == user.id
                )
            )
        ).scalar_one()
    )
    if total - old_size + incoming > settings.max_user_blob_bytes:
        raise ApiError(
            status_code=413,
            detail="storage quota reached (total size)",
            code="blob_quota_exceeded",
        )


def _decode_entry_blob(value: str) -> bytes:
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(
            status_code=422, detail="blob must be base64", code="validation_error"
        ) from None
    if len(blob) < MIN_BLOB_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"blob must be at least {MIN_BLOB_SIZE} bytes",
            code="validation_error",
        )
    return blob


def _validate_entry_date(entry_date: date_type, user: User) -> None:
    """Shared create/replace calendar boundary enforcement.

    ``today`` is server-UTC (2026-09-20 audit fix L-5): ``date.today()``
    answers in the host's local timezone, so on any non-UTC host the
    forward-grace bound drifted by hours from the "server-UTC today + 1"
    contract the grace-day reasoning (and the threshold math) assumes.
    """
    today = datetime.now(timezone.utc).date()
    if entry_date > today + timedelta(days=FORWARD_GRACE_DAYS):
        raise ApiError(
            status_code=422, detail="entry_date cannot be in the future", code="validation_error"
        )
    # Earliest believable entry: the account's creation day, or the server's
    # today if UTC ran ahead of the client's local calendar — whichever is
    # earlier — minus one day of timezone grace. Bulk backdating (the 30-day
    # threshold fast-forward) stays impossible either way.
    created_day = user.created_at.date() if user.created_at else today
    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)
    if entry_date < earliest:
        raise ApiError(
            status_code=422,
            detail="entry_date is before this account existed",
            code="validation_error",
        )


async def _fresh_active_entry_user(
    session: AsyncSession, user_id: str, expected_epoch: int
) -> User:
    """Re-check an entry mutation's authorization inside the lifecycle fence.

    Authentication necessarily happens before a route can acquire its
    per-account locks. Account deletion or logout can therefore win while a
    request waits; using the stale ORM user would turn create into an FK 500
    or let a retired bearer write after logout. This returns only a current,
    active account at the same token epoch.
    """
    fresh = await session.get(User, user_id, populate_existing=True)
    if fresh is None or not fresh.is_active or fresh.token_epoch != expected_epoch:
        raise ApiError(status_code=401, detail="invalid token", code="unauthorized")
    return fresh


@router.post(
    "",
    response_model=EntryOut,
    status_code=201,
    dependencies=[
        Depends(make_rate_limiter("entries-create", "entries_rate_limit", "entries_rate_window"))
    ],
)
async def create_entry(
    body: EntryCreate,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    blob = _decode_entry_blob(body.blob)
    expected_epoch = user.token_epoch

    # Serialize quota-check + insert per user: without the lock, N concurrent
    # creates each see the quota as un-consumed and all commit. The outer
    # lifecycle fence is shared with account deletion/logout, so a stale
    # authenticated request can neither race the user-row cascade nor write
    # after its epoch has been revoked.
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"entries:{user.id}"):
            fresh_user = await _fresh_active_entry_user(session, user.id, expected_epoch)
            _validate_entry_date(body.entry_date, fresh_user)

            # Duplicate BEFORE quota (2026-09-20 audit fix L-6): an
            # idempotent retry of an already-stored client_entry_id at the
            # quota boundary used to answer 413, so an offline queue could
            # not distinguish "already applied" from "genuinely full" and
            # wedged on an unretryable error. The 409 is the terminal,
            # correct verdict for a retry — it must win the race.
            existing = await session.execute(
                select(Entry.id).where(
                    Entry.user_id == fresh_user.id, Entry.client_entry_id == body.client_entry_id
                )
            )
            if existing.scalar_one_or_none() is not None:
                raise ApiError(status_code=409, detail="entry already exists", code="conflict")
            # A create is always the FIRST content generation (M-2): the
            # client bound this version into its v2 AAD, so any other value
            # would store a row whose ciphertext and version echo disagree.
            if body.content_version != 1:
                raise ApiError(
                    status_code=422,
                    detail="content_version must be 1 on create",
                    code="validation_error",
                )
            await _assert_within_quota(session, fresh_user, len(blob), request.app.state.settings)

            row = Entry(
                user_id=fresh_user.id,
                client_entry_id=body.client_entry_id,
                blob=blob,
                entry_date=body.entry_date,
                content_version=1,
            )
            session.add(row)
            try:
                # The insert and revision advance must commit together: a
                # page reader can only trust its marker if every collection
                # mutation is represented by it.
                await _increment_entries_revision(session, fresh_user)
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                if _is_unique_violation(exc):
                    # Concurrent sync of the same client_entry_id (e.g. an
                    # offline queue flushed twice): the unique index decides,
                    # the pre-check is fast-path.
                    raise ApiError(
                        status_code=409, detail="entry already exists", code="conflict"
                    ) from exc
                raise
            # Construct the response before relinquishing the lifecycle
            # fence. A concurrent account deletion may cascade this row as
            # soon as the fence opens, so a post-lock refresh could otherwise
            # turn a successfully committed create into a stale-row 500.
            await session.refresh(row)
            response = entry_out(row)
            await session.commit()
    return response


@router.put(
    "/{client_entry_id}",
    response_model=EntryOut,
    dependencies=[
        Depends(make_rate_limiter("entries-replace", "entries_rate_limit", "entries_rate_window"))
    ],
)
async def replace_entry(
    client_entry_id: str,
    body: EntryReplace,
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """Atomically replace ciphertext for one stable client entry id.

    Mobile edits used to issue DELETE followed by POST. A network failure
    between those two independent commits permanently erased the original
    journal record. This PUT changes the opaque blob/date in one transaction
    and is safely retryable: replaying the same body leaves the same row.
    """
    if _CLIENT_ENTRY_ID_RE.fullmatch(client_entry_id) is None:
        raise ApiError(status_code=404, detail="entry not found", code="not_found")
    blob = _decode_entry_blob(body.blob)
    expected_epoch = user.token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"entries:{user.id}"):
            fresh_user = await _fresh_active_entry_user(session, user.id, expected_epoch)
            _validate_entry_date(body.entry_date, fresh_user)
            row = (
                (
                    await session.execute(
                        select(Entry).where(
                            Entry.user_id == fresh_user.id,
                            Entry.client_entry_id == client_entry_id,
                        )
                    )
                )
                .scalars()
                .first()
            )
            if row is None:
                raise ApiError(status_code=404, detail="entry not found", code="not_found")
            # Version binding (M-2): a modern client sends the version it
            # bound into the replacement blob's v2 AAD; it must be exactly
            # the successor of the stored version. A mismatch is a retryable
            # 409 (another device edited first — refetch and retry), never a
            # silent overwrite of the AAD/version contract. Legacy clients
            # omit the field; the stored version still advances monotonically.
            if body.content_version is not None and body.content_version != row.content_version + 1:
                raise ApiError(
                    status_code=409,
                    detail="entry was modified by another device; refetch and retry",
                    code="version_conflict",
                    headers={"Retry-After": "1"},
                )
            await _assert_replacement_within_quota(
                session, fresh_user, len(bytes(row.blob)), len(blob), request.app.state.settings
            )
            changed = bytes(row.blob) != blob or row.entry_date != body.entry_date
            if changed:
                row.blob = blob
                row.entry_date = body.entry_date
                row.content_version = body.content_version or row.content_version + 1
                await _increment_entries_revision(session, fresh_user)
            await session.commit()
            await session.refresh(row)
            response = entry_out(row)
            await session.commit()
    return response


@router.get(
    "",
    response_model=list[EntryOut],
    dependencies=[
        Depends(make_rate_limiter("entries-read", "read_rate_limit", "read_rate_window"))
    ],
)
async def list_entries(
    response: Response,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
    since: date_type | None = Query(default=None),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=100, ge=1, le=500),
    page_bytes: int | None = Query(default=None, ge=1, le=ENTRY_PAGE_BLOB_BYTES),
    expected_revision: str | None = None,
):
    """Return one bounded ciphertext page.

    ``page_bytes`` is the explicit modern-client opt-in to a short page and
    ``X-Next-Offset`` continuation.  A legacy client does not understand that
    header, so it never receives a *short* byte-truncated page: if its
    requested page exceeds the hard response budget it gets an explicit 413
    instead of silently losing later history.  Metadata (id + byte length) is
    selected first; the database never materializes up to 500 full blobs just
    to discover a response would be too large.
    """
    expected_epoch = user.token_epoch
    expected = parse_expected_revision(expected_revision)
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"entries:{user.id}"):
            fresh_user = await _fresh_active_entry_user(session, user.id, expected_epoch)
            revision = await current_entries_revision(session, fresh_user.id)
            assert_expected_revision(
                expected,
                revision,
                collection="entries",
                header_name=ENTRIES_REVISION_HEADER,
            )
            metadata_query = select(Entry.id, _blob_length(session).label("blob_bytes")).where(
                Entry.user_id == fresh_user.id
            )
            if since is not None:
                metadata_query = metadata_query.where(Entry.entry_date >= since)
            metadata_query = (
                # id breaks (entry_date, received_at) ties so paginated
                # clients see one stable order across pages.
                metadata_query.order_by(
                    Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc()
                )
                .offset(offset)
                # The extra metadata-only row says whether a full item-count
                # page has more history without loading another ciphertext.
                .limit(limit + 1)
            )
            metadata = (await session.execute(metadata_query)).all()
            requested = [(str(row[0]), int(row[1])) for row in metadata[:limit]]
            selected: list[tuple[str, int]]

            if page_bytes is None:
                selected = requested
                if sum(size for _, size in selected) > ENTRY_PAGE_BLOB_BYTES:
                    raise ApiError(
                        status_code=413,
                        detail=(
                            "requested entry page exceeds the 2 MiB ciphertext budget; "
                            "upgrade to a byte-paginating client"
                        ),
                        code="payload_too_large",
                    )
            else:
                selected = []
                total_bytes = 0
                for entry_id, blob_bytes in requested:
                    if blob_bytes > page_bytes:
                        # A caller must not receive an empty, apparently
                        # complete page when it asks for less than a single
                        # valid entry's ciphertext.  Make that configuration
                        # error explicit so it can retry with a real budget.
                        if not selected:
                            raise ApiError(
                                status_code=413,
                                detail="an entry exceeds the requested page byte budget",
                                code="payload_too_large",
                            )
                        break
                    if total_bytes + blob_bytes > page_bytes:
                        break
                    selected.append((entry_id, blob_bytes))
                    total_bytes += blob_bytes

            selected_ids = [entry_id for entry_id, _ in selected]
            ordered_rows: list[Entry] = []
            if selected_ids:
                rows = (
                    (
                        await session.execute(
                            select(Entry).where(
                                Entry.user_id == fresh_user.id, Entry.id.in_(selected_ids)
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                rows_by_id = {row.id: row for row in rows}
                if len(rows_by_id) != len(selected_ids):
                    # A second process changed the page between metadata and blob
                    # fetches.  Do not fabricate a non-advancing cursor or claim
                    # completion; the caller can retry a fresh stable page.
                    raise ApiError(
                        status_code=409,
                        detail="entries changed while paging; retry the request",
                        code="conflict",
                    )
                ordered_rows = [rows_by_id[entry_id] for entry_id in selected_ids]
                # The in-process entry lock makes this check a defensive backstop
                # for a multi-process deployment accidentally started despite the
                # documented one-worker model.  Never serialize a page that grew
                # after its metadata sizing pass.
                if sum(len(bytes(row.blob)) for row in ordered_rows) > (
                    page_bytes if page_bytes is not None else ENTRY_PAGE_BLOB_BYTES
                ):
                    raise ApiError(
                        status_code=409,
                        detail="entries changed while paging; retry the request",
                        code="conflict",
                    )
            has_more = len(selected) < len(requested) or len(metadata) > limit
            result = [entry_out(row) for row in ordered_rows]
            final_revision = await current_entries_revision(session, fresh_user.id)
            if final_revision != revision:
                raise collection_changed_error("entries", ENTRIES_REVISION_HEADER, final_revision)
            # Set it even for an empty or terminal page. The client stores
            # this exact snapshot marker before deciding whether to continue.
            response.headers[ENTRIES_REVISION_HEADER] = str(revision)
            if has_more:
                # A continuation is always exactly the number of rows the
                # caller received.  This is deliberately stricter than a
                # guessed item-size increment so clients can reject hostile
                # or malformed continuation headers.
                response.headers["X-Next-Offset"] = str(offset + len(result))
    return result


@router.get(
    "/{client_entry_id}",
    response_model=EntryOut,
    dependencies=[
        Depends(make_rate_limiter("entries-read-one", "read_rate_limit", "read_rate_window"))
    ],
)
async def get_entry(
    client_entry_id: str,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    """One entry by its stable client id (2026-09-20, audit fix M-5).

    The idempotency-verification primitive: an offline queue that receives
    409 "already exists" on a replayed upload can prove the server really
    holds the row before discarding its only local copy — a hostile or flaky
    server answering 409 without persisting is exposed as a 404 here, and
    the queue parks the item for user-visible recovery instead of silently
    deleting the sole ciphertext.
    """
    if _CLIENT_ENTRY_ID_RE.fullmatch(client_entry_id) is None:
        raise ApiError(status_code=404, detail="entry not found", code="not_found")
    row = (
        (
            await session.execute(
                select(Entry).where(
                    Entry.user_id == user.id, Entry.client_entry_id == client_entry_id
                )
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ApiError(status_code=404, detail="entry not found", code="not_found")
    return entry_out(row)


@router.delete(
    "/{client_entry_id}",
    status_code=204,
    # Deletes hit the database like any other write; leaving them unlimited
    # let a valid token bypass every other bucket with raw DB load.
    dependencies=[
        Depends(make_rate_limiter("entries-delete", "read_rate_limit", "read_rate_window"))
    ],
)
async def delete_entry(
    client_entry_id: str,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    # Use the same fence as create/replace.  A set-based DELETE is atomic by
    # itself, but without this lock it can interleave with a replacement that
    # already loaded the ORM row and turn an ordinary edit/delete race into a
    # stale-row database error at commit time.
    expected_epoch = user.token_epoch
    async with lifecycle_locks.hold(f"llm-lifecycle:{user.id}"):
        async with _user_locks.hold(f"entries:{user.id}"):
            fresh_user = await _fresh_active_entry_user(session, user.id, expected_epoch)
            result = await session.execute(
                delete(Entry).where(
                    Entry.user_id == fresh_user.id, Entry.client_entry_id == client_entry_id
                )
            )
            if db_rowcount(result) == 0:
                raise ApiError(status_code=404, detail="entry not found", code="not_found")
            await _increment_entries_revision(session, fresh_user)
            await session.commit()
