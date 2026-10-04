"""Bounded retained-sharing state and optimistic collection revisions."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import rowcount as db_rowcount
from ..deps import ApiError
from ..models import Consent, ConsentEvent, User
from ._paging import MAX_COLLECTION_REVISION

CONSENTS_REVISION_HEADER = "X-Consents-Revision"
PATIENTS_REVISION_HEADER = "X-Patients-Revision"

# Active relationships remain capped at 100 on each side.  A separate
# lifetime cap keeps account-deletion cascades and retained notes/consents
# finite without making ordinary grant/revoke cycles consume active quota.
MAX_RETAINED_RELATIONSHIPS_PER_ACCOUNT = 1_000

# Permission-increasing events stop before the hard history ceiling, leaving
# enough reserve to record withdrawal of every active relationship plus both
# account-wide provider consents.  Revocation/withdrawal is never blocked.
MAX_CONSENT_EVENTS_PER_PATIENT = 10_000
CONSENT_EVENT_WITHDRAWAL_RESERVE = 202
CONSENT_EVENT_PERMISSION_CEILING = MAX_CONSENT_EVENTS_PER_PATIENT - CONSENT_EVENT_WITHDRAWAL_RESERVE


async def add_consent_event(
    session: AsyncSession,
    event: ConsentEvent,
    *,
    permission_increasing: bool,
) -> None:
    """Append an event while preserving space for safety withdrawals."""
    # Serialize every producer on the patient row.  In-process locks are
    # deliberately not the authority here: API workers do not share them.
    await session.scalar(select(User.id).where(User.id == event.user_id).with_for_update())
    count = int(
        await session.scalar(
            select(func.count(ConsentEvent.id)).where(ConsentEvent.user_id == event.user_id)
        )
        or 0
    )
    ceiling = (
        CONSENT_EVENT_PERMISSION_CEILING
        if permission_increasing
        else MAX_CONSENT_EVENTS_PER_PATIENT
    )
    if count >= ceiling:
        raise ApiError(
            status_code=413,
            detail="consent history has reached the retained safety limit",
            code="payload_too_large",
        )
    session.add(event)


async def _advance_revision(
    session: AsyncSession,
    user_ids: Iterable[str],
    column,
) -> None:
    identifiers = sorted(set(user_ids))
    if not identifiers:
        return
    result = await session.execute(
        update(User)
        .where(
            User.id.in_(identifiers),
            User.is_active.is_(True),
            column < MAX_COLLECTION_REVISION,
        )
        .values({column.key: column + 1})
    )
    if db_rowcount(result) != len(identifiers):
        raise ApiError(
            status_code=503,
            detail="unable to advance sharing snapshot",
            code="service_unavailable",
        )


async def advance_sharing_revisions(
    session: AsyncSession,
    *,
    patient_ids: Iterable[str] = (),
    therapist_ids: Iterable[str] = (),
) -> None:
    """Advance patient and therapist collection snapshots atomically."""
    await _advance_revision(session, patient_ids, User.consents_revision)
    await _advance_revision(session, therapist_ids, User.patients_revision)


async def advance_counterpart_revisions_for_deletion(
    session: AsyncSession,
    *,
    account_id: str,
    therapist: bool,
) -> None:
    """Fence counterpart lists before a relationship cascade."""
    if therapist:
        counterpart_ids = select(Consent.user_id).where(Consent.therapist_id == account_id)
        column = User.consents_revision
    else:
        counterpart_ids = select(Consent.therapist_id).where(Consent.user_id == account_id)
        column = User.patients_revision
    await session.execute(
        update(User)
        .where(User.id.in_(counterpart_ids), column < MAX_COLLECTION_REVISION)
        .values({column.key: column + 1})
    )
