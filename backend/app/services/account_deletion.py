"""Immediate logical erasure followed by a bounded, restart-safe purge."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import (
    ROLE_THERAPIST,
    AccountDeletionJob,
    AudioAttachment,
    AudioDeletion,
    Consent,
    ConsentEvent,
    Entry,
    Insight,
    Measure,
    PairingCode,
    RekeyJournal,
    TherapistNote,
    TherapistNoteRevision,
    TotpBackupCode,
    User,
    utcnow,
)
from .audio_store import enqueue_audio_delete, get_audio_store_cached


ACCOUNT_PURGE_ROW_BATCH = 100
ACCOUNT_PURGE_AUDIO_BATCH = 50
ACCOUNT_DELETION_STATUS_PROBE_LIMIT = 1_001


@dataclass(frozen=True)
class AccountPurgeProgress:
    found: bool
    backlog: bool
    rows_deleted: int
    user_id: str | None = None


@dataclass(frozen=True)
class AccountDeletionStatus:
    """Bounded aggregate worker status; never contains account identifiers."""

    pending_probe: int
    oldest_requested_at: datetime | None
    runnable: bool
    next_due_at: datetime | None


async def account_deletion_status(session: AsyncSession) -> AccountDeletionStatus:
    """Return a capped backlog probe and the next actionable-work instant."""

    pending_rows = list(
        (
            await session.execute(
                select(AccountDeletionJob.user_id, AccountDeletionJob.requested_at)
                .order_by(AccountDeletionJob.requested_at, AccountDeletionJob.user_id)
                .limit(ACCOUNT_DELETION_STATUS_PROBE_LIMIT)
            )
        ).all()
    )
    if not pending_rows:
        return AccountDeletionStatus(0, None, False, None)

    now = utcnow()
    matching_tombstone = (
        select(AudioDeletion.id)
        .where(
            or_(
                AudioDeletion.owner_id.is_(None),
                AudioDeletion.owner_id == AccountDeletionJob.user_id,
            )
        )
        .correlate(AccountDeletionJob)
    )
    due_tombstone = matching_tombstone.where(AudioDeletion.not_before <= now)
    runnable = (
        await session.scalar(
            select(AccountDeletionJob.user_id)
            .where(
                or_(
                    AccountDeletionJob.phase != "audio_wait",
                    ~matching_tombstone.exists(),
                    due_tombstone.exists(),
                )
            )
            .limit(1)
        )
        is not None
    )
    waiting_owner_ids = select(AccountDeletionJob.user_id).where(
        AccountDeletionJob.phase == "audio_wait"
    )
    next_due_at = await session.scalar(
        select(AudioDeletion.not_before)
        .where(
            or_(
                AudioDeletion.owner_id.is_(None),
                AudioDeletion.owner_id.in_(waiting_owner_ids),
            )
        )
        .order_by(AudioDeletion.not_before)
        .limit(1)
    )
    return AccountDeletionStatus(
        pending_probe=len(pending_rows),
        oldest_requested_at=pending_rows[0][1],
        runnable=runnable,
        next_due_at=next_due_at,
    )


def stage_account_deletion(session: AsyncSession, user: User) -> AccountDeletionJob:
    """Make an account unusable and cryptographically opaque in one row write.

    Large child collections remain only as inaccessible ciphertext until the
    bounded worker removes them.  No plaintext username, display name,
    credential, recovery material, wrapped key, or consent remains on User.
    """
    requested_at = utcnow()
    user.is_active = False
    user.username = f"deleted-{secrets.token_hex(16)}"
    user.salt = secrets.token_urlsafe(32)
    user.verifier = secrets.token_bytes(32)
    user.scrypt_salt = secrets.token_bytes(16)
    user.age_attestation_version = None
    user.age_attested_at = None
    user.display_name = None
    user.wrap_pub_key = None
    user.wrap_key_blob = None
    user.notes_keyring_blob = None
    user.custody_version = 0
    user.custody_operation_id = None
    user.custody_operation_digest = None
    user.custody_operation_epoch = None
    user.rekey_operation_id = None
    user.rekey_operation_digest = None
    user.rekey_operation_epoch = None
    user.rekey_operation_result = None
    user.llm_consent = False
    user.llm_consent_at = None
    user.llm_consent_disclosure = None
    user.llm_consent_policy = None
    user.voice_consent = False
    user.voice_consent_at = None
    user.voice_consent_disclosure = None
    user.voice_consent_policy = None
    user.totp_secret = None
    user.totp_enabled = None
    user.totp_last_counter = None
    user.key_scheme = "v1"
    user.wrapped_data_key = None
    user.recovery_salt = None
    user.recovery_verifier = None
    user.recovery_wrapped_data_key = None
    user.recovery_set_at = None
    user.recovery_scheme = None
    user.kdf_params = None
    # Collection sizes and revision counters reveal account activity even
    # though the corresponding ciphertext is inaccessible. Erase them with
    # the credentials; the physical child rows are worker-private from here.
    user.entries_revision = 0
    user.notes_revision = 0
    user.measures_revision = 0
    user.consents_revision = 0
    user.patients_revision = 0
    user.entry_count = 0
    user.entry_blob_bytes = 0
    user.measure_count = 0
    user.created_at = requested_at
    job = AccountDeletionJob(
        user_id=user.id,
        role=user.role,
        phase="note_revisions",
        requested_at=requested_at,
        updated_at=requested_at,
    )
    session.add(job)
    return job


async def _delete_page(session: AsyncSession, model, condition, *, limit: int) -> int:
    identifiers = list(
        (await session.scalars(select(model.id).where(condition).limit(limit))).all()
    )
    if identifiers:
        await session.execute(delete(model).where(model.id.in_(identifiers)))
    return len(identifiers)


async def _first_remaining_phase(
    session: AsyncSession,
    owner: str,
    *,
    therapist: bool,
) -> str | None:
    """Point-probe every cascading collection while the parent is locked.

    The final User delete must be constant work even if a request that was
    already in flight at logical retirement committed a child row after its
    earlier purge phase.  Returning the earliest affected phase makes the
    state machine revisit that collection instead of asking the database to
    perform a surprise unbounded cascade.
    """

    if therapist:
        revision_probe = select(TherapistNoteRevision.id).where(
            TherapistNoteRevision.therapist_id == owner
        )
    else:
        revision_probe = (
            select(TherapistNoteRevision.id)
            .join(TherapistNote, TherapistNote.id == TherapistNoteRevision.note_id)
            .where(TherapistNote.user_id == owner)
        )
    probes = [
        ("note_revisions", revision_probe),
        (
            "notes",
            select(TherapistNote.id).where(
                TherapistNote.therapist_id == owner if therapist else TherapistNote.user_id == owner
            ),
        ),
        ("audio", select(AudioAttachment.id).where(AudioAttachment.user_id == owner)),
    ]
    if not therapist:
        probes.append(
            (
                "consent_events",
                select(ConsentEvent.id).where(ConsentEvent.user_id == owner),
            )
        )
    probes.append(
        (
            "consents",
            select(Consent.id).where(
                Consent.therapist_id == owner if therapist else Consent.user_id == owner
            ),
        )
    )
    if not therapist:
        probes.extend(
            [
                ("entries", select(Entry.id).where(Entry.user_id == owner)),
                ("insights", select(Insight.id).where(Insight.user_id == owner)),
                ("measures", select(Measure.id).where(Measure.user_id == owner)),
            ]
        )
    if therapist:
        probes.append(
            (
                "pairing_codes",
                select(PairingCode.id).where(PairingCode.therapist_id == owner),
            )
        )
    probes.extend(
        [
            ("totp_codes", select(TotpBackupCode.id).where(TotpBackupCode.user_id == owner)),
            ("rekey", select(RekeyJournal.id).where(RekeyJournal.user_id == owner)),
        ]
    )
    for phase, probe in probes:
        if await session.scalar(probe.limit(1)) is not None:
            return phase
    return None


async def purge_one_account_page(
    session: AsyncSession,
    settings: Settings,
    *,
    owner_id: str | None = None,
) -> AccountPurgeProgress:
    """Delete at most one fixed aggregate child-row page.

    Empty phases and phases smaller than the remaining aggregate budget are
    crossed in one call. Ordinary small accounts therefore finish promptly,
    while a legacy oversized account can never exceed the fixed row bound.
    """
    if owner_id is not None:
        job = await session.scalar(
            select(AccountDeletionJob)
            .where(AccountDeletionJob.user_id == owner_id)
            .with_for_update(skip_locked=True)
        )
    else:
        # Every attempted page refreshes updated_at, including an object-
        # waiting job. Oldest-progress-first therefore rotates fairly across
        # large database purges and provider retries without one blocking all
        # later accounts.
        job = await session.scalar(
            select(AccountDeletionJob)
            .order_by(AccountDeletionJob.updated_at, AccountDeletionJob.user_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
    if job is None:
        return AccountPurgeProgress(found=False, backlog=False, rows_deleted=0)

    owner = job.user_id
    therapist = job.role == ROLE_THERAPIST
    phases = (
        "note_revisions",
        "notes",
        "audio",
        "consent_events",
        "consents",
        "entries",
        "insights",
        "measures",
        "pairing_codes",
        "totp_codes",
        "rekey",
        "user",
        "audio_wait",
        "complete",
    )
    try:
        phase_index = phases.index(job.phase)
    except ValueError:
        raise RuntimeError("account deletion job has an invalid phase") from None

    total_deleted = 0
    while phase_index < len(phases):
        phase = phases[phase_index]
        remaining_budget = ACCOUNT_PURGE_ROW_BATCH - total_deleted
        if remaining_budget <= 0:
            job.updated_at = utcnow()
            job.attempts += 1
            return AccountPurgeProgress(
                found=True,
                backlog=True,
                rows_deleted=total_deleted,
                user_id=owner,
            )
        phase_limit = remaining_budget
        phase_deleted = 0
        if phase == "note_revisions":
            if therapist:
                condition = TherapistNoteRevision.therapist_id == owner
            else:
                note_ids = select(TherapistNote.id).where(TherapistNote.user_id == owner)
                condition = TherapistNoteRevision.note_id.in_(note_ids)
            phase_deleted = await _delete_page(
                session,
                TherapistNoteRevision,
                condition,
                limit=phase_limit,
            )
        elif phase == "notes":
            condition = (
                TherapistNote.therapist_id == owner if therapist else TherapistNote.user_id == owner
            )
            phase_deleted = await _delete_page(
                session,
                TherapistNote,
                condition,
                limit=phase_limit,
            )
        elif phase == "audio":
            audio_limit = min(ACCOUNT_PURGE_AUDIO_BATCH, phase_limit)
            rows = list(
                (
                    await session.scalars(
                        select(AudioAttachment)
                        .where(AudioAttachment.user_id == owner)
                        .limit(audio_limit)
                    )
                ).all()
            )
            if rows:
                store = get_audio_store_cached(settings)
                for row in rows:
                    enqueue_audio_delete(session, row, store=store)
                await session.execute(
                    delete(AudioAttachment).where(AudioAttachment.id.in_([row.id for row in rows]))
                )
            phase_deleted = len(rows)
        elif phase == "consent_events":
            phase_deleted = (
                0
                if therapist
                else await _delete_page(
                    session,
                    ConsentEvent,
                    ConsentEvent.user_id == owner,
                    limit=phase_limit,
                )
            )
        elif phase == "consents":
            counterpart_column = Consent.user_id if therapist else Consent.therapist_id
            revision_column = User.consents_revision if therapist else User.patients_revision
            consent_rows = list(
                (
                    await session.execute(
                        select(Consent.id, counterpart_column)
                        .where(
                            Consent.therapist_id == owner if therapist else Consent.user_id == owner
                        )
                        .limit(phase_limit)
                    )
                ).all()
            )
            if consent_rows:
                counterpart_ids = {str(row[1]) for row in consent_rows}
                # The sharing-list revision and the membership deletion are
                # one snapshot mutation. Lock the bounded counterpart set
                # first so account retirement cannot move a row between the
                # liveness decision and the bump. Revision exhaustion must
                # fail *before* deleting any consent; silently skipping a
                # maxed-out counter would let membership change beneath a
                # still-valid client snapshot.
                locked_counterparts = list(
                    (
                        await session.execute(
                            select(User.id, revision_column, User.is_active)
                            .where(User.id.in_(counterpart_ids))
                            .with_for_update()
                        )
                    ).all()
                )
                active_counterparts = [
                    (str(counterpart_id), int(revision))
                    for counterpart_id, revision, is_active in locked_counterparts
                    if bool(is_active)
                ]
                if any(revision >= 2**63 - 1 for _, revision in active_counterparts):
                    raise RuntimeError("counterpart sharing revision exhausted")
                active_counterpart_ids = [
                    counterpart_id for counterpart_id, _ in active_counterparts
                ]
                if active_counterpart_ids:
                    await session.execute(
                        update(User)
                        .where(User.id.in_(active_counterpart_ids))
                        .values({revision_column.key: revision_column + 1})
                    )
                await session.execute(
                    delete(Consent).where(Consent.id.in_([str(row[0]) for row in consent_rows]))
                )
            phase_deleted = len(consent_rows)
        elif phase == "entries":
            phase_deleted = (
                0
                if therapist
                else await _delete_page(
                    session,
                    Entry,
                    Entry.user_id == owner,
                    limit=phase_limit,
                )
            )
        elif phase == "insights":
            phase_deleted = (
                0
                if therapist
                else await _delete_page(
                    session,
                    Insight,
                    Insight.user_id == owner,
                    limit=phase_limit,
                )
            )
        elif phase == "measures":
            phase_deleted = (
                0
                if therapist
                else await _delete_page(
                    session,
                    Measure,
                    Measure.user_id == owner,
                    limit=phase_limit,
                )
            )
        elif phase == "pairing_codes":
            phase_deleted = (
                await _delete_page(
                    session,
                    PairingCode,
                    PairingCode.therapist_id == owner,
                    limit=phase_limit,
                )
                if therapist
                else 0
            )
        elif phase == "totp_codes":
            phase_deleted = await _delete_page(
                session,
                TotpBackupCode,
                TotpBackupCode.user_id == owner,
                limit=phase_limit,
            )
        elif phase == "rekey":
            phase_deleted = await _delete_page(
                session,
                RekeyJournal,
                RekeyJournal.user_id == owner,
                limit=phase_limit,
            )
        elif phase == "user":
            # Lock the parent before the final point probes. PostgreSQL FK
            # inserts take a conflicting key-share lock, so no in-flight
            # child writer can slip between the empty proof and DELETE.
            user_id = await session.scalar(
                select(User.id).where(User.id == owner).with_for_update()
            )
            remaining_phase = await _first_remaining_phase(
                session,
                owner,
                therapist=therapist,
            )
            if remaining_phase is not None:
                job.phase = remaining_phase
                job.updated_at = utcnow()
                job.attempts += 1
                return AccountPurgeProgress(
                    found=True,
                    backlog=True,
                    rows_deleted=total_deleted,
                    user_id=owner,
                )
            if user_id is not None:
                await session.execute(delete(User).where(User.id == owner))
                phase_deleted = 1
            else:
                # A crash can occur after the parent DELETE commits but
                # before a future version advances the job. Resume safely.
                phase_deleted = 0
        elif phase == "audio_wait":
            pending_audio = await session.scalar(
                select(AudioDeletion.id)
                .where(
                    or_(
                        AudioDeletion.owner_id == owner,
                        # Legacy/pre-upgrade crash tombstones did not carry
                        # an owner. They must block every account-completion
                        # claim until drained; guessing that they belong to
                        # someone else could orphan an uploaded object.
                        AudioDeletion.owner_id.is_(None),
                    )
                )
                .limit(1)
            )
            if pending_audio is not None:
                job.updated_at = utcnow()
                job.attempts += 1
                return AccountPurgeProgress(
                    found=True,
                    backlog=True,
                    rows_deleted=total_deleted,
                    user_id=owner,
                )
            phase_deleted = 0
        else:  # complete
            await session.delete(job)
            await session.flush()
            another = await session.scalar(select(AccountDeletionJob.user_id).limit(1))
            return AccountPurgeProgress(
                found=True,
                backlog=another is not None,
                rows_deleted=total_deleted,
                user_id=owner,
            )

        total_deleted += phase_deleted
        selected_limit = (
            min(ACCOUNT_PURGE_AUDIO_BATCH, phase_limit) if phase == "audio" else phase_limit
        )
        # A full selection may have a successor. Stop without another query;
        # the durable phase repeats on the next cooperative worker turn.
        if phase_deleted == selected_limit:
            job.updated_at = utcnow()
            job.attempts += 1
            return AccountPurgeProgress(
                found=True,
                backlog=True,
                rows_deleted=total_deleted,
                user_id=owner,
            )
        phase_index += 1
        if phase_index < len(phases):
            job.phase = phases[phase_index]
            job.updated_at = utcnow()

    raise RuntimeError("account deletion job did not terminate")
