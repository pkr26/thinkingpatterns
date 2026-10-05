"""Logical privacy erasure and actual bounded SQLite purge transitions."""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import FrozenInstanceError, asdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def _modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return (
        importlib.import_module("app.services.account_deletion"),
        importlib.import_module("app.models"),
    )


def _user(models, identifier="patient", role="user"):
    return models.User(
        id=identifier,
        username=identifier,
        role=role,
        salt="account-salt",
        verifier=b"v" * 32,
        scrypt_salt=b"s" * 16,
        created_at=NOW - timedelta(days=5),
    )


async def _database(models, exercise):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(models.Base.metadata.create_all)
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            await exercise(session)
    finally:
        await engine.dispose()


def test_logical_deletion_erases_every_private_channel_and_persists_a_durable_job(
    monkeypatch,
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    entropy = []
    monkeypatch.setattr(
        module.secrets,
        "token_hex",
        lambda size: entropy.append(("hex", size)) or "f" * (size * 2),
    )
    monkeypatch.setattr(
        module.secrets,
        "token_urlsafe",
        lambda size: entropy.append(("urlsafe", size)) or "new-salt",
    )
    monkeypatch.setattr(
        module.secrets,
        "token_bytes",
        lambda size: entropy.append(("bytes", size)) or bytes(size),
    )
    nullable_text = [
        "age_attestation_version",
        "display_name",
        "wrap_pub_key",
        "custody_operation_id",
        "custody_operation_digest",
        "rekey_operation_id",
        "rekey_operation_digest",
        "rekey_operation_result",
        "llm_consent_disclosure",
        "llm_consent_policy",
        "voice_consent_disclosure",
        "voice_consent_policy",
        "totp_secret",
        "recovery_salt",
        "recovery_scheme",
        "kdf_params",
    ]
    nullable_bytes = [
        "wrap_key_blob",
        "notes_keyring_blob",
        "wrapped_data_key",
        "recovery_verifier",
        "recovery_wrapped_data_key",
    ]
    nullable_numbers = [
        "custody_operation_epoch",
        "rekey_operation_epoch",
        "totp_last_counter",
    ]
    nullable_times = [
        "age_attested_at",
        "llm_consent_at",
        "voice_consent_at",
        "totp_enabled",
        "recovery_set_at",
    ]
    counters = [
        "custody_version",
        "entries_revision",
        "notes_revision",
        "measures_revision",
        "consents_revision",
        "patients_revision",
        "entry_count",
        "entry_blob_bytes",
        "measure_count",
    ]

    async def exercise(session):
        user = _user(models, role="therapist")
        for field in nullable_text:
            setattr(user, field, "private")
        for field in nullable_bytes:
            setattr(user, field, b"private ciphertext")
        for field in nullable_numbers + counters:
            setattr(user, field, 9)
        for field in nullable_times:
            setattr(user, field, NOW - timedelta(days=5))
        user.key_scheme = "v2"
        user.llm_consent = user.voice_consent = True
        session.add(user)
        job = module.stage_account_deletion(session, user)
        assert entropy == [("hex", 16), ("urlsafe", 32), ("bytes", 32), ("bytes", 16)]
        assert user.username == "deleted-" + "f" * 32 and user.salt == "new-salt"
        assert user.verifier == bytes(32) and user.scrypt_salt == bytes(16)
        assert (
            user.is_active is False
            and user.llm_consent is False
            and user.voice_consent is False
        )
        assert user.key_scheme == "v1" and user.created_at == NOW
        assert all(
            getattr(user, field) is None
            for field in nullable_text
            + nullable_bytes
            + nullable_numbers
            + nullable_times
        )
        assert all(getattr(user, field) == 0 for field in counters)
        assert (job.user_id, job.role, job.phase, job.requested_at, job.updated_at) == (
            "patient",
            "therapist",
            "note_revisions",
            NOW,
            NOW,
        )
        await session.commit()
        assert await session.get(models.AccountDeletionJob, "patient") is job

    asyncio.run(_database(models, exercise))


def test_deletion_status_caps_actual_1002_jobs_and_reports_oldest_without_identity(
    monkeypatch,
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)

    async def exercise(session):
        assert asdict(await module.account_deletion_status(session)) == {
            "pending_probe": 0,
            "oldest_requested_at": None,
            "runnable": False,
            "next_due_at": None,
        }
        session.add_all(
            [
                models.AccountDeletionJob(
                    user_id=f"job-{n:04d}",
                    role="user",
                    phase="entries",
                    requested_at=NOW + timedelta(seconds=n),
                    updated_at=NOW,
                )
                for n in range(1002)
            ]
        )
        await session.commit()
        status = await module.account_deletion_status(session)
        assert asdict(status) == {
            "pending_probe": 1001,
            "oldest_requested_at": NOW,
            "runnable": True,
            "next_due_at": None,
        }
        with pytest.raises(FrozenInstanceError):
            status.pending_probe = 0

    asyncio.run(_database(models, exercise))


def test_deletion_status_waits_for_owner_or_legacy_tombstone_and_reports_exact_due(
    monkeypatch,
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import delete

    async def exercise(session):
        session.add(
            models.AccountDeletionJob(
                user_id="owner",
                role="user",
                phase="audio_wait",
                requested_at=NOW,
                updated_at=NOW,
            )
        )
        later = NOW + timedelta(seconds=60)
        session.add_all(
            [
                models.AudioDeletion(
                    id="own",
                    owner_id="owner",
                    backend="local",
                    storage_key="audio/owner/key",
                    not_before=later,
                    created_at=NOW,
                ),
                models.AudioDeletion(
                    id="foreign",
                    owner_id="foreign",
                    backend="local",
                    storage_key="audio/foreign/key",
                    not_before=NOW,
                    created_at=NOW,
                ),
            ]
        )
        await session.commit()
        status = await module.account_deletion_status(session)
        assert status.runnable is False and status.next_due_at == later
        tombstone = await session.get(models.AudioDeletion, "own")
        tombstone.not_before = NOW
        await session.commit()
        assert (await module.account_deletion_status(session)).runnable is True
        await session.execute(
            delete(models.AudioDeletion).where(models.AudioDeletion.id == "own")
        )
        await session.commit()
        status = await module.account_deletion_status(session)
        assert status.runnable is True and status.next_due_at is None
        session.add(
            models.AudioDeletion(
                id="legacy",
                owner_id=None,
                backend="local",
                storage_key="audio/legacy/key",
                not_before=later,
                created_at=NOW,
            )
        )
        await session.commit()
        status = await module.account_deletion_status(session)
        assert status.runnable is False and status.next_due_at == later

    asyncio.run(_database(models, exercise))


def test_purge_native_row_budget_durable_phase_and_other_account_isolation(monkeypatch):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import func, select

    async def exercise(session):
        owner, foreign = _user(models), _user(models, "foreign")
        session.add_all([owner, foreign])
        session.add_all(
            [
                models.Entry(
                    id=f"entry-{n}",
                    user_id="patient",
                    client_entry_id=f"client-{n}",
                    entry_date=date(2026, 10, 5),
                    blob=b"opaque",
                )
                for n in range(101)
            ]
        )
        session.add(
            models.Entry(
                id="foreign-entry",
                user_id="foreign",
                client_entry_id="foreign-client",
                entry_date=date(2026, 10, 5),
                blob=b"opaque",
            )
        )
        module.stage_account_deletion(session, owner)
        await session.commit()
        progress = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id="patient"
        )
        assert asdict(progress) == {
            "found": True,
            "backlog": True,
            "rows_deleted": 100,
            "user_id": "patient",
        }
        with pytest.raises(FrozenInstanceError):
            progress.rows_deleted = 0
        await session.commit()
        assert (
            await session.scalar(
                select(func.count(models.Entry.id)).where(
                    models.Entry.user_id == "patient"
                )
            )
            == 1
        )
        assert (
            await session.get(models.AccountDeletionJob, "patient")
        ).phase == "entries"
        progress = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id="patient"
        )
        assert asdict(progress) == {
            "found": True,
            "backlog": False,
            "rows_deleted": 2,
            "user_id": "patient",
        }
        await session.commit()
        assert await session.get(models.User, "patient", populate_existing=True) is None
        assert await session.get(models.User, "foreign") is foreign
        assert await session.get(models.Entry, "foreign-entry") is not None
        assert (
            await session.get(
                models.AccountDeletionJob, "patient", populate_existing=True
            )
            is None
        )
        progress = await module.purge_one_account_page(session, SimpleNamespace())
        assert asdict(progress) == {
            "found": False,
            "backlog": False,
            "rows_deleted": 0,
            "user_id": None,
        }

    asyncio.run(_database(models, exercise))


def test_purge_phase_validation_and_oldest_progress_first_fairness(monkeypatch):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)

    async def exercise(session):
        session.add_all(
            [
                models.AccountDeletionJob(
                    user_id="later",
                    role="user",
                    phase="complete",
                    requested_at=NOW - timedelta(days=2),
                    updated_at=NOW,
                ),
                models.AccountDeletionJob(
                    user_id="older",
                    role="user",
                    phase="complete",
                    requested_at=NOW,
                    updated_at=NOW - timedelta(days=1),
                ),
            ]
        )
        await session.commit()
        progress = await module.purge_one_account_page(session, SimpleNamespace())
        assert asdict(progress) == {
            "found": True,
            "backlog": True,
            "rows_deleted": 0,
            "user_id": "older",
        }
        await session.commit()
        remaining = await session.get(models.AccountDeletionJob, "later")
        remaining.phase = "malformed"
        await session.commit()
        with pytest.raises(
            RuntimeError, match="^account deletion job has an invalid phase$"
        ):
            await module.purge_one_account_page(session, SimpleNamespace())

    asyncio.run(_database(models, exercise))


def _child(models, phase, owner, *, therapist=False, suffix=""):
    identifier = phase + suffix
    patient, clinician = ("foreign", owner) if therapist else (owner, "foreign")
    if phase == "note_revisions":
        note = models.TherapistNote(
            id="note" + suffix,
            therapist_id=clinician,
            user_id=patient,
            client_note_id="note" + suffix,
            blob=b"private",
        )
        return [
            note,
            models.TherapistNoteRevision(
                id=identifier,
                note_id=note.id,
                therapist_id=clinician,
                blob=b"old private",
            ),
        ]
    if phase == "notes":
        return [
            models.TherapistNote(
                id=identifier,
                therapist_id=clinician,
                user_id=patient,
                client_note_id=identifier,
                blob=b"private",
            )
        ]
    if phase == "audio":
        return [
            models.AudioAttachment(
                id=identifier,
                user_id=owner,
                client_entry_id=identifier,
                backend="local",
                storage_key="audio/" + owner + "/" + identifier + ".enc",
                size_bytes=32,
                mime_type="audio/webm",
                duration_seconds=1,
                expires_at=NOW,
            )
        ]
    if phase == "consent_events":
        return [
            models.ConsentEvent(
                id=identifier, user_id=owner, kind="voice", action="grant"
            )
        ]
    if phase == "consents":
        return [models.Consent(id=identifier, user_id=patient, therapist_id=clinician)]
    if phase == "entries":
        return [
            models.Entry(
                id=identifier,
                user_id=owner,
                client_entry_id=identifier,
                entry_date=date(2026, 10, 5),
                blob=b"private",
            )
        ]
    if phase == "insights":
        return [
            models.Insight(
                id=identifier, user_id=owner, kind="patterns", blob=b"private"
            )
        ]
    if phase == "measures":
        return [
            models.Measure(
                id=identifier,
                user_id=owner,
                client_measure_id=identifier,
                measure_date=date(2026, 10, 5),
                blob=b"private",
            )
        ]
    if phase == "pairing_codes":
        return [
            models.PairingCode(
                id=identifier, therapist_id=owner, code_hash=identifier, expires_at=NOW
            )
        ]
    if phase == "totp_codes":
        return [models.TotpBackupCode(id=identifier, user_id=owner, digest="d" * 64)]
    if phase == "rekey":
        return [models.RekeyJournal(id=identifier, user_id=owner)]
    raise AssertionError("unknown fixture phase")


@pytest.mark.parametrize(
    "therapist,phase",
    [
        (False, "note_revisions"),
        (True, "note_revisions"),
        (False, "notes"),
        (True, "notes"),
        (False, "audio"),
        (False, "consent_events"),
        (False, "consents"),
        (True, "consents"),
        (False, "entries"),
        (False, "insights"),
        (False, "measures"),
        (True, "pairing_codes"),
        (False, "totp_codes"),
        (False, "rekey"),
    ],
)
def test_final_parent_probe_requeues_every_late_child_without_cascade(
    monkeypatch, therapist, phase
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)

    async def exercise(session):
        owner = _user(models, role="therapist" if therapist else "user")
        foreign = _user(models, "foreign", "user" if therapist else "therapist")
        session.add_all([owner, foreign])
        session.add(
            models.AccountDeletionJob(
                user_id=owner.id,
                role=owner.role,
                phase="user",
                requested_at=NOW - timedelta(days=1),
                updated_at=NOW - timedelta(seconds=1),
            )
        )
        children = _child(models, phase, owner.id, therapist=therapist)
        session.add_all(children)
        await session.commit()
        result = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert asdict(result) == {
            "found": True,
            "backlog": True,
            "rows_deleted": 0,
            "user_id": owner.id,
        }
        await session.commit()
        job = await session.get(models.AccountDeletionJob, owner.id)
        assert job.phase == phase and job.attempts == 1 and job.updated_at == NOW
        assert await session.get(models.User, owner.id) is owner
        for child in children:
            assert await session.get(type(child), child.id) is not None
        job.phase = "user"
        await session.commit()
        repeated = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert repeated.found is True and repeated.backlog is True
        await session.commit()
        assert job.phase == phase and job.attempts == 2

    asyncio.run(_database(models, exercise))


def test_native_fifty_audio_page_is_durable_and_waits_for_own_and_legacy_objects(
    monkeypatch,
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import delete, func, select

    async def exercise(session):
        settings = SimpleNamespace(
            audio_bucket="", audio_local_dir="", environment="production"
        )
        owner = _user(models)
        session.add(owner)
        session.add_all(
            [_child(models, "audio", owner.id, suffix=str(n))[0] for n in range(51)]
        )
        module.stage_account_deletion(session, owner)
        await session.commit()
        first = await module.purge_one_account_page(
            session, settings, owner_id=owner.id
        )
        assert first.rows_deleted == 50 and first.backlog is True
        await session.commit()
        job = await session.get(models.AccountDeletionJob, owner.id)
        assert job.phase == "audio" and job.attempts == 1 and job.updated_at == NOW
        assert await session.scalar(select(func.count(models.AudioAttachment.id))) == 1
        assert await session.scalar(select(func.count(models.AudioDeletion.id))) == 50
        second = await module.purge_one_account_page(
            session, settings, owner_id=owner.id
        )
        assert second.rows_deleted == 2 and second.backlog is True
        await session.commit()
        assert job.phase == "audio_wait" and job.attempts == 2
        assert await session.scalar(select(func.count(models.AudioDeletion.id))) == 51
        assert await session.get(models.User, owner.id, populate_existing=True) is None
        await session.execute(delete(models.AudioDeletion))
        session.add_all(
            [
                models.AudioDeletion(
                    id="legacy",
                    owner_id=None,
                    backend="local",
                    storage_key="legacy",
                    not_before=NOW,
                ),
                models.AudioDeletion(
                    id="foreign",
                    owner_id="foreign",
                    backend="local",
                    storage_key="foreign",
                    not_before=NOW,
                ),
            ]
        )
        await session.commit()
        assert (
            await module.purge_one_account_page(
                session, SimpleNamespace(), owner_id=owner.id
            )
        ).backlog is True
        await session.commit()
        assert job.attempts == 3
        await session.execute(
            delete(models.AudioDeletion).where(models.AudioDeletion.id == "legacy")
        )
        await session.commit()
        last = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert asdict(last) == {
            "found": True,
            "backlog": False,
            "rows_deleted": 0,
            "user_id": owner.id,
        }
        await session.commit()
        assert (
            await session.get(
                models.AccountDeletionJob, owner.id, populate_existing=True
            )
            is None
        )
        assert await session.get(models.AudioDeletion, "foreign") is not None

    asyncio.run(_database(models, exercise))


@pytest.mark.parametrize("therapist", [False, True])
def test_consent_purge_bumps_only_live_counterparts_and_rejects_exhaustion_before_delete(
    monkeypatch, therapist
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import select

    async def exercise(session):
        owner = _user(models, role="therapist" if therapist else "user")
        peers = [
            _user(models, "live", "user" if therapist else "therapist"),
            _user(models, "inactive", "user" if therapist else "therapist"),
        ]
        peers[1].is_active = False
        for peer in peers:
            peer.consents_revision = 2
            peer.patients_revision = 3
        session.add_all([owner, *peers])
        job = module.stage_account_deletion(session, owner)
        job.phase = "consents"
        for peer in peers:
            session.add(
                models.Consent(
                    id=peer.id,
                    user_id=peer.id if therapist else owner.id,
                    therapist_id=owner.id if therapist else peer.id,
                )
            )
        await session.commit()
        relevant = "consents_revision" if therapist else "patients_revision"
        setattr(peers[0], relevant, 2**63 - 1)
        await session.commit()
        with pytest.raises(
            RuntimeError, match="^counterpart sharing revision exhausted$"
        ):
            await module.purge_one_account_page(
                session, SimpleNamespace(), owner_id=owner.id
            )
        assert len(list((await session.scalars(select(models.Consent))).all())) == 2
        assert await session.get(models.User, owner.id) is owner
        setattr(peers[0], relevant, 10)
        # An inactive exhausted counterpart is deliberately skipped.
        setattr(peers[1], relevant, 2**63 - 1)
        await session.commit()
        result = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert result.rows_deleted == 3 and result.backlog is False
        await session.commit()
        await session.refresh(peers[0])
        await session.refresh(peers[1])
        assert (
            getattr(peers[0], relevant) == 11
            and getattr(peers[1], relevant) == 2**63 - 1
        )
        assert getattr(
            peers[0], "patients_revision" if therapist else "consents_revision"
        ) == (3 if therapist else 2)
        assert list((await session.scalars(select(models.Consent))).all()) == []

    asyncio.run(_database(models, exercise))


@pytest.mark.parametrize("therapist", [False, True])
def test_all_retired_collections_are_deleted_but_foreign_children_survive(
    monkeypatch, therapist
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)

    async def exercise(session):
        owner = _user(models, role="therapist" if therapist else "user")
        counterpart = _user(models, "foreign", "user" if therapist else "therapist")
        unrelated_patient = _user(models, "untouched")
        unrelated_therapist = _user(models, "clinician", "therapist")
        session.add_all([owner, counterpart, unrelated_patient, unrelated_therapist])
        phases = ["note_revisions", "consents", "totp_codes", "rekey"]
        phases += (
            ["pairing_codes"]
            if therapist
            else ["consent_events", "entries", "insights", "measures"]
        )
        children = [
            child
            for phase in phases
            for child in _child(models, phase, owner.id, therapist=therapist)
        ]
        session.add_all(children)
        preserved = [
            models.TherapistNote(
                id="foreign-note",
                therapist_id="clinician",
                user_id="untouched",
                client_note_id="foreign-note",
                blob=b"private",
            ),
            models.TherapistNoteRevision(
                id="foreign-revision",
                note_id="foreign-note",
                therapist_id="clinician",
                blob=b"private",
            ),
            models.Consent(
                id="foreign-consent", user_id="untouched", therapist_id="clinician"
            ),
        ]
        for phase in [
            "consent_events",
            "entries",
            "insights",
            "measures",
            "totp_codes",
            "rekey",
        ]:
            preserved.extend(_child(models, phase, "untouched", suffix="-foreign"))
        preserved.extend(
            _child(
                models, "pairing_codes", "clinician", therapist=True, suffix="-foreign"
            )
        )
        session.add_all(preserved)
        job = module.stage_account_deletion(session, owner)
        await session.commit()
        progress = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert (
            progress.rows_deleted == len(children) + 1
            and progress.found is True
            and progress.backlog is False
        )
        await session.commit()
        for child in children:
            assert (
                await session.get(type(child), child.id, populate_existing=True) is None
            )
        for child in preserved:
            assert (
                await session.get(type(child), child.id, populate_existing=True)
                is not None
            )
        assert (
            await session.get(
                models.AccountDeletionJob, job.user_id, populate_existing=True
            )
            is None
        )

    asyncio.run(_database(models, exercise))


def test_shared_row_budget_crosses_phases_and_accepts_last_available_sharing_revision(
    monkeypatch,
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import select

    async def exercise(session):
        owner, counterpart = _user(models), _user(models, "foreign", "therapist")
        counterpart.patients_revision = 2**63 - 2
        session.add_all([owner, counterpart])
        session.add_all(
            [
                models.TherapistNote(
                    id=f"note-{n}",
                    user_id=owner.id,
                    therapist_id=counterpart.id,
                    client_note_id=f"note-{n}",
                    blob=b"private",
                )
                for n in range(98)
            ]
        )
        session.add(
            models.Consent(id="consent", user_id=owner.id, therapist_id=counterpart.id)
        )
        session.add_all(
            [
                models.Entry(
                    id=f"entry-{n}",
                    user_id=owner.id,
                    client_entry_id=f"entry-{n}",
                    entry_date=date(2026, 10, 5),
                    blob=b"private",
                )
                for n in range(2)
            ]
        )
        job = module.stage_account_deletion(session, owner)
        await session.commit()
        first = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert first.rows_deleted == 100 and first.backlog is True
        await session.commit()
        await session.refresh(counterpart)
        assert counterpart.patients_revision == 2**63 - 1
        assert job.phase == "entries" and job.attempts == 1 and job.updated_at == NOW
        assert len(list((await session.scalars(select(models.Entry))).all())) == 1
        second = await module.purge_one_account_page(
            session, SimpleNamespace(), owner_id=owner.id
        )
        assert second.rows_deleted == 2 and second.backlog is False
        await session.commit()

    asyncio.run(_database(models, exercise))


def test_exact_native_audio_page_retains_parent_and_original_locator(
    monkeypatch, tmp_path
):
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    audio = importlib.import_module("app.services.audio_store")
    settings = SimpleNamespace(
        audio_bucket="",
        audio_bucket_region="",
        audio_s3_endpoint="",
        audio_local_dir=str(tmp_path / "recordings"),
        environment="production",
        audio_aws_access_key_id="",
        audio_aws_secret_access_key="",
    )
    target = audio.storage_locator(audio.get_audio_store_cached(settings))

    async def exercise(session):
        owner = _user(models)
        session.add(owner)
        session.add_all(
            [_child(models, "audio", owner.id, suffix=str(n))[0] for n in range(50)]
        )
        job = module.stage_account_deletion(session, owner)
        job.attempts = 2
        await session.commit()
        result = await module.purge_one_account_page(
            session, settings, owner_id=owner.id
        )
        assert asdict(result) == {
            "found": True,
            "backlog": True,
            "rows_deleted": 50,
            "user_id": "patient",
        }
        await session.commit()
        assert job.phase == "audio" and job.attempts == 3
        assert (
            await session.get(models.User, "patient", populate_existing=True)
            is not None
        )
        from sqlalchemy import select

        rows = list((await session.scalars(select(models.AudioDeletion))).all())
        assert len(rows) == 50 and all(row.storage_locator == target for row in rows)

    asyncio.run(_database(models, exercise))


@pytest.mark.parametrize(
    "locked,explicit", [(False, False), (True, False), (True, True)]
)
def test_postgresql_workers_skip_locked_jobs_and_lock_only_one_claim(
    monkeypatch, locked, explicit
):
    import os
    import uuid

    url = os.environ.get("ACCOUNT_MUTATION_POSTGRES_URL")
    if not url:
        pytest.skip("dedicated PostgreSQL account-deletion locking oracle")
    module, models = _modules(monkeypatch)
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from sqlalchemy import select, text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    async def exercise():
        schema = "account_mutation_" + uuid.uuid4().hex
        admin = create_async_engine(url)
        engine = create_async_engine(
            url,
            connect_args={
                "server_settings": {"search_path": schema, "statement_timeout": "1000"}
            },
        )
        try:
            async with admin.begin() as connection:
                await connection.execute(text("CREATE SCHEMA " + schema))
            async with engine.begin() as connection:
                await connection.run_sync(models.Base.metadata.create_all)
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as seed:
                seed.add_all(
                    [
                        models.AccountDeletionJob(
                            user_id=owner,
                            role="user",
                            phase="audio_wait",
                            requested_at=NOW,
                            updated_at=NOW + timedelta(seconds=n),
                        )
                        for n, owner in enumerate(("a", "b", "c"))
                    ]
                )
                seed.add_all(
                    [
                        models.AudioDeletion(
                            id=owner,
                            owner_id=owner,
                            backend="local",
                            storage_key=owner,
                            not_before=NOW,
                            created_at=NOW,
                        )
                        for owner in ("a", "b", "c")
                    ]
                )
                await seed.commit()
            async with maker() as blocker, maker() as worker, maker() as other:
                if locked:
                    assert (
                        await blocker.scalar(
                            select(models.AccountDeletionJob)
                            .where(models.AccountDeletionJob.user_id == "a")
                            .with_for_update()
                        )
                        is not None
                    )
                progress = await module.purge_one_account_page(
                    worker, SimpleNamespace(), owner_id="a" if explicit else None
                )
                if explicit:
                    assert asdict(progress) == {
                        "found": False,
                        "backlog": False,
                        "rows_deleted": 0,
                        "user_id": None,
                    }
                else:
                    assert (
                        progress.user_id == ("b" if locked else "a")
                        and progress.found is True
                    )
                    # A cooperative page owns exactly one queue claim. Another
                    # worker must be able to claim the following unclaimed job.
                    available = await other.scalar(
                        select(models.AccountDeletionJob.user_id)
                        .where(
                            models.AccountDeletionJob.user_id
                            == ("c" if locked else "b")
                        )
                        .with_for_update(skip_locked=True)
                    )
                    assert available == ("c" if locked else "b")
        finally:
            await engine.dispose()
            async with admin.begin() as connection:
                await connection.execute(
                    text("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
                )
            await admin.dispose()

    asyncio.run(exercise())
