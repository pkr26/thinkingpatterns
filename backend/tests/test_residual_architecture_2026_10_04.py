"""Regression pins for the final independent-audit architecture fixes."""

from __future__ import annotations

import asyncio
import gc
import warnings
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import Response
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import _audit as audit_mod
from app.api import consents as consents_mod
from app.api import therapist as therapist_mod
from app.api._audit import (
    append_access_log,
    close_reusable_journal_evidence_index,
    flush_audit_journal,
    reusable_journal_evidence_index,
    verify_access_log_chain_incremental,
)
from app.config import Settings
from app.deps import ApiError
from app.models import (
    AccessLog,
    AccountDeletionJob,
    AudioDeletion,
    AuditSweepCursor,
    Base,
    Consent,
    Entry,
    ROLE_THERAPIST,
    User,
    new_id,
    utcnow,
)
from app.metrics import MetricsRegistry
from app.main import _purge_deleted_account_once
from app.services.account_deletion import (
    ACCOUNT_PURGE_ROW_BATCH,
    account_deletion_status,
    purge_one_account_page,
    stage_account_deletion,
)
from app.services.audio_store import LocalAudioStore


def _user(identifier: str, username: str, *, role: str = "user") -> User:
    return User(
        id=identifier,
        username=username,
        salt="public-salt",
        verifier=b"v" * 32,
        scrypt_salt=b"s" * 16,
        role=role,
    )


@pytest_asyncio.fixture
async def architecture_sessionmaker():
    from app.db import build_engine, build_sessionmaker

    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield build_sessionmaker(engine)
    await engine.dispose()


async def _seed_mac_chain(sessionmaker, owner: str, key: bytes, count: int) -> None:
    async with sessionmaker() as session:
        for index in range(count):
            await append_access_log(
                session,
                actor_id=new_id(),
                actor_role="user",
                user_id=owner,
                action=f"bounded-{index}",
                mac_keys={1: key},
                current_mac_key_version=1,
                allow_new_chain=index == 0,
            )
        await session.commit()


async def test_incremental_audit_verifier_resumes_signed_pages_across_sessions(
    architecture_sessionmaker,
):
    owner = new_id()
    key = b"v" * 32
    await _seed_mac_chain(architecture_sessionmaker, owner, key, 5)

    observed: list[tuple[int, bool]] = []
    for _ in range(3):
        async with architecture_sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            if cursor is None:
                cursor = AuditSweepCursor(id=1, updated_at=utcnow())
                session.add(cursor)
            verdict = await verify_access_log_chain_incremental(
                session,
                cursor,
                owner,
                mac_keys={1: key},
                current_mac_key_version=1,
                journal_evidence={},
                row_budget=2,
            )
            observed.append((verdict.rows_checked, verdict.complete))
            await session.commit()

    assert observed == [(2, False), (2, False), (1, True)]
    async with architecture_sessionmaker() as session:
        cursor = await session.get(AuditSweepCursor, 1)
        assert cursor is not None
        assert cursor.last_user_id == owner
        assert cursor.verification_owner_id is None
        assert cursor.verification_checkpoint_mac is not None


async def test_incremental_audit_verifier_rejects_checkpoint_tampering(
    architecture_sessionmaker,
):
    owner = new_id()
    key = b"w" * 32
    await _seed_mac_chain(architecture_sessionmaker, owner, key, 3)
    async with architecture_sessionmaker() as session:
        cursor = AuditSweepCursor(id=1, updated_at=utcnow())
        session.add(cursor)
        first = await verify_access_log_chain_incremental(
            session,
            cursor,
            owner,
            mac_keys={1: key},
            current_mac_key_version=1,
            journal_evidence={},
            row_budget=1,
        )
        assert first.ok and not first.complete
        await session.commit()

    async with architecture_sessionmaker() as session:
        cursor = await session.get(AuditSweepCursor, 1)
        assert cursor is not None
        cursor.verification_next_seq = int(cursor.verification_next_seq or 0) + 1
        await session.commit()

    async with architecture_sessionmaker() as session:
        cursor = await session.get(AuditSweepCursor, 1)
        assert cursor is not None
        with pytest.raises(ApiError, match="checkpoint does not authenticate"):
            await verify_access_log_chain_incremental(
                session,
                cursor,
                owner,
                mac_keys={1: key},
                current_mac_key_version=1,
                journal_evidence={},
                row_budget=1,
            )


async def test_reusable_journal_index_scans_once_and_absorbs_controlled_append(
    tmp_path, monkeypatch
):
    close_reusable_journal_evidence_index()
    owner = "a" * 32
    journal = tmp_path / "audit.journal"
    at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    journal.write_text(
        f"{owner} 1 {'1' * 64} {'2' * 64} {at.isoformat()}\n"
        f"{owner} 2 {'3' * 64} {'4' * 64} {at.isoformat()}\n",
        encoding="utf-8",
    )
    calls = 0
    real_parse = audit_mod._parse_journal_line

    def counted(line: str):
        nonlocal calls
        calls += 1
        return real_parse(line)

    monkeypatch.setattr(audit_mod, "_parse_journal_line", counted)
    rebuilt_path: Path | None = None
    try:
        first = reusable_journal_evidence_index(str(journal))
        assert reusable_journal_evidence_index(str(journal)) is first
        assert reusable_journal_evidence_index(str(journal)) is first
        assert calls == 2

        session = AsyncSession()
        session.info["mindpattern_audit_journal_pending"] = [(owner, 3, "5" * 64, "6" * 64, at)]
        try:
            assert await flush_audit_journal(session, str(journal)) == 1
        finally:
            await session.close()
        assert reusable_journal_evidence_index(str(journal)) is first
        assert first.get(owner).seq == 3
        assert calls == 2

        with journal.open("a", encoding="utf-8") as handle:
            handle.write(f"{owner} 4 {'7' * 64} {'8' * 64} {at.isoformat()}\n")
        rebuilt = reusable_journal_evidence_index(str(journal))
        assert rebuilt is not first
        assert rebuilt.get(owner).seq == 4
        assert calls == 6
        rebuilt_path = Path(rebuilt.path)
    finally:
        close_reusable_journal_evidence_index()
    assert rebuilt_path is not None and not rebuilt_path.exists()


async def test_local_inventory_scans_tree_once_per_cursor_cycle(tmp_path, monkeypatch):
    owner = "b" * 32
    root = tmp_path / "audio-store"
    for index in range(5):
        path = root / "audio" / owner / f"{index:032x}.enc"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ciphertext")

    real_glob = Path.glob
    scans = 0

    def counted_glob(path: Path, pattern: str):
        nonlocal scans
        if path == root.resolve() and pattern == "audio/**/*.enc":
            scans += 1
        return real_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", counted_glob)
    store = LocalAudioStore(str(root))
    first, cursor = await store.inventory_page(after_key=None, limit=2)
    second, cursor = await store.inventory_page(after_key=cursor, limit=2)
    third, cursor = await store.inventory_page(after_key=cursor, limit=2)
    assert len(first) + len(second) + len(third) == 5
    assert cursor is None
    assert scans == 1

    await store.inventory_page(after_key=None, limit=2)
    assert scans == 2

    restarted = LocalAudioStore(str(root))
    await restarted.inventory_page(after_key=first[-1][0], limit=2)
    assert scans == 3


async def test_sqlite_indexes_close_every_connection_without_resource_warnings(tmp_path):
    """RVI-071: both derived SQLite indexes own and close every handle."""
    journal = tmp_path / "resource-audit.journal"
    owner = "c" * 32
    at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    journal.write_text(
        f"{owner} 1 {'1' * 64} {'2' * 64} {at.isoformat()}\n",
        encoding="utf-8",
    )
    root = tmp_path / "resource-audio"
    store = LocalAudioStore(str(root))
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always", ResourceWarning)
        for index in range(4):
            key = f"audio/{owner}/{index:032x}.enc"
            await store.put(key, b"ciphertext")
            await store.inventory_page(after_key=None, limit=2)
            await store.delete(key)
        close_reusable_journal_evidence_index()
        try:
            evidence = reusable_journal_evidence_index(str(journal))
            for _ in range(4):
                assert evidence.get(owner) is not None
                assert evidence.owner_ids_after(None, 2) == [owner]
                assert evidence.all_evidence()[owner].seq == 1
        finally:
            close_reusable_journal_evidence_index()
        gc.collect()
    resource_warnings = [item for item in emitted if issubclass(item.category, ResourceWarning)]
    assert resource_warnings == []


async def test_account_deletion_worker_deletes_at_most_one_aggregate_page(
    architecture_sessionmaker,
):
    owner = new_id()
    settings = Settings(environment="development")
    async with architecture_sessionmaker() as session:
        user = User(
            id=owner,
            username="bounded-delete",
            salt="public-salt",
            verifier=b"v" * 32,
            scrypt_salt=b"s" * 16,
            role="user",
        )
        session.add(user)
        await session.commit()
        session.add_all(
            [
                Entry(
                    user_id=owner,
                    client_entry_id=f"bounded-delete-{index}",
                    blob=b"x" * 40,
                    entry_date=date.today(),
                )
                for index in range(ACCOUNT_PURGE_ROW_BATCH + 1)
            ]
        )
        await session.commit()
        stage_account_deletion(session, user)
        await session.commit()

    async with architecture_sessionmaker() as session:
        first = await purge_one_account_page(session, settings, owner_id=owner)
        await session.commit()
        assert first.rows_deleted == ACCOUNT_PURGE_ROW_BATCH

    async with architecture_sessionmaker() as session:
        scrubbed = await session.get(User, owner)
        job = await session.get(AccountDeletionJob, owner)
        remaining = int(
            await session.scalar(select(func.count(Entry.id)).where(Entry.user_id == owner)) or 0
        )
        assert scrubbed is not None and scrubbed.is_active is False
        assert scrubbed.username.startswith("deleted-")
        assert scrubbed.wrapped_data_key is None and scrubbed.recovery_verifier is None
        assert job is not None and job.phase == "entries"
        assert remaining == 1

    async with architecture_sessionmaker() as session:
        progress = await purge_one_account_page(
            session,
            settings,
            owner_id=owner,
        )
        await session.commit()
        assert progress.rows_deleted <= ACCOUNT_PURGE_ROW_BATCH
    async with architecture_sessionmaker() as session:
        assert await session.get(User, owner) is None
        assert await session.get(AccountDeletionJob, owner) is None
        assert await session.scalar(select(func.count(Entry.id)).where(Entry.user_id == owner)) == 0


async def test_ownerless_audio_tombstone_blocks_account_purge_completion(
    architecture_sessionmaker,
):
    owner = new_id()
    settings = Settings(environment="development")
    tombstone_id = new_id()
    async with architecture_sessionmaker() as session:
        session.add(
            AccountDeletionJob(
                user_id=owner,
                role="user",
                phase="audio_wait",
                requested_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        session.add(
            AudioDeletion(
                id=tombstone_id,
                owner_id=None,
                backend="local",
                storage_key=f"audio/{owner}/{new_id()}.enc",
                storage_locator="/unavailable/legacy-store",
                not_before=utcnow(),
            )
        )
        await session.commit()

    async with architecture_sessionmaker() as session:
        blocked = await purge_one_account_page(session, settings, owner_id=owner)
        await session.commit()
        assert blocked.backlog
        assert await session.get(AccountDeletionJob, owner) is not None

    async with architecture_sessionmaker() as session:
        await session.execute(delete(AudioDeletion).where(AudioDeletion.id == tombstone_id))
        await session.commit()
    async with architecture_sessionmaker() as session:
        done = await purge_one_account_page(session, settings, owner_id=owner)
        await session.commit()
        assert not done.backlog
        assert await session.get(AccountDeletionJob, owner) is None


@pytest.mark.parametrize(
    ("deleted_role", "counterpart_revision"),
    [("user", "patients_revision"), (ROLE_THERAPIST, "consents_revision")],
)
async def test_consent_purge_bumps_counterpart_snapshot_in_both_directions(
    architecture_sessionmaker,
    deleted_role,
    counterpart_revision,
):
    owner = new_id()
    counterpart = new_id()
    patient_id = owner if deleted_role == "user" else counterpart
    therapist_id = counterpart if deleted_role == "user" else owner
    counterpart_role = ROLE_THERAPIST if deleted_role == "user" else "user"
    settings = Settings(environment="development")
    async with architecture_sessionmaker() as session:
        deleted_user = _user(owner, f"deleted-{owner}", role=deleted_role)
        deleted_user.is_active = False
        survivor = _user(counterpart, f"survivor-{counterpart}", role=counterpart_role)
        setattr(survivor, counterpart_revision, 7)
        session.add_all([deleted_user, survivor])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=new_id(),
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                ),
                AccountDeletionJob(
                    user_id=owner,
                    role=deleted_role,
                    phase="consents",
                    requested_at=utcnow(),
                    updated_at=utcnow(),
                ),
            ]
        )
        await session.commit()

    async with architecture_sessionmaker() as session:
        await purge_one_account_page(session, settings, owner_id=owner)
        await session.commit()

    async with architecture_sessionmaker() as session:
        survivor = await session.get(User, counterpart)
        assert survivor is not None
        assert getattr(survivor, counterpart_revision) == 8
        assert await session.scalar(select(func.count(Consent.id))) == 0


@pytest.mark.parametrize(
    ("deleted_role", "counterpart_revision"),
    [("user", "patients_revision"), (ROLE_THERAPIST, "consents_revision")],
)
async def test_consent_purge_fails_before_delete_when_counterpart_revision_is_exhausted(
    architecture_sessionmaker,
    deleted_role,
    counterpart_revision,
):
    owner = new_id()
    counterpart = new_id()
    patient_id = owner if deleted_role == "user" else counterpart
    therapist_id = counterpart if deleted_role == "user" else owner
    counterpart_role = ROLE_THERAPIST if deleted_role == "user" else "user"
    consent_id = new_id()
    async with architecture_sessionmaker() as session:
        deleted_user = _user(owner, f"deleted-max-{owner}", role=deleted_role)
        deleted_user.is_active = False
        survivor = _user(counterpart, f"survivor-max-{counterpart}", role=counterpart_role)
        setattr(survivor, counterpart_revision, 2**63 - 1)
        session.add_all([deleted_user, survivor])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=consent_id,
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                ),
                AccountDeletionJob(
                    user_id=owner,
                    role=deleted_role,
                    phase="consents",
                    requested_at=utcnow(),
                    updated_at=utcnow(),
                ),
            ]
        )
        await session.commit()

    async with architecture_sessionmaker() as session:
        with pytest.raises(RuntimeError, match="counterpart sharing revision exhausted"):
            await purge_one_account_page(
                session,
                Settings(environment="development"),
                owner_id=owner,
            )
        await session.rollback()

    async with architecture_sessionmaker() as session:
        survivor = await session.get(User, counterpart)
        assert survivor is not None
        assert getattr(survivor, counterpart_revision) == 2**63 - 1
        assert await session.get(Consent, consent_id) is not None


async def test_patient_consent_list_final_fence_catches_counterpart_retirement(
    architecture_sessionmaker, monkeypatch
):
    patient_id = new_id()
    therapist_id = new_id()
    async with architecture_sessionmaker() as session:
        patient = _user(patient_id, "list-race-patient")
        therapist = _user(therapist_id, "list-race-therapist", role=ROLE_THERAPIST)
        therapist.display_name = "Before Retirement"
        session.add_all([patient, therapist])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=new_id(),
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                ),
            ]
        )
        await session.commit()
        real_execute = session.execute
        retired = False

        async def execute_with_retirement(statement, *args, **kwargs):
            nonlocal retired
            result = await real_execute(statement, *args, **kwargs)
            sql = str(statement).lower()
            if not retired and "order by consents.granted_at desc" in sql:
                retired = True
                await real_execute(
                    update(User)
                    .where(User.id == therapist_id)
                    .values(is_active=False)
                    .execution_options(synchronize_session=False)
                )
            return result

        monkeypatch.setattr(session, "execute", execute_with_retirement)
        with pytest.raises(ApiError) as excinfo:
            await consents_mod._list_consents_page(Response(), patient, session, 100, 0, None)
        assert excinfo.value.code == "collection_changed"


async def test_therapist_patient_list_final_fence_catches_revoked_patient_retirement(
    architecture_sessionmaker, monkeypatch
):
    patient_id = new_id()
    therapist_id = new_id()
    async with architecture_sessionmaker() as session:
        patient = _user(patient_id, "roster-race-patient")
        therapist = _user(therapist_id, "roster-race-therapist", role=ROLE_THERAPIST)
        session.add_all([patient, therapist])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=new_id(),
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                ),
            ]
        )
        await session.commit()
        real_execute = session.execute
        retired = False

        async def execute_with_retirement(statement, *args, **kwargs):
            nonlocal retired
            result = await real_execute(statement, *args, **kwargs)
            sql = str(statement).lower()
            if not retired and "order by consents.granted_at desc" in sql:
                retired = True
                await real_execute(
                    update(User)
                    .where(User.id == patient_id)
                    .values(is_active=False)
                    .execution_options(synchronize_session=False)
                )
            return result

        async def no_audit(*_args, **_kwargs):
            return None

        monkeypatch.setattr(session, "execute", execute_with_retirement)
        monkeypatch.setattr(therapist_mod, "_audit", no_audit)
        with pytest.raises(ApiError) as excinfo:
            await therapist_mod.list_patients(
                request=SimpleNamespace(),
                response=Response(),
                user=therapist,
                session=session,
                limit=100,
                offset=0,
                expected_revision=None,
            )
        assert excinfo.value.code == "collection_changed"


async def test_therapist_guard_reauthorizes_after_waiting_behind_retirement(
    architecture_sessionmaker,
):
    therapist_id = new_id()
    async with architecture_sessionmaker() as session:
        session.add(_user(therapist_id, "queued-therapist", role=ROLE_THERAPIST))
        await session.commit()
        therapist = await session.get(User, therapist_id)
        assert therapist is not None
        gate = therapist_mod.sharing_locks.hold(
            therapist_mod.sharing_therapist_lock_key(therapist_id)
        )
        await gate.__aenter__()

        async def attempt_read():
            try:
                async with therapist_mod._therapist_sharing_guard(session, therapist):
                    return None
            except ApiError as exc:
                return exc

        task = asyncio.create_task(attempt_read())
        await asyncio.sleep(0)
        therapist.is_active = False
        await session.commit()
        await gate.__aexit__(None, None, None)
        result = await task
        assert isinstance(result, ApiError)
        assert result.status_code == 401


async def test_patient_consent_list_reauthorizes_after_waiting_behind_retirement(
    architecture_sessionmaker,
):
    patient_id = new_id()
    async with architecture_sessionmaker() as session:
        session.add(_user(patient_id, "queued-patient"))
        await session.commit()
        patient = await session.get(User, patient_id)
        assert patient is not None
        gate = consents_mod.sharing_locks.hold(consents_mod.sharing_patient_lock_key(patient_id))
        await gate.__aenter__()

        async def attempt_read():
            try:
                await consents_mod.list_consents(Response(), patient, session, 100, 0, None)
                return None
            except ApiError as exc:
                return exc

        task = asyncio.create_task(attempt_read())
        await asyncio.sleep(0)
        patient.is_active = False
        await session.commit()
        await gate.__aexit__(None, None, None)
        result = await task
        assert isinstance(result, ApiError)
        assert result.status_code == 401


async def test_staged_patient_is_not_a_direct_note_target(architecture_sessionmaker):
    patient_id = new_id()
    therapist_id = new_id()
    async with architecture_sessionmaker() as session:
        patient = _user(patient_id, "retired-note-patient")
        patient.is_active = False
        therapist = _user(therapist_id, "note-therapist", role=ROLE_THERAPIST)
        session.add_all([patient, therapist])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=new_id(),
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                ),
            ]
        )
        await session.commit()
        with pytest.raises(ApiError) as excinfo:
            await therapist_mod._note_target(session, therapist, patient_id)
        assert excinfo.value.status_code == 404


async def test_retired_therapist_cannot_receive_post_delete_consent_mutations(
    architecture_sessionmaker, monkeypatch
):
    patient_id = new_id()
    therapist_id = new_id()
    consent_id = new_id()

    async def accept_proof(*_args, **_kwargs):
        return None

    monkeypatch.setattr(consents_mod, "_require_step_up_or_verifier", accept_proof)
    async with architecture_sessionmaker() as session:
        patient = _user(patient_id, "mutation-patient")
        therapist = _user(therapist_id, "retired-mutation-therapist", role=ROLE_THERAPIST)
        therapist.is_active = False
        session.add_all([patient, therapist])
        await session.commit()
        session.add_all(
            [
                Consent(
                    id=consent_id,
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="active",
                    share_voice=False,
                ),
            ]
        )
        await session.commit()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(audio_enabled=True)))
        )
        with pytest.raises(ApiError) as voice_error:
            await consents_mod.set_share_voice(
                consent_id,
                consents_mod.ShareVoiceRequest(enabled=True),
                request,
                patient,
                session,
                None,
                None,
            )
        assert voice_error.value.status_code == 404
        await session.rollback()
        patient = await session.get(User, patient_id, populate_existing=True)
        assert patient is not None
        with pytest.raises(ApiError) as revoke_error:
            await consents_mod.revoke_consent(
                consent_id,
                request,
                patient,
                session,
                None,
                None,
            )
        assert revoke_error.value.status_code == 404
        await session.rollback()
        consent = await session.get(Consent, consent_id, populate_existing=True)
        retired = await session.get(User, therapist_id, populate_existing=True)
        assert consent is not None and consent.status == "active" and not consent.share_voice
        assert retired is not None and retired.patients_revision == 0


async def test_account_deletion_audio_wait_uses_due_aware_cadence_and_metrics(
    architecture_sessionmaker,
):
    owner = new_id()
    requested_at = utcnow() - timedelta(hours=3)
    not_before = utcnow() + timedelta(hours=1)
    async with architecture_sessionmaker() as session:
        session.add_all(
            [
                AccountDeletionJob(
                    user_id=owner,
                    role="user",
                    phase="audio_wait",
                    requested_at=requested_at,
                    updated_at=requested_at,
                ),
                AudioDeletion(
                    id=new_id(),
                    owner_id=owner,
                    backend="local",
                    storage_key=f"audio/{owner}/{new_id()}.enc",
                    storage_locator="/unavailable/store",
                    not_before=not_before,
                ),
            ]
        )
        await session.commit()
        status = await account_deletion_status(session)
        assert status.pending_probe == 1
        assert not status.runnable
        assert status.next_due_at == not_before

    metrics = MetricsRegistry()
    app = SimpleNamespace(
        state=SimpleNamespace(
            sessionmaker=architecture_sessionmaker,
            settings=Settings(environment="development"),
            metrics=metrics,
            account_deletion_backlog=False,
            account_deletion_failure_streak=0,
        )
    )
    assert await _purge_deleted_account_once(app)
    assert 1 <= app.state.account_deletion_retry_delay_seconds <= 60
    rendered = metrics.render(0)
    assert "mindpattern_account_deletion_pending_probe 1" in rendered
    oldest = next(
        line
        for line in rendered.splitlines()
        if line.startswith("mindpattern_account_deletion_oldest_seconds ")
    )
    assert float(oldest.split()[1]) >= 3 * 60 * 60
    metrics.observe_account_deletion_failure("database")
    metrics.observe_account_deletion_failure("untrusted-exception-text")
    rendered = metrics.render(0)
    assert 'mindpattern_account_deletion_failures_total{category="database"} 1' in rendered
    assert 'mindpattern_account_deletion_failures_total{category="unexpected"} 1' in rendered
    assert "untrusted-exception-text" not in rendered
