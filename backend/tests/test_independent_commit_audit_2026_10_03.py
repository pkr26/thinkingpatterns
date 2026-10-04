"""Independent failure probes for the last commit's export guarantees.

These use real sessions and the shipping mutation/authentication paths. A
paused response iterator represents a slow downloader between bounded pages.
"""

from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select, update

from app.api import account, insights
from app.api._audit import read_journal_head, verify_access_log_chain
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError, require_user
from app.locks import lifecycle_locks
from app.models import AccessLog, AudioDeletion, Base, Entry, Insight, RekeyJournal, User, utcnow
from app.services import audio_store
from tests.helpers import ClientEmulator


async def _export_response(app, patient):
    request = SimpleNamespace(app=app, state=SimpleNamespace(), method="GET")
    async with app.state.sessionmaker() as session:
        user = await require_user(request, patient.headers["Authorization"], session)
        return await account.export_account(request, user=user, session=session)


async def _advance_to(response, marker):
    while True:
        chunk = await anext(response.body_iterator)
        if marker in chunk:
            return


async def _finish(response):
    return "".join([chunk async for chunk in response.body_iterator])


async def test_export_rejects_retired_epoch_before_refreshing_same_orm_user(client, app):
    patient = ClientEmulator("audit-export-epoch", "password")
    await patient.register(client)
    request = SimpleNamespace(app=app, state=SimpleNamespace(), method="GET")
    async with app.state.sessionmaker() as session:
        user = await require_user(request, patient.headers["Authorization"], session)
        expected_epoch = user.token_epoch
        async with app.state.sessionmaker() as retire_session:
            await retire_session.execute(
                update(User)
                .where(User.id == patient.user_id)
                .values(token_epoch=expected_epoch + 1)
            )
            await retire_session.commit()
        response = None
        try:
            with pytest.raises(ApiError) as raised:
                response = await account.export_account(request, user=user, session=session)
            assert raised.value.status_code == 401
        finally:
            if response is not None:
                await response.body_iterator.aclose()


async def test_export_stops_after_same_device_logout_without_epoch_change(client, app):
    patient = ClientEmulator("audit-export-logout", "password")
    await patient.register(client)
    response = await _export_response(app, patient)
    await _advance_to(response, ',"entries":[')
    assert (await client.post("/api/auth/logout", headers=patient.headers)).status_code == 204
    try:
        with pytest.raises(ApiError) as raised:
            await _finish(response)
        assert raised.value.status_code == 401
    finally:
        await response.body_iterator.aclose()


async def test_export_stops_when_rotation_is_interrupted_before_revision_bump(client, app):
    patient = ClientEmulator("audit-export-rekey", "password")
    await patient.register(client)
    await patient.create_entry(
        client, "preserve every generation", utcnow().date(), "partial-entry"
    )
    response = await _export_response(app, patient)
    await _advance_to(response, ',"entries":[')
    # A committed journal is the durable state of an interrupted rekey. Its
    # early batches leave the account epoch/collection revisions unchanged.
    async with lifecycle_locks.hold(f"llm-lifecycle:{patient.user_id}"):
        async with app.state.sessionmaker() as session:
            entry = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
            rewritten, already_new = insights._rekey_entry_batch(
                bytearray(patient.data_key),
                bytearray(os.urandom(32)),
                [(entry.id, entry.client_entry_id, entry.content_version, bytes(entry.blob))],
                patient.user_id,
            )
            assert already_new == 0
            entry.blob = rewritten[0][1]
            session.add(RekeyJournal(user_id=patient.user_id, stage="entries"))
            await session.commit()
    try:
        with pytest.raises(ApiError) as raised:
            await _finish(response)
        assert raised.value.code == "rekey_in_progress"
    finally:
        await response.body_iterator.aclose()


async def test_export_refuses_insight_replaced_before_size_metadata_fetch(client, app):
    patient = ClientEmulator("audit-export-analysis", "password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        await insights._replace_insight(session, patient.user_id, "brain", None, b"a" * 60)
        await session.commit()
        original_id = await session.scalar(select(Insight.id))
    response = await _export_response(app, patient)
    await _advance_to(response, '],"insights":[')
    # This is the exact delete/insert write used by successful recompute.
    async with lifecycle_locks.hold(f"llm-lifecycle:{patient.user_id}"):
        async with app.state.sessionmaker() as session:
            await insights._replace_insight(session, patient.user_id, "brain", None, b"b" * 60)
            await session.commit()
            assert await session.scalar(select(Insight.id)) != original_id
    try:
        with pytest.raises(ApiError) as raised:
            await _finish(response)
        assert raised.value.status_code == 409
        assert raised.value.code == "collection_changed"
    finally:
        await response.body_iterator.aclose()


async def test_export_rejects_access_log_retention_between_pages(client, app, monkeypatch):
    """A retention/delete race must truncate with an explicit snapshot
    conflict, never complete a valid-looking JSON bundle missing an unseen
    audit row."""
    patient = ClientEmulator("audit-export-access-snapshot", "password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        for index in range(3):
            await account.append_access_log(
                session,
                actor_id=patient.user_id,
                actor_role="patient",
                user_id=patient.user_id,
                action=f"snapshot_event_{index}",
            )
        await session.commit()
    monkeypatch.setattr(account, "EXPORT_METADATA_PAGE_SIZE", 1)
    response = await _export_response(app, patient)
    await _advance_to(response, '],"access_log":[')
    first_row = await anext(response.body_iterator)
    assert "snapshot_event_" in first_row or '"action"' in first_row

    async with app.state.sessionmaker() as session:
        unseen = await session.scalar(
            select(AccessLog)
            .where(AccessLog.user_id == patient.user_id)
            .order_by(AccessLog.at.desc(), AccessLog.id.desc())
        )
        assert unseen is not None
        await session.delete(unseen)
        await session.commit()
    try:
        with pytest.raises(ApiError) as raised:
            await _finish(response)
        assert raised.value.status_code == 409
        assert raised.value.code == "collection_changed"
    finally:
        await response.body_iterator.aclose()


async def test_export_head_cancellation_releases_admission_capacity(client, app, monkeypatch):
    patient = ClientEmulator("audit-export-cancel", "password")
    await patient.register(client)
    request = SimpleNamespace(app=app, state=SimpleNamespace(), method="GET")
    async with app.state.sessionmaker() as session:
        user = await require_user(request, patient.headers["Authorization"], session)
        started = asyncio.Event()

        async def blocked_read(*args, **kwargs):
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(session, "execute", blocked_read)
        limiter = app.state.export_limiter
        task = asyncio.create_task(account.export_account(request, user=user, session=session))
        await asyncio.wait_for(started.wait(), timeout=2)
        assert limiter.borrowed_tokens == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert limiter.borrowed_tokens == 0


async def test_atomic_rotation_journals_commit_and_detects_tail_deletion(
    client, app, settings, tmp_path
):
    settings.audit_journal_path = str(tmp_path / "audit.journal")
    patient = ClientEmulator("audit-rekey-journal", "password")
    await patient.register(client)
    old_token = await patient.open_processing_session(client)
    new_token = await patient.open_processing_session_for(client, os.urandom(32))
    headers = {
        **patient.headers,
        "X-Account-Verifier": patient.auth_key_b64,
        "X-Processing-Token": old_token,
        "X-New-Processing-Token": new_token,
    }
    payload = patient.rekey_payload()
    response = await client.post("/api/processing/rekey", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    journal = (tmp_path / "audit.journal").read_bytes()
    retried = await client.post("/api/processing/rekey", headers=headers, json=payload)
    assert retried.status_code == 200 and retried.json() == response.json()
    assert (tmp_path / "audit.journal").read_bytes() == journal
    async with app.state.sessionmaker() as session:
        row = await session.scalar(
            select(AccessLog).where(AccessLog.action == "corpus_credential_rotated")
        )
        assert row is not None
        assert read_journal_head(settings.audit_journal_path, patient.user_id) == (
            row.chain_seq,
            row.at.isoformat(),
        )
        await session.execute(delete(AccessLog).where(AccessLog.id == row.id))
        await session.commit()
        proof = await verify_access_log_chain(
            session,
            patient.user_id,
            mac_key=bytes.fromhex(settings.audit_mac_secret_hex),
            journal_path=settings.audit_journal_path,
            retention_cutoff=row.at - timedelta(seconds=1),
        )
        assert proof.ok is False
    assert proof.reason in {
        "tail truncation detected: durable journal is ahead of database",
        "database tail differs from durable chain head",
    }


async def test_audio_cleanup_claims_each_tombstone_before_provider_io(
    app, settings, tmp_path, monkeypatch
):
    settings.audio_local_dir = str(tmp_path / "audio")
    store = audio_store.get_audio_store_cached(settings)
    key = audio_store.new_storage_key("0" * 32)
    await store.put(key, b"ciphertext" * 8)
    async with app.state.sessionmaker() as session:
        row = AudioDeletion(
            backend=store.backend,
            storage_key=key,
            storage_locator=audio_store.storage_locator(store),
            not_before=utcnow(),
        )
        session.add(row)
        await session.commit()
        identifier = row.id

    entered = asyncio.Event()
    resume = asyncio.Event()
    original_delete = audio_store.LocalAudioStore.delete
    calls = 0

    async def transient_failure(self, storage_key):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await resume.wait()
            raise audio_store.AudioStoreError("transient first-drain failure")
        await original_delete(self, storage_key)

    monkeypatch.setattr(audio_store.LocalAudioStore, "delete", transient_failure)

    async def drain():
        async with app.state.sessionmaker() as session:
            return await audio_store.drain_audio_deletions(session, settings)

    first = asyncio.create_task(drain())
    await asyncio.wait_for(entered.wait(), timeout=2)
    try:
        # The sweeper/request cleanup must see the first provider call's
        # durable lease instead of dispatching a competing deletion.
        competing_result = await drain()
    finally:
        resume.set()
        outcome = await asyncio.gather(first, return_exceptions=True)
    assert outcome == [0]
    assert competing_result == 0
    assert calls == 1
    async with app.state.sessionmaker() as session:
        pending = await session.get(AudioDeletion, identifier)
        assert pending is not None and pending.attempts == 1
        pending.not_before = utcnow()
        await session.commit()
        monkeypatch.setattr(audio_store.LocalAudioStore, "delete", original_delete)
        assert await audio_store.drain_audio_deletions(session, settings) == 1
        assert await session.get(AudioDeletion, identifier) is None


async def test_cancelled_audio_cleanup_retains_durable_expiring_lease(
    app, settings, tmp_path, monkeypatch
):
    settings.audio_local_dir = str(tmp_path / "audio")
    store = audio_store.get_audio_store_cached(settings)
    key = audio_store.new_storage_key("0" * 32)
    await store.put(key, b"ciphertext" * 8)
    async with app.state.sessionmaker() as session:
        row = AudioDeletion(
            backend=store.backend,
            storage_key=key,
            storage_locator=audio_store.storage_locator(store),
            not_before=utcnow(),
        )
        session.add(row)
        await session.commit()
        identifier = row.id

    entered = asyncio.Event()
    original_delete = audio_store.LocalAudioStore.delete

    async def cancelled_delete(self, storage_key):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(audio_store.LocalAudioStore, "delete", cancelled_delete)

    async def drain():
        async with app.state.sessionmaker() as session:
            return await audio_store.drain_audio_deletions(session, settings)

    task = asyncio.create_task(drain())
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await asyncio.wait_for(drain(), timeout=2) == 0
    async with app.state.sessionmaker() as session:
        pending = await session.get(AudioDeletion, identifier)
        assert pending is not None and pending.attempts == 0
        assert pending.not_before > utcnow()
        pending.not_before = utcnow()
        await session.commit()
        monkeypatch.setattr(audio_store.LocalAudioStore, "delete", original_delete)
        assert await audio_store.drain_audio_deletions(session, settings) == 1
        assert await session.get(AudioDeletion, identifier) is None


async def test_audio_cleanup_uses_authoritative_attempts_after_another_drains_retry(
    app, settings, tmp_path, monkeypatch
):
    clock = [utcnow()]
    monkeypatch.setattr(audio_store, "utcnow", lambda: clock[0])
    first_id, second_id = "1" * 32, "2" * 32
    engine = None
    sessionmaker = app.state.sessionmaker
    if settings.database_url == "sqlite+aiosqlite://":
        engine = build_engine(f"sqlite+aiosqlite:///{tmp_path / 'audio-claims.sqlite'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessionmaker = build_sessionmaker(engine)

    try:
        async with sessionmaker() as session:
            session.add_all(
                [
                    AudioDeletion(
                        id=first_id,
                        backend="local",
                        storage_key="first",
                        not_before=clock[0] - timedelta(seconds=2),
                    ),
                    AudioDeletion(
                        id=second_id,
                        backend="local",
                        storage_key="second",
                        not_before=clock[0] - timedelta(seconds=1),
                    ),
                ]
            )
            await session.commit()

        started, resume = asyncio.Event(), asyncio.Event()

        class Store:
            backend = "local"

            async def delete(self, key):
                if key == "first":
                    started.set()
                    await resume.wait()
                    return
                raise audio_store.AudioStoreError("second object temporarily unavailable")

        monkeypatch.setattr(audio_store, "get_audio_store_cached", lambda _settings: Store())

        async def drain(identifiers=None):
            async with sessionmaker() as session:
                return await audio_store.drain_audio_deletions(
                    session, settings, identifiers=identifiers
                )

        first = asyncio.create_task(drain())
        await asyncio.wait_for(started.wait(), timeout=2)
        try:
            assert await drain([second_id]) == 0
            async with sessionmaker() as session:
                pending = await session.get(AudioDeletion, second_id)
                assert pending.attempts == 1
                assert pending.not_before == clock[0] + timedelta(seconds=60)
            clock[0] += timedelta(seconds=61)
        finally:
            resume.set()
            outcome = await asyncio.gather(first, return_exceptions=True)
        assert outcome == [1]
        async with sessionmaker() as session:
            pending = await session.get(AudioDeletion, second_id)
            assert pending.attempts == 2
            assert pending.not_before == clock[0] + timedelta(seconds=120)
    finally:
        if engine is not None:
            await engine.dispose()
