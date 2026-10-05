"""Portable account JSON, native page budgets and durable export capabilities."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _unique_json_object(pairs):
    result = {}
    for name, value in pairs:
        assert name not in result, (
            "portable JSON must have one unambiguous value per field"
        )
        result[name] = value
    return result


def _modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.api.account"), importlib.import_module(
        "app.models"
    )


@asynccontextmanager
async def _fixture(monkeypatch, tmp_path, count=1, v2=True):
    account, models = _modules(monkeypatch)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)

    monkeypatch.setattr(account, "datetime", Clock)
    from app.cache import TokenRevocationStore
    from app.config import Settings
    from app.services.audio_store import get_audio_store_cached, storage_locator
    from fastapi import FastAPI
    from sqlalchemy import event
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from starlette.requests import Request

    engine = create_async_engine(
        "sqlite+aiosqlite:///" + str(tmp_path / "export.sqlite3")
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(models.Base.metadata.create_all)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        settings = Settings(
            environment="development",
            audio_local_dir=str(tmp_path / "recordings"),
            token_secret="s" * 32,
        )
        store = get_audio_store_cached(settings)
        active, queries = [], []

        @asynccontextmanager
        async def pages():
            async with maker() as session:
                active.append(session)
                try:
                    yield session
                finally:
                    active.remove(session)

        app = FastAPI()
        app.state.settings = settings
        app.state.sessionmaker = pages
        app.state.export_limiter = anyio.CapacityLimiter(1)
        app.state.token_revocations = TokenRevocationStore()
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "path": "/api/v1/account/export",
                "query_string": b"",
                "headers": [],
                "app": app,
            }
        )
        request.state.mindpattern_token_jti = None
        user = models.User(
            id="patient",
            username="patient",
            salt="portable-salt",
            verifier=b"private-verifier",
            scrypt_salt=b"private-scrypt",
            created_at=NOW,
            key_scheme="v2" if v2 else "v1",
            wrapped_data_key=b"wrapped" if v2 else None,
            recovery_verifier=b"recovery" if v2 else None,
            recovery_scheme=2 if v2 else None,
            recovery_set_at=NOW if v2 else None,
            age_attestation_version="age-v1",
            age_attested_at=NOW,
            llm_consent=True,
            llm_consent_at=NOW,
            llm_consent_disclosure="llm-v1",
            llm_consent_policy="llm-policy",
            voice_consent=False,
            voice_consent_at=NOW,
            voice_consent_disclosure="voice-v1",
            voice_consent_policy="voice-policy",
        )
        foreign = models.User(
            id="foreign",
            username="foreign",
            salt="salt",
            verifier=b"v",
            scrypt_salt=b"s",
            is_active=False,
        )
        blobs = {}
        expected = {
            name: []
            for name in (
                "entries",
                "insights",
                "measures",
                "audio",
                "shares",
                "consent_events",
                "access_log",
            )
        }
        async with maker() as session:
            session.add_all([user, foreign])
            for n in range(count):
                identity = f"{n:04d}"
                blob = b"c" * (
                    (1 << 20)
                    if n == 0 and count > 1
                    else ((1 << 20) - 27 if n == 1 and count > 1 else 28)
                )
                blobs["entry" + identity] = len(blob)
                blobs["insight" + identity] = len(blob)
                session.add(
                    models.Entry(
                        id="entry" + identity,
                        user_id="patient",
                        client_entry_id="client" + identity,
                        entry_date=date(2026, 10, 4),
                        received_at=NOW,
                        blob=blob,
                        content_version=2,
                    )
                )
                expected["entries"].append(
                    {
                        "id": "entry" + identity,
                        "client_entry_id": "client" + identity,
                        "blob": base64.b64encode(blob).decode(),
                        "entry_date": "2026-10-04",
                        "received_at": NOW.isoformat().replace("+00:00", "Z"),
                        "content_version": 2,
                        "audio": None,
                    }
                )
                session.add(
                    models.Insight(
                        id="insight" + identity,
                        user_id="patient",
                        kind="question",
                        for_date=date(2026, 10, 4) - timedelta(days=n),
                        blob=blob,
                        created_at=NOW,
                        state_seq=7,
                    )
                )
                expected["insights"].append(
                    {
                        "kind": "question",
                        "for_date": (date(2026, 10, 4) - timedelta(days=n)).isoformat(),
                        "blob": base64.b64encode(blob).decode(),
                        "created_at": NOW.isoformat().replace("+00:00", "Z"),
                        "state_seq": 7,
                    }
                )
                session.add(
                    models.Measure(
                        id="measure" + identity,
                        user_id="patient",
                        client_measure_id="questionnaire" + identity,
                        measure_date=date(2026, 10, 4),
                        received_at=NOW,
                        blob=b"m" * 28,
                    )
                )
                expected["measures"].append(
                    {
                        "id": "measure" + identity,
                        "client_measure_id": "questionnaire" + identity,
                        "measure_date": "2026-10-04",
                        "received_at": NOW.isoformat().replace("+00:00", "Z"),
                        "blob": base64.b64encode(b"m" * 28).decode(),
                    }
                )
                clinician = models.User(
                    id="clinician" + identity,
                    username="clinician" + identity,
                    role="therapist",
                    display_name="Name" + identity if n % 2 else None,
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
                session.add(clinician)
                session.add(
                    models.Consent(
                        id=f"{n:032x}",
                        user_id="patient",
                        therapist_id=clinician.id,
                        status="active",
                        scope="full",
                        disclosure="share-v1",
                        share_voice=bool(n % 2),
                        granted_at=NOW,
                    )
                )
                expected["shares"].append(
                    {
                        "id": f"{n:032x}",
                        "therapist_id": clinician.id,
                        "therapist_username": clinician.username,
                        "therapist_display_name": clinician.display_name
                        or clinician.username,
                        "status": "active",
                        "granted_at": NOW.isoformat().replace("+00:00", "Z"),
                        "revoked_at": None,
                        "scope": "full",
                        "disclosure": "share-v1",
                        "share_voice": bool(n % 2),
                    }
                )
                session.add(
                    models.ConsentEvent(
                        id="event" + identity,
                        user_id="patient",
                        kind="voice",
                        action="grant",
                        disclosure="voice-v1",
                        policy="policy",
                        consent_id=f"{n:032x}",
                        share_voice=bool(n % 2),
                        occurred_at=NOW,
                        event_version=1,
                    )
                )
                expected["consent_events"].append(
                    {
                        "id": "event" + identity,
                        "kind": "voice",
                        "action": "grant",
                        "disclosure": "voice-v1",
                        "policy": "policy",
                        "consent_id": f"{n:032x}",
                        "share_voice": bool(n % 2),
                        "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
                        "event_version": 1,
                    }
                )
                session.add(
                    models.AccessLog(
                        id="log" + identity,
                        user_id="patient",
                        actor_id=clinician.id,
                        actor_role="therapist",
                        action="read_entries",
                        at=NOW,
                        chain_seq=n + 1,
                    )
                )
                expected["access_log"].append(
                    {
                        "id": "log" + identity,
                        "actor_id": clinician.id,
                        "actor_role": "therapist",
                        "action": "read_entries",
                        "at": NOW.isoformat().replace("+00:00", "Z"),
                        "chain_seq": n + 1,
                    }
                )
                key = "audio/patient/" + identity + ".enc"
                await store.put(key, b"a" * 28)
                session.add(
                    models.AudioAttachment(
                        id="audio" + identity,
                        user_id="patient",
                        client_entry_id="client" + identity,
                        backend="local",
                        storage_key=key,
                        storage_locator=storage_locator(store),
                        size_bytes=28,
                        mime_type="audio/webm",
                        duration_seconds=1.25,
                        created_at=NOW,
                        expires_at=NOW + timedelta(days=30),
                        content_version=3,
                    )
                )
                expected["audio"].append(
                    {
                        "id": "audio" + identity,
                        "client_entry_id": "client" + identity,
                        "mime_type": "audio/webm",
                        "duration_seconds": 1.25,
                        "size_bytes": 28,
                        "created_at": str(NOW),
                        "expires_at": str(NOW + timedelta(days=30)),
                        "content_version": 3,
                        "blob": base64.b64encode(b"a" * 28).decode(),
                    }
                )
            session.add(
                models.AuditChainState(
                    user_id="patient",
                    head_seq=count,
                    head_hash="f" * 64,
                    head_at=NOW,
                    first_retained_seq=1,
                    first_retained_hash="f" * 64,
                    state_mac="m" * 64,
                )
            )
            session.add(
                models.Entry(
                    id="foreign-entry",
                    user_id="foreign",
                    client_entry_id="foreign",
                    entry_date=date(2026, 10, 4),
                    received_at=NOW,
                    blob=b"f" * 28,
                )
            )
            # Future records are outside the response's frozen cutoff.
            session.add(
                models.Entry(
                    id="future-entry",
                    user_id="patient",
                    client_entry_id="future",
                    entry_date=date(2026, 10, 4),
                    received_at=NOW + timedelta(days=365),
                    blob=b"f" * 28,
                )
            )
            await session.commit()

        def observed_sql(
            connection, cursor, statement, parameters, context, executemany
        ):
            if not statement.startswith("SELECT"):
                return
            queries.append((statement, parameters))
            for table in ("entries", "measures", "audio_attachments"):
                if (
                    ("FROM " + table) in statement
                    and "ORDER BY" in statement
                    and table + ".user_id" in statement
                ):
                    assert context.compiled.statement._limit_clause.value == 100, (
                        "native metadata page bound"
                    )
                    key = (statement, tuple(parameters))
                    assert (
                        sum((sql, tuple(params)) == key for sql, params in queries) == 1
                    ), "export cursor must advance"
            for table in ("entries", "insights"):
                if (
                    ("FROM " + table) in statement
                    and table + ".id IN" in statement
                    and table + ".blob," in statement
                ):
                    requested = [value for value in parameters if value in blobs]
                    assert len(requested) <= 100
                    assert (
                        len(requested) == 1
                        or sum(blobs[value] for value in requested) <= 2 * 1024 * 1024
                    )

        event.listen(engine.sync_engine, "before_cursor_execute", observed_sql)
        yield SimpleNamespace(
            account=account,
            models=models,
            engine=engine,
            maker=maker,
            user=user,
            request=request,
            expected=expected,
            active=active,
            settings=settings,
            store=store,
            blobs=blobs,
            queries=queries,
        )
    finally:
        await engine.dispose()


@pytest.mark.parametrize("count,v2", [(1, False), (105, True)])
def test_complete_portable_bundle_preserves_every_ciphertext_and_native_page_bounds(
    monkeypatch, tmp_path, count, v2
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count, v2) as db:
            async with db.maker() as session:
                owner = await session.get(db.models.User, "patient")
                response = await db.account.export_account(db.request, owner, session)
                assert not session.in_transaction()
            assert (
                response.media_type == "application/json"
                and db.request.app.state.export_limiter.borrowed_tokens == 1
            )
            chunks = []
            async for chunk in response.body_iterator:
                assert not db.active, (
                    "network output must not retain a pooled page transaction"
                )
                chunks.append(chunk.decode() if isinstance(chunk, bytes) else chunk)
                assert len(chunks) <= 1024, "one finite item per portable record"
            result = json.loads("".join(chunks), object_pairs_hook=_unique_json_object)
            for name, expected in db.expected.items():
                assert result.pop(name) == expected, name
            timestamp = datetime.fromisoformat(result.pop("exported_at"))
            assert timestamp.tzinfo is not None and timestamp == NOW
            assert result == {
                "version": 3,
                "username": "patient",
                "user_id": "patient",
                "salt": "portable-salt",
                "age_attestation_version": "age-v1",
                "age_attested_at": NOW.isoformat().replace("+00:00", "Z"),
                "recovery_enabled": v2,
                "recovery_set_at": NOW.isoformat().replace("+00:00", "Z")
                if v2
                else None,
                "recovery_scheme": "v2" if v2 else None,
                "key_scheme": "v2" if v2 else "v1",
                "wrapped_data_key": base64.b64encode(b"wrapped").decode()
                if v2
                else None,
                "kdf_params": None,
                "llm_consent": True,
                "llm_consent_at": NOW.isoformat().replace("+00:00", "Z"),
                "llm_consent_disclosure": "llm-v1",
                "llm_consent_policy": "llm-policy",
                "voice_consent": False,
                "voice_consent_at": NOW.isoformat().replace("+00:00", "Z"),
                "voice_consent_disclosure": "voice-v1",
                "voice_consent_policy": "voice-policy",
            }
            assert db.request.app.state.export_limiter.borrowed_tokens == 0

    asyncio.run(asyncio.wait_for(exercise(), 10))


def _assert_error(error, status, code, detail, headers=None):
    assert (error.status_code, error.code, error.detail) == (status, code, detail)
    assert error.headers == headers


@pytest.mark.parametrize(
    "fault",
    [
        "busy",
        "missing",
        "inactive",
        "epoch",
        "revoked",
        "rekey",
        "history",
        "audit_missing",
        "audit_prefix",
        "audio_unconfigured",
    ],
)
def test_export_header_refuses_unavailable_or_retired_state_and_releases_slot(
    monkeypatch, tmp_path, fault
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from sqlalchemy import delete, update

            db.request.state.mindpattern_token_jti = "a" * 32
            limiter = db.request.app.state.export_limiter
            borrower = object()
            expected = (401, "unauthorized", "invalid token", None)
            async with db.maker() as session:
                user = await session.get(db.models.User, "patient")
                await session.commit()
                async with db.maker() as writer:
                    if fault == "busy":
                        limiter.acquire_on_behalf_of_nowait(borrower)
                        expected = (
                            503,
                            "service_unavailable",
                            "export service busy; retry shortly",
                            {"Retry-After": "1"},
                        )
                    elif fault == "missing":
                        await writer.execute(
                            delete(db.models.User).where(db.models.User.id == "patient")
                        )
                    elif fault == "inactive":
                        await writer.execute(
                            update(db.models.User)
                            .where(db.models.User.id == "patient")
                            .values(is_active=False)
                        )
                    elif fault == "epoch":
                        await writer.execute(
                            update(db.models.User)
                            .where(db.models.User.id == "patient")
                            .values(token_epoch=user.token_epoch + 1)
                        )
                    elif fault == "revoked":
                        db.request.app.state.token_revocations.revoke(
                            "a" * 32, datetime.now(timezone.utc).timestamp() + 3600
                        )
                    elif fault == "rekey":
                        writer.add(
                            db.models.RekeyJournal(id="rotation", user_id="patient")
                        )
                        expected = (
                            409,
                            "rekey_in_progress",
                            "complete the pending key rotation before writing",
                            None,
                        )
                    elif fault == "history":
                        writer.add_all(
                            [
                                db.models.User(
                                    id=f"new-clinician-{n}",
                                    username=f"new-clinician-{n}",
                                    role="therapist",
                                    salt="s",
                                    verifier=b"v",
                                    scrypt_salt=b"s",
                                )
                                for n in range(1000)
                            ]
                        )
                        writer.add_all(
                            [
                                db.models.Consent(
                                    id=f"retained-{n}",
                                    user_id="patient",
                                    therapist_id=f"new-clinician-{n}",
                                )
                                for n in range(1000)
                            ]
                        )
                        expected = (
                            413,
                            "payload_too_large",
                            "retained sharing history exceeds the supported export size",
                            None,
                        )
                    elif fault == "audit_missing":
                        await writer.execute(
                            delete(db.models.AuditChainState).where(
                                db.models.AuditChainState.user_id == "patient"
                            )
                        )
                        expected = (
                            409,
                            "collection_changed",
                            "access history changed during export; retry",
                            None,
                        )
                    elif fault == "audit_prefix":
                        await writer.execute(
                            update(db.models.AuditChainState)
                            .where(db.models.AuditChainState.user_id == "patient")
                            .values(first_retained_seq=2)
                        )
                        expected = (
                            409,
                            "collection_changed",
                            "access history changed during export; retry",
                            None,
                        )
                    else:
                        db.settings.audio_local_dir = ""
                        db.settings.environment = "production"
                        expected = (
                            503,
                            "audio_storage_unconfigured",
                            "audio export storage unavailable",
                            None,
                        )
                    await writer.commit()
                try:
                    with pytest.raises(ApiError) as failure:
                        await db.account.export_account(db.request, user, session)
                    _assert_error(failure.value, *expected)
                    assert limiter.borrowed_tokens == (1 if fault == "busy" else 0)
                finally:
                    if fault == "busy":
                        limiter.release_on_behalf_of(borrower)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "inactive",
        "epoch",
        "revoked",
        "entries_revision",
        "measures_revision",
        "consents_revision",
        "rekey",
        "clinician_inactive",
        "audit_missing",
        "audit_head",
        "audit_gap",
        "insight_missing",
        "insight_future",
        "audio_missing",
        "audio_target",
        "audio_fetch_cap",
    ],
)
def test_stream_rechecks_each_portable_snapshot_and_reports_precise_refusal(
    monkeypatch, tmp_path, fault
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from app.deps import ApiError
            from sqlalchemy import delete, update

            db.request.state.mindpattern_token_jti = "a" * 32
            async with db.maker() as session:
                user = await session.get(db.models.User, "patient")
                response = await db.account.export_account(db.request, user, session)
            assert await anext(response.body_iterator) == "{"
            expected = (
                409,
                "collection_changed",
                "account changed during export; retry",
                None,
            )
            async with db.maker() as writer:
                if fault == "missing":
                    await writer.execute(
                        delete(db.models.User).where(db.models.User.id == "patient")
                    )
                elif fault == "inactive":
                    await writer.execute(
                        update(db.models.User)
                        .where(db.models.User.id == "patient")
                        .values(is_active=False)
                    )
                elif fault == "epoch":
                    await writer.execute(
                        update(db.models.User)
                        .where(db.models.User.id == "patient")
                        .values(token_epoch=user.token_epoch + 1)
                    )
                elif fault == "revoked":
                    db.request.app.state.token_revocations.revoke(
                        "a" * 32, datetime.now(timezone.utc).timestamp() + 3600
                    )
                elif fault.endswith("_revision"):
                    await writer.execute(
                        update(db.models.User)
                        .where(db.models.User.id == "patient")
                        .values({fault: 1})
                    )
                elif fault == "rekey":
                    writer.add(db.models.RekeyJournal(id="rotation", user_id="patient"))
                    expected = (
                        409,
                        "rekey_in_progress",
                        "complete the pending key rotation before writing",
                        None,
                    )
                elif fault == "clinician_inactive":
                    await writer.execute(
                        update(db.models.User)
                        .where(db.models.User.id == "clinician0000")
                        .values(is_active=False)
                    )
                elif fault == "audit_missing":
                    await writer.execute(
                        delete(db.models.AuditChainState).where(
                            db.models.AuditChainState.user_id == "patient"
                        )
                    )
                elif fault == "audit_head":
                    await writer.execute(
                        update(db.models.AuditChainState)
                        .where(db.models.AuditChainState.user_id == "patient")
                        .values(head_seq=0)
                    )
                elif fault == "audit_gap":
                    await writer.execute(
                        delete(db.models.AccessLog).where(
                            db.models.AccessLog.id == "log0000"
                        )
                    )
                elif fault == "insight_missing":
                    await writer.execute(
                        delete(db.models.Insight).where(
                            db.models.Insight.id == "insight0000"
                        )
                    )
                elif fault == "insight_future":
                    await writer.execute(
                        update(db.models.Insight)
                        .where(db.models.Insight.id == "insight0000")
                        .values(created_at=NOW + timedelta(seconds=1))
                    )
                elif fault == "audio_missing":
                    await db.store.delete("audio/patient/0000.enc")
                elif fault == "audio_target":
                    db.settings.audio_local_dir = str(tmp_path / "new-provider")
                elif fault == "audio_fetch_cap":
                    db.settings.audio_max_body_bytes = 27
                await writer.commit()
            if fault in {"missing", "inactive", "epoch", "revoked"}:
                expected = (401, "unauthorized", "export session retired", None)
            elif fault.startswith("audit_"):
                expected = (
                    409,
                    "collection_changed",
                    "access history changed during export; retry",
                    None,
                )
            elif fault.startswith("insight_"):
                expected = (
                    409,
                    "collection_changed",
                    "analysis changed during export; retry",
                    None,
                )
            elif fault.startswith("audio_"):
                expected = (
                    503,
                    "audio_storage_failed",
                    "audio export is incomplete; retry",
                    None,
                )
            try:
                with pytest.raises(ApiError) as failure:
                    async for _chunk in response.body_iterator:
                        pass
                _assert_error(failure.value, *expected)
                assert db.request.app.state.export_limiter.borrowed_tokens == 0
            finally:
                await response.body_iterator.aclose()

    asyncio.run(asyncio.wait_for(exercise(), 5))


def test_two_concurrent_exports_have_distinct_borrowers_and_disconnect_releases_both(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            db.request.app.state.export_limiter = anyio.CapacityLimiter(2)
            responses = []
            try:
                for _ in range(2):
                    async with db.maker() as session:
                        user = await session.get(db.models.User, "patient")
                        responses.append(
                            await db.account.export_account(db.request, user, session)
                        )
                assert db.request.app.state.export_limiter.borrowed_tokens == 2
                for response in responses:
                    assert await anext(response.body_iterator) == "{"
                    await response.body_iterator.aclose()
                assert db.request.app.state.export_limiter.borrowed_tokens == 0
            finally:
                for response in responses:
                    await response.body_iterator.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize("section", ["entries", "insights", "measures", "audio"])
def test_each_ciphertext_page_waits_for_the_shared_account_lifecycle(
    monkeypatch, tmp_path, section
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from app.locks import UserLocks

            lifecycle_locks = UserLocks()
            monkeypatch.setattr(db.account, "lifecycle_locks", lifecycle_locks)
            async with db.maker() as session:
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            iterator = response.body_iterator
            task = None
            try:
                async for chunk in iterator:
                    if chunk == '],"' + section + '":[':
                        break
                async with lifecycle_locks.hold("llm-lifecycle:patient"):
                    task = asyncio.create_task(anext(iterator))
                    with pytest.raises(TimeoutError):
                        await asyncio.wait_for(asyncio.shield(task), 0.15)
                chunk = await asyncio.wait_for(task, 2)
                assert json.loads(chunk)["blob"]
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                await iterator.aclose()
                assert db.request.app.state.export_limiter.borrowed_tokens == 0

    asyncio.run(asyncio.wait_for(exercise(), 5))


@pytest.mark.parametrize(
    "table,identity,detail",
    [
        ("entries", "entry0000", "record disappeared during export; retry"),
        ("insights", "insight0000", "analysis changed during export; retry"),
        ("measures", "measure0000", "record disappeared during export; retry"),
    ],
)
def test_a_durably_missing_selected_ciphertext_aborts_the_bundle(
    monkeypatch, tmp_path, table, identity, detail
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            import sqlite3

            from app.deps import ApiError
            from sqlalchemy import event

            mutated = []

            def retire_before_blob_fetch(
                connection, cursor, statement, parameters, context, executemany
            ):
                if (
                    not mutated
                    and ("FROM " + table) in statement
                    and table + ".id IN" in statement
                    and table + ".blob," in statement
                ):
                    with sqlite3.connect(tmp_path / "export.sqlite3") as writer:
                        writer.execute(
                            "DELETE FROM " + table + " WHERE id=?", (identity,)
                        )
                        writer.commit()
                    mutated.append(identity)

            event.listen(
                db.engine.sync_engine, "before_cursor_execute", retire_before_blob_fetch
            )
            async with db.maker() as session:
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            try:
                with pytest.raises(ApiError) as failure:
                    async for _chunk in response.body_iterator:
                        pass
                _assert_error(failure.value, 409, "collection_changed", detail)
                assert mutated == [identity]
                assert db.request.app.state.export_limiter.borrowed_tokens == 0
            finally:
                await response.body_iterator.aclose()

    asyncio.run(asyncio.wait_for(exercise(), 5))


@pytest.mark.parametrize("scheme", [None, 1])
def test_legacy_password_recovery_exports_the_v1_scheme(monkeypatch, tmp_path, scheme):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, v2=False) as db:
            from sqlalchemy import update

            async with db.maker() as session:
                await session.execute(
                    update(db.models.User)
                    .where(db.models.User.id == "patient")
                    .values(
                        recovery_verifier=b"legacy-recovery-proof",
                        recovery_scheme=scheme,
                        recovery_set_at=NOW,
                    )
                )
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            chunks = [chunk async for chunk in response.body_iterator]
            result = json.loads("".join(chunks), object_pairs_hook=_unique_json_object)
            assert (
                result["recovery_enabled"] is True and result["recovery_scheme"] == "v1"
            )
            assert result["wrapped_data_key"] is None and result["key_scheme"] == "v1"

    asyncio.run(asyncio.wait_for(exercise(), 5))


def test_export_preserves_a_nullable_envelope_without_manufacturing_bytes(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, v2=True) as db:
            from sqlalchemy import update

            async with db.maker() as session:
                await session.execute(
                    update(db.models.User)
                    .where(db.models.User.id == "patient")
                    .values(wrapped_data_key=None)
                )
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            chunks = [chunk async for chunk in response.body_iterator]
            result = json.loads("".join(chunks), object_pairs_hook=_unique_json_object)
            assert result["key_scheme"] == "v2" and result["wrapped_data_key"] is None

    asyncio.run(asyncio.wait_for(exercise(), 5))


def test_an_export_without_an_optional_admission_limiter_completes(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            db.request.app.state.export_limiter = None
            async with db.maker() as session:
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            chunks = [chunk async for chunk in response.body_iterator]
            result = json.loads("".join(chunks), object_pairs_hook=_unique_json_object)
            assert result["entries"] == db.expected["entries"]

    asyncio.run(asyncio.wait_for(exercise(), 5))


@pytest.mark.parametrize("legacy", ["expired_at_cutoff", "zero_analysis_sequence"])
def test_export_retains_exact_expiry_and_legacy_sequence_boundaries(
    monkeypatch, tmp_path, legacy
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from sqlalchemy import update

            async with db.maker() as session:
                if legacy == "expired_at_cutoff":
                    await session.execute(
                        update(db.models.AudioAttachment).values(expires_at=NOW)
                    )
                else:
                    await session.execute(update(db.models.Insight).values(state_seq=0))
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            if legacy == "expired_at_cutoff":
                assert result["audio"] == []
            else:
                assert result["insights"][0]["state_seq"] == 0

    asyncio.run(asyncio.wait_for(exercise(), 5))


def test_a_native_byte_page_with_one_analysis_preserves_its_entire_tail(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count=105) as db:
            from sqlalchemy import update

            large = b"i" * (2 * 1024 * 1024 - 1)
            db.blobs["insight0000"] = len(large)
            async with db.maker() as session:
                await session.execute(
                    update(db.models.Insight)
                    .where(db.models.Insight.id == "insight0000")
                    .values(blob=large)
                )
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            expected = db.expected["insights"]
            expected[0]["blob"] = base64.b64encode(large).decode()
            assert result["insights"] == expected

    asyncio.run(asyncio.wait_for(exercise(), 10))


def test_expired_voice_records_do_not_require_a_live_audio_provider(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from sqlalchemy import update

            db.settings.audio_local_dir = ""
            db.settings.environment = "production"
            async with db.maker() as session:
                await session.execute(
                    update(db.models.AudioAttachment).values(expires_at=NOW)
                )
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            assert result["audio"] == [] and result["entries"] == db.expected["entries"]

    asyncio.run(asyncio.wait_for(exercise(), 5))


@pytest.mark.parametrize("voice_state", ["live", "expired", "empty"])
def test_live_settings_swap_cannot_silently_omit_durable_voice(
    monkeypatch, tmp_path, voice_state
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path) as db:
            from app.config import Settings
            from app.deps import ApiError
            from app.services.audio_store import get_audio_store_cached
            from sqlalchemy import delete, update

            async with db.maker() as session:
                if voice_state == "expired":
                    await session.execute(
                        update(db.models.AudioAttachment).values(expires_at=NOW)
                    )
                elif voice_state == "empty":
                    await session.execute(delete(db.models.AudioAttachment))
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            iterator = response.body_iterator
            chunks = [await anext(iterator)]
            # Settings swaps are supported during streaming. Construct a valid
            # production policy rather than bypassing Settings validation.
            replacement = Settings(
                environment="production",
                token_secret="s" * 32,
                database_url="postgresql+asyncpg://postgres:postgres@127.0.0.1:55488/mindpattern_mutation_test",
                audio_local_dir="",
                therapist_sharing_enabled=False,
                auth_token_secret_explicit="a" * 32,
                totp_wrap_secret_explicit="t" * 32,
                pairing_secret_explicit="p" * 32,
                decoy_secret="d" * 32,
                audit_mac_secret_explicit="01" * 32,
                audit_journal_path=str(tmp_path / "replacement-audit.jsonl"),
            )
            assert get_audio_store_cached(replacement) is None
            db.request.app.state.settings = replacement
            if voice_state == "live":
                with pytest.raises(ApiError) as failure:
                    chunks.extend([chunk async for chunk in iterator])
                assert (
                    failure.value.status_code,
                    failure.value.code,
                    failure.value.detail,
                ) == (503, "audio_storage_failed", "audio export is incomplete; retry")
            else:
                chunks.extend([chunk async for chunk in iterator])
                result = json.loads(
                    "".join(chunks), object_pairs_hook=_unique_json_object
                )
                assert (
                    result["audio"] == []
                    and result["entries"] == db.expected["entries"]
                )
            assert db.request.app.state.export_limiter.borrowed_tokens == 0

    asyncio.run(asyncio.wait_for(exercise(), 5))


def test_small_complete_exports_use_finite_database_pages(monkeypatch, tmp_path):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count=105) as db:
            from sqlalchemy import update

            small = b"c" * 28
            for identifier in db.blobs:
                db.blobs[identifier] = len(small)
            async with db.maker() as session:
                for model in (db.models.Entry, db.models.Insight):
                    await session.execute(
                        update(model)
                        .where(model.user_id == "patient")
                        .values(blob=small)
                    )
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            for name in ["entries", "insights"]:
                expected = db.expected[name]
                for row in expected:
                    row["blob"] = base64.b64encode(small).decode()
                assert result[name] == expected
            # Each 105-item collection fits far below the native byte budget.
            # Two nonempty metadata pages plus exhaustion must not turn into
            # a transaction and repeated100-item scan for every record.
            for table in ("entries", "measures"):
                reads = [
                    sql
                    for sql, _params in db.queries
                    if ("FROM " + table) in sql
                    and "ORDER BY" in sql
                    and table + ".user_id" in sql
                ]
                assert len(reads) <= 4, (
                    "a small export must make bounded page-level progress"
                )

    asyncio.run(asyncio.wait_for(exercise(), 10))


@pytest.mark.parametrize("table", ["entries", "insights"])
def test_exact_native_byte_pages_do_not_refetch_stable_ciphertext(
    monkeypatch, tmp_path, table
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count=3) as db:
            from sqlalchemy import update

            model = db.models.Entry if table == "entries" else db.models.Insight
            prefix = "entry" if table == "entries" else "insight"
            opaque = b"c" * (1024 * 1024)
            async with db.maker() as session:
                for n in range(2):
                    identity = prefix + f"{n:04d}"
                    values = {"blob": opaque}
                    if table == "insights":
                        values.update(
                            kind="brain" if n == 0 else "patterns", for_date=None
                        )
                    await session.execute(
                        update(model).where(model.id == identity).values(**values)
                    )
                    db.blobs[identity] = len(opaque)
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            expected = db.expected[table]
            for n in range(2):
                expected[n]["blob"] = base64.b64encode(opaque).decode()
                if table == "insights":
                    expected[n].update(
                        kind="brain" if n == 0 else "patterns", for_date=None
                    )
            assert result[table] == expected
            fetched = [
                value
                for sql, params in db.queries
                if ("FROM " + table) in sql
                and table + ".id IN" in sql
                and table + ".blob," in sql
                for value in params
                if value in db.blobs
            ]
            # A stable page already fits the native cap. Reading a selected
            # MiB ciphertext again on the next page is avoidable amplification,
            # independently of the exact private counter implementation.
            assert len(fetched) == 3 and len(set(fetched)) == 3, (
                "stable ciphertext must not be refetched across byte pages"
            )

    asyncio.run(asyncio.wait_for(exercise(), 10))
