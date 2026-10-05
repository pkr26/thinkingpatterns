"""Actual ciphertext, SQLite pagination, and processing lifecycle contracts."""

# Imported pytest fixtures are intentionally requested again as parameters.
# ruff: noqa: F811
from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import pytest
from fastapi import FastAPI
from sqlalchemy import delete, event, select, update
from sqlalchemy.exc import IntegrityError

from app.api import insights
from app.db import build_sessionmaker
from app.deps import ApiError
from app.locks import UserLocks
from app.models import Entry, Insight, Measure, RekeyJournal, User
from app.schemas import LocalRecomputeRequest, ProcessingSessionRequest, RekeyRequest
from app.security import crypto
from app.security.enclave import InMemoryKeyStore, KeyNotFound
from tests.test_full_backend_collection_mutation import (
    BLOB,
    NOW,
    OTHER,
    OWNER,
    FixedDateTime,
    b64,
    collection_db,  # noqa: F401
    envelope,
)

OLD = bytearray(b"o" * 32)
NEW = bytearray(b"n" * 32)
OPERATION = "12345678-1234-1234-1234-123456789abc"


def prepare(db, monkeypatch):
    locks = UserLocks()
    monkeypatch.setattr(insights, "lifecycle_locks", locks)
    monkeypatch.setattr(insights, "_recompute_locks", UserLocks())
    monkeypatch.setattr(insights, "_utc_today", lambda: NOW.date())
    db.settings.unlock_threshold_days = 3
    db.request.app.state.key_store = InMemoryKeyStore()
    preflight = insights._preflight_legacy_rotation

    async def bounded_preflight(*args, **kwargs):
        # These real fixtures contain at most 101 rows per collection.
        # With the native 100-row page, each collection needs at most
        # three reads, including its terminal empty page. Allow a spare
        # read, then fail inside the test instead of timing out on a loop.
        reads = {}

        def observe(connection, cursor, statement, parameters, context, executemany):
            normalized = statement.lower()
            if not normalized.startswith("select"):
                return
            for table in ("entries", "insights", "measures", "audio_attachments"):
                if f"from {table}" in normalized:
                    reads[table] = reads.get(table, 0) + 1
                    assert reads[table] <= 4, f"legacy {table} scan failed to make bounded progress"

        event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
        try:
            return await preflight(*args, **kwargs)
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", observe)

    monkeypatch.setattr(insights, "_preflight_legacy_rotation", bounded_preflight)
    return locks


async def seed_entries(db, user_id=OWNER, sizes=(28, 30, 40), days=(0, 1, 2)):
    rows = [
        Entry(
            id=f"{i + (1 if user_id == OWNER else 100):032x}",
            user_id=user_id,
            client_entry_id=f"e-{i}",
            entry_date=NOW.date() - timedelta(days=day),
            received_at=NOW,
            blob=bytes([65 + i]) * size,
        )
        for i, (size, day) in enumerate(zip(sizes, days, strict=True))
    ]
    db.session.add_all(rows)
    await db.session.commit()
    return rows


def test_insights_api_documents_its_public_routes():
    app = FastAPI()
    app.include_router(insights.router)
    paths = app.openapi()["paths"]
    for path, verb in [
        ("/processing/sessions", "post"),
        ("/processing/rekey", "post"),
        ("/insights/recompute", "post"),
        ("/insights/local-recompute", "post"),
        ("/insights", "get"),
        ("/questions/today", "get"),
    ]:
        assert paths[path][verb]["tags"] == ["insights"]
    assert paths["/processing/sessions"]["post"]["responses"]["201"]["content"]


def test_insights_calendar_day_uses_utc(monkeypatch):
    monkeypatch.setattr(insights, "datetime", FixedDateTime)
    assert insights._utc_today() == NOW.date()


@pytest.mark.asyncio
async def test_analysis_database_rows_stop_at_first_byte_budget_and_use_all_tie_breaks(
    collection_db,
):
    db = collection_db
    rows = await seed_entries(db, days=(0, 0, 1))
    rows[1].received_at = NOW - timedelta(seconds=1)
    await db.session.commit()
    await seed_entries(db, OTHER, sizes=(1,), days=(0,))
    for limit, budget, expected in [
        (3, 98, [rows[2], rows[1], rows[0]]),
        (3, 58, [rows[1], rows[0]]),
        (3, 57, [rows[0]]),
        (3, 27, []),
        (1, 1000, [rows[0]]),
        (0, 1000, []),
    ]:
        actual = await insights._load_rows(db.session, OWNER, limit, budget)
        assert [(r.id, bytes(r.blob)) for r in actual] == [(r.id, bytes(r.blob)) for r in expected]
    assert await insights._entry_dates(db.session, OWNER) == [
        NOW.date() - timedelta(days=1),
        NOW.date(),
    ]


@pytest.mark.asyncio
async def test_insight_replacement_preserves_other_accounts_kinds_and_daily_uniqueness(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    now = NOW
    monkeypatch.setattr(insights, "utcnow", lambda: now)
    db.session.add_all(
        [
            Insight(
                id=f"{i:032x}",
                user_id=uid,
                kind=kind,
                for_date=day,
                blob=blob,
                created_at=NOW - timedelta(days=i),
                state_seq=i,
            )
            for i, uid, kind, day, blob in [
                (1, OWNER, "patterns", None, b"old"),
                (2, OWNER, "patterns", NOW.date(), b"legacy"),
                (3, OTHER, "patterns", None, b"foreign"),
                (4, OWNER, "brain", None, b"brain"),
            ]
        ]
    )
    await db.session.commit()
    await insights._replace_insight(db.session, OWNER, "patterns", None, BLOB, state_seq=7)
    await insights._replace_insight(
        db.session, OWNER, "question", NOW.date(), b"first", state_seq=4
    )
    await db.session.commit()
    now += timedelta(seconds=1)
    await insights._replace_insight(
        db.session, OWNER, "question", NOW.date(), b"second", state_seq=9
    )
    await db.session.commit()
    rows = list((await db.session.scalars(select(Insight))).all())
    assert sorted(
        (r.user_id, r.kind, r.for_date, bytes(r.blob), r.state_seq) for r in rows
    ) == sorted(
        [
            (OWNER, "patterns", None, BLOB, 7),
            (OTHER, "patterns", None, b"foreign", 3),
            (OWNER, "brain", None, b"brain", 4),
            (OWNER, "question", NOW.date(), b"second", 9),
        ]
    )
    q = next(r for r in rows if r.kind == "question")
    assert q.created_at == now
    assert (await insights._latest_insight(db.session, OWNER, "brain")).blob == b"brain"
    assert await insights._latest_insight(db.session, OTHER, "brain") is None


@pytest.mark.asyncio
async def test_reads_hide_old_insights_and_require_the_current_day_and_account(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    db.session.add_all(
        [
            Insight(user_id=OWNER, kind="patterns", blob=BLOB, state_seq=7),
            Insight(user_id=OTHER, kind="question", for_date=NOW.date(), blob=b"foreign"),
            Insight(
                user_id=OWNER,
                kind="question",
                for_date=NOW.date() - timedelta(days=1),
                blob=b"yesterday",
            ),
        ]
    )
    await db.session.commit()
    out = await insights.get_insights(db.request, db.owner, db.session)
    assert out.model_dump() == dict(
        phase="baseline", active_days=0, streak=0, days_remaining=3, blob=None, state_seq=7
    )
    detail = "no question for today; open a processing session and run /insights/recompute"
    with pytest.raises(ApiError) as failure:
        await insights.get_question_today(db.request, db.owner, db.session)
    envelope(failure, 404, detail, "not_found")
    await seed_entries(db)
    with pytest.raises(ApiError) as failure:
        await insights.get_question_today(db.request, db.owner, db.session)
    envelope(failure, 404, detail, "not_found")
    db.session.add(Insight(user_id=OWNER, kind="question", for_date=NOW.date(), blob=b"today"))
    await db.session.commit()
    question = await insights.get_question_today(db.request, db.owner, db.session)
    assert question.model_dump() == dict(for_date=NOW.date(), blob=b64(b"today"))
    out = await insights.get_insights(db.request, db.owner, db.session)
    assert out.model_dump() == dict(
        phase="insight", active_days=3, streak=3, days_remaining=0, blob=b64(BLOB), state_seq=7
    )
    await db.session.execute(
        delete(Insight).where(Insight.user_id == OWNER, Insight.kind == "patterns")
    )
    await db.session.commit()
    out = await insights.get_insights(db.request, db.owner, db.session)
    assert out.blob is None and out.state_seq == 0


@pytest.mark.asyncio
async def test_processing_sessions_bind_real_keys_and_report_capacity(collection_db, monkeypatch):
    db = collection_db
    prepare(db, monkeypatch)
    db.settings.processing_session_ttl = 17
    db.request.app.state.key_store = InMemoryKeyStore(max_sessions_per_owner=1)
    out = await insights.create_processing_session(
        ProcessingSessionRequest(data_key=b64(OLD)), db.request, db.owner, db.session
    )
    assert out.expires_in == 17
    assert db.request.app.state.key_store.get(out.session_token, owner=OWNER) == OLD
    with pytest.raises(KeyNotFound):
        db.request.app.state.key_store.get(out.session_token, owner=OTHER)
    with pytest.raises(ApiError) as failure:
        await insights.create_processing_session(
            ProcessingSessionRequest(data_key=b64(NEW)), db.request, db.owner, db.session
        )
    envelope(
        failure,
        503,
        "processing session capacity reached; consume an existing session or retry shortly",
        "service_unavailable",
        {"Retry-After": "1"},
    )
    for raw, detail in [
        ("!!!!", "data_key must be base64"),
        (b64(b"x" * 31), "data_key must be 32 bytes"),
        (b64(b"x" * 33), "data_key must be 32 bytes"),
    ]:
        with pytest.raises(ApiError) as failure:
            await insights.create_processing_session(
                ProcessingSessionRequest(data_key=raw), db.request, db.owner, db.session
            )
        envelope(failure, 422, detail, "validation_error")


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["epoch", "retire", "remove"])
@pytest.mark.parametrize("operation", ["mint", "local"])
async def test_insights_waiting_work_rechecks_real_database_account(
    collection_db, monkeypatch, change, operation
):
    db = collection_db
    locks = prepare(db, monkeypatch)
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()],
    )
    async with locks.hold(f"llm-lifecycle:{OWNER}"):
        call = (
            insights.create_processing_session(
                ProcessingSessionRequest(data_key=b64(OLD)), db.request, db.owner, db.session
            )
            if operation == "mint"
            else insights.local_recompute(body, db.request, db.owner, db.session)
        )
        task = asyncio.create_task(call)
        await asyncio.sleep(0.015)
        async with build_sessionmaker(db.engine)() as writer:
            if change == "remove":
                await writer.execute(delete(User).where(User.id == OWNER))
            else:
                await writer.execute(
                    update(User)
                    .where(User.id == OWNER)
                    .values(**({"token_epoch": 3} if change == "epoch" else {"is_active": False}))
                )
            await writer.commit()
        assert not task.done()
    with pytest.raises(ApiError) as failure:
        await asyncio.wait_for(task, 2)
    if operation == "local" and change != "epoch":
        envelope(failure, 404, "account not found", "not_found")
    else:
        envelope(failure, 401, "invalid token", "unauthorized")
    assert not list((await db.session.scalars(select(Insight))).all())


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [None, 0, 9])
async def test_local_upload_counts_real_dates_increments_sequence_and_stores_exact_blobs(
    collection_db, monkeypatch, count
):
    db = collection_db
    prepare(db, monkeypatch)
    await seed_entries(db, sizes=(28, 28), days=(0, 1))
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(b"p" * 28),
        analysis_dates=[(NOW.date() - timedelta(days=i)).isoformat() for i in range(10)],
        patterns_count=count,
    )
    out = await insights.local_recompute(body, db.request, db.owner, db.session)
    assert out.model_dump() == dict(
        phase="baseline",
        active_days=2,
        streak=2,
        days_remaining=1,
        patterns_stored=count or 0,
        patterns_new=0,
        patterns_fading=0,
        question_stored=False,
        analyzer="local",
        state_seq=1,
    )
    rows = list((await db.session.scalars(select(Insight).where(Insight.user_id == OWNER))).all())
    assert sorted((r.kind, r.for_date, bytes(r.blob), r.state_seq) for r in rows) == [
        ("brain", None, BLOB, 1),
        ("patterns", None, b"p" * 28, 1),
    ]
    with pytest.raises(ApiError) as failure:
        await insights.local_recompute(body, db.request, db.owner, db.session)
    envelope(failure, 409, "the stored brain state moved since this analysis ran", "conflict")
    body.base_state_seq = 1
    assert (await insights.local_recompute(body, db.request, db.owner, db.session)).state_seq == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value,detail",
    [
        ("base_state_seq", -1, "base_state_seq must be >= 0"),
        ("state_blob", "!!!!", "state_blob and patterns_blob must be base64"),
        ("patterns_blob", b64(b"x" * 27), "blobs must be within the storage size bounds"),
        ("state_blob", b64(b"x" * 27), "blobs must be within the storage size bounds"),
        ("analysis_dates", ["2026-02-30"], "analysis_dates must be ISO dates"),
    ],
)
async def test_local_upload_rejects_invalid_opaque_input(
    collection_db, monkeypatch, field, value, detail
):
    db = collection_db
    prepare(db, monkeypatch)
    values = dict(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()],
    )
    values[field] = value
    with pytest.raises(ApiError) as failure:
        await insights.local_recompute(
            LocalRecomputeRequest(**values), db.request, db.owner, db.session
        )
    envelope(failure, 422, detail, "validation_error")


@pytest.mark.asyncio
async def test_local_upload_respects_live_key_rotation_fence(collection_db, monkeypatch):
    db = collection_db
    prepare(db, monkeypatch)
    db.session.add(RekeyJournal(user_id=OWNER))
    await db.session.commit()
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()],
    )
    with pytest.raises(ApiError) as failure:
        await insights.local_recompute(body, db.request, db.owner, db.session)
    envelope(failure, 409, "complete the pending key rotation before analysis", "rekey_in_progress")


@pytest.mark.parametrize("kind", ["brain", "patterns", "question", "custom"])
def test_rekey_insight_ciphertexts_preserve_plaintext_and_advance_only_analysis(kind):
    day = NOW.date() if kind == "question" else None
    aad = (
        crypto.build_aad("question", OWNER, day.isoformat())
        if day
        else crypto.build_aad("insights", OWNER, kind)
    )
    plain = b'{"patterns":[],"state_seq":7}' if kind in ("brain", "patterns") else b"opaque content"
    source = crypto.encrypt(OLD, plain, aad)
    rewritten, already = insights._rekey_insight_batch(
        OLD, NEW, [("id", kind, day, source, 7)], OWNER
    )
    assert already == 0 and len(rewritten) == 1 and rewritten[0]["id"] == "id"
    target = crypto.decrypt(NEW, rewritten[0]["blob"], aad)
    if kind in ("brain", "patterns"):
        assert (
            json.loads(target) == dict(patterns=[], state_seq=8) and rewritten[0]["state_seq"] == 8
        )
    else:
        assert target == plain and rewritten[0]["state_seq"] == 7
    assert insights._rekey_insight_batch(
        OLD, NEW, [("id", kind, day, rewritten[0]["blob"], rewritten[0]["state_seq"])], OWNER
    ) == ([], 1)
    with pytest.raises(insights._RekeyMismatch):
        insights._rekey_insight_batch(
            bytearray(b"z" * 32), NEW, [("id", kind, day, source, 7)], OWNER
        )


@pytest.mark.parametrize("kind", ["brain", "patterns"])
@pytest.mark.parametrize("payload", [b"not json", b"[]", b'"text"', b"\xff"])
def test_rekey_refuses_unsafe_stored_analysis_json(kind, payload):
    blob = crypto.encrypt(OLD, payload, crypto.build_aad("insights", OWNER, kind))
    with pytest.raises(ApiError) as failure:
        insights._rekey_insight_batch(OLD, NEW, [("id", kind, None, blob, 7)], OWNER)
    envelope(failure, 409, "stored analysis cannot be migrated safely", "conflict")


def test_rekey_analysis_stops_at_exact_javascript_generation_limit():
    aad = crypto.build_aad("insights", OWNER, "brain")
    blob = crypto.encrypt(OLD, b"{}", aad)
    rows, _ = insights._rekey_insight_batch(
        OLD, NEW, [("id", "brain", None, blob, 2**53 - 2)], OWNER
    )
    assert json.loads(crypto.decrypt(NEW, rows[0]["blob"], aad)) == dict(state_seq=2**53 - 1)
    with pytest.raises(ApiError) as failure:
        insights._rekey_insight_batch(OLD, NEW, [("id", "brain", None, blob, 2**53 - 1)], OWNER)
    envelope(failure, 503, "analysis generation exhausted", "service_unavailable")


def test_rekey_entry_and_measure_batches_support_legacy_modern_and_resumed_generations():
    modern = crypto.entry_aad_v2(OWNER, "modern", 3)
    legacy = crypto.entry_aad_candidates(OWNER, "legacy", 2)[-1]
    rows = [
        ("one", "modern", 3, crypto.encrypt(OLD, b"modern", modern)),
        ("two", "legacy", 2, crypto.encrypt(OLD, b"legacy", legacy)),
        ("three", "done", 4, crypto.encrypt(NEW, b"done", crypto.entry_aad_v2(OWNER, "done", 4))),
    ]
    rewritten, already = insights._rekey_entry_batch(OLD, NEW, rows, OWNER)
    assert already == 1 and [r[0] for r in rewritten] == ["one", "two"]
    assert [
        crypto.decrypt(NEW, blob, crypto.entry_aad_v2(OWNER, cid, version))
        for (rid, cid, version, _), (newid, blob) in zip(rows, rewritten)
    ] == [b"modern", b"legacy"]
    aad = crypto.build_aad("measure", OWNER, "m1")
    rewritten, already = insights._rekey_blob_batch(
        OLD,
        NEW,
        [("one", crypto.encrypt(OLD, b"measure", aad)), ("two", crypto.encrypt(NEW, b"new", aad))],
        lambda rid: aad,
    )
    assert (
        already == 1
        and len(rewritten) == 1
        and crypto.decrypt(NEW, rewritten[0][1], aad) == b"measure"
    )
    with pytest.raises(insights._RekeyMismatch):
        insights._rekey_blob_batch(
            OLD, NEW, [("one", crypto.encrypt(b"x" * 32, b"measure", aad))], lambda rid: aad
        )


@pytest.mark.asyncio
async def test_rekey_journal_resumes_only_the_same_operation_credentials_and_real_keys(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    body = RekeyRequest(
        operation_id=OPERATION, new_salt=b64(b"s" * 16), new_verifier=b64(b"v" * 32)
    )

    async def journal(body=body, digest="request", old=OLD, new=NEW):
        return await insights._load_or_create_rekey_journal(
            db.session,
            OWNER,
            body=body,
            digest=digest,
            old_key=old,
            new_key=new,
            settings=db.settings,
        )

    first = await journal()
    assert (await journal()).id == first.id
    variants = [
        dict(digest="different"),
        dict(old=bytearray(b"x" * 32)),
        dict(new=bytearray(b"x" * 32)),
        dict(body=body.model_copy(update={"operation_id": "87654321-1234-1234-1234-123456789abc"})),
    ]
    for changes in variants:
        with pytest.raises(ApiError) as failure:
            await journal(**changes)
        envelope(
            failure,
            409,
            "resume the original operation with the same credentials and keys",
            "rekey_operation_conflict",
        )


@pytest.mark.asyncio
async def test_legacy_journal_authenticates_all_native_batches_before_adoption(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    for i in range(101):
        key = bytearray(b"x" * 32) if i == 100 else OLD
        db.session.add(
            Measure(
                id=f"{i + 1:032x}",
                user_id=OWNER,
                client_measure_id=f"m{i}",
                measure_date=NOW.date(),
                blob=crypto.encrypt(key, b"private", crypto.build_aad("measure", OWNER, f"m{i}")),
            )
        )
    legacy = RekeyJournal(user_id=OWNER)
    db.session.add(legacy)
    await db.session.commit()
    body = RekeyRequest(
        operation_id=OPERATION, new_salt=b64(b"s" * 16), new_verifier=b64(b"v" * 32)
    )
    with pytest.raises(ApiError) as failure:
        await insights._load_or_create_rekey_journal(
            db.session,
            OWNER,
            body=body,
            digest="request",
            old_key=OLD,
            new_key=NEW,
            settings=db.settings,
        )
    envelope(
        failure,
        400,
        "legacy interrupted rotation contains an unknown key generation; no further rows changed",
        "rekey_key_mismatch",
    )
    assert legacy.operation_id is None


def test_insights_strict_base64_and_supported_fk_diagnostics():
    from sqlalchemy.exc import IntegrityError

    assert insights._decode_b64(b64(BLOB), "blob") == BLOB
    with pytest.raises(ApiError) as failure:
        insights._decode_b64("!!!!" + b64(BLOB), "blob")
    envelope(failure, 422, "blob must be base64", "validation_error")
    for attribute in ["pgcode", "sqlstate"]:
        origin = RuntimeError("database foreign-key classification")
        setattr(origin, attribute, "23503")
        assert insights._is_fk_violation(IntegrityError("statement", {}, origin)) is True
        setattr(origin, attribute, "23505")
        assert insights._is_fk_violation(IntegrityError("statement", {}, origin)) is False
    assert (
        insights._is_fk_violation(
            IntegrityError("statement", {}, RuntimeError("FOREIGN KEY constraint failed"))
        )
        is True
    )
    assert insights._is_fk_violation(IntegrityError("statement", {}, None)) is False
    assert (
        insights._is_fk_violation(IntegrityError("statement", {}, RuntimeError("other constraint")))
        is False
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("helper", ["_fresh_processing_session_user", "_rekey_fresh_user"])
@pytest.mark.parametrize("change", ["epoch", "retire", "remove"])
async def test_processing_authorization_helpers_refresh_actual_cached_accounts(
    collection_db, helper, change
):
    db = collection_db
    async with build_sessionmaker(db.engine)() as writer:
        if change == "remove":
            await writer.execute(delete(User).where(User.id == OWNER))
        else:
            await writer.execute(
                update(User)
                .where(User.id == OWNER)
                .values(**({"token_epoch": 3} if change == "epoch" else {"is_active": False}))
            )
        await writer.commit()
    with pytest.raises(ApiError) as failure:
        await getattr(insights, helper)(db.session, OWNER, 2)
    envelope(failure, 401, "invalid token", "unauthorized")


@pytest.mark.asyncio
async def test_processing_mint_rechecks_real_single_bearer_revocation(collection_db, monkeypatch):
    from app.cache import TokenRevocationStore

    db = collection_db
    prepare(db, monkeypatch)
    db.request.state.mindpattern_token_jti = "j" * 32
    store = TokenRevocationStore()
    db.request.app.state.token_revocations = store
    await store.revoke_durable(db.session, "j" * 32, NOW.timestamp() + 3600)
    await db.session.commit()
    monkeypatch.setattr("app.cache.time.time", lambda: NOW.timestamp())
    with pytest.raises(ApiError) as failure:
        await insights.create_processing_session(
            ProcessingSessionRequest(data_key=b64(OLD)), db.request, db.owner, db.session
        )
    envelope(failure, 401, "invalid token", "unauthorized")
    assert len(db.request.app.state.key_store) == 0


@pytest.mark.asyncio
async def test_analysis_drops_the_whole_oldest_tail_after_one_oversized_middle_entry(collection_db):
    db = collection_db
    rows = await seed_entries(db, sizes=(28, 100, 40), days=(0, 1, 2))
    actual = await insights._load_rows(db.session, OWNER, 3, 68)
    assert [(r.id, bytes(r.blob)) for r in actual] == [(rows[0].id, bytes(rows[0].blob))]


@pytest.mark.asyncio
async def test_insight_default_sequence_and_latest_time_id_ties_are_preserved(collection_db):
    db = collection_db
    await insights._replace_insight(db.session, OWNER, "patterns", None, BLOB)
    for i, at in [(1, NOW), (2, NOW), (3, NOW - timedelta(seconds=1))]:
        db.session.add(
            Insight(
                id=f"{i:032x}",
                user_id=OWNER,
                kind="brain",
                for_date=NOW.date() - timedelta(days=i),
                blob=f"brain-{i}".encode(),
                created_at=at,
            )
        )
    await db.session.commit()
    assert (await insights._latest_insight(db.session, OWNER, "patterns")).state_seq == 0
    assert (await insights._latest_insight(db.session, OWNER, "brain")).blob == b"brain-2"


@pytest.mark.asyncio
async def test_local_blob_bounds_are_inclusive_for_an_actual_configured_minimum_quota(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    db.settings.max_user_blob_bytes = 28
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(b"s" * 28),
        patterns_blob=b64(b"p" * 28),
        analysis_dates=[NOW.date().isoformat()],
    )
    assert (await insights.local_recompute(body, db.request, db.owner, db.session)).state_seq == 1
    for field in ["state_blob", "patterns_blob"]:
        for size in [27, 29]:
            invalid = body.model_copy(update={field: b64(b"x" * size), "base_state_seq": 1})
            with pytest.raises(ApiError) as failure:
                await insights.local_recompute(invalid, db.request, db.owner, db.session)
            envelope(
                failure, 422, "blobs must be within the storage size bounds", "validation_error"
            )
    invalid = body.model_copy(
        update={"patterns_blob": "!!!!" + body.patterns_blob, "base_state_seq": 1}
    )
    with pytest.raises(ApiError) as failure:
        await insights.local_recompute(invalid, db.request, db.owner, db.session)
    envelope(failure, 422, "state_blob and patterns_blob must be base64", "validation_error")


@pytest.mark.asyncio
async def test_local_upload_serializes_on_the_same_analysis_lock(collection_db, monkeypatch):
    db = collection_db
    prepare(db, monkeypatch)
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()],
    )
    async with insights._recompute_locks.hold(f"insights:{OWNER}"):
        task = asyncio.create_task(insights.local_recompute(body, db.request, db.owner, db.session))
        await asyncio.sleep(0.02)
        try:
            assert not task.done()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert not list((await db.session.scalars(select(Insight))).all())


@pytest.mark.asyncio
async def test_deleted_account_during_local_blob_write_returns_flat_gone_error(
    collection_db, monkeypatch
):
    db = collection_db
    prepare(db, monkeypatch)
    actual = insights._replace_insight
    deleted = False

    async def replace(session, *args, **kw):
        nonlocal deleted
        if not deleted:
            deleted = True
            async with build_sessionmaker(db.engine)() as writer:
                await writer.execute(delete(User).where(User.id == OWNER))
                await writer.commit()
        return await actual(session, *args, **kw)

    monkeypatch.setattr(insights, "_replace_insight", replace)
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()],
    )
    with pytest.raises(ApiError) as failure:
        await insights.local_recompute(body, db.request, db.owner, db.session)
    envelope(failure, 410, "account no longer exists", "account_deleted")


@pytest.mark.asyncio
async def test_legacy_rotation_adoption_authenticates_entries_questions_and_actual_audio(
    collection_db, monkeypatch
):
    from app.models import AudioAttachment
    from app.security.entry_guard import seal_entry_guard
    from app.services.audio_store import storage_locator

    db = collection_db
    prepare(db, monkeypatch)
    entry = Entry(
        id="c" * 32,
        user_id=OWNER,
        client_entry_id="legacy",
        entry_date=NOW.date(),
        received_at=NOW,
        content_version=1,
        blob=crypto.encrypt(OLD, b"entry", crypto.entry_aad_v2(OWNER, "legacy", 1)),
    )
    seal_entry_guard(entry, db.settings, v2_bound=True)
    db.session.add(entry)
    db.session.add_all(
        [
            Insight(
                user_id=OWNER,
                kind="brain",
                blob=crypto.encrypt(OLD, b"{}", crypto.build_aad("insights", OWNER, "brain")),
            ),
            Insight(
                user_id=OWNER,
                kind="question",
                for_date=NOW.date(),
                blob=crypto.encrypt(
                    NEW, b"question?", crypto.build_aad("question", OWNER, NOW.date().isoformat())
                ),
            ),
        ]
    )
    # Pre-upgrade dated brain rows retain their kind AAD. Cross the native
    # measure page boundary using both valid old and already-new keys.
    db.session.add(
        Insight(
            user_id=OWNER,
            kind="brain",
            for_date=NOW.date() - timedelta(days=1),
            blob=crypto.encrypt(OLD, b"{}", crypto.build_aad("insights", OWNER, "brain")),
        )
    )
    for i in range(101):
        db.session.add(
            Measure(
                id=f"{i + 1:032x}",
                user_id=OWNER,
                client_measure_id=f"legacy-m{i}",
                measure_date=NOW.date(),
                blob=crypto.encrypt(
                    OLD if i % 2 else NEW,
                    b"private measure",
                    crypto.build_aad("measure", OWNER, f"legacy-m{i}"),
                ),
            )
        )
    source_key = f"audio/{OWNER}/" + ("d" * 32) + ".enc"
    source = crypto.encrypt(OLD, b"recording", crypto.build_aad("audio", OWNER, "legacy", "1"))
    await db.store.put(source_key, source)
    db.session.add(
        AudioAttachment(
            id="d" * 32,
            user_id=OWNER,
            client_entry_id="legacy",
            backend=db.store.backend,
            storage_key=source_key,
            storage_locator=storage_locator(db.store),
            size_bytes=len(source),
            mime_type="audio/webm",
            duration_seconds=3,
            content_version=1,
            created_at=NOW,
            expires_at=NOW,
        )
    )
    legacy = RekeyJournal(user_id=OWNER)
    db.session.add(legacy)
    await db.session.commit()
    body = RekeyRequest(
        operation_id=OPERATION, new_salt=b64(b"s" * 16), new_verifier=b64(b"v" * 32)
    )
    out = await insights._load_or_create_rekey_journal(
        db.session,
        OWNER,
        body=body,
        digest="request",
        old_key=OLD,
        new_key=NEW,
        settings=db.settings,
    )
    assert out.id == legacy.id and out.operation_id == OPERATION
    assert (
        await insights._load_or_create_rekey_journal(
            db.session,
            OWNER,
            body=body,
            digest="request",
            old_key=OLD,
            new_key=NEW,
            settings=db.settings,
        )
    ).id == legacy.id
    assert (
        crypto.decrypt(OLD, bytes(entry.blob), crypto.entry_aad_v2(OWNER, "legacy", 1)) == b"entry"
    )
    assert await db.store.get(source_key, max_bytes=1024) == source
    entry.aad_guard_mac = "invalid"
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await insights._preflight_legacy_rotation(db.session, OWNER, OLD, NEW, db.settings)
    envelope(failure, 400, "entry blob failed authentication", "entry_blob_invalid")
