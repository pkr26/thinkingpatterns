"""Regression tests for the API+DB remediation round (2026-09-07).

Covers: SQL-bounded recompute corpus, transaction discipline around
analysis, insights upsert idempotency + question retention, the forward
timezone grace on entry dates, the recompute × account-delete race (410),
/api/v1 mounting, the unified error envelope, export ISO timestamps,
the X-Account-Verifier header, /readyz, pool/export settings, SQLite
timezone normalization, and the atomic logout.
"""

from __future__ import annotations

import base64
import logging
from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import event, select

from app.config import Settings
from app.main import create_app
from app.middleware import HardeningMiddleware
from tests.helpers import ClientEmulator, daterange

TODAY = date.today()


def _assert_envelope(response, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert isinstance(body["detail"], str) and body["detail"], body
    assert body["code"] == code, body


# --- P0-1/P0-2: recompute corpus load and transaction discipline ---------------


async def test_load_rows_emits_a_sql_limit(client, app):
    """The corpus cap must be enforced by the query itself, not by fetching
    every blob and slicing in Python."""
    emu = ClientEmulator("sqllimit", "pw-sql-limit")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    for offset in range(3):
        await emu.create_entry(client, f"day {offset}", TODAY - timedelta(days=offset),
                               client_entry_id=f"e-lim-{offset}")

    statements: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    from app.api.insights import _load_rows

    async with app.state.sessionmaker() as s:
        rows = await _load_rows(s, emu.user_id, limit=2)
    assert len(rows) == 2
    entry_selects = [s for s in statements if "FROM entries" in s]
    assert entry_selects, statements
    assert any("LIMIT" in s.upper() for s in entry_selects), entry_selects
    assert "DESC" in entry_selects[-1].upper()  # recency ordering, reversed in Python


async def test_recompute_holds_no_transaction_across_analysis(client, app, settings, monkeypatch):
    """While the brain/LLM analysis runs (seconds of CPU), NO session of this
    request holds an open transaction — reads committed/closed beforehand,
    the write transaction opens only after analysis."""
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("txwindow", "pw-tx-window")
    await emu.register(client)
    await emu.create_entry(client, "one calm day", TODAY, client_entry_id="e-tx")

    real_sessionmaker = app.state.sessionmaker
    live_sessions = []

    def tracking_sessionmaker():
        session = real_sessionmaker()
        live_sessions.append(session)
        return session

    monkeypatch.setattr(app.state, "sessionmaker", tracking_sessionmaker)

    from app.security import enclave

    observed: list[bool] = []
    real_run = enclave.SecureProcessingContext.run

    def run_spy(self, encrypted, analyze):
        # Runs on a worker thread; attribute reads are sync-safe.
        observed.append(all(not s.in_transaction() for s in live_sessions))
        return real_run(self, encrypted, analyze)

    monkeypatch.setattr(enclave.SecureProcessingContext, "run", run_spy)

    result = await emu.recompute(client)
    assert result["phase"] == "insight"
    assert observed == [True], "a session still held a transaction during analysis"


# --- P0-3: insight idempotency, retention, and the unique constraint -----------


async def _insight_rows(app, user_id: str):
    from app.models import Insight

    async with app.state.sessionmaker() as session:
        return (
            (await session.execute(select(Insight).where(Insight.user_id == user_id)))
            .scalars()
            .all()
        )


async def test_repeated_recomputes_are_idempotent(client, app, settings):
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("idem", "pw-idem")
    await emu.register(client)
    await emu.create_entry(client, "steady day", TODAY, client_entry_id="e-idem")

    first = await emu.recompute(client)
    assert first["phase"] == "insight"
    rows1 = await _insight_rows(app, emu.user_id)
    counts1 = {}
    for row in rows1:
        counts1[row.kind] = counts1.get(row.kind, 0) + 1
    assert counts1 == {"patterns": 1, "brain": 1}  # no patterns -> no question

    await emu.recompute(client)
    await emu.recompute(client)
    rows2 = await _insight_rows(app, emu.user_id)
    counts2 = {}
    for row in rows2:
        counts2[row.kind] = counts2.get(row.kind, 0) + 1
    # Upsert/delete-then-insert must never accumulate duplicate rows.
    assert counts2 == counts1


async def test_same_day_question_upserts_in_place(client, app):
    """Two recomputes on one day leave exactly ONE question row for the day,
    and it still decrypts (the upsert path rewrites blob, not history)."""
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator("qidem", "pw-q-idem")
    await emu.register(client)
    await seed_corpus(client, emu, days=35)
    await emu.recompute(client)
    await emu.recompute(client)

    rows = await _insight_rows(app, emu.user_id)
    questions_today = [r for r in rows if r.kind == "question" and r.for_date == TODAY]
    assert len(questions_today) == 1
    question = await emu.decrypt_question(client, TODAY)
    assert question["for_date"] == TODAY.isoformat()


async def test_question_rows_older_than_90_days_are_purged(client, app):
    from app.models import Insight

    emu = ClientEmulator("qpurge", "pw-q-purge")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    for d in daterange(32, TODAY):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)

    ancient = TODAY - timedelta(days=100)
    recent = TODAY - timedelta(days=5)
    async with app.state.sessionmaker() as session:
        session.add(Insight(user_id=emu.user_id, kind="question", for_date=ancient, blob=b"old"))
        session.add(Insight(user_id=emu.user_id, kind="question", for_date=recent, blob=b"keep"))
        await session.commit()

    await emu.recompute(client)

    rows = await _insight_rows(app, emu.user_id)
    question_dates = {r.for_date for r in rows if r.kind == "question"}
    assert ancient not in question_dates  # retention purge
    assert recent in question_dates  # recent history survives


async def test_insights_unique_constraint_is_enforced(client, app):
    """The (user_id, kind, for_date) constraint exists in the create_all
    schema too (migration parity is pinned in test_migrations.py)."""
    import sqlalchemy.exc

    from app.models import Insight

    emu = ClientEmulator("uniqpin", "pw-uniq-pin")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        session.add(Insight(user_id=emu.user_id, kind="question", for_date=TODAY, blob=b"a"))
        session.add(Insight(user_id=emu.user_id, kind="question", for_date=TODAY, blob=b"b"))
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            await session.commit()


# --- P0-4: forward timezone grace on entry dates -------------------------------


async def test_tomorrow_dated_entry_is_accepted(client):
    """A UTC+9..+14 user's morning entry is dated 'tomorrow' in server UTC;
    one day of forward grace must accept it."""
    emu = ClientEmulator("aotearoa", "pw-aotearoa")
    await emu.register(client)
    tomorrow = TODAY + timedelta(days=1)
    created = await emu.create_entry(client, "morning pages", tomorrow,
                                     client_entry_id="e-tomorrow")
    assert created["entry_date"] == tomorrow.isoformat()

    # Two days out is still beyond any real timezone skew: rejected.
    beyond = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "e-plus2",
        "blob": emu.encrypt_entry("too far", TODAY + timedelta(days=2), "e-plus2"),
        "entry_date": (TODAY + timedelta(days=2)).isoformat(),
    })
    assert beyond.status_code == 422
    assert beyond.json()["code"] == "validation_error"


# --- P0-5: recompute x account deletion race -----------------------------------


async def test_recompute_write_after_account_delete_is_410(client, settings, monkeypatch):
    """DELETE /account committing mid-recompute makes the insight write hit
    the FK; that must surface as 410 account_deleted, not a bare 500.
    (Interlock simulated the same way the commit-race 409 tests do: the
    write transaction's commit raises the FK violation.)"""
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import AsyncSession

    settings.unlock_threshold_days = 1
    emu = ClientEmulator("gonerace", "pw-gone-race")
    await emu.register(client)
    await emu.create_entry(client, "last entry", TODAY, client_entry_id="e-gone")
    token = await emu.open_processing_session(client)

    async def fk_failing_commit(self):
        raise IntegrityError("INSERT", {}, Exception("FOREIGN KEY constraint failed"))

    monkeypatch.setattr(AsyncSession, "commit", fk_failing_commit)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert response.status_code == 410
    _assert_envelope(response, 410, "account_deleted")


def test_is_fk_violation_classifier():
    from sqlalchemy.exc import IntegrityError

    from app.api.insights import _is_fk_violation

    class _PgError(Exception):
        pass

    pg = _PgError('insert violates foreign key constraint "insights_user_id_fkey"')
    pg.pgcode = "23503"
    assert _is_fk_violation(IntegrityError("INSERT", {}, pg)) is True
    sqlite = Exception("FOREIGN KEY constraint failed")
    assert _is_fk_violation(IntegrityError("INSERT", {}, sqlite)) is True
    # Unique violations and unwrapped errors are NOT the delete race.
    assert _is_fk_violation(IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))) is False


# --- P1-6: /api/v1 mounting ------------------------------------------------------


async def test_v1_and_legacy_mounts_serve_meta_identically(client):
    legacy = await client.get("/api/meta")
    v1 = await client.get("/api/v1/meta")
    assert legacy.status_code == v1.status_code == 200
    assert legacy.json() == v1.json()
    assert v1.json()["api_version"] == "v1"


async def test_v1_mount_serves_the_full_flow(client):
    emu = ClientEmulator("v1flow", "pw-v1-flow")
    registered = await client.post("/api/v1/auth/register", json={
        "username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64,
    })
    assert registered.status_code == 201, registered.text
    emu.user_id = registered.json()["user_id"]
    emu.token = registered.json()["token"]

    blob = emu.encrypt_entry("v1 entry", TODAY, "e-v1")
    created = await client.post("/api/v1/entries", headers=emu.headers, json={
        "client_entry_id": "e-v1", "blob": blob, "entry_date": TODAY.isoformat(),
    })
    assert created.status_code == 201, created.text
    listed = await client.get("/api/v1/entries", headers=emu.headers)
    assert [e["client_entry_id"] for e in listed.json()] == ["e-v1"]

    insights = await client.get("/api/v1/insights", headers=emu.headers)
    assert insights.status_code == 200
    assert insights.json()["phase"] == "baseline"


async def test_v1_and_legacy_share_rate_buckets(client, settings):
    # Same routers under two mounts must not double the allowance.
    settings.auth_rate_limit = 3
    paths = ["/api/auth/salt", "/api/v1/auth/salt", "/api/auth/salt", "/api/v1/auth/salt"]
    statuses = [
        (await client.post(path, json={"username": "shared-bucket"})).status_code
        for path in paths
    ]
    assert statuses == [200, 200, 200, 429]


# --- P1-7: unified error envelope ------------------------------------------------


async def test_error_envelope_codes_across_endpoints(client, settings):
    emu = ClientEmulator("envelope", "pw-envelope")
    await emu.register(client)

    # 401 bearer failures
    _assert_envelope(await client.get("/api/entries"), 401, "unauthorized")
    # 404 unknown route (framework-raised, no ApiError involved)
    _assert_envelope(await client.get("/api/nowhere"), 404, "not_found")
    # 405 wrong method
    _assert_envelope(await client.post("/api/meta"), 405, "method_not_allowed")
    # 401 login failure
    bad_login = await client.post("/api/auth/login", json={
        "username": emu.username, "verifier": base64.b64encode(b"\x00" * 32).decode(),
    })
    _assert_envelope(bad_login, 401, "invalid_credentials")
    # 409 duplicate username
    dup = await client.post("/api/auth/register", json={
        "username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64,
    })
    _assert_envelope(dup, 409, "conflict")
    # 409 duplicate entry
    created = await emu.create_entry(client, "one", TODAY, client_entry_id="e-env")
    replay = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "e-env", "blob": created["blob"], "entry_date": TODAY.isoformat(),
    })
    _assert_envelope(replay, 409, "conflict")
    # 422 schema validation
    bad_schema = await client.post("/api/auth/register", json={"username": "!!"})
    _assert_envelope(bad_schema, 422, "validation_error")
    # 422 handler-level format check — same shape, string detail
    bad_blob = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "e-bad", "blob": "!!!", "entry_date": TODAY.isoformat(),
    })
    _assert_envelope(bad_blob, 422, "validation_error")
    # 404 entry
    missing = await client.delete("/api/entries/never", headers=emu.headers)
    _assert_envelope(missing, 404, "not_found")
    # 403 wrong verifier on an authenticated request
    wrong_verifier = await client.request(
        "DELETE", "/api/account", headers=emu.headers,
        json={"verifier": base64.b64encode(b"\x00" * 32).decode()},
    )
    _assert_envelope(wrong_verifier, 403, "verification_failed")
    # 413 body cap (middleware-produced — outside the exception handlers)
    huge = base64.b64encode(b"x" * 2_000_000).decode()
    too_big = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "e-huge", "blob": huge, "entry_date": TODAY.isoformat(),
    })
    _assert_envelope(too_big, 413, "payload_too_large")
    # 429 rate limiting keeps its Retry-After
    settings.auth_rate_limit = 1
    await client.post("/api/auth/salt", json={"username": "rl-one"})
    limited = await client.post("/api/auth/salt", json={"username": "rl-two"})
    _assert_envelope(limited, 429, "rate_limited")
    assert int(limited.headers["Retry-After"]) >= 1


async def test_quota_errors_carry_distinct_codes(client, settings):
    emu = ClientEmulator("quotacodes", "pw-quota-codes")
    await emu.register(client)
    settings.max_entries_per_user = 1
    settings.max_user_blob_bytes = 10_000
    await emu.create_entry(client, "only one", TODAY, client_entry_id="e-q1")
    count_full = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "e-q2",
        "blob": emu.encrypt_entry("second", TODAY, "e-q2"),
        "entry_date": TODAY.isoformat(),
    })
    _assert_envelope(count_full, 413, "quota_exceeded")

    emu2 = ClientEmulator("quotacodes2", "pw-quota-codes-2")
    await emu2.register(client)
    settings.max_entries_per_user = 100
    settings.max_user_blob_bytes = 64  # below one entry's ciphertext size
    bytes_full = await client.post("/api/entries", headers=emu2.headers, json={
        "client_entry_id": "e-qb",
        "blob": emu2.encrypt_entry("too big for the byte cap", TODAY, "e-qb"),
        "entry_date": TODAY.isoformat(),
    })
    _assert_envelope(bytes_full, 413, "blob_quota_exceeded")


# --- P1-8: export format ----------------------------------------------------------


async def test_export_timestamps_are_iso8601_with_offsets(client):
    emu = ClientEmulator("exportiso", "pw-export-iso")
    await emu.register(client)
    await emu.backdate_account(client, days=34)
    for d in daterange(32, TODAY):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)
    await emu.recompute(client)

    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    bundle = response.json()

    # The whole document validates against the ExportBundle schema...
    from app.schemas import ExportBundle

    parsed = ExportBundle.model_validate(bundle)
    assert parsed.version == 1 and len(parsed.entries) == 32

    # ...and every timestamp is ISO-8601 with an explicit offset — never the
    # str(datetime) form ("2026-09-07 12:00:00+00:00", note the space).
    stamps = [bundle["exported_at"]]
    stamps += [e["received_at"] for e in bundle["entries"]]
    stamps += [i["created_at"] for i in bundle["insights"]]
    assert len(stamps) > 2
    for stamp in stamps:
        assert "T" in stamp and " " not in stamp, stamp
        parsed_at = datetime.fromisoformat(stamp)
        assert parsed_at.tzinfo is not None, stamp
        assert parsed_at.utcoffset() == timedelta(0), stamp


# --- P1-10: X-Account-Verifier header ---------------------------------------------


async def test_delete_account_accepts_the_verifier_header(client, app):
    from tests.helpers import delete_account_via_header

    emu = ClientEmulator("headerdel", "pw-header-del")
    await emu.register(client)
    await emu.create_entry(client, "to be deleted", TODAY, client_entry_id="e-del")
    assert await delete_account_via_header(client, emu) == 204
    stale = await client.get("/api/entries", headers=emu.headers)
    assert stale.status_code == 401


async def test_delete_account_header_and_body_semantics(client):
    # Header wins over a conflicting body (preferred transport).
    emu = ClientEmulator("headerwins", "pw-header-wins")
    await emu.register(client)
    response = await client.request(
        "DELETE", "/api/account",
        headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64},
        json={"verifier": base64.b64encode(b"\x00" * 32).decode()},
    )
    assert response.status_code == 204

    # A wrong header is 403 even with a correct body.
    emu2 = ClientEmulator("headerloses", "pw-header-loses")
    await emu2.register(client)
    refused = await client.request(
        "DELETE", "/api/account",
        headers={**emu2.headers, "X-Account-Verifier": base64.b64encode(b"\x00" * 32).decode()},
        json={"verifier": emu2.auth_key_b64},
    )
    _assert_envelope(refused, 403, "verification_failed")
    assert await emu2.delete_account(client) == 204  # deprecated body fallback still works

    # Neither header nor body: 422, and nothing is deleted.
    emu3 = ClientEmulator("neverified", "pw-ne-verified")
    await emu3.register(client)
    bare = await client.request("DELETE", "/api/account", headers=emu3.headers)
    _assert_envelope(bare, 422, "validation_error")
    still = await client.get("/api/entries", headers=emu3.headers)
    assert still.status_code == 200


# --- P1-11: /readyz ----------------------------------------------------------------


async def test_readyz_checks_the_database(client):
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    # Liveness stays cheap and separate.
    health = await client.get("/healthz")
    assert health.json()["status"] == "ok"


async def test_readyz_503_when_database_unreachable(settings):
    settings.database_url = "sqlite+aiosqlite:////nonexistent-mindpattern-dir/probe.db"
    application = create_app(settings)
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=application)
    try:
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            response = await c.get("/readyz")
            health = await c.get("/healthz")
    finally:
        await application.state.engine.dispose()
    _assert_envelope(response, 503, "service_unavailable")
    assert health.status_code == 200  # liveness never touches the DB


# --- P1-12 / P2-18: pool config + numeric maxima -----------------------------------


def test_pool_settings_are_range_validated():
    base = dict(environment="development", database_url="sqlite+aiosqlite://")
    for bad in ({"db_pool_size": 0}, {"db_pool_timeout": 0}, {"db_max_overflow": -1}):
        with pytest.raises(RuntimeError, match="must be >="):
            Settings(**base, **bad)
    ok = Settings(**base, db_pool_size=1, db_max_overflow=0, db_pool_timeout=1)
    assert (ok.db_pool_size, ok.db_max_overflow, ok.db_pool_timeout) == (1, 0, 1)


def test_numeric_upper_bounds_abort_startup():
    base = dict(environment="development", database_url="sqlite+aiosqlite://")
    with pytest.raises(RuntimeError, match="token_ttl_seconds must be <="):
        Settings(**base, token_ttl_seconds=30 * 86_400 + 1)
    with pytest.raises(RuntimeError, match="processing_session_ttl must be <="):
        Settings(**base, processing_session_ttl=3601)
    with pytest.raises(RuntimeError, match="auth_rate_window must be <="):
        Settings(**base, auth_rate_window=3601)
    with pytest.raises(RuntimeError, match="read_rate_limit must be <="):
        Settings(**base, read_rate_limit=100_001)
    # Exactly at the maxima: valid.
    Settings(
        **base,
        token_ttl_seconds=30 * 86_400,
        processing_session_ttl=3600,
        export_rate_limit=100_000,
        export_rate_window=3600,
    )


def test_export_and_pool_env_vars_wire_through(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.setenv("MINDPATTERN_DB_URL", "sqlite+aiosqlite://")
    monkeypatch.setenv("MINDPATTERN_EXPORT_RATE_LIMIT", "7")
    monkeypatch.setenv("MINDPATTERN_EXPORT_RATE_WINDOW", "120")
    monkeypatch.setenv("MINDPATTERN_DB_POOL_SIZE", "9")
    monkeypatch.setenv("MINDPATTERN_DB_MAX_OVERFLOW", "3")
    monkeypatch.setenv("MINDPATTERN_DB_POOL_TIMEOUT", "11")
    s = Settings.from_env()
    assert (s.export_rate_limit, s.export_rate_window) == (7, 120)
    assert (s.db_pool_size, s.db_max_overflow, s.db_pool_timeout) == (9, 3, 11)


def test_llm_url_without_api_key_warns_but_boots(caplog):
    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        s = Settings(
            environment="development",
            database_url="sqlite+aiosqlite://",
            llm_url="https://llm.example.com/v1",
        )
    assert s.llm_url  # booted
    assert any("MINDPATTERN_LLM_API_KEY" in r.message for r in caplog.records)


# --- P1-13: SQLite timezone normalization ------------------------------------------


async def test_timestamps_read_back_tz_aware_on_sqlite(client, app, settings):
    """SQLite storage is naive; the UTCDateTime type must attach UTC on read
    so API responses serialize identically on both backends."""
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("tznorm", "pw-tz-norm")
    await emu.register(client)
    await emu.create_entry(client, "timestamp probe", TODAY, client_entry_id="e-tz")
    await emu.recompute(client)

    from app.models import Entry, Insight, User

    async with app.state.sessionmaker() as session:
        user = await session.get(User, emu.user_id)
        entry = (await session.execute(select(Entry))).scalars().first()
        insight = (await session.execute(select(Insight))).scalars().first()
    for stamp in (user.created_at, entry.received_at, insight.created_at):
        assert stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0), stamp

    listed = await client.get("/api/entries", headers=emu.headers)
    received_at = listed.json()[0]["received_at"]
    assert "+00:00" in received_at or received_at.endswith("Z")


# --- P1-14: distinct date scan -----------------------------------------------------


async def test_get_insights_uses_a_distinct_date_scan(client, app):
    emu = ClientEmulator("datescan", "pw-date-scan")
    await emu.register(client)
    await emu.backdate_account(client, days=5)
    for offset in range(3):
        await emu.create_entry(client, f"scan {offset}", TODAY - timedelta(days=offset),
                               client_entry_id=f"e-scan-{offset}")

    statements: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    response = await client.get("/api/insights", headers=emu.headers)
    assert response.status_code == 200
    assert response.json()["active_days"] == 3
    entry_reads = [s for s in statements if "FROM entries" in s]
    assert any("DISTINCT" in s.upper() for s in entry_reads), entry_reads
    # No blob column leaves the DB for the phase computation.
    assert not any("blob" in s for s in entry_reads if "DISTINCT" in s.upper())


# --- P1-15: atomic logout + keystore purge ------------------------------------------


async def test_logout_epoch_bump_is_a_single_atomic_update(client, app):
    emu = ClientEmulator("atomiclogout", "pw-atomic-logout")
    await emu.register(client)

    statements: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    assert (await client.post("/api/auth/logout", headers=emu.headers)).status_code == 204

    epoch_updates = [s for s in statements if "UPDATE" in s.upper() and "token_epoch" in s]
    assert epoch_updates, statements
    # SET token_epoch = token_epoch + 1 — atomic in the DB, not read-modify-write.
    assert any("token_epoch +" in s or "token_epoch +(" in s or "(token_epoch +" in s
               for s in epoch_updates), epoch_updates

    from app.models import User

    async with app.state.sessionmaker() as session:
        user = await session.get(User, emu.user_id)
    assert user.token_epoch == 2


async def test_logout_purges_processing_sessions(client, app):
    emu = ClientEmulator("keypurgeout", "pw-key-purge-out")
    await emu.register(client)
    await emu.open_processing_session(client)
    assert len(app.state.key_store) == 1

    assert (await client.post("/api/auth/logout", headers=emu.headers)).status_code == 204
    assert len(app.state.key_store) == 0


# --- P2-16: version single-sourcing ---------------------------------------------------


async def test_version_is_single_sourced(client):
    import app
    import app.main
    from app.api.meta import API_VERSION

    assert app.main.APP_VERSION == app.__version__
    meta = await client.get("/api/v1/meta")
    assert meta.json()["version"] == app.__version__
    assert meta.json()["api_version"] == API_VERSION == "v1"
    health = await client.get("/healthz")
    assert health.json()["version"] == app.__version__


# --- P2-22: X-Forwarded-For warning ----------------------------------------------------


async def _call_asgi(app, scope, incoming):
    sent = []
    queue = list(incoming)

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def _xff_scope(with_xff: bool) -> dict:
    return {
        "type": "http", "asgi": {"version": "2.3"}, "http_version": "1.1",
        "method": "GET", "path": "/x",
        "headers": [(b"x-forwarded-for", b"1.2.3.4")] if with_xff else [],
    }


async def test_xff_warns_once_when_proxy_headers_not_trusted(caplog):
    async def ok_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    wrapped = HardeningMiddleware(ok_app, max_body_bytes=100, trust_proxy_headers=False)
    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        for _ in range(3):
            await _call_asgi(wrapped, _xff_scope(with_xff=True), [])
    warnings = [r for r in caplog.records if "X-Forwarded-For" in r.message]
    assert len(warnings) == 1  # first-seen only


async def test_xff_no_warning_when_trusted_or_absent(caplog):
    async def ok_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        trusted = HardeningMiddleware(ok_app, max_body_bytes=100, trust_proxy_headers=True)
        await _call_asgi(trusted, _xff_scope(with_xff=True), [])
        untrusted = HardeningMiddleware(ok_app, max_body_bytes=100, trust_proxy_headers=False)
        await _call_asgi(untrusted, _xff_scope(with_xff=False), [])
    assert not [r for r in caplog.records if "X-Forwarded-For" in r.message]


# --- P2-20: MINDPATTERN_TEST_DB_URL contract -------------------------------------


async def test_test_db_url_guard_refuses_non_test_databases(monkeypatch):
    """The per-test cleanup wipes all rows; it must refuse anything but a
    throwaway database (name containing "test") on a real server."""
    from tests import conftest

    raw = conftest._shared_test_db_cleanup.__wrapped__

    monkeypatch.setenv("MINDPATTERN_TEST_DB_URL", "postgresql+asyncpg://u:p@db/prod_main")
    gen = raw()
    with pytest.raises(RuntimeError, match="throwaway"):
        await gen.__anext__()

    # Unset: complete no-op, no engine built.
    monkeypatch.delenv("MINDPATTERN_TEST_DB_URL", raising=False)
    gen = raw()
    await gen.__anext__()
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()


# --- misc: insights payload passthrough stays opaque ------------------------------------


async def test_insights_payload_passes_pattern_dicts_through(client, settings):
    """The API layer never interprets the pattern payload: whatever the
    engine's to_dict() emits (including new keys like a "sensitive" flag)
    lands verbatim in the encrypted blob."""
    settings.unlock_threshold_days = 1
    emu = ClientEmulator("opaque", "pw-opaque")
    await emu.register(client)
    await emu.create_entry(client, "work work work work deadline", TODAY, client_entry_id="e-op")
    await emu.recompute(client)
    payload = await emu.decrypt_insights(client)
    assert payload["v"] == 2
    for pattern in payload["stats"]["patterns"]:
        assert isinstance(pattern, dict)
        # The API adds nothing and removes nothing relative to the engine's
        # own serialization (pinned by the engine's suite): keys come from
        # Pattern.to_dict().
        assert {"kind", "label"} <= set(pattern)
