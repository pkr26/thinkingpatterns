"""Ops hardening regression pins (metrics, byte budget, retention, guards).

Pins from the 2026-09-17 ops hardening wave and its round-B follow-up
(live metrics token, constant-time compare, retention sweep), plus the
cross-host boot guard. If one starts failing, an operational safety fix
regressed -- treat it as a release blocker.
"""

from __future__ import annotations
from app.config import Settings
from app.main import _acquire_cross_host_guard, create_app
from app.metrics import MetricsRegistry, RECOMPUTE_BUCKETS
from app.models import AccessLog, AuditChainState, Entry, new_id, utcnow
from app.security import crypto
from datetime import date, datetime, timedelta, timezone
from sqlalchemy import select
from tests.helpers import ClientEmulator, TherapistEmulator
import asyncio
import base64
import hmac
import json
import app.main as main_mod
import os
import pytest
import uuid


# ---------------------------------------------------------------------------
# Pins from test_ops_hardening_2026_09_17.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
# Clock-anchored (independent audit 2026-09-27): the entry API validates
# against the server's UTC today minus a 1-day grace; a fixed date ages
# out at UTC midnight. Engine math here is date-agnostic.
TODAY = datetime.now(timezone.utc).date()


# ---------------------------------------------------------------------------
# 1. Metrics registry + endpoint
# ---------------------------------------------------------------------------


class TestMetricsRegistry:
    def test_request_counters_aggregate_by_status_family(self):
        registry = MetricsRegistry()
        for _ in range(3):
            registry.observe_request(200)
        registry.observe_request(429)
        registry.observe_request(500)
        text = registry.render(keystore_sessions=2)
        assert 'mindpattern_requests_total{status="2xx"} 3' in text
        assert 'mindpattern_requests_total{status="4xx"} 1' in text
        assert 'mindpattern_requests_total{status="5xx"} 1' in text
        assert "mindpattern_keystore_sessions 2" in text

    def test_recompute_histogram_is_cumulative(self):
        registry = MetricsRegistry()
        registry.observe_recompute(0.3)  # <= 0.25? no; <= 0.5 yes
        registry.observe_recompute(3.0)  # <= 5.0 yes
        text = registry.render(keystore_sessions=0)
        assert 'mindpattern_recompute_seconds_bucket{le="0.25"} 0' in text
        assert 'mindpattern_recompute_seconds_bucket{le="0.5"} 1' in text
        assert 'mindpattern_recompute_seconds_bucket{le="2.0"} 1' in text
        assert 'mindpattern_recompute_seconds_bucket{le="5.0"} 2' in text
        assert 'mindpattern_recompute_seconds_bucket{le="+Inf"} 2' in text
        assert "mindpattern_recompute_seconds_count 2" in text

    def test_llm_counters(self):
        registry = MetricsRegistry()
        registry.observe_llm(failed=True)
        registry.observe_llm(failed=False)
        text = registry.render(keystore_sessions=0)
        assert 'mindpattern_llm_calls_total{outcome="failure"} 1' in text
        assert 'mindpattern_llm_calls_total{outcome="success"} 1' in text

    def test_render_carries_no_user_derivable_data(self):
        registry = MetricsRegistry()
        registry.observe_request(200)
        registry.observe_recompute(1.0)
        text = registry.render(keystore_sessions=0)
        for secret in ("user", "entry", "token=", "label"):
            assert secret not in text.lower().replace("outcome=", ""), text


async def test_metrics_open_in_development(client):
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "mindpattern_requests_total" in response.text


async def test_metrics_hidden_without_token_in_production(app):
    # Fail-closed: the moment the settings say non-development and no
    # metrics token is configured, the endpoint 404s (read at request
    # time, so flipping the environment on a live app pins the branch).
    app.state.settings.environment = "production"
    app.state.settings.metrics_token = ""
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        response = await ac.get("/metrics")
    assert response.status_code == 404


async def test_metrics_requires_the_bearer_token_when_configured():
    token_settings = Settings(environment="development")
    token_settings.metrics_token = "ops-secret-token"
    token_app = create_app(token_settings)
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=token_app), base_url="http://t") as ac:
        no_auth = await ac.get("/metrics")
        assert no_auth.status_code == 401
        wrong = await ac.get("/metrics", headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401
        good = await ac.get("/metrics", headers={"Authorization": "Bearer ops-secret-token"})
        assert good.status_code == 200
        assert "mindpattern_requests_total" in good.text


async def test_recompute_records_duration_and_429s_are_visible(client, settings):
    emu = ClientEmulator("metricsuser", "p")
    await emu.register(client)
    await emu.backdate_account(client, 40)
    for i in range(32):
        await emu.create_entry(client, f"day {i} notes", TODAY - timedelta(days=31 - i))
    await emu.recompute(client)

    response = await client.get("/metrics")
    text = response.text
    assert "mindpattern_recompute_seconds_count 1" in text, text
    # Rate-limited responses flow through the counter: hammer salt lookups.
    from app.cache import SlidingWindowCounter  # noqa: F401  (documentation)

    for _ in range(25):
        await client.post("/api/auth/salt", json={"username": "metricsuser"})
    text2 = (await client.get("/metrics")).text

    def _family(text: str, family: str) -> int:
        for line in text.splitlines():
            if line.startswith("mindpattern_requests_total") and f'"{family}"' in line:
                return int(line.rsplit(" ", 1)[1])
        return 0

    assert _family(text2, "4xx") > _family(text, "4xx"), "429s must be visible in metrics"


# ---------------------------------------------------------------------------
# 2. Analysis blob budget
# ---------------------------------------------------------------------------


async def test_load_rows_respects_the_byte_budget(client, app, settings):
    emu = ClientEmulator("budgetuser", "p")
    await emu.register(client)
    await emu.backdate_account(client, 40)

    # 5 entries of ~8 KB ciphertext each; budget admits only the newest 2.
    for i in range(5):
        await emu.create_entry(
            client, "filler " * 1000 + f"entry-{i}", TODAY - timedelta(days=10 - i)
        )
    async with app.state.sessionmaker() as session:
        from app.api.insights import _load_rows

        rows = await _load_rows(session, emu.user_id, limit=100, blob_budget=16 * 1024)
    assert len(rows) == 2, [r.entry_date for r in rows]
    # The NEWEST rows survive; the oldest are dropped in SQL, pre-decrypt.
    assert [r.entry_date for r in rows] == [TODAY - timedelta(days=7), TODAY - timedelta(days=6)]


async def test_load_rows_budget_large_enough_changes_nothing(client, app):
    emu = ClientEmulator("budgetok", "p")
    await emu.register(client)
    await emu.backdate_account(client, 40)
    ids = []
    for i in range(5):
        cid = f"e-{i}"
        ids.append(cid)
        await emu.create_entry(
            client, f"plain day {i}", TODAY - timedelta(days=10 - i), client_entry_id=cid
        )
    async with app.state.sessionmaker() as session:
        from app.api.insights import _load_rows

        rows = await _load_rows(session, emu.user_id, limit=100, blob_budget=8 * 1024 * 1024)
    assert len(rows) == 5


async def test_tiny_budget_still_recomputes(client, settings, monkeypatch):
    # End-to-end: a budget tighter than the corpus must degrade gracefully
    # (analyze the newest rows only), never 500.
    settings.analysis_blob_budget = 16 * 1024
    emu = ClientEmulator("tinybudget", "p")
    await emu.register(client)
    await emu.backdate_account(client, 45)
    for i in range(35):
        await emu.create_entry(client, "filler " * 900 + f"day {i}", TODAY - timedelta(days=34 - i))
    body = await emu.recompute(client)
    assert body["phase"] in ("baseline", "insight")
    assert body["analyzer"] == "brain"


# ---------------------------------------------------------------------------
# 3. Cross-host boot guard
# ---------------------------------------------------------------------------


async def test_cross_host_guard_skips_non_postgres():
    class FakeSqliteEngine:
        dialect = type("D", (), {"name": "sqlite"})()

    assert await _acquire_cross_host_guard(FakeSqliteEngine()) is None


async def test_cross_host_guard_acquires_and_releases_on_postgres(monkeypatch):
    import app.main as main_mod

    class FakePgConnection:
        def __init__(self):
            self.locks = []
            self.commits = 0
            self.closed = False

        async def exec_driver_sql(self, sql):
            assert "pg_try_advisory_lock" in sql or "pg_advisory_unlock" in sql
            self.locks.append(sql)

            class _Scalar:
                def scalar(self):
                    return True

            return _Scalar()

        async def commit(self):
            self.commits += 1

        async def close(self):
            self.closed = True

    conn = FakePgConnection()
    calls = []

    class FakePgEngine:
        dialect = type("D", (), {"name": "postgresql"})()

        async def connect(self):
            calls.append("connect")
            return conn

    got = await _acquire_cross_host_guard(FakePgEngine())
    assert got is conn
    # The SELECT autobegins a transaction; it must be COMMITTED (session
    # advisory locks survive commit) — an open one would leave the guard
    # connection idle-in-transaction for the app lifetime, pinning xmin.
    assert conn.commits == 1
    await main_mod._release_cross_host_guard(got)
    assert conn.closed
    assert len(conn.locks) == 2  # lock + unlock


async def test_cross_host_guard_refuses_when_lock_taken():
    class TakenConnection:
        async def exec_driver_sql(self, sql):
            class _Scalar:
                def scalar(self):
                    return False

            return _Scalar()

        async def close(self):
            pass

    class TakenEngine:
        dialect = type("D", (), {"name": "postgresql"})()

        async def connect(self):
            return TakenConnection()

    with pytest.raises(RuntimeError, match="another host"):
        await _acquire_cross_host_guard(TakenEngine())


# ---------------------------------------------------------------------------
# Pins from test_ops_fixes_2026_09_17b.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 1-2. /metrics token: live settings + constant-time compare
# ---------------------------------------------------------------------------


def test_edge_rate_table_covers_all_three_ops_routes(app):
    """Re-audit (2026-09-27): _rate_limit_rules(app) is evaluated EAGERLY at
    HardeningMiddleware registration, so every route whose bucket the edge
    malformed-body counter must mirror has to exist BEFORE that call. The
    three ops routes used to be registered after it and were silently
    missing from the edge table. Pin the built table's contents, not the
    registration order: each ops path must appear with its ops-health
    bucket check attached."""
    hardening = next(m for m in app.user_middleware if m.cls.__name__ == "HardeningMiddleware")
    rules = hardening.kwargs["rate_limit_rules"]
    covered: set[str] = set()
    for _methods, pattern, checks in rules:
        if not any(check.bucket == "ops-health" for check in checks):
            continue
        for path in ("/healthz", "/metrics", "/readyz"):
            if pattern.match(path):
                covered.add(path)
    assert covered == {"/healthz", "/metrics", "/readyz"}, (
        f"edge rate-limit table misses ops routes: {covered}"
    )


async def test_metrics_token_comes_from_the_live_settings():
    # The closure's settings carry NO token; a runtime replacement does.
    # Against the stale closure the empty "Bearer " expectation used to
    # be accepted — the live read must reject everything but the token
    # the app is actually running with.
    closure_settings = Settings(environment="development")
    assert closure_settings.metrics_token == ""
    app = create_app(closure_settings)
    app.state.settings = Settings(
        environment="development",
        token_secret="live-settings-secret-not-for-production",
        metrics_token="live-token",
    )
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        assert (await ac.get("/metrics")).status_code == 401
        # The stale-closure expectation (empty token) must NOT authenticate.
        stale = await ac.get("/metrics", headers={"Authorization": "Bearer "})
        assert stale.status_code == 401
        ok = await ac.get("/metrics", headers={"Authorization": "Bearer live-token"})
        assert ok.status_code == 200


async def test_metrics_token_comparison_is_constant_time(monkeypatch):
    token_settings = Settings(environment="development")
    token_settings.metrics_token = "ops-secret"
    token_app = create_app(token_settings)
    seen: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(left, right):
        seen.append((left, right))
        return real(left, right)

    monkeypatch.setattr(main_mod.hmac, "compare_digest", spy)
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=token_app), base_url="http://t") as ac:
        response = await ac.get("/metrics", headers={"Authorization": "Bearer ops-secret"})
    assert response.status_code == 200
    byte_pairs = [
        pair for pair in seen if isinstance(pair[0], bytes) and isinstance(pair[1], bytes)
    ]
    assert byte_pairs, "the /metrics token check must call hmac.compare_digest on bytes"


# ---------------------------------------------------------------------------
# 3. access_log retention sweep
# ---------------------------------------------------------------------------


async def test_sweep_task_is_created_and_cancelled_with_the_lifespan(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        task = application.state.access_log_sweep_task
        assert isinstance(task, asyncio.Task)
        assert not task.done()
    # Shutdown cancels the sweep (and reaps it) before the engine is
    # disposed — a lingering task would race the dispose.
    assert task.cancelled() or task.done()


async def test_prune_once_deletes_only_rows_past_retention(client, app):
    now = utcnow()
    from app.api._audit import compute_chain_state_mac, compute_entry_hash, compute_entry_mac

    mac_version = app.state.settings.audit_mac_key_version
    mac_key = app.state.settings.audit_mac_keyring[mac_version]

    def signed_genesis(*, action: str, at: datetime) -> tuple[AccessLog, AuditChainState]:
        user_id = new_id()
        actor_id = new_id()
        entry_hash = compute_entry_hash(
            None,
            actor_id,
            user_id,
            action,
            at,
            actor_role="therapist",
            record_version=2,
        )
        row = AccessLog(
            id=new_id(),
            actor_id=actor_id,
            actor_role="therapist",
            user_id=user_id,
            action=action,
            at=at,
            chain_seq=1,
            prev_hash=None,
            entry_hash=entry_hash,
            entry_mac=compute_entry_mac(mac_key, user_id, 1, entry_hash),
            mac_key_version=mac_version,
            record_version=2,
        )
        state = AuditChainState(
            user_id=user_id,
            head_seq=1,
            head_hash=entry_hash,
            head_at=at,
            first_retained_seq=1,
            first_retained_hash=entry_hash,
            state_version=1,
            mac_key_version=mac_version,
            updated_at=now,
        )
        state.state_mac = compute_chain_state_mac(mac_key, state)
        return row, state

    async with app.state.sessionmaker() as session:
        # Seed fully authenticated one-row chains without invoking the
        # append helper's retry savepoint on the fixture's shared SQLite
        # connection. Production append behavior has dedicated coverage.
        old = signed_genesis(action="read_insights", at=now - timedelta(days=731))
        recent = signed_genesis(action="read_notes", at=now)
        session.add_all([*old, *recent])
        await session.commit()

    await main_mod._prune_access_log_once(app)

    async with app.state.sessionmaker() as session:
        remaining = (await session.execute(select(AccessLog.action))).scalars().all()
    assert remaining == ["read_notes"]


async def test_pairing_prune_runs_only_in_the_bounded_sweep(client, monkeypatch):
    seen = []
    real = main_mod._prune_auxiliary_retention_once

    async def spy(*args, **kwargs):
        seen.append(True)
        return await real(*args, **kwargs)

    monkeypatch.setattr(main_mod, "_prune_auxiliary_retention_once", spy)

    doc = TherapistEmulator("sweepshare", "pw")
    await doc.register(client)
    await doc.create_pairing_code(client)
    assert seen == []

    await main_mod._prune_access_log_once(client._transport.app)  # the sweep path
    assert len(seen) == 1
