"""2026-09-17 ops hardening — metrics, byte budget, cross-host guard.

Three changes, pinned here:

  1. /metrics — privacy-safe aggregate counters (status families, recompute
     histogram, LLM failure counts, keystore length). Fail-closed auth:
     without MINDPATTERN_METRICS_TOKEN the endpoint is development-only.
  2. ANALYSIS BLOB BUDGET — _load_rows fetches ids+sizes first and only
     then the newest rows within the byte budget, so peak recompute
     memory is bounded by the analysis budget, not the storage quota.
  3. CROSS-HOST BOOT GUARD — on Postgres the app holds a lifetime session
     advisory lock; a second host on the same database refuses to boot
     (the 2026-09-16 flock guard is per-host only). The lock's autobegun
     transaction is COMMITTED — session locks survive commit, and an
     idle-in-transaction guard connection would pin xmin for the app
     lifetime (see test_ops_fixes_2026_09_17b.py for the rest of the
     2026-09-17 ops fixes).
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import date, timedelta

import pytest

from app.config import Settings
from app.main import _acquire_cross_host_guard, create_app
from app.metrics import RECOMPUTE_BUCKETS, MetricsRegistry
from app.models import Entry
from app.security import crypto

from .helpers import ClientEmulator

TODAY = date(2026, 9, 17)


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
    from app.cache import FixedWindowCounter  # noqa: F401  (documentation)

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
