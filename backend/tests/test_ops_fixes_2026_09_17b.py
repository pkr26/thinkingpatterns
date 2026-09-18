"""2026-09-17 ops fixes, round B — live metrics token, access_log sweep.

Three pins (round A lives in test_ops_hardening_2026_09_17.py):

  1. /metrics reads the bearer token from the LIVE app.state.settings —
     the create_app closure's copy goes stale when settings are replaced
     at runtime, and the old (possibly empty) token must stop working.
  2. The token comparison goes through hmac.compare_digest on UTF-8
     encodings (the account.py idiom), never a plain ==/!=.
  3. The access_log retention sweep is created with the lifespan,
     cancelled on shutdown, deletes only rows past the 730-day window,
     and issues the SAME prune statement the pairing-code path uses
     (api.therapist.access_log_prune_statement).
"""

from __future__ import annotations

import asyncio
import hmac
from datetime import timedelta

import app.main as main_mod
from app.config import Settings
from app.main import create_app
from app.models import AccessLog, new_id, utcnow
from sqlalchemy import select

from .helpers import TherapistEmulator


# ---------------------------------------------------------------------------
# 1-2. /metrics token: live settings + constant-time compare
# ---------------------------------------------------------------------------


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

    def _row(action: str, at) -> AccessLog:
        return AccessLog(
            actor_id=new_id(), actor_role="therapist", user_id=new_id(), action=action, at=at
        )

    async with app.state.sessionmaker() as session:
        session.add(_row("read_insights", now - timedelta(days=731)))
        session.add(_row("read_notes", now))
        await session.commit()

    await main_mod._prune_access_log_once(app)

    async with app.state.sessionmaker() as session:
        remaining = (await session.execute(select(AccessLog.action))).scalars().all()
    assert remaining == ["read_notes"]


async def test_pairing_codes_and_sweep_share_one_prune_statement(client, monkeypatch):
    import app.api.therapist as therapist_mod

    seen = []
    real = therapist_mod.access_log_prune_statement

    def spy(now, retention_days=730):
        statement = real(now, retention_days)
        seen.append(statement)
        return statement

    monkeypatch.setattr(therapist_mod, "access_log_prune_statement", spy)

    doc = TherapistEmulator("sweepshare", "pw")
    await doc.register(client)
    await doc.create_pairing_code(client)  # the opportunistic prune path
    assert len(seen) == 1

    await main_mod._prune_access_log_once(client._transport.app)  # the sweep path
    assert len(seen) == 2
