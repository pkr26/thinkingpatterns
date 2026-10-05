"""Startup and shutdown custody, with live SQLite and controlled outages."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


@pytest.mark.parametrize("failure", ["none", "init", "hydrate", "prune", "purge"])
@pytest.mark.asyncio
async def test_lifespan_owns_every_worker_and_releases_resources_on_boot_or_shutdown(
    failure, tmp_path, monkeypatch, caplog
):
    import httpx
    from app import main
    from app.config import Settings
    from app.security.enclave import KeyNotFound

    settings = Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        trust_proxy_headers=True,
        trusted_proxy_ips=["127.0.0.0/8", "10.0.0.0/8"],
    )
    settings.ops_rate_limit = 1000
    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path / "locks"))
    app = main.create_app(settings)
    app.state.guard_healthy = False
    entered, finished = {}, {}
    for name in [
        "_access_log_retention_sweep",
        "_processing_key_sweep",
        "_audio_retention_sweep",
        "_account_deletion_sweep",
        "_guard_monitor",
    ]:
        entered[name], finished[name] = asyncio.Event(), asyncio.Event()
        original = getattr(main, name)

        async def watched(application, original=original, name=name):
            entered[name].set()
            try:
                await original(application)
            finally:
                finished[name].set()

        monkeypatch.setattr(main, name, watched)

    class GuardConnection:
        closed = False

        async def exec_driver_sql(self, statement):
            class Scalar:
                @staticmethod
                def scalar():
                    return True

            return Scalar()

        async def commit(self):
            pass

        async def close(self):
            self.closed = True

    guard = GuardConnection()

    async def acquire(engine):
        return guard

    monkeypatch.setattr(main, "_acquire_cross_host_guard", acquire)
    if failure == "init":

        async def fail_init(engine):
            raise RuntimeError("initial schema unavailable")

        monkeypatch.setattr(main, "init_models", fail_init)
    if failure == "hydrate":

        async def fail_hydrate(session):
            raise RuntimeError("storage unavailable")

        monkeypatch.setattr(app.state.token_revocations, "hydrate", fail_hydrate)
    if failure == "prune":

        async def fail_prune(application, **kwargs):
            raise RuntimeError("housekeeping unavailable")

        monkeypatch.setattr(main, "_prune_access_log_once_with_evidence", fail_prune)
    if failure == "purge":

        async def fail_purge(application):
            raise RuntimeError("erasure storage unavailable")

        monkeypatch.setattr(main, "_purge_deleted_account_once", fail_purge)
    token = app.state.key_store.create(b"k" * 32, 60, owner="owner")
    binding = {
        "user_id": "owner",
        "action": "delete",
        "token_jti": "token",
        "token_epoch": 1,
    }
    proof, _ = await app.state.step_up_store.issue(**binding)
    assert await app.state.step_up_store.consume(proof, **binding)
    if failure == "init":
        with pytest.raises(RuntimeError, match=r"^initial schema unavailable$"):
            async with app.router.lifespan_context(app):
                pytest.fail("schema failure must abort development boot")
    else:
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(
                asyncio.gather(*(event.wait() for event in entered.values())), 3
            )
            assert app.state.guard_connection is guard and app.state.guard_healthy
            for name in [
                "access_log_sweep_task",
                "processing_key_sweep_task",
                "audio_sweep_task",
                "account_deletion_sweep_task",
            ]:
                task = getattr(app.state, name)
                assert isinstance(task, asyncio.Task) and not task.done()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                assert (await client.get("/healthz")).status_code == 200
            if failure == "hydrate":
                assert (
                    "token-revocation hydration skipped because storage is unavailable"
                    in caplog.messages
                )
            if failure == "prune":
                assert (
                    "initial housekeeping pass failed; retrying shortly"
                    in caplog.messages
                )
            if failure == "purge":
                assert app.state.account_deletion_failure_streak == 1
                assert app.state.account_deletion_retry_delay_seconds == 2
        assert all(event.is_set() for event in finished.values())
    assert guard.closed
    with pytest.raises(KeyNotFound):
        app.state.key_store.get(token, owner="owner")
    assert (
        "MINDPATTERN_TRUST_PROXY_HEADERS is on: rate-limit identity comes only from X-Forwarded-For received over a direct peer in MINDPATTERN_TRUSTED_PROXY_IPS=127.0.0.0/8,10.0.0.0/8. Keep the API unreachable except through that proxy, which must append its observation; do not enable uvicorn --proxy-headers because this middleware needs the raw peer to verify the boundary."
        in caplog.messages
    )


@pytest.mark.asyncio
async def test_factory_tracks_active_http_work_and_cancels_it_when_ownership_is_lost():
    import httpx
    from app import main
    from app.config import Settings
    from app.security.enclave import KeyNotFound

    app = main.create_app(
        Settings(environment="development", database_url="sqlite+aiosqlite://")
    )
    entered, release = asyncio.Event(), asyncio.Event()

    class Connection:
        owned = True

        async def exec_driver_sql(self, statement):
            connection = self

            class Result:
                def scalar(self):
                    return connection.owned

            return Result()

        async def commit(self):
            pass

    connection = Connection()
    app.state.guard_connection = connection
    key = app.state.key_store.create(b"k" * 32, 60, owner="owner")

    @app.get("/ownership-slow")
    async def slow():
        entered.set()
        await release.wait()
        return {"status": "finished"}

    pending = None
    try:
        assert await main._guard_is_healthy(app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            pending = asyncio.create_task(client.get("/ownership-slow"))
            await asyncio.wait_for(entered.wait(), 1)
            assert pending in app.state.request_tasks
            connection.owned = False
            assert await main._guard_is_healthy(app) is False
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert not app.state.request_tasks
            assert (await client.get("/ownership-slow")).status_code == 503
        with pytest.raises(KeyNotFound):
            app.state.key_store.get(key, owner="owner")
    finally:
        release.set()
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
        await app.state.engine.dispose()
