"""App ownership against PostgreSQL's actual session-scoped advisory locks."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


def postgres_url():
    value = os.environ.get("MINDPATTERN_MUTATION_POSTGRES")
    if not value:
        pytest.skip(
            "set MINDPATTERN_MUTATION_POSTGRES to the disposable PostgreSQL database"
        )
    return value


@pytest.mark.asyncio
async def test_cross_host_advisory_guard_refuses_a_second_host_and_survives_read_commits():
    from app import main
    from app.db import build_engine

    engine = build_engine(postgres_url())
    connection = None
    try:
        assert await main._acquire_cross_host_guard(SimpleNamespace()) is None
        connection = await main._acquire_cross_host_guard(engine)
        assert connection is not None and not connection.in_transaction()
        # Check the documented application lock independently of the helper.
        owned = await connection.exec_driver_sql(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=0 AND objid=727273 AND objsubid=1 AND granted)"
        )
        assert owned.scalar() is True
        await connection.commit()
        with pytest.raises(RuntimeError) as rejected:
            await main._acquire_cross_host_guard(engine)
        assert (
            str(rejected.value)
            == "another host is already serving this database: the rate limiter, per-user locks, and processing-session keystore are all in-process (see singleprocess.py). One host per database; move shared counters/locks to Redis &c. before scaling out."
        )
        await main._release_cross_host_guard(connection)
        assert connection.closed
        connection = await main._acquire_cross_host_guard(engine)
        assert connection is not None
    finally:
        await main._release_cross_host_guard(connection)
        await main._release_cross_host_guard(None)
        await engine.dispose()


@pytest.mark.asyncio
async def test_ownership_loss_zeroizes_keys_cancels_other_requests_and_never_reacquires(
    caplog,
):
    from app import main
    from app.db import build_engine
    from app.security.enclave import InMemoryKeyStore

    engine = build_engine(postgres_url())
    connection, sleeper = None, None
    keys = InMemoryKeyStore()
    key = bytearray(b"k" * 32)
    try:
        connection = await main._acquire_cross_host_guard(engine)
        assert connection is not None
        token = keys.create(key, 60, owner="owner")
        stored_key = keys._keys[token][0]
        sleeper = asyncio.create_task(asyncio.sleep(60))
        current = asyncio.current_task()
        app = SimpleNamespace(
            state=SimpleNamespace(
                guard_healthy=True,
                guard_connection=connection,
                guard_check_lock=asyncio.Lock(),
                key_store=keys,
                request_tasks={sleeper, current},
            )
        )
        assert await main._guard_is_healthy(app) is True
        assert not connection.in_transaction()
        await connection.exec_driver_sql("SELECT pg_advisory_unlock(727273)")
        await connection.commit()
        assert await main._guard_is_healthy(app) is False
        with pytest.raises(asyncio.CancelledError):
            await sleeper
        assert not current.cancelling()
        assert len(keys) == 0 and stored_key == bytearray(32)
        assert app.state.guard_healthy is False
        assert await main._guard_is_healthy(app) is False
        assert (
            caplog.messages[-1]
            == "cross-host ownership lost; admission is closed until restart"
        )
        assert caplog.records[-1].name == "mindpattern"
        app.state.guard_connection = None
        assert await main._guard_is_healthy(app) is False
        app.state.guard_healthy = True
        assert await main._guard_is_healthy(app) is True
    finally:
        if sleeper is not None and not sleeper.done():
            sleeper.cancel()
            await asyncio.gather(sleeper, return_exceptions=True)
        await main._release_cross_host_guard(connection)
        await engine.dispose()


@pytest.mark.asyncio
async def test_guard_monitor_cooperatively_probes_each_second_then_stops_on_loss(
    monkeypatch,
):
    from app import main

    delays, probes = [], []
    app = SimpleNamespace(state=SimpleNamespace(guard_healthy=True))

    async def sleep(seconds):
        delays.append(seconds)

    async def probe(application):
        probes.append(application)
        application.state.guard_healthy = False
        return False

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main, "_guard_is_healthy", probe)
    await main._guard_monitor(app)
    assert delays == [1] and probes == [app]


@pytest.mark.asyncio
async def test_probe_failure_and_release_failure_keep_refusal_and_close_custody(
    monkeypatch, caplog
):
    from app import main
    from app.db import build_engine
    from app.security.enclave import InMemoryKeyStore

    engine = build_engine(postgres_url())
    connection = await main._acquire_cross_host_guard(engine)
    try:
        assert connection is not None
        timeouts = []
        original_wait = asyncio.wait_for

        async def measured(awaitable, timeout):
            timeouts.append(timeout)
            return await original_wait(awaitable, timeout)

        monkeypatch.setattr(main.asyncio, "wait_for", measured)
        app = SimpleNamespace(
            state=SimpleNamespace(
                guard_healthy=True,
                guard_connection=connection,
                guard_check_lock=asyncio.Lock(),
                key_store=InMemoryKeyStore(),
                request_tasks=set(),
            )
        )
        assert await main._guard_is_healthy(app) is True and timeouts == [2]

        async def unavailable(*args, **kwargs):
            raise OSError("connection unavailable")

        monkeypatch.setattr(type(connection), "exec_driver_sql", unavailable)
        assert await main._guard_is_healthy(app) is False
        await main._release_cross_host_guard(connection)
        assert connection.closed
        assert (
            caplog.messages[-1]
            == "pg_advisory_unlock failed; disconnect releases the lock"
        )
    finally:
        await connection.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_a_request_waiting_for_an_ownership_probe_observes_terminal_loss():
    from app import main

    lock = asyncio.Lock()
    await lock.acquire()
    app = SimpleNamespace(
        state=SimpleNamespace(
            guard_healthy=True, guard_connection=object(), guard_check_lock=lock
        )
    )
    waiting = asyncio.create_task(main._guard_is_healthy(app))
    await asyncio.sleep(0)
    app.state.guard_healthy = False
    lock.release()
    assert await asyncio.wait_for(waiting, 1) is False
