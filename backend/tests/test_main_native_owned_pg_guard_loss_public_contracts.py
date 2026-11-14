"""Public readiness after disconnecting only this test's native PG guard."""

import asyncio
import fcntl
import os
import uuid
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app import main
from app.config import Settings


@pytest.fixture
def owned_postgres_profile():
    url = os.environ.get("MINDPATTERN_MUTATION_POSTGRES")
    lock_name = os.environ.get("MINDPATTERN_MUTATION_POSTGRES_SCHEMA_LOCK")
    if not url or not lock_name:
        pytest.skip("requires the dedicated owned PostgreSQL and shared profile flock")
    parsed = make_url(url)
    assert (parsed.drivername, parsed.username, parsed.host, parsed.port, parsed.database) == (
        "postgresql+asyncpg",
        "postgres",
        "127.0.0.1",
        55488,
        "mindpattern_mutation_test",
    )
    assert not parsed.query
    lock_path = Path(lock_name)
    assert lock_path.is_absolute() and lock_path.is_file()
    with lock_path.open("a") as resource:
        fcntl.flock(resource, fcntl.LOCK_EX)
        yield url


@pytest.mark.asyncio
async def test_real_owned_guard_disconnect_closes_public_readiness(
    owned_postgres_profile, tmp_path, monkeypatch
):
    url = owned_postgres_profile
    identity = "native_guard_" + uuid.uuid4().hex
    schema = identity
    lock_dir = tmp_path / "owned-native-flocks"
    lock_dir.mkdir(mode=0o700)
    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(lock_dir))
    journal = tmp_path / "owned-audit.journal"
    journal.touch(mode=0o600)
    settings = Settings(
        environment="development",
        database_url=url,
        token_secret=identity,
        audit_journal_path=str(journal),
    )
    admin = create_async_engine(url)
    application = None
    created = False
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        created = True
        # Keep the application's actual engine factory and native provider.
        # Its native connect hook only confines schema/name before first use.
        application = main.create_app(settings)

        async def configure_owned_connection(raw_connection):
            await raw_connection.execute(f'SET search_path TO "{schema}"')
            await raw_connection.execute(f"SET application_name TO '{identity}'")

        @event.listens_for(application.state.engine.sync_engine, "connect")
        def owned_connection_namespace(dbapi_connection, _record):
            dbapi_connection.run_async(configure_owned_connection)

        async with (
            application.router.lifespan_context(application),
            AsyncClient(
                transport=ASGITransport(app=application, raise_app_exceptions=False),
                base_url="http://owned-native-guard",
            ) as client,
        ):
            healthy = await client.get("/readyz")
            assert healthy.status_code == 200, healthy.text
            assert healthy.json()["status"] == "ready"

            async with admin.begin() as connection:
                # The unique application_name is set only on this app's
                # connections. The matching granted advisory lock proves
                # which native backend is exclusively this test's guard.
                rows = (
                    await connection.execute(
                        text(
                            "SELECT l.pid, a.application_name FROM pg_locks l "
                            "JOIN pg_stat_activity a ON a.pid = l.pid "
                            "WHERE l.locktype = 'advisory' AND l.granted "
                            "AND l.classid = 0 AND l.objid = :lock_id AND l.objsubid = 1 "
                            "AND a.datname = current_database() AND a.application_name = :identity"
                        ),
                        {"lock_id": main.CROSS_HOST_ADVISORY_LOCK_ID, "identity": identity},
                    )
                ).all()
                assert len(rows) == 1
                owned_pid, observed_identity = rows[0]
                assert observed_identity == identity and owned_pid > 0
                terminated = await connection.scalar(
                    text("SELECT pg_terminate_backend(:owned_pid)"), {"owned_pid": owned_pid}
                )
                assert terminated is True

            # Allow only the real server disconnect to propagate. Observe
            # the public refusal, without reading a private guard handle.
            refused = None
            for _ in range(10):
                refused = await client.get("/readyz")
                if refused.status_code == 503:
                    break
                await asyncio.sleep(0.05)
            assert refused.status_code == 503, refused.text
            assert refused.json() == {
                "detail": "instance ownership unavailable",
                "code": "service_unavailable",
            }
            live = await client.get("/healthz")
            assert live.status_code == 200 and live.json()["status"] == "ok"
    finally:
        if application is not None:
            await application.state.engine.dispose()
        if created:
            async with admin.begin() as connection:
                await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()
