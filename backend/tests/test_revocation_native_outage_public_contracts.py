"""Owned native partial-SQLite outage exposes unnecessary revocation queries."""

import time

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.cache import TokenRevocationStore
from app.db import build_engine, build_sessionmaker, init_models
from tests.helpers import ClientEmulator


@pytest.mark.asyncio
async def test_hydrated_default_revocation_cache_keeps_live_auth_during_owned_partial_outage(
    client, app
):
    settings = app.state.settings
    assert app.state.engine.dialect.name == "sqlite"
    assert make_url(settings.database_url).database in (None, "", ":memory:")
    owner = ClientEmulator("native-revocation-outage", "native-revocation-password")
    await owner.register(client)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    ) as observer:
        healthy = await observer.get("/api/auth/key-envelope", headers=owner.headers)
        assert healthy.status_code == 200, healthy.text
        async with app.state.engine.begin() as connection:
            # Only this test's already-hydrated fresh in-memory table is
            # removed. Users, credentials, and the actual cache stay live.
            await connection.execute(text("DROP TABLE token_revocation"))
        after = await observer.get("/api/auth/key-envelope", headers=owner.headers)
        assert after.status_code == 200, after.text
        assert after.json() == healthy.json()


@pytest.mark.asyncio
async def test_exact_configured_cache_capacity_keeps_authoritative_miss_without_native_table():
    # An explicit supported component capacity1, not the server default.
    engine = build_engine("sqlite+aiosqlite://")
    try:
        await init_models(engine)
        sessions = build_sessionmaker(engine)
        store = TokenRevocationStore(max_entries=1)
        async with sessions() as session:
            assert await store.hydrate(session) == 0
            await store.revoke_durable(session, "cached-revoked-token", time.time() + 300)
            await session.commit()
            assert await store.is_revoked_checked(session, "live-token") is False
            await session.commit()
        async with engine.begin() as connection:
            await connection.execute(text("DROP TABLE token_revocation"))
        async with sessions() as session:
            # Exactly filling the cache did not evict an entry, so the
            # documented complete-mirror fast path remains authoritative.
            assert await store.is_revoked_checked(session, "live-token") is False
    finally:
        await engine.dispose()
