"""Shared fixtures: fresh app per test on in-memory SQLite, httpx client."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    s = Settings()
    s.database_url = "sqlite+aiosqlite://"
    s.token_secret = "test-secret-not-for-production"
    s.processing_session_ttl = 300
    s.unlock_threshold_days = 30
    s.auth_rate_limit = 10
    s.entries_rate_limit = 1000  # tests seed many entries quickly
    return s


@pytest_asyncio.fixture
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
