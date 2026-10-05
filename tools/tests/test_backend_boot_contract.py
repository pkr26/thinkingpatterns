"""The ASGI entry point must load before the backend test fixtures can run.

Keep this oracle outside backend/tests so its conftest cannot turn a broken
application import into a collection error instead of a failing test call.
"""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path


def test_backend_asgi_entry_point_loads(monkeypatch):
    backend = Path(__file__).resolve().parents[2] / "backend"
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_DB_URL", raising=False)
    module = importlib.import_module("app.main")
    assert callable(module.app), "the server must expose a callable ASGI entry point"
    assert callable(module.create_app), "the server must expose its application factory"


def test_backend_journal_cleanup_is_idempotent(monkeypatch):
    backend = Path(__file__).resolve().parents[2] / "backend"
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_DB_URL", raising=False)
    audit = importlib.import_module("app.api._audit")
    # Shutdown, a startup failure, and explicit reconfiguration may all close
    # the process-scoped evidence index. Releasing it twice must stay safe.
    audit.close_reusable_journal_evidence_index()
    audit.close_reusable_journal_evidence_index()


def test_backend_asgi_application_starts_serves_and_shuts_down(monkeypatch):
    backend = Path(__file__).resolve().parents[2] / "backend"
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_DB_URL", raising=False)

    from app import main
    from app.config import Settings
    from httpx import ASGITransport, AsyncClient

    settings = Settings(environment="development", database_url="sqlite+aiosqlite://")
    application = main.create_app(settings)
    initial_purge = asyncio.Event()
    purge_once = main._purge_deleted_account_once

    async def observe_first_purge(app):
        try:
            return await purge_once(app)
        finally:
            if app is application:
                initial_purge.set()

    monkeypatch.setattr(main, "_purge_deleted_account_once", observe_first_purge)

    async def serve_once():
        async with application.router.lifespan_context(application):
            await asyncio.wait_for(initial_purge.wait(), timeout=10)
            async with AsyncClient(
                transport=ASGITransport(app=application), base_url="http://testserver"
            ) as client:
                response = await client.get("/healthz")
                assert response.status_code == 200

    asyncio.run(asyncio.wait_for(serve_once(), timeout=15))
