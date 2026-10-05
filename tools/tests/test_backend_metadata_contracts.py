"""Actual public deployment declarations and the shared operations quota."""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path

import pytest


def _app(monkeypatch, **settings):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_DB_URL", raising=False)
    main = importlib.import_module("app.main")
    config = importlib.import_module("app.config")
    return main.create_app(
        config.Settings(
            environment="development", database_url="sqlite+aiosqlite://", **settings
        )
    )


def test_metadata_documents_the_canonical_public_group(monkeypatch):
    app = _app(monkeypatch)
    try:
        assert app.openapi()["paths"]["/api/v1/meta"]["get"]["tags"] == ["meta"]
    finally:
        asyncio.run(app.state.engine.dispose())


@pytest.mark.parametrize("configured", [False, True])
def test_metadata_serves_the_supported_version_and_meaningful_llm_declarations(
    monkeypatch, configured
):
    async def exercise():
        from httpx import ASGITransport, AsyncClient

        app = _app(
            monkeypatch,
            llm_url="https://provider.example/v1" if configured else "",
            llm_provider_name="Example Provider",
            llm_data_retention="30 days",
        )
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                response = await client.get("/api/v1/meta")
            assert response.status_code == 200
            body = response.json()
            assert body["api_version"] == "v1" and body["version"] == "1.0.0"
            assert body["llm_available"] is configured
            assert body["llm_provider_name"] == (
                "Example Provider" if configured else None
            )
            assert body["llm_data_retention"] == ("30 days" if configured else None)
        finally:
            await app.state.engine.dispose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "enabled,url,available",
    [
        (False, "https://voice.example", False),
        (True, "", False),
        (True, "https://voice.example", True),
    ],
)
def test_voice_declarations_require_both_a_live_flag_and_provider(
    monkeypatch, enabled, url, available
):
    async def exercise():
        from httpx import ASGITransport, AsyncClient

        app = _app(
            monkeypatch,
            audio_enabled=enabled,
            stt_url=url,
            stt_provider_name="Voice Provider",
            stt_data_retention="one day",
        )
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                response = await client.get("/api/v1/meta")
            assert response.status_code == 200
            body = response.json()
            assert body["audio_available"] is available
            assert body["stt_provider_name"] == (
                "Voice Provider" if available else None
            )
            assert body["stt_data_retention"] == ("one day" if available else None)
            assert bool(body["stt_policy_fingerprint"]) is available
        finally:
            await app.state.engine.dispose()

    asyncio.run(exercise())


def test_public_metadata_cannot_split_the_shared_health_quota(monkeypatch):
    async def exercise():
        from httpx import ASGITransport, AsyncClient

        app = _app(monkeypatch, ops_rate_limit=2, ops_rate_window=60)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                assert (await client.get("/healthz")).status_code == 200
                assert (await client.get("/api/v1/meta")).status_code == 200
                limited = await client.get("/api/v1/meta")
            assert (
                limited.status_code == 429 and int(limited.headers["retry-after"]) >= 1
            )
        finally:
            await app.state.engine.dispose()

    asyncio.run(exercise())
