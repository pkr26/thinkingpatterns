"""Audit helpers remain usable before the ASGI application is constructed."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path


def test_unconfigured_audit_is_healthy_and_has_an_empty_legacy_key_ring(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")

    from app.api import _audit

    assert _audit.audit_journal_health() == (True, None)
    assert _audit._effective_mac_keys(None, None, None) == ({}, 1)


def test_standalone_legacy_retention_has_no_implicit_journal_target(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")

    from app.api import _audit
    from app.db import build_engine, build_sessionmaker
    from app.models import Base

    async def prune_standalone_chain():
        engine = build_engine("sqlite+aiosqlite://")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            sessions = build_sessionmaker(engine)
            async with sessions() as session:
                key = b"s" * 32
                await _audit.append_access_log(
                    session,
                    actor_id="a" * 32,
                    actor_role="patient",
                    user_id="b" * 32,
                    action="read_entries",
                    at=datetime(2026, 10, 1, tzinfo=timezone.utc),
                    mac_key=key,
                    allow_new_chain=True,
                )
                await session.commit()
                assert (
                    await _audit.prune_access_logs(
                        session,
                        cutoff=datetime(2026, 10, 4, tzinfo=timezone.utc),
                        mac_key=key,
                    )
                    == 1
                )
        finally:
            await engine.dispose()

    asyncio.run(asyncio.wait_for(prune_standalone_chain(), timeout=10))


def test_standalone_journal_health_retains_named_failures_and_recovers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")

    from app.api import _audit

    try:
        _audit._set_journal_health(False, "io_failure")
        assert _audit.audit_journal_health() == (False, "io_failure")
        _audit._set_journal_health(True)
        assert _audit.audit_journal_health() == (True, None)
    finally:
        _audit._set_journal_health(True)
