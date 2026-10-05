"""Measure the verifier's actual database buffering under a large trail."""

from __future__ import annotations

from sqlalchemy.dialects.sqlite.aiosqlite import AsyncAdapt_aiosqlite_ss_cursor

from app.api import _audit

from .test_full_backend_audit_maintenance_contracts import KEY, OWNERS, chains


async def test_full_chain_verification_keeps_the_five_hundred_row_memory_budget(monkeypatch):
    # Include a second full buffer after SQLAlchemy's one-row initial prefetch.
    async with chains([1003]) as (session, _owners, _states):
        fetched = []
        fetchmany = AsyncAdapt_aiosqlite_ss_cursor.fetchmany

        def measured(cursor, size=None):
            values = fetchmany(cursor, size)
            fetched.append(len(values))
            return values

        monkeypatch.setattr(AsyncAdapt_aiosqlite_ss_cursor, "fetchmany", measured)
        assert await _audit.verify_access_log_chain(
            session, OWNERS[0], mac_keys={7: KEY}
        ) == _audit.ChainVerification(True, 1003, None, None, 0)
        assert sum(fetched) == 1003
        assert max(fetched) <= 500
