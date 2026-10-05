"""Native audit admission and page budgets over real persisted trails."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import timedelta

import pytest
from sqlalchemy import insert, select

from app.api import _audit
from app.db import build_engine, build_sessionmaker
from app.models import AccessLog, AuditChainState, AuditSweepCursor, Base

from . import test_full_backend_audit_maintenance_contracts as support


@asynccontextmanager
async def native_chains(counts, *, sealed=True):
    engine = build_engine("sqlite+aiosqlite://")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with build_sessionmaker(engine)() as session:
            states = []
            for owner_index, count in enumerate(counts):
                owner = f"{owner_index:032x}"
                previous, first_hash = None, None
                batch = []
                for seq in range(1, count + 1):
                    at = support.AT + timedelta(seconds=seq - 1)
                    entry_hash = _audit.compute_entry_hash(
                        previous,
                        "actor",
                        owner,
                        "read_entries",
                        at,
                        actor_role="patient",
                        record_version=2,
                    )
                    first_hash = first_hash or entry_hash
                    batch.append(
                        dict(
                            id=f"{owner_index:08x}{seq:024x}",
                            actor_id="actor",
                            actor_role="patient",
                            user_id=owner,
                            action="read_entries",
                            at=at,
                            chain_seq=seq,
                            record_version=2,
                            mac_key_version=7,
                            prev_hash=previous,
                            entry_hash=entry_hash,
                            entry_mac=_audit.compute_entry_mac(support.KEY, owner, seq, entry_hash),
                        )
                    )
                    previous = entry_hash
                    if len(batch) == 1000:
                        await session.execute(insert(AccessLog), batch)
                        batch.clear()
                if batch:
                    await session.execute(insert(AccessLog), batch)
                state = AuditChainState(
                    user_id=owner,
                    head_seq=count,
                    head_hash=previous,
                    head_at=at,
                    first_retained_seq=1,
                    first_retained_hash=first_hash,
                    state_version=1,
                    mac_key_version=7,
                    updated_at=at,
                )
                state.state_mac = (
                    _audit.compute_chain_state_mac(support.KEY, state) if sealed else None
                )
                states.append(state)
                session.add(state)
            await session.commit()
            yield session, states
    finally:
        await engine.dispose()


async def test_default_incremental_page_advances_by_exactly_five_hundred_rows():
    async with support.chains([501]) as (session, _, _):
        cursor = AuditSweepCursor(id=1, updated_at=support.AT)
        session.add(cursor)
        verdict = await _audit.verify_access_log_chain_incremental(
            session, cursor, support.OWNERS[0], **support.OPTIONS
        )
        assert verdict.ok and not verdict.complete and verdict.rows_checked == 500
        assert cursor.verification_next_seq == 501


async def test_incremental_budget_refuses_more_than_five_thousand_rows():
    async with support.chains([1]) as (session, _, _):
        cursor = AuditSweepCursor(id=1, updated_at=support.AT)
        with pytest.raises(ValueError, match=r"^audit verification row budget is invalid$"):
            await _audit.verify_access_log_chain_incremental(
                session, cursor, support.OWNERS[0], row_budget=5001, **support.OPTIONS
            )


async def test_default_prune_page_removes_exactly_five_hundred_rows():
    async with support.chains([502]) as (session, _, _):
        deleted = await _audit.prune_access_logs(
            session, cutoff=support.AT + timedelta(days=1000), **support.OPTIONS
        )
        assert deleted == 500
        assert len(list(await session.scalars(select(AccessLog)))) == 2


@pytest.mark.parametrize("mode", ["owners", "aggregate"])
async def test_native_prune_owner_and_aggregate_row_budgets(mode):
    counts = [1] * 503 if mode == "owners" else [500] * 11
    async with native_chains(counts) as (session, _):
        progress = []
        deleted = await _audit.prune_access_logs(
            session,
            cutoff=support.AT + timedelta(days=1000),
            progress_observer=lambda **values: progress.append(values),
            **support.OPTIONS,
        )
        expected = 500 if mode == "owners" else 5000
        assert deleted == expected
        assert len(list(await session.scalars(select(AccessLog)))) == sum(counts) - expected
        assert progress[-1]["backlog"]


def test_diagnostic_journal_reader_preserves_its_reserved_corruption_marker(tmp_path):
    path = tmp_path / "journal"
    path.write_text("malformed evidence\n")
    assert list(_audit.read_journal_evidence(str(path))) == ["__journal_corrupt__"]
    _audit._set_journal_health(True)


async def test_native_legacy_upgrade_refuses_a_trail_over_one_hundred_thousand_rows():
    from app.deps import ApiError

    async with native_chains([100001], sealed=False) as (session, states):
        with pytest.raises(ApiError) as rejected:
            await _audit.seal_legacy_audit_states(session, **support.OPTIONS)
        assert (rejected.value.status_code, rejected.value.detail, rejected.value.code) == (
            500,
            "legacy audit chain exceeds the bounded online sealing budget",
            "audit_integrity_error",
        )
        assert states[0].state_mac is None
