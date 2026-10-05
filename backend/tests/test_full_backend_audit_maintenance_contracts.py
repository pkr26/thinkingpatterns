"""Retention convergence and trusted legacy bridging over real SQLite rows."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select
from sqlalchemy.sql.dml import Delete

from app.api import _audit
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError
from app.locks import UserLocks
from app.models import AccessLog, AuditChainState, Base

KEY = b"k" * 32
OLD_KEY = b"o" * 32
AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
OWNERS = [character * 32 for character in "abcd"]
OPTIONS = {"mac_keys": {7: KEY}, "current_mac_key_version": 7}


@pytest.fixture(autouse=True)
def independent_owner_lock_registry(monkeypatch):
    # Contended asyncio locks bind to one loop; each pytest case owns a loop.
    monkeypatch.setattr(_audit, "_audit_chain_locks", UserLocks())


@asynccontextmanager
async def chains(counts, *, sealed=True):
    _audit.configure_audit_mac_key(None)
    engine = build_engine("sqlite+aiosqlite://")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with build_sessionmaker(engine)() as session:
            owners, states = {}, {}
            for user_id, count in zip(OWNERS, counts):
                rows, previous = [], None
                for seq in range(1, count + 1):
                    row = AccessLog(
                        id=f"{user_id[0]}{seq:031x}",
                        actor_id="actor",
                        actor_role="patient",
                        user_id=user_id,
                        action="read_entries",
                        at=AT + timedelta(days=seq - 1),
                        chain_seq=seq,
                        record_version=2,
                        mac_key_version=7,
                        prev_hash=previous,
                    )
                    row.entry_hash = _audit.compute_entry_hash(
                        previous,
                        row.actor_id,
                        user_id,
                        row.action,
                        row.at,
                        actor_role=row.actor_role,
                        record_version=2,
                    )
                    row.entry_mac = _audit.compute_entry_mac(KEY, user_id, seq, row.entry_hash)
                    session.add(row)
                    rows.append(row)
                    previous = row.entry_hash
                state = AuditChainState(
                    user_id=user_id,
                    head_seq=count,
                    head_hash=previous,
                    head_at=rows[-1].at,
                    first_retained_seq=1,
                    first_retained_hash=rows[0].entry_hash,
                    state_version=1,
                    mac_key_version=7,
                    updated_at=rows[-1].at,
                )
                state.state_mac = _audit.compute_chain_state_mac(KEY, state) if sealed else None
                session.add(state)
                owners[user_id], states[user_id] = rows, state
            await session.commit()
            yield session, owners, states
    finally:
        await engine.dispose()


async def remaining(session):
    return [
        (row.user_id, row.chain_seq)
        for row in (
            await session.scalars(
                select(AccessLog).order_by(AccessLog.user_id, AccessLog.chain_seq)
            )
        ).all()
    ]


def error_is(exc, detail):
    assert (exc.status_code, exc.detail, exc.code) == (500, detail, "audit_integrity_error")


def limits(monkeypatch, *, owners=3, rows=2, total=3):
    monkeypatch.setattr(_audit, "AUDIT_MAINTENANCE_OWNER_BATCH", owners)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_ROW_BATCH", rows)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_TOTAL_ROW_BATCH", total)


async def test_retention_spends_aggregate_budget_across_owners_and_reports_exact_backlog(
    monkeypatch,
):
    limits(monkeypatch)
    async with chains([3, 2, 1]) as (session, owners, states):
        progress = []
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=10),
                progress_observer=lambda **values: progress.append(values),
                **OPTIONS,
            )
            == 3
        )
        assert await remaining(session) == [(OWNERS[0], 3), (OWNERS[1], 2), (OWNERS[2], 1)]
        assert progress == [
            {
                "backlog": True,
                "next_owner": OWNERS[1],
                "owners_processed": 3,
                "rows_deleted": 3,
                "pending_rows_probe": 3,
                "oldest_pending_at": AT,
            }
        ]
        assert states[OWNERS[0]].first_retained_seq == 3
        assert states[OWNERS[1]].first_retained_seq == 2
        for owner in OWNERS[:2]:
            assert states[owner].state_mac == _audit.compute_chain_state_mac(KEY, states[owner])
        await session.commit()
        progress.clear()
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=10),
                owner_after=OWNERS[1],
                progress_observer=lambda **values: progress.append(values),
                **OPTIONS,
            )
            == 1
        )
        assert progress == [
            {
                "backlog": True,
                "next_owner": None,
                "owners_processed": 1,
                "rows_deleted": 1,
                "pending_rows_probe": 2,
                "oldest_pending_at": AT + timedelta(days=1),
            }
        ]


async def test_owner_cursor_skips_partly_pruned_owner_and_wraps_after_last_page(monkeypatch):
    limits(monkeypatch, owners=1, rows=1, total=10)
    async with chains([3, 1, 1]) as (session, owners, states):
        progress = []
        for owner, pending in zip(OWNERS[:3], (4, 3, 2)):
            cursor = None if owner == OWNERS[0] else OWNERS[OWNERS.index(owner) - 1]
            assert (
                await _audit.prune_access_logs(
                    session,
                    cutoff=AT + timedelta(days=10),
                    owner_after=cursor,
                    progress_observer=lambda **values: progress.append(values),
                    **OPTIONS,
                )
                == 1
            )
            assert progress[-1]["pending_rows_probe"] == pending
            assert progress[-1]["next_owner"] == (owner if owner != OWNERS[2] else None)
        assert await remaining(session) == [(OWNERS[0], 2), (OWNERS[0], 3)]
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=10),
                owner_after=OWNERS[2],
                progress_observer=lambda **values: progress.append(values),
                **OPTIONS,
            )
            == 0
        )
        assert progress[-1] == {
            "backlog": True,
            "next_owner": None,
            "owners_processed": 0,
            "rows_deleted": 0,
            "pending_rows_probe": 2,
            "oldest_pending_at": AT + timedelta(days=1),
        }


async def test_retention_keeps_exact_cutoff_and_reports_single_remaining_backlog(monkeypatch):
    limits(monkeypatch, rows=1, total=1)
    async with chains([3]) as (session, owners, states):
        progress = []
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=2),
                progress_observer=lambda **values: progress.append(values),
                **OPTIONS,
            )
            == 1
        )
        assert progress[-1]["backlog"] is True and progress[-1]["pending_rows_probe"] == 1
        assert progress[-1]["oldest_pending_at"] == AT + timedelta(days=1)
        assert (
            await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=2), **OPTIONS) == 1
        )
        assert await remaining(session) == [(OWNERS[0], 3)]
        assert states[OWNERS[0]].first_retained_seq == 3


@pytest.mark.parametrize("owner_batch", [1, 3])
async def test_nonexpired_prefix_does_not_stop_other_owners(owner_batch, monkeypatch):
    limits(monkeypatch, owners=owner_batch)
    async with chains([2, 1]) as (session, owners, states):
        row = owners[OWNERS[0]][0]
        row.at = AT + timedelta(days=20)
        row.entry_hash = _audit.compute_entry_hash(
            None,
            row.actor_id,
            row.user_id,
            row.action,
            row.at,
            actor_role=row.actor_role,
            record_version=2,
        )
        row.entry_mac = _audit.compute_entry_mac(KEY, row.user_id, row.chain_seq, row.entry_hash)
        second = owners[OWNERS[0]][1]
        second.prev_hash = row.entry_hash
        second.entry_hash = _audit.compute_entry_hash(
            second.prev_hash,
            second.actor_id,
            second.user_id,
            second.action,
            second.at,
            actor_role=second.actor_role,
            record_version=2,
        )
        second.entry_mac = _audit.compute_entry_mac(KEY, second.user_id, 2, second.entry_hash)
        state = states[OWNERS[0]]
        state.first_retained_hash, state.head_hash = row.entry_hash, second.entry_hash
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        progress = []
        assert await _audit.prune_access_logs(
            session,
            cutoff=AT + timedelta(days=10),
            progress_observer=lambda **values: progress.append(values),
            **OPTIONS,
        ) == (0 if owner_batch == 1 else 1)
        expected_rows = [(OWNERS[0], 1), (OWNERS[0], 2)]
        if owner_batch == 1:
            expected_rows.append((OWNERS[1], 1))
        assert await remaining(session) == expected_rows
        assert progress[-1] == {
            "backlog": True,
            "next_owner": OWNERS[0] if owner_batch == 1 else None,
            "owners_processed": 1 if owner_batch == 1 else 2,
            "rows_deleted": 0 if owner_batch == 1 else 1,
            "pending_rows_probe": 2 if owner_batch == 1 else 1,
            "oldest_pending_at": AT if owner_batch == 1 else AT + timedelta(days=1),
        }


@pytest.mark.parametrize(
    "fault", ["ahead", "same_hash_wrong", "same_mac_wrong", "behind", "valid", "tail_unsealed"]
)
async def test_retention_uses_authenticated_journal_head_boundaries(fault):
    async with chains([5]) as (session, owners, states):
        tail = owners[OWNERS[0]][-1]
        seq, digest, mac = tail.chain_seq, tail.entry_hash, tail.entry_mac
        if fault == "ahead":
            seq += 1
        elif fault == "same_hash_wrong":
            digest = "e" * 64
        elif fault == "same_mac_wrong":
            mac = "e" * 64
        elif fault == "behind":
            seq, digest, mac = 1, "e" * 64, "e" * 64
        elif fault == "tail_unsealed":
            tail.entry_mac = None
        await session.flush()
        evidence = {OWNERS[0]: _audit.JournalEvidence(seq, digest, mac, tail.at.isoformat())}
        if fault in ("ahead", "same_hash_wrong", "same_mac_wrong"):
            with pytest.raises(ApiError) as caught:
                await _audit.prune_access_logs(
                    session, cutoff=AT + timedelta(days=1), journal_evidence=evidence, **OPTIONS
                )
            error_is(
                caught.value,
                "audit chain failed verification before retention prune: journal differs from durable chain head",
            )
            assert len(await remaining(session)) == 5
        else:
            assert (
                await _audit.prune_access_logs(
                    session, cutoff=AT + timedelta(days=1), journal_evidence=evidence, **OPTIONS
                )
                == 1
            )


async def test_retention_reads_its_configured_journal_and_refuses_corrupt_evidence(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("not a valid journal row\n")
    async with chains([1]) as (session, owners, states):
        _audit.configure_audit_mac_key(KEY, journal_path=str(journal))
        with pytest.raises(ApiError) as caught:
            await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
        error_is(caught.value, "audit journal evidence is unavailable")
        assert await remaining(session) == [(OWNERS[0], 1)]


async def test_retention_detects_delete_result_drift_and_rolls_back_anchors(monkeypatch):
    async with chains([3]) as (session, owners, states):
        original = session.scalars
        injected = []

        async def racing_delete(statement, *args, **kwargs):
            if isinstance(statement, Delete) and not injected:
                injected.append(True)
                await session.execute(
                    delete(AccessLog).where(AccessLog.id == owners[OWNERS[0]][0].id)
                )
            return await original(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalars", racing_delete)
        with pytest.raises(ApiError) as caught:
            await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
        error_is(caught.value, "audit retention prefix changed during deletion")
        assert injected == [True]
        await session.rollback()
        assert len(await remaining(session)) == 3
        state = await session.get(AuditChainState, OWNERS[0])
        assert state.first_retained_seq == 1
        assert state.state_mac == _audit.compute_chain_state_mac(KEY, state)


async def test_legacy_bridge_defers_a_later_owner_when_remaining_budget_is_too_small(monkeypatch):
    async with chains([2, 2, 1], sealed=False) as (session, owners, states):
        monkeypatch.setattr(_audit, "AUDIT_LEGACY_SEAL_ROW_BUDGET", 3)
        assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == 1
        assert states[OWNERS[0]].state_mac == _audit.compute_chain_state_mac(KEY, states[OWNERS[0]])
        assert states[OWNERS[1]].state_mac is None
        assert states[OWNERS[2]].state_mac is None
        await session.commit()
        assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == 2
        assert states[OWNERS[1]].state_mac == _audit.compute_chain_state_mac(KEY, states[OWNERS[1]])
        assert states[OWNERS[2]].state_mac == _audit.compute_chain_state_mac(KEY, states[OWNERS[2]])


async def test_legacy_bridge_spends_exact_budget_without_touching_next_owner(monkeypatch):
    async with chains([2, 1], sealed=False) as (session, owners, states):
        monkeypatch.setattr(_audit, "AUDIT_LEGACY_SEAL_ROW_BUDGET", 2)
        calls, original = [], session.stream_scalars

        async def streaming(statement, *args, **kwargs):
            calls.append(statement)
            return await original(statement, *args, **kwargs)

        monkeypatch.setattr(session, "stream_scalars", streaming)
        assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == 1
        assert len(calls) == 1
        assert states[OWNERS[0]].state_mac is not None and states[OWNERS[1]].state_mac is None


@pytest.mark.parametrize(
    "fault",
    ["valid_genesis", "genesis_has_predecessor", "valid_retained", "retained_missing_predecessor"],
)
async def test_legacy_bridge_validates_first_predecessor_independently_of_hash(fault):
    async with chains([1], sealed=False) as (session, owners, states):
        row, state = owners[OWNERS[0]][0], states[OWNERS[0]]
        if "retained" in fault:
            row.chain_seq = 2
        row.prev_hash = "e" * 64 if fault in ("genesis_has_predecessor", "valid_retained") else None
        row.entry_hash = _audit.compute_entry_hash(
            row.prev_hash,
            row.actor_id,
            row.user_id,
            row.action,
            row.at,
            actor_role=row.actor_role,
            record_version=2,
        )
        row.entry_mac = _audit.compute_entry_mac(KEY, row.user_id, row.chain_seq, row.entry_hash)
        state.first_retained_seq = state.head_seq = row.chain_seq
        state.first_retained_hash = state.head_hash = row.entry_hash
        await session.flush()
        if fault.startswith("valid"):
            assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == 1
        else:
            with pytest.raises(ApiError) as caught:
                await _audit.seal_legacy_audit_states(session, **OPTIONS)
            error_is(caught.value, "legacy audit state failed authenticated verification")
            assert state.state_mac is None


@pytest.mark.parametrize("fault", ["predecessor", "hash", "mac"])
async def test_legacy_bridge_stops_before_sealing_rows_after_first_defect(fault):
    async with chains([3], sealed=False) as (session, owners, states):
        rows = owners[OWNERS[0]]
        if fault == "predecessor":
            rows[0].prev_hash = "e" * 64
        elif fault == "hash":
            rows[0].entry_hash = "e" * 64
        else:
            rows[0].entry_mac = "e" * 64
        for row in rows[1:]:
            row.entry_mac = None
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(session, **OPTIONS)
        error_is(caught.value, "legacy audit state failed authenticated verification")
        assert all(row.entry_mac is None for row in rows[1:])


async def test_legacy_bridge_accepts_legacy_zero_versions_with_key_one():
    async with chains([2], sealed=False) as (session, owners, states):
        previous = None
        for row in owners[OWNERS[0]]:
            row.record_version = row.mac_key_version = 0
            row.prev_hash = previous
            row.entry_hash = _audit.compute_entry_hash(
                previous,
                row.actor_id,
                row.user_id,
                row.action,
                row.at,
                actor_role=row.actor_role,
                record_version=1,
            )
            row.entry_mac = _audit.compute_entry_mac(
                OLD_KEY, row.user_id, row.chain_seq, row.entry_hash
            )
            previous = row.entry_hash
        state = states[OWNERS[0]]
        state.first_retained_hash = owners[OWNERS[0]][0].entry_hash
        state.head_hash = previous
        await session.flush()
        assert (
            await _audit.seal_legacy_audit_states(
                session, mac_keys={1: OLD_KEY, 7: KEY}, current_mac_key_version=7
            )
            == 1
        )
        assert state.state_mac == _audit.compute_chain_state_mac(KEY, state)


async def test_legacy_bridge_rejects_head_hash_drift_even_when_head_sequence_matches():
    async with chains([1], sealed=False) as (session, owners, states):
        states[OWNERS[0]].head_hash = "e" * 64
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(session, **OPTIONS)
        error_is(caught.value, "legacy audit state failed authenticated verification")


async def test_retention_reads_only_one_boundary_row_per_bounded_page(monkeypatch):
    limits(monkeypatch, owners=1, rows=1, total=1)
    async with chains([5, 5, 5, 5]) as (session, owners, states):
        execute, scalars, scalar = session.execute, session.scalars, session.scalar
        reads = {"owners": [], "prefix": [], "tail": [], "oldest": []}

        async def counted_execute(statement, *args, **kwargs):
            result = await execute(statement, *args, **kwargs)
            if isinstance(statement, Delete):
                return result
            desc = statement.column_descriptions
            if desc[0]["entity"] is AccessLog and desc[0]["name"] == "user_id":
                values = list(result.scalars())
                reads["owners"].append(len(values))
                return SimpleNamespace(scalars=lambda: iter(values))
            if desc[0]["entity"] is AccessLog and desc[0]["name"] == "chain_seq":
                values = result.all()
                reads["tail"].append(len(values))
                return SimpleNamespace(first=lambda: values[0] if values else None)
            return result

        async def counted_scalars(statement, *args, **kwargs):
            result = await scalars(statement, *args, **kwargs)
            if (
                not isinstance(statement, Delete)
                and statement.column_descriptions[0]["name"] == "AccessLog"
            ):
                values = result.all()
                reads["prefix"].append(len(values))
                return SimpleNamespace(all=lambda: values)
            return result

        async def counted_scalar(statement, *args, **kwargs):
            if statement.column_descriptions[0]["name"] == "at":
                values = list((await execute(statement, *args, **kwargs)).scalars())
                reads["oldest"].append(len(values))
                return values[0] if values else None
            return await scalar(statement, *args, **kwargs)

        monkeypatch.setattr(session, "execute", counted_execute)
        monkeypatch.setattr(session, "scalars", counted_scalars)
        monkeypatch.setattr(session, "scalar", counted_scalar)
        progress = []
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=10),
                progress_observer=lambda **values: progress.append(values),
                **OPTIONS,
            )
            == 1
        )
        assert reads == {"owners": [2], "prefix": [2], "tail": [1], "oldest": [1]}
        assert progress[-1]["pending_rows_probe"] == 2


@pytest.mark.parametrize(
    "fault", ["expected_empty_cursor", "expected_empty_continues", "unexpected_empty"]
)
async def test_retention_rechecks_owner_disappearance_between_listing_and_locked_read(
    fault, monkeypatch
):
    limits(monkeypatch, owners=2 if fault == "expected_empty_continues" else 1, total=3)
    async with chains([1, 1, 1]) as (session, owners, states):
        scalar, injected = session.scalar, []

        async def vanished_owner(statement, *args, **kwargs):
            if statement.column_descriptions[0]["name"] == "AuditChainState" and not injected:
                injected.append(True)
                await session.execute(delete(AccessLog).where(AccessLog.user_id == OWNERS[0]))
                if fault != "unexpected_empty":
                    state = states[OWNERS[0]]
                    state.first_retained_seq = state.first_retained_hash = None
                    state.state_mac = _audit.compute_chain_state_mac(KEY, state)
                    await session.flush()
            return await scalar(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalar", vanished_owner)
        progress = []
        if fault == "unexpected_empty":
            with pytest.raises(ApiError) as caught:
                await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
            error_is(
                caught.value,
                "audit chain failed verification before retention prune: durable state expects retained rows but the database is empty",
            )
        else:
            expected = 1 if fault == "expected_empty_continues" else 0
            assert (
                await _audit.prune_access_logs(
                    session,
                    cutoff=AT + timedelta(days=10),
                    progress_observer=lambda **values: progress.append(values),
                    **OPTIONS,
                )
                == expected
            )
            assert progress[-1]["next_owner"] == OWNERS[expected]
            assert progress[-1]["pending_rows_probe"] == 2 - expected
        assert injected == [True]


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("empty_page", "retained-prefix page disappeared"),
        ("missing_boundary", "bounded prefix did not reach a surviving boundary"),
    ],
)
async def test_retention_rejects_missing_prefix_read_boundaries(fault, reason, monkeypatch):
    limits(monkeypatch, rows=2, total=2)
    async with chains([4]) as (session, owners, states):
        scalars, injected = session.scalars, []

        async def incomplete_page(statement, *args, **kwargs):
            result = await scalars(statement, *args, **kwargs)
            if (
                not isinstance(statement, Delete)
                and statement.column_descriptions[0]["name"] == "AccessLog"
                and not injected
            ):
                injected.append(True)
                values = result.all()
                return SimpleNamespace(all=lambda: [] if fault == "empty_page" else values[:2])
            return result

        monkeypatch.setattr(session, "scalars", incomplete_page)
        with pytest.raises(ApiError) as caught:
            await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
        error_is(caught.value, "audit chain failed verification before retention prune: " + reason)
        assert injected == [True]
        assert len(await remaining(session)) == 4


async def test_legacy_stream_buffer_never_materializes_more_than_five_hundred_rows(monkeypatch):
    from sqlalchemy.dialects.sqlite.aiosqlite import AsyncAdapt_aiosqlite_ss_cursor

    async with chains([1501], sealed=False) as (session, owners, states):
        fetched, fetchmany = [], AsyncAdapt_aiosqlite_ss_cursor.fetchmany

        def counted(cursor, size=None):
            values = fetchmany(cursor, size)
            fetched.append(len(values))
            return values

        monkeypatch.setattr(AsyncAdapt_aiosqlite_ss_cursor, "fetchmany", counted)
        assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == 1
        assert sum(fetched) == 1501 and max(fetched) == 500


async def test_retention_refuses_missing_predecessor_on_a_self_consistent_retained_row():
    async with chains([1]) as (session, owners, states):
        row, state = owners[OWNERS[0]][0], states[OWNERS[0]]
        row.chain_seq = 2
        row.entry_mac = _audit.compute_entry_mac(KEY, row.user_id, 2, row.entry_hash)
        state.first_retained_seq = state.head_seq = 2
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
        error_is(
            caught.value,
            "audit chain failed verification before retention prune: retained-prefix predecessor is malformed",
        )


@pytest.mark.parametrize("fault", ["hash", "mac"])
async def test_legacy_bridge_rejects_a_bad_extra_row_beyond_reviewed_head(fault):
    async with chains([2], sealed=False) as (session, owners, states):
        first, second = owners[OWNERS[0]]
        state = states[OWNERS[0]]
        state.head_seq, state.head_hash, state.head_at = first.chain_seq, first.entry_hash, first.at
        if fault == "hash":
            second.entry_hash = "e" * 64
        else:
            second.entry_mac = "e" * 64
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(session, **OPTIONS)
        error_is(caught.value, "legacy audit state failed authenticated verification")
        assert state.state_mac is None


@pytest.mark.parametrize(("counts", "budget", "sealed"), [([1, 1, 1, 1], 2, 2), ([2, 1], 3, 2)])
async def test_legacy_bridge_aggregate_budget_counts_every_preceding_owner(
    counts, budget, sealed, monkeypatch
):
    async with chains(counts, sealed=False) as (session, owners, states):
        monkeypatch.setattr(_audit, "AUDIT_LEGACY_SEAL_ROW_BUDGET", budget)
        assert await _audit.seal_legacy_audit_states(session, **OPTIONS) == sealed
        assert sum(state.state_mac is not None for state in states.values()) == sealed
        assert all(states[owner].state_mac is None for owner in OWNERS[sealed : len(counts)])


async def test_legacy_oversized_owner_reads_only_one_row_beyond_its_budget(monkeypatch):
    from sqlalchemy.dialects.sqlite.aiosqlite import AsyncAdapt_aiosqlite_ss_cursor

    async with chains([4], sealed=False) as (session, owners, states):
        monkeypatch.setattr(_audit, "AUDIT_LEGACY_SEAL_ROW_BUDGET", 1)
        fetched, fetchmany = [], AsyncAdapt_aiosqlite_ss_cursor.fetchmany

        def counted(cursor, size=None):
            values = fetchmany(cursor, size)
            fetched.append(len(values))
            return values

        monkeypatch.setattr(AsyncAdapt_aiosqlite_ss_cursor, "fetchmany", counted)
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(session, **OPTIONS)
        error_is(caught.value, "legacy audit chain exceeds the bounded online sealing budget")
        assert sum(fetched) == 2
        assert all(fetched), "a rejected budget overrun must stop before requesting another page"


async def test_retention_waits_for_the_same_owner_lock_as_append(monkeypatch):
    import asyncio

    async with chains([1]) as (session, owners, states):
        entered, scalar = asyncio.Event(), session.scalar

        async def storage(statement, *args, **kwargs):
            if statement.column_descriptions[0]["name"] == "AuditChainState":
                entered.set()
            return await scalar(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalar", storage)
        task = None
        try:
            async with _audit._audit_chain_locks.hold("audit-chain:" + OWNERS[0]):
                task = asyncio.create_task(
                    _audit.prune_access_logs(session, cutoff=AT + timedelta(days=10), **OPTIONS)
                )
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(entered.wait(), timeout=0.05)
            assert await asyncio.wait_for(task, timeout=5) == 1
            assert entered.is_set()
        finally:
            if task is not None:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
