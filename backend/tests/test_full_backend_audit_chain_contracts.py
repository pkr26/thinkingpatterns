"""Authenticated chains, diagnostic failures and finite incremental walks."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from app.api import _audit
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError
from app.models import AuditChainState, AuditSweepCursor, Base

KEY = b"k" * 32
OWNER = "a" * 32
OTHER = "b" * 32
AT = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("fault", "detail"),
    [
        ("missing_key", "audit chain state does not verify"),
        ("missing_mac", "audit chain state does not verify"),
        ("wrong_mac", "audit chain state does not verify"),
        ("empty_database", "audit chain head differs from durable state"),
        ("truncated_database", "audit chain head differs from durable state"),
        ("missing_state", "audit chain state is missing"),
    ],
)
async def test_append_refuses_damaged_existing_state_with_the_complete_envelope(fault, detail):
    async with seeded_chain() as (session, rows, state):
        if fault == "missing_key":
            state.mac_key_version = 8
        elif fault == "missing_mac":
            state.state_mac = None
        elif fault == "wrong_mac":
            state.state_mac = "f" * 64
        elif fault == "empty_database":
            for row in rows:
                await session.delete(row)
        elif fault == "truncated_database":
            await session.delete(rows[-1])
        elif fault == "missing_state":
            await session.delete(state)
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.append_access_log(
                session,
                actor_id=OTHER,
                actor_role="patient",
                user_id=OWNER,
                action="read_entries",
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            detail,
            "audit_integrity_error",
        )


@pytest.mark.parametrize("conflicts", [1, 2, 3])
async def test_append_retries_savepoint_conflicts_and_preserves_the_last_error(conflicts):
    async with seeded_chain() as (session, _rows, state):
        previous_head = state.head_hash
        attempts = []
        errors = []

        def conflict_before_insert(connection, cursor, statement, parameters, context, many):
            if statement.startswith("INSERT INTO access_log"):
                attempts.append(parameters)
                if len(attempts) <= conflicts:
                    error = IntegrityError(statement, parameters, RuntimeError("unique-seq race"))
                    errors.append(error)
                    raise error

        engine = session.bind.sync_engine
        event.listen(engine, "before_cursor_execute", conflict_before_insert)
        try:
            values = dict(
                actor_id=OTHER,
                actor_role="patient",
                user_id=OWNER,
                action="read_entries",
                at=AT + timedelta(days=3),
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            if conflicts == 3:
                with pytest.raises(ApiError) as caught:
                    await _audit.append_access_log(session, **values)
                assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
                    500,
                    "audit chain append lost the seq race repeatedly",
                    "internal_error",
                )
                assert caught.value.__cause__ is errors[-1]
                assert len(attempts) == 3
            else:
                row = await _audit.append_access_log(session, **values)
                assert row.chain_seq == 4 and row.prev_hash == previous_head
                assert len(attempts) == conflicts + 1
                assert session.info["mindpattern_audit_journal_pending"][-1][:2] == (OWNER, 4)
        finally:
            event.remove(engine, "before_cursor_execute", conflict_before_insert)


@pytest.mark.parametrize("version", [0])
async def test_legacy_falsy_key_versions_resolve_to_key_one(version):
    async with seeded_chain() as (session, rows, state):
        for row in rows:
            row.mac_key_version = version
        state.mac_key_version = version
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={1: KEY}) == (
            _audit.ChainVerification(True, 3, None, None, 0)
        )
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session, cursor, OWNER, mac_keys={1: KEY}, current_mac_key_version=1
        ) == _audit.IncrementalChainVerification(True, True, 3, None)
        appended = await _audit.append_access_log(
            session,
            actor_id=OTHER,
            actor_role="patient",
            user_id=OWNER,
            action="read_entries",
            mac_keys={1: KEY},
        )
        assert appended.chain_seq == 4 and appended.mac_key_version == 1


@pytest.mark.parametrize("evidence_kind", ["index", "path"])
@pytest.mark.parametrize("corrupt", [False, True])
async def test_full_verification_reads_owned_disk_evidence(tmp_path, evidence_kind, corrupt):
    async with seeded_chain() as (session, rows, _state):
        head = rows[-1]
        journal = tmp_path / "journal"
        journal.write_text(
            "invalid evidence\n"
            if corrupt
            else f"{OWNER} 3 {head.entry_hash} {head.entry_mac} "
            f"{_audit.canonical_occurred_at(head.at)}\n"
        )
        with _audit.build_journal_evidence_index(str(journal)) as index:
            arguments = (
                {"journal_evidence": index}
                if evidence_kind == "index"
                else {"journal_path": str(journal)}
            )
            expected = (
                _audit.ChainVerification(
                    False, 0, None, "audit journal evidence is unavailable or malformed", 0
                )
                if corrupt
                else _audit.ChainVerification(True, 3, None, None, 0)
            )
            assert (
                await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}, **arguments)
                == expected
            )


@pytest.mark.parametrize(
    "head_at", ["", "not-an-instant", "2026-10-01T00:00:00+00:00", "2026-10-02T00:00:00+00:00"]
)
@pytest.mark.parametrize("kind", ["evidence", "legacy"])
async def test_empty_unkeyed_trail_checks_external_head_time_against_cutoff(head_at, kind):
    async with seeded_chain() as (session, rows, state):
        for row in rows:
            await session.delete(row)
        await session.delete(state)
        await session.flush()
        cutoff = AT
        arguments = (
            {"journal_evidence": {OWNER: _audit.JournalEvidence(3, "f" * 64, "-", head_at)}}
            if kind == "evidence"
            else {"journal_heads": {OWNER: (3, head_at)}}
        )
        newer = head_at == "2026-10-02T00:00:00+00:00"
        expected = (
            _audit.ChainVerification(
                False,
                0,
                None,
                "journal records rows this database no longer has (tail truncation)",
                0,
            )
            if newer
            else _audit.ChainVerification(True, 0, None, None, 0)
        )
        assert (
            await _audit.verify_access_log_chain(
                session, OWNER, mac_keys={}, retention_cutoff=cutoff, **arguments
            )
            == expected
        )


async def test_non_genesis_unkeyed_prefix_requires_a_predecessor_seal():
    async with seeded_chain() as (session, rows, state):
        await session.delete(rows[0])
        await session.delete(state)
        rows[1].prev_hash = None
        await session.flush()
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={}) == (
            _audit.ChainVerification(
                False,
                0,
                2,
                "non-genesis row has no prev_hash (pruned prefix cannot be anchored)",
                0,
            )
        )


@pytest.mark.parametrize("retained_anchor", [False, True])
@pytest.mark.parametrize("cutoff_delta", [None, 0, 1])
async def test_empty_keyed_database_requires_a_pruned_anchor_and_strictly_later_cutoff(
    retained_anchor, cutoff_delta
):
    async with seeded_chain() as (session, rows, state):
        for row in rows:
            await session.delete(row)
        if not retained_anchor:
            state.first_retained_seq = None
            state.first_retained_hash = None
            state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        cutoff = None if cutoff_delta is None else state.head_at + timedelta(days=cutoff_delta)
        if retained_anchor:
            reason = (
                "durable state expects retained rows but the database is empty (tail truncation)"
            )
            incremental_reason = "durable state expects retained rows but the database is empty"
        elif cutoff_delta != 1:
            reason = incremental_reason = (
                "empty retained trail is not explained by the retention cutoff"
            )
        else:
            reason = incremental_reason = None
        assert await _audit.verify_access_log_chain(
            session, OWNER, mac_keys={7: KEY}, retention_cutoff=cutoff
        ) == _audit.ChainVerification(reason is None, 0, None, reason, 0)
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            retention_cutoff=cutoff,
        ) == _audit.IncrementalChainVerification(
            incremental_reason is None, incremental_reason is None, 0, incremental_reason
        )
        if incremental_reason is None:
            assert cursor.last_user_id == OWNER
            _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)


@pytest.mark.parametrize("evidence_kind", ["disk", "map", "legacy"])
async def test_missing_state_fails_before_streaming_external_owner_evidence(
    tmp_path, evidence_kind
):
    async with seeded_chain() as (session, rows, state):
        await session.delete(state)
        for row in rows:
            await session.delete(row)
        await session.flush()
        journal = tmp_path / "journal"
        journal.write_text(f"{OWNER} 3 {'f' * 64} {'e' * 64} {_audit.canonical_occurred_at(AT)}\n")
        with _audit.build_journal_evidence_index(str(journal)) as index:
            arguments = {
                "disk": {"journal_evidence": index},
                "map": {"journal_evidence": index.all_evidence()},
                "legacy": {"journal_heads": {OWNER: (3, _audit.canonical_occurred_at(AT))}},
            }[evidence_kind]
            assert await _audit.verify_access_log_chain(
                session, OWNER, mac_keys={7: KEY}, **arguments
            ) == _audit.ChainVerification(False, 0, None, "durable audit chain state is missing", 0)


async def test_cursor_timestamp_with_separator_still_uses_only_the_first_cursor_separator():
    # datetime.fromisoformat accepts an arbitrary one-character date/time separator.
    # A '|' separator is invalid in this API's timestamp|row-id cursor grammar.
    with pytest.raises(ApiError) as caught:
        _audit.parse_access_log_cursor("2026-10-01|00:00:00+00:00|" + OWNER)
    assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
        422,
        "malformed cursor",
        "validation_error",
    )


async def test_append_after_total_pruning_restores_both_authenticated_anchor_fields():
    async with seeded_chain() as (session, rows, state):
        last_hash = rows[-1].entry_hash
        assert (
            await _audit.prune_access_logs(
                session, cutoff=AT + timedelta(days=4), mac_keys={7: KEY}, current_mac_key_version=7
            )
            == 3
        )
        assert state.first_retained_seq is None and state.first_retained_hash is None
        row = await _audit.append_access_log(
            session,
            actor_id=OTHER,
            actor_role="patient",
            user_id=OWNER,
            action="read_entries",
            at=AT + timedelta(days=5),
            mac_keys={7: KEY},
            current_mac_key_version=7,
        )
        assert row.chain_seq == 4 and row.prev_hash == last_hash
        assert state.first_retained_seq == 4 and state.first_retained_hash == row.entry_hash
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 1, None, None, 0)
        )


@pytest.mark.parametrize("field", ["head_seq", "head_hash"])
async def test_full_verification_checks_each_authenticated_head_component(field):
    async with seeded_chain() as (session, _rows, state):
        setattr(state, field, 4 if field == "head_seq" else "f" * 64)
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(
                False, 3, 3, "database tail differs from durable chain head", 0
            )
        )


@pytest.mark.parametrize("kind", ["row", "state"])
async def test_unavailable_legacy_zero_key_version_reports_the_effective_key_one(kind):
    async with seeded_chain() as (session, rows, state):
        if kind == "row":
            rows[0].mac_key_version = 0
            assert _audit._audit_row_integrity_error(rows[0], {7: KEY}) == (
                "audit MAC key version 1 is unavailable"
            )
        else:
            state.mac_key_version = 0
            assert _audit._authenticated_state_error(state, {7: KEY}) == (
                "audit MAC key version 1 is unavailable"
            )
        await session.flush()
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(
                False, 0, 1 if kind == "row" else None, "audit MAC key version 1 is unavailable", 0
            )
        )


async def test_historical_zero_record_version_uses_the_v1_wire_encoding():
    async with seeded_chain() as (session, rows, state):
        row = rows[-1]
        row.record_version = 0
        row.entry_hash = _audit.compute_entry_hash(
            row.prev_hash,
            row.actor_id,
            row.user_id,
            row.action,
            row.at,
            actor_role=row.actor_role,
            record_version=1,
        )
        row.entry_mac = _audit.compute_entry_mac(KEY, OWNER, 3, row.entry_hash)
        state.head_hash = row.entry_hash
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        assert _audit._audit_row_integrity_error(row, {7: KEY}) is None
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 3, None, None, 0)
        )


@pytest.mark.parametrize(
    "scenario", ["equal", "behind", "ahead_with_missing_tail", "hash_with_missing_tail"]
)
@pytest.mark.parametrize("disk", [False, True])
async def test_incremental_journal_precedence_and_benign_behind_head(tmp_path, scenario, disk):
    async with seeded_chain() as (session, rows, _state):
        head = rows[-1]
        seq = 2 if scenario == "behind" else 4 if scenario.startswith("ahead") else 3
        entry_hash = (
            "f" * 64 if scenario.startswith("hash") or scenario == "behind" else head.entry_hash
        )
        at = _audit.canonical_occurred_at(head.at)
        journal = tmp_path / "journal"
        journal.write_text(f"{OWNER} {seq} {entry_hash} {head.entry_mac} {at}\n")
        if "missing_tail" in scenario:
            await session.delete(head)
            await session.flush()
        with _audit.build_journal_evidence_index(str(journal)) as index:
            evidence = index if disk else index.all_evidence()
            cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
            expected = (
                _audit.IncrementalChainVerification(
                    False, False, 0, "journal differs from durable chain head"
                )
                if "missing_tail" in scenario
                else _audit.IncrementalChainVerification(True, True, 3, None)
            )
            assert (
                await _audit.verify_access_log_chain_incremental(
                    session,
                    cursor,
                    OWNER,
                    mac_keys={7: KEY},
                    current_mac_key_version=7,
                    journal_evidence=evidence,
                )
                == expected
            )


@pytest.mark.parametrize("explicit_version", [None, 0, 1])
async def test_retention_accepts_the_legacy_single_key_and_version_one_boundary(explicit_version):
    async with seeded_chain() as (session, rows, state):
        for row in rows:
            row.mac_key_version = 1
        state.mac_key_version = 1
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=1),
                mac_key=KEY,
                current_mac_key_version=explicit_version,
            )
            == 1
        )
        assert state.first_retained_seq == 2 and state.first_retained_hash == rows[1].entry_hash
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=4),
                mac_keys={1: KEY},
                current_mac_key_version=explicit_version,
            )
            == 2
        )


async def test_incremental_cursor_at_the_new_pruned_anchor_preserves_prior_verified_work():
    async with seeded_chain() as (session, _rows, _state):
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session, cursor, OWNER, mac_keys={7: KEY}, current_mac_key_version=7, row_budget=1
        ) == _audit.IncrementalChainVerification(True, False, 1, None)
        assert (
            await _audit.prune_access_logs(
                session, cutoff=AT + timedelta(days=1), mac_keys={7: KEY}, current_mac_key_version=7
            )
            == 1
        )
        assert await _audit.verify_access_log_chain_incremental(
            session, cursor, OWNER, mac_keys={7: KEY}, current_mac_key_version=7, row_budget=1
        ) == _audit.IncrementalChainVerification(True, False, 1, None)
        assert cursor.verification_next_seq == 3 and cursor.verification_rows_checked == 2
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)


async def test_incremental_pruned_sequence_two_requires_its_predecessor_even_when_resealed():
    async with seeded_chain() as (session, rows, state):
        assert (
            await _audit.prune_access_logs(
                session, cutoff=AT + timedelta(days=1), mac_keys={7: KEY}, current_mac_key_version=7
            )
            == 1
        )
        previous_hash = None
        for row in rows[1:]:
            row.prev_hash = previous_hash
            row.entry_hash = _audit.compute_entry_hash(
                previous_hash,
                row.actor_id,
                row.user_id,
                row.action,
                row.at,
                actor_role=row.actor_role,
                record_version=2,
            )
            row.entry_mac = _audit.compute_entry_mac(KEY, OWNER, row.chain_seq, row.entry_hash)
            previous_hash = row.entry_hash
        state.first_retained_hash = rows[1].entry_hash
        state.head_hash = rows[-1].entry_hash
        state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        await session.flush()
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
        ) == _audit.IncrementalChainVerification(
            False, False, 0, "retained-prefix predecessor is malformed"
        )


@pytest.mark.parametrize("fault", ["ahead", "hash", "mac"])
async def test_full_verification_reads_external_head_conflicts_from_a_journal_path(tmp_path, fault):
    async with seeded_chain() as (session, rows, _state):
        head = rows[-1]
        seq = 4 if fault == "ahead" else 3
        entry_hash = "f" * 64 if fault == "hash" else head.entry_hash
        entry_mac = "f" * 64 if fault == "mac" else head.entry_mac
        journal = tmp_path / "journal"
        journal.write_text(
            f"{OWNER} {seq} {entry_hash} {entry_mac} {_audit.canonical_occurred_at(head.at)}\n"
        )
        reason = (
            "journal is ahead of the database head (journal seq 4 > db seq 3; tail truncation)"
            if fault == "ahead"
            else "journal seal conflicts with database head"
        )
        assert await _audit.verify_access_log_chain(
            session, OWNER, mac_keys={7: KEY}, journal_path=str(journal)
        ) == _audit.ChainVerification(False, 3, 3, reason, 0)


@pytest.mark.parametrize("seq", [2, 3])
async def test_legacy_journal_head_at_or_behind_the_database_is_benign(seq):
    async with seeded_chain() as (session, rows, _state):
        assert await _audit.verify_access_log_chain(
            session,
            OWNER,
            mac_keys={7: KEY},
            journal_heads={OWNER: (seq, _audit.canonical_occurred_at(rows[-1].at))},
        ) == _audit.ChainVerification(True, 3, None, None, 0)


def test_verification_results_are_immutable_snapshots_with_no_unknown_error():
    for result in (
        _audit.ChainVerification(ok=True, rows_checked=0),
        _audit.IncrementalChainVerification(ok=True, complete=True, rows_checked=0),
    ):
        assert result.reason is None
        with pytest.raises(FrozenInstanceError):
            result.ok = False


@asynccontextmanager
async def seeded_chain():
    _audit.configure_audit_mac_key(None)
    engine = build_engine("sqlite+aiosqlite://")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with build_sessionmaker(engine)() as session:
            rows = []
            for seq in range(1, 4):
                row = await _audit.append_access_log(
                    session,
                    actor_id=OTHER,
                    actor_role="patient",
                    user_id=OWNER,
                    action="read_entries",
                    at=AT + timedelta(days=seq - 1),
                    row_id=f"{seq:032x}",
                    mac_keys={7: KEY},
                    current_mac_key_version=7,
                    allow_new_chain=seq == 1,
                )
                assert row.id == f"{seq:032x}"
                assert row.chain_seq == seq
                assert row.record_version == 2
                assert row.mac_key_version == 7
                assert row.at == AT + timedelta(days=seq - 1)
                assert row.actor_id == OTHER and row.actor_role == "patient"
                assert row.user_id == OWNER and row.action == "read_entries"
                assert row.prev_hash == (None if seq == 1 else rows[-1].entry_hash)
                rows.append(row)
            await session.commit()
            state = await session.get(AuditChainState, OWNER)
            assert state.head_seq == 3 and state.head_hash == rows[-1].entry_hash
            assert state.first_retained_seq == 1 and state.first_retained_hash == rows[0].entry_hash
            assert state.state_version == 1 and state.mac_key_version == 7
            assert state.head_at == rows[-1].at and state.updated_at == rows[-1].at
            assert session.info["mindpattern_audit_journal_pending"] == [
                (OWNER, row.chain_seq, row.entry_hash, row.entry_mac, row.at) for row in rows
            ]
            yield session, rows, state
    finally:
        await engine.dispose()


async def test_complete_chain_and_absent_owner_have_exact_counts():
    async with seeded_chain() as (session, rows, _state):
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 3, None, None, 0)
        )
        assert await _audit.verify_access_log_chain(session, OTHER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 0, None, None, 0)
        )
        for row in rows:
            row.entry_mac = None
        await session.flush()
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={}) == (
            _audit.ChainVerification(True, 3, None, None, 3)
        )


@pytest.mark.parametrize(
    ("fault", "reason", "broken", "checked"),
    [
        ("missing_state", "durable audit chain state is missing", None, 0),
        ("unsealed_state", "durable audit chain state is unsealed", None, 0),
        ("wrong_state_key", "audit MAC key version 8 is unavailable", None, 0),
        ("wrong_state_mac", "durable audit chain state MAC does not verify", None, 0),
        ("genesis_predecessor", "genesis row carries a prev_hash", 1, 0),
        ("middle_deleted", "chain_seq gap after 1 (mid-trail deletion or forged insert)", 3, 0),
        ("hash_missing", "missing or malformed entry_hash", 2, 0),
        ("hash_short", "missing or malformed entry_hash", 2, 0),
        ("hash_wrong", "entry_hash does not match the row's contents", 2, 0),
        ("role_wrong", "entry_hash does not match the row's contents", 2, 0),
        ("link_wrong", "prev_hash does not link to the previous row's seal", 2, 0),
        (
            "mac_missing",
            "missing entry_mac (legacy rows require explicit offline review; MAC stripping is not accepted)",
            2,
            0,
        ),
        ("mac_wrong", "entry_mac does not verify (row rewritten without the chain key)", 2, 0),
        ("row_key_wrong", "audit MAC key version 8 is unavailable", 2, 0),
        ("anchor_wrong", "retained-prefix anchor differs from durable state", 1, 0),
        ("tail_deleted", "database tail differs from durable chain head", 2, 2),
        ("journal_corrupt", "audit journal evidence is unavailable or malformed", None, 0),
        ("journal_conflict", "audit journal sequence conflict", None, 0),
        (
            "journal_ahead",
            "journal is ahead of the database head (journal seq 4 > db seq 3; tail truncation)",
            3,
            3,
        ),
        ("journal_hash_wrong", "journal seal conflicts with database head", 3, 3),
        ("journal_mac_wrong", "journal seal conflicts with database head", 3, 3),
        (
            "legacy_journal_ahead",
            "journal is ahead of the database head (journal seq 4 > db seq 3; tail truncation)",
            3,
            3,
        ),
    ],
)
async def test_chain_diagnostics_name_the_actual_broken_boundary(fault, reason, broken, checked):
    async with seeded_chain() as (session, rows, state):
        evidence = None
        legacy_heads = None
        if fault == "missing_state":
            await session.delete(state)
        elif fault == "unsealed_state":
            state.state_mac = None
        elif fault == "wrong_state_key":
            state.mac_key_version = 8
        elif fault == "wrong_state_mac":
            state.state_mac = "e" * 64
        elif fault == "genesis_predecessor":
            rows[0].prev_hash = "e" * 64
        elif fault == "middle_deleted":
            await session.delete(rows[1])
        elif fault == "hash_missing":
            rows[1].entry_hash = None
        elif fault == "hash_short":
            rows[1].entry_hash = "short"
        elif fault == "hash_wrong":
            rows[1].entry_hash = "e" * 64
        elif fault == "role_wrong":
            rows[1].actor_role = "therapist"
        elif fault == "link_wrong":
            row = rows[1]
            row.prev_hash = "e" * 64
            row.entry_hash = _audit.compute_entry_hash(
                row.prev_hash,
                row.actor_id,
                row.user_id,
                row.action,
                row.at,
                actor_role=row.actor_role,
                record_version=2,
            )
            row.entry_mac = _audit.compute_entry_mac(KEY, OWNER, row.chain_seq, row.entry_hash)
        elif fault == "mac_missing":
            rows[1].entry_mac = None
        elif fault == "mac_wrong":
            rows[1].entry_mac = "e" * 64
        elif fault == "row_key_wrong":
            rows[1].mac_key_version = 8
        elif fault == "anchor_wrong":
            state.first_retained_hash = "e" * 64
            state.state_mac = _audit.compute_chain_state_mac(KEY, state)
        elif fault == "tail_deleted":
            await session.delete(rows[-1])
        elif fault == "journal_corrupt":
            evidence = {_audit.JOURNAL_CORRUPTION_KEY: _audit.JournalEvidence(0, "", "", "", True)}
        elif fault.startswith("journal_"):
            head = rows[-1]
            evidence = {
                OWNER: _audit.JournalEvidence(
                    4 if fault == "journal_ahead" else 3,
                    "e" * 64 if fault == "journal_hash_wrong" else head.entry_hash,
                    "e" * 64 if fault == "journal_mac_wrong" else head.entry_mac,
                    _audit.canonical_occurred_at(head.at),
                    fault == "journal_conflict",
                )
            }
        elif fault == "legacy_journal_ahead":
            legacy_heads = {OWNER: (4, _audit.canonical_occurred_at(rows[-1].at))}
        else:
            raise AssertionError(f"unhandled scenario {fault}")
        await session.flush()
        result = await _audit.verify_access_log_chain(
            session,
            OWNER,
            mac_keys={7: KEY},
            journal_evidence=evidence,
            journal_heads=legacy_heads,
        )
        assert result == _audit.ChainVerification(False, checked, broken, reason, 0)
        if fault != "legacy_journal_ahead":
            incremental_reason = {
                "genesis_predecessor": "retained-prefix predecessor is malformed",
                "middle_deleted": "chain_seq gap before 3",
                "link_wrong": "prev_hash does not link to the verification checkpoint",
                "journal_ahead": "journal differs from durable chain head",
                "journal_hash_wrong": "journal differs from durable chain head",
                "journal_mac_wrong": "journal differs from durable chain head",
            }.get(fault, reason)
            cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
            assert await _audit.verify_access_log_chain_incremental(
                session,
                cursor,
                OWNER,
                mac_keys={7: KEY},
                current_mac_key_version=7,
                journal_evidence=evidence,
            ) == _audit.IncrementalChainVerification(False, False, 0, incremental_reason)
            prefix = "audit chain failed verification before retention prune: "
            prune_detail = {
                "missing_state": "audit chain state is missing",
                "genesis_predecessor": prefix + "retained-prefix predecessor is malformed",
                "middle_deleted": prefix + "chain_seq gap after 1",
                "journal_corrupt": "audit journal evidence is unavailable",
                "journal_ahead": prefix + "journal differs from durable chain head",
                "journal_hash_wrong": prefix + "journal differs from durable chain head",
                "journal_mac_wrong": prefix + "journal differs from durable chain head",
            }.get(fault, prefix + reason)
            with pytest.raises(ApiError) as caught:
                await _audit.prune_access_logs(
                    session,
                    cutoff=AT + timedelta(days=4),
                    mac_keys={7: KEY},
                    current_mac_key_version=7,
                    journal_evidence=evidence,
                )
            assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
                500,
                prune_detail,
                "audit_integrity_error",
            )


async def test_incremental_walk_resumes_authentically_and_finishes_its_captured_head():
    async with seeded_chain() as (session, rows, _state):
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        original_head = rows[-1].entry_hash
        for page in (1, 2):
            result = await _audit.verify_access_log_chain_incremental(
                session,
                cursor,
                OWNER,
                mac_keys={7: KEY},
                current_mac_key_version=7,
                row_budget=1,
            )
            assert result == _audit.IncrementalChainVerification(True, False, 1, None)
            assert cursor.last_user_id is None
            assert cursor.verification_owner_id == OWNER
            assert cursor.verification_snapshot_head_seq == 3
            assert cursor.verification_snapshot_head_hash == original_head
            assert cursor.verification_next_seq == page + 1
            assert cursor.verification_previous_hash == rows[page - 1].entry_hash
            assert cursor.verification_rows_checked == page
            assert cursor.verification_mac_key_version == 7
            _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)
        await _audit.append_access_log(
            session,
            actor_id=OTHER,
            actor_role="patient",
            user_id=OWNER,
            action="read_entries",
            at=AT + timedelta(days=3),
            mac_keys={7: KEY},
            current_mac_key_version=7,
        )
        result = await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        )
        assert result == _audit.IncrementalChainVerification(True, True, 1, None)
        assert cursor.last_user_id == OWNER
        assert cursor.verification_owner_id is None
        assert cursor.verification_snapshot_head_seq is None
        assert cursor.verification_snapshot_head_hash is None
        assert cursor.verification_next_seq is None
        assert cursor.verification_previous_hash is None
        assert cursor.verification_rows_checked == 0
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 4, None, None, 0)
        )


async def test_incremental_walk_budget_owner_and_absent_owner_contracts():
    async with seeded_chain() as (session, _rows, _state):
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        for budget in (0, _audit.AUDIT_VERIFY_TOTAL_ROW_BATCH + 1):
            with pytest.raises(ValueError, match=r"^audit verification row budget is invalid$"):
                await _audit.verify_access_log_chain_incremental(
                    session,
                    cursor,
                    OWNER,
                    mac_keys={7: KEY},
                    current_mac_key_version=7,
                    row_budget=budget,
                )
        cursor.verification_owner_id = OTHER
        _audit.seal_verification_checkpoint(cursor, {7: KEY}, 7)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
        ) == _audit.IncrementalChainVerification(
            False,
            False,
            0,
            "audit verification checkpoint owner differs from requested owner",
        )
        cursor.verification_checkpoint_mac = None
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OTHER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=_audit.AUDIT_VERIFY_TOTAL_ROW_BATCH,
        ) == _audit.IncrementalChainVerification(True, True, 0, None)
        assert cursor.last_user_id == OTHER and cursor.verification_owner_id is None
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)


async def test_retention_advances_authenticated_anchor_and_empty_trail_is_explained():
    async with seeded_chain() as (session, rows, state):
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        ) == _audit.IncrementalChainVerification(True, False, 1, None)
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=rows[-1].at,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            == 2
        )
        assert state.first_retained_seq == 3 and state.first_retained_hash == rows[-1].entry_hash
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 1, None, None, 0)
        )
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        ) == _audit.IncrementalChainVerification(True, True, 1, None)
        cutoff = AT + timedelta(days=4)
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=cutoff,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            == 1
        )
        assert state.first_retained_seq is None and state.first_retained_hash is None
        assert await _audit.verify_access_log_chain(
            session,
            OWNER,
            mac_keys={7: KEY},
            retention_cutoff=cutoff,
        ) == _audit.ChainVerification(True, 0, None, None, 0)
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(
                False, 0, None, "empty retained trail is not explained by the retention cutoff", 0
            )
        )
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            retention_cutoff=cutoff,
        ) == _audit.IncrementalChainVerification(True, True, 0, None)


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"mac_key": b"short"},
        {"mac_key": b"k" * 33},
        {"mac_key": "k" * 32},
        {"mac_key": bytearray(b"k" * 32)},
        {"mac_keys": {}},
        {"mac_keys": {1: KEY}, "current_mac_key_version": 7},
        {"mac_keys": {1: KEY}, "current_mac_key_version": 1.0},
        {"mac_keys": {1: KEY, 0: KEY}},
        {"mac_keys": {1: KEY, -1: KEY}},
        {"mac_keys": {1: KEY, "2": KEY}},
        {"mac_keys": {1: KEY, 2.0: KEY}},
        {"mac_keys": {1: KEY, 2: None}},
        {"mac_keys": {1: KEY, 2: "k" * 32}},
        {"mac_keys": {1: KEY, 2: b"short"}},
    ],
)
async def test_retention_refuses_invalid_key_material_before_touching_storage(options):
    with pytest.raises(ApiError) as caught:
        await _audit.prune_access_logs(SimpleNamespace(), cutoff=AT, **options)
    assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
        500,
        "current audit MAC key is unavailable",
        "audit_integrity_error",
    )


async def test_retention_progress_reports_survivors_and_exhaustion_exactly():
    async with seeded_chain() as (session, rows, state):
        progress = []
        cutoff = AT + timedelta(days=1)
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=cutoff,
                mac_keys={7: KEY},
                current_mac_key_version=7,
                progress_observer=lambda **values: progress.append(values),
            )
            == 1
        )
        assert progress == [
            {
                "backlog": False,
                "next_owner": None,
                "owners_processed": 1,
                "rows_deleted": 1,
                "pending_rows_probe": 0,
                "oldest_pending_at": None,
            }
        ]
        assert state.first_retained_seq == 2 and state.first_retained_hash == rows[1].entry_hash
        assert state.mac_key_version == 7 and state.state_version == 1
        progress.clear()
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=cutoff,
                mac_keys={7: KEY},
                current_mac_key_version=7,
                progress_observer=lambda **values: progress.append(values),
            )
            == 0
        )
        assert progress == [
            {
                "backlog": False,
                "next_owner": None,
                "owners_processed": 0,
                "rows_deleted": 0,
                "pending_rows_probe": 0,
                "oldest_pending_at": None,
            }
        ]
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 2, None, None, 0)
        )


async def test_legacy_bridge_seals_all_retained_rows_and_becomes_a_noop():
    async with seeded_chain() as (session, rows, state):
        state.state_mac = None
        for row in rows:
            row.entry_mac = None
        await session.flush()
        assert (
            await _audit.seal_legacy_audit_states(
                session,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            == 1
        )
        for row in rows:
            assert row.mac_key_version == 7
            assert row.entry_mac == _audit.compute_entry_mac(
                KEY, OWNER, row.chain_seq, row.entry_hash
            )
        assert state.mac_key_version == 7
        assert state.state_mac == _audit.compute_chain_state_mac(KEY, state)
        assert state.updated_at > AT + timedelta(days=2)
        assert (
            await _audit.seal_legacy_audit_states(
                session,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            == 0
        )
        assert await _audit.verify_access_log_chain(session, OWNER, mac_keys={7: KEY}) == (
            _audit.ChainVerification(True, 3, None, None, 0)
        )


@pytest.mark.parametrize(
    "fault",
    [
        "genesis",
        "middle_deleted",
        "hash",
        "mac",
        "missing_key",
        "link",
        "first_hash",
        "head_hash",
        "first_seq",
        "head_seq",
        "empty",
    ],
)
async def test_legacy_bridge_refuses_forged_rows_and_migration_endpoints(fault):
    async with seeded_chain() as (session, rows, state):
        state.state_mac = None
        if fault == "genesis":
            rows[0].prev_hash = "e" * 64
        elif fault == "middle_deleted":
            await session.delete(rows[1])
        elif fault == "hash":
            rows[1].entry_hash = "e" * 64
        elif fault == "mac":
            rows[1].entry_mac = "e" * 64
        elif fault == "missing_key":
            rows[1].mac_key_version = 8
        elif fault == "link":
            row = rows[1]
            row.prev_hash = "e" * 64
            row.entry_hash = _audit.compute_entry_hash(
                row.prev_hash,
                row.actor_id,
                row.user_id,
                row.action,
                row.at,
                actor_role=row.actor_role,
                record_version=2,
            )
            row.entry_mac = _audit.compute_entry_mac(KEY, OWNER, row.chain_seq, row.entry_hash)
        elif fault == "first_hash":
            state.first_retained_hash = "e" * 64
        elif fault == "head_hash":
            state.head_hash = "e" * 64
        elif fault == "first_seq":
            state.first_retained_seq = 2
        elif fault == "head_seq":
            state.head_seq = 4
        elif fault == "empty":
            for row in rows:
                await session.delete(row)
        await session.flush()
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(
                session,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            "legacy audit state failed authenticated verification",
            "audit_integrity_error",
        )
        assert state.state_mac is None


async def test_legacy_bridge_rejects_unknown_current_key_and_bounds_its_work(monkeypatch):
    with pytest.raises(ApiError) as caught:
        await _audit.seal_legacy_audit_states(
            SimpleNamespace(),
            mac_keys={7: KEY},
            current_mac_key_version=8,
        )
    assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
        500,
        "current audit MAC key is unavailable",
        "audit_integrity_error",
    )
    async with seeded_chain() as (session, _rows, state):
        state.state_mac = None
        await session.flush()
        monkeypatch.setattr(_audit, "AUDIT_LEGACY_SEAL_ROW_BUDGET", 2)
        with pytest.raises(ApiError) as caught:
            await _audit.seal_legacy_audit_states(
                session,
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            "legacy audit chain exceeds the bounded online sealing budget",
            "audit_integrity_error",
        )
        assert state.state_mac is None


@pytest.mark.parametrize(
    ("fault", "reason", "checked"),
    [
        ("snapshot_seq_missing", "audit verification checkpoint snapshot is incomplete", 0),
        ("snapshot_hash_missing", "audit verification checkpoint snapshot is incomplete", 0),
        ("head_rollback", "durable audit head moved behind verification snapshot", 0),
        ("finished_wrong_hash", "verification checkpoint does not end at the snapshot head", 0),
        ("missing_page", "verification snapshot row is missing", 0),
        ("gap_page", "chain_seq gap before 3", 0),
        ("snapshot_hash_forged", "verification snapshot head hash differs from captured state", 2),
    ],
)
async def test_incremental_checkpoint_rejects_incomplete_or_rolled_back_snapshots(
    fault, reason, checked
):
    async with seeded_chain() as (session, rows, _state):
        cursor = AuditSweepCursor(
            id=1,
            last_user_id=None,
            verification_owner_id=OWNER,
            verification_snapshot_head_seq=3,
            verification_snapshot_head_hash=rows[-1].entry_hash,
            verification_next_seq=1,
            verification_previous_hash=None,
            verification_rows_checked=0,
        )
        if fault == "snapshot_seq_missing":
            cursor.verification_snapshot_head_seq = None
        elif fault == "snapshot_hash_missing":
            cursor.verification_snapshot_head_hash = None
        elif fault == "head_rollback":
            cursor.verification_snapshot_head_seq = 4
        elif fault == "finished_wrong_hash":
            cursor.verification_next_seq = 4
            cursor.verification_previous_hash = "e" * 64
        elif fault == "missing_page":
            cursor.verification_snapshot_head_seq = 2
            cursor.verification_snapshot_head_hash = rows[1].entry_hash
            cursor.verification_next_seq = 2
            cursor.verification_previous_hash = rows[0].entry_hash
            await session.delete(rows[1])
        elif fault == "gap_page":
            cursor.verification_next_seq = 2
            cursor.verification_previous_hash = rows[0].entry_hash
            await session.delete(rows[1])
        elif fault == "snapshot_hash_forged":
            cursor.verification_snapshot_head_seq = 2
            cursor.verification_snapshot_head_hash = "e" * 64
        _audit.seal_verification_checkpoint(cursor, {7: KEY}, 7)
        await session.flush()
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
        ) == _audit.IncrementalChainVerification(False, False, checked, reason)


@pytest.mark.parametrize("next_seq", [None, 0, 4])
async def test_incremental_resume_recovers_pruned_or_completed_page_boundaries(next_seq):
    async with seeded_chain() as (session, rows, _state):
        cursor = AuditSweepCursor(
            id=1,
            last_user_id=None,
            verification_owner_id=OWNER,
            verification_snapshot_head_seq=3,
            verification_snapshot_head_hash=rows[-1].entry_hash,
            verification_next_seq=next_seq,
            verification_previous_hash=rows[-1].entry_hash if next_seq == 4 else "e" * 64,
            verification_rows_checked=99,
        )
        _audit.seal_verification_checkpoint(cursor, {7: KEY}, 7)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        ) == _audit.IncrementalChainVerification(
            True, next_seq == 4, 0 if next_seq == 4 else 1, None
        )
        if next_seq == 4:
            assert cursor.last_user_id == OWNER
            assert cursor.verification_owner_id is None
            assert cursor.verification_rows_checked == 0
        else:
            assert cursor.verification_next_seq == 2
            assert cursor.verification_previous_hash == rows[0].entry_hash
            assert cursor.verification_rows_checked == 1
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)


async def test_incremental_snapshot_completes_when_pruning_overtakes_its_head():
    async with seeded_chain() as (session, _rows, _state):
        cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        ) == _audit.IncrementalChainVerification(True, False, 1, None)
        await _audit.append_access_log(
            session,
            actor_id=OTHER,
            actor_role="patient",
            user_id=OWNER,
            action="read_entries",
            at=AT + timedelta(days=3),
            mac_keys={7: KEY},
            current_mac_key_version=7,
        )
        assert (
            await _audit.prune_access_logs(
                session,
                cutoff=AT + timedelta(days=3),
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            == 3
        )
        assert await _audit.verify_access_log_chain_incremental(
            session,
            cursor,
            OWNER,
            mac_keys={7: KEY},
            current_mac_key_version=7,
            row_budget=1,
        ) == _audit.IncrementalChainVerification(True, True, 0, None)
        assert cursor.last_user_id == OWNER and cursor.verification_owner_id is None
        assert cursor.verification_rows_checked == 0
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)


async def test_append_requires_registration_authority_and_current_key():
    with pytest.raises(ApiError) as caught:
        await _audit.append_access_log(
            SimpleNamespace(),
            actor_id=OTHER,
            actor_role="patient",
            user_id=OWNER,
            action="read_entries",
            mac_keys={7: KEY},
            current_mac_key_version=8,
        )
    assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
        500,
        "current audit MAC key is unavailable",
        "audit_integrity_error",
    )
    async with seeded_chain() as (session, _rows, _state):
        with pytest.raises(ApiError) as caught:
            await _audit.append_access_log(
                session,
                actor_id=OWNER,
                actor_role="patient",
                user_id=OTHER,
                action="read_entries",
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            "audit chain state is missing",
            "audit_integrity_error",
        )


async def test_append_waits_for_the_patient_lock_shared_with_retention(monkeypatch):
    # Each pytest case has a separate event loop; production has one app loop.
    monkeypatch.setattr(_audit, "_audit_chain_locks", _audit.UserLocks())
    async with seeded_chain() as (session, _rows, _state):
        entered_storage = asyncio.Event()
        started = asyncio.Event()
        scalar = session.scalar

        async def observed_scalar(*args, **kwargs):
            entered_storage.set()
            return await scalar(*args, **kwargs)

        monkeypatch.setattr(session, "scalar", observed_scalar)

        async def append():
            started.set()
            return await _audit.append_access_log(
                session,
                actor_id=OTHER,
                actor_role="patient",
                user_id=OWNER,
                action="read_entries",
                at=AT + timedelta(days=3),
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )

        task = None
        try:
            async with _audit._audit_chain_locks.hold(f"audit-chain:{OWNER}"):
                task = asyncio.create_task(append())
                await asyncio.wait_for(started.wait(), timeout=5)
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(entered_storage.wait(), timeout=0.05)
                assert not task.done()
            assert (await asyncio.wait_for(task, timeout=5)).chain_seq == 4
            assert entered_storage.is_set()
        finally:
            if task is not None:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("operation", ["append", "prune", "incremental"])
async def test_locked_operations_refresh_state_cached_before_another_commit(operation):
    async with seeded_chain() as (session, _rows, state):
        async with build_sessionmaker(session.bind)() as other_session:
            await _audit.append_access_log(
                other_session,
                actor_id=OTHER,
                actor_role="patient",
                user_id=OWNER,
                action="read_entries",
                at=AT + timedelta(days=3),
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            await other_session.commit()
        assert state.head_seq == 3
        if operation == "append":
            row = await _audit.append_access_log(
                session,
                actor_id=OTHER,
                actor_role="patient",
                user_id=OWNER,
                action="read_entries",
                at=AT + timedelta(days=4),
                mac_keys={7: KEY},
                current_mac_key_version=7,
            )
            assert row.chain_seq == 5 and state.head_seq == 5
        elif operation == "prune":
            assert (
                await _audit.prune_access_logs(
                    session,
                    cutoff=AT + timedelta(days=1),
                    mac_keys={7: KEY},
                    current_mac_key_version=7,
                )
                == 1
            )
            assert state.head_seq == 4 and state.first_retained_seq == 2
        else:
            cursor = AuditSweepCursor(id=1, verification_checkpoint_mac=None)
            assert await _audit.verify_access_log_chain_incremental(
                session,
                cursor,
                OWNER,
                mac_keys={7: KEY},
                current_mac_key_version=7,
                row_budget=3,
            ) == _audit.IncrementalChainVerification(True, False, 3, None)
            assert state.head_seq == 4 and cursor.verification_snapshot_head_seq == 4
            assert cursor.verification_next_seq == 4
