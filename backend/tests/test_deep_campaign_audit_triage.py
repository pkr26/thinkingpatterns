"""Independent durable-state oracles for audit mutation survivors.

Authenticated negative fixtures isolate structural invariants from MAC/link
checks. The test signer uses hashlib/hmac directly and never disables a
production authenticator or verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from app.api import _audit as audit
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError
from app.models import AccessLog, AuditChainState, AuditSweepCursor, Base, new_id, utcnow

KEY = b"independent-audit-integrity-key!"
AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _canonical(at):
    return at.astimezone(timezone.utc).isoformat()


def _hash_row(row):
    payload = json.dumps(
        [
            row.prev_hash or "",
            row.actor_id,
            row.user_id,
            row.action,
            _canonical(row.at),
            row.actor_role,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _row_mac(row):
    return hmac.new(
        KEY, f"{row.user_id}:{row.chain_seq}:{row.entry_hash}".encode(), hashlib.sha256
    ).hexdigest()


def _state_mac(state):
    payload = json.dumps(
        [
            state.state_version,
            state.mac_key_version,
            state.user_id,
            state.head_seq,
            state.head_hash,
            _canonical(state.head_at),
            state.first_retained_seq,
            state.first_retained_hash,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()


def _checkpoint_mac(cursor):
    payload = json.dumps(
        [
            "mindpattern/audit-verification-checkpoint/v1",
            cursor.id,
            cursor.last_user_id,
            cursor.verification_owner_id,
            cursor.verification_snapshot_head_seq,
            cursor.verification_snapshot_head_hash,
            cursor.verification_next_seq,
            cursor.verification_previous_hash,
            cursor.verification_rows_checked,
            cursor.verification_mac_key_version,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()


def _assert_seals(rows, state):
    assert len(KEY) == 32
    for row in rows:
        assert row.record_version == 2
        assert row.entry_hash == _hash_row(row)
        assert row.entry_mac == _row_mac(row)
    assert state.state_mac == _state_mac(state)


@pytest_asyncio.fixture
async def audit_sessions():
    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield build_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _append(session, owner, index, *, genesis=False):
    return await audit.append_access_log(
        session,
        actor_id="a" * 32,
        actor_role="user",
        user_id=owner,
        action=f"read-{index}",
        at=AT + timedelta(seconds=index),
        mac_keys={1: KEY},
        current_mac_key_version=1,
        allow_new_chain=genesis,
    )


async def test_ordinary_audit_append_cannot_restart_an_erased_database_trail(
    audit_sessions, tmp_path
):
    owner = new_id()
    journal = tmp_path / "audit.journal"
    async with audit_sessions() as session:
        rows = [await _append(session, owner, i, genesis=i == 0) for i in range(2)]
        state = await session.get(AuditChainState, owner)
        _assert_seals(rows, state)
        await session.commit()
        assert await audit.flush_audit_journal(session, str(journal)) == 2
    evidence = audit.read_journal_evidence(str(journal))[owner]
    assert evidence.seq == 2 and evidence.entry_hash == rows[-1].entry_hash
    durable_journal = journal.read_bytes()

    # A database writer can erase both markers. Only the registration path
    # has permission to create a genesis; ordinary reads cannot infer it.
    async with audit_sessions() as session:
        await session.execute(delete(AccessLog).where(AccessLog.user_id == owner))
        await session.execute(delete(AuditChainState).where(AuditChainState.user_id == owner))
        await session.commit()
    async with audit_sessions() as session:
        with pytest.raises(ApiError) as failure:
            await _append(session, owner, 2)
        assert (failure.value.status_code, failure.value.code) == (500, "audit_integrity_error")
        assert "state is missing" in failure.value.detail
        await session.rollback()
    async with audit_sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AccessLog)) == 0
        assert await session.get(AuditChainState, owner) is None
    assert journal.read_bytes() == durable_journal


@pytest.mark.parametrize("sequences", [(1, 2), (1, 3)], ids=["consecutive", "signed-gap"])
async def test_incremental_checkpoint_never_advances_across_an_authenticated_sequence_gap(
    audit_sessions, tmp_path, sequences
):
    owner = new_id()
    rows = []
    previous = None
    for sequence in sequences:
        row = AccessLog(
            id=new_id(),
            actor_id="a" * 32,
            actor_role="user",
            user_id=owner,
            action=f"read-{sequence}",
            at=AT + timedelta(seconds=sequence),
            chain_seq=sequence,
            prev_hash=previous,
            mac_key_version=1,
            record_version=2,
        )
        row.entry_hash = _hash_row(row)
        row.entry_mac = _row_mac(row)
        previous = row.entry_hash
        rows.append(row)
    state = AuditChainState(
        user_id=owner,
        head_seq=rows[-1].chain_seq,
        head_hash=rows[-1].entry_hash,
        head_at=rows[-1].at,
        first_retained_seq=1,
        first_retained_hash=rows[0].entry_hash,
        state_version=1,
        mac_key_version=1,
        updated_at=AT,
    )
    state.state_mac = _state_mac(state)
    _assert_seals(rows, state)
    async with audit_sessions() as session:
        session.add_all([*rows, state])
        await session.commit()
    journal = tmp_path / "audit.journal"
    journal.write_text(
        "".join(
            f"{owner} {row.chain_seq} {row.entry_hash} {row.entry_mac} {_canonical(row.at)}\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    async with audit_sessions() as session:
        cursor = AuditSweepCursor(id=1, updated_at=utcnow())
        session.add(cursor)
        verdict = await audit.verify_access_log_chain_incremental(
            session,
            cursor,
            owner,
            mac_keys={1: KEY},
            current_mac_key_version=1,
            journal_evidence=audit.read_journal_evidence(str(journal)),
            row_budget=2,
        )
        if sequences == (1, 2):
            assert verdict.ok and verdict.complete and verdict.rows_checked == 2
            assert cursor.last_user_id == owner
            assert cursor.verification_checkpoint_mac == _checkpoint_mac(cursor)
        else:
            assert not verdict.ok and not verdict.complete
            assert verdict.reason == "chain_seq gap before 3"
            assert cursor.last_user_id is None
            assert cursor.verification_next_seq == 1
            assert cursor.verification_previous_hash is None
            assert cursor.verification_rows_checked == 0


async def test_incremental_snapshot_rejects_an_authenticated_alternate_historical_tail(
    audit_sessions, tmp_path
):
    owner = new_id()
    journal = tmp_path / "audit.journal"
    async with audit_sessions() as session:
        old_rows = [await _append(session, owner, i, genesis=i == 0) for i in range(2)]
        await session.commit()
        assert await audit.flush_audit_journal(session, str(journal)) == 2
        cursor = AuditSweepCursor(id=1, updated_at=utcnow())
        session.add(cursor)
        first = await audit.verify_access_log_chain_incremental(
            session,
            cursor,
            owner,
            mac_keys={1: KEY},
            current_mac_key_version=1,
            journal_evidence=audit.read_journal_evidence(str(journal)),
            row_budget=1,
        )
        assert first.ok and not first.complete and first.rows_checked == 1
        await session.commit()
        captured_hash = cursor.verification_snapshot_head_hash
        assert captured_hash == old_rows[-1].entry_hash
        assert cursor.verification_checkpoint_mac == _checkpoint_mac(cursor)

    # Live appends may extend the captured snapshot. Model an authenticated
    # alternate history below that live head: row seals and state seal are
    # valid, but they cannot substitute for the previously captured tail.
    # The journal may legitimately lag at the older, fsynced snapshot.
    async with audit_sessions() as session:
        await _append(session, owner, 2)
        await session.commit()
    async with audit_sessions() as session:
        rows = list(
            (
                await session.scalars(
                    select(AccessLog)
                    .where(AccessLog.user_id == owner)
                    .order_by(AccessLog.chain_seq)
                )
            ).all()
        )
        rows[1].action = "alternate-read"
        rows[1].entry_hash = _hash_row(rows[1])
        rows[1].entry_mac = _row_mac(rows[1])
        rows[2].prev_hash = rows[1].entry_hash
        rows[2].entry_hash = _hash_row(rows[2])
        rows[2].entry_mac = _row_mac(rows[2])
        state = await session.get(AuditChainState, owner)
        state.head_hash = rows[-1].entry_hash
        state.state_mac = _state_mac(state)
        _assert_seals(rows, state)
        await session.commit()

    async with audit_sessions() as session:
        evidence = audit.read_journal_evidence(str(journal))
        diagnostic = await audit.verify_access_log_chain(
            session, owner, mac_keys={1: KEY}, journal_evidence=evidence
        )
        assert diagnostic.ok and diagnostic.rows_checked == 3
        cursor = await session.get(AuditSweepCursor, 1)
        assert cursor.verification_checkpoint_mac == _checkpoint_mac(cursor)
        assert cursor.verification_snapshot_head_hash == captured_hash
        verdict = await audit.verify_access_log_chain_incremental(
            session,
            cursor,
            owner,
            mac_keys={1: KEY},
            current_mac_key_version=1,
            journal_evidence=evidence,
            row_budget=1,
        )
        assert not verdict.ok and not verdict.complete and verdict.rows_checked == 1
        assert verdict.reason == "verification snapshot head hash differs from captured state"
        assert cursor.last_user_id is None
