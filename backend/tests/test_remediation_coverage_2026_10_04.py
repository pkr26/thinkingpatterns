"""Meaningful branch and fault coverage for RVI-069 remediation paths."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app import config as config_mod
from app.api import _audit as audit_mod
from app.api import _sharing_state as sharing_state
from app.config import Settings
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError
from app.models import (
    ROLE_THERAPIST,
    AccessLog,
    AccountDeletionJob,
    AudioAttachment,
    AudioDeletion,
    AudioInventoryCursor,
    AuditChainState,
    AuditSweepCursor,
    Base,
    Consent,
    Entry,
    User,
    new_id,
    utcnow,
)
from app.security import deletion_tombstone, step_up
from app.services import account_deletion, audio_store


def _user(identifier: str, username: str, *, role: str = "user", active: bool = True) -> User:
    return User(
        id=identifier,
        username=username,
        salt="public-salt",
        verifier=b"v" * 32,
        scrypt_salt=b"s" * 16,
        role=role,
        is_active=active,
    )


@pytest_asyncio.fixture
async def coverage_sessionmaker():
    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield build_sessionmaker(engine)
    await engine.dispose()


class _Rows:
    def __init__(self, *, first=None, rows=()):
        self._first = first
        self._rows = list(rows)

    def first(self):
        return self._first

    def all(self):
        return list(self._rows)


class _AuditSession:
    """Small deterministic seam for integrity-verifier query results."""

    def __init__(self, *, scalar_values=(), tail=None, page=()):
        self._scalar_values = iter(scalar_values)
        self._tail = tail
        self._page = page

    async def scalar(self, _query):
        return next(self._scalar_values)

    async def execute(self, _query):
        return _Rows(first=self._tail)

    async def scalars(self, _query):
        return _Rows(rows=self._page)


class _Stream:
    def __init__(self, rows):
        self._rows = list(rows)
        self.closed = False

    def __aiter__(self):
        self._iterator = iter(self._rows)
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration:
            raise StopAsyncIteration from None

    async def close(self):
        self.closed = True


class _VerifySession:
    def __init__(self, *, state=None, row_exists=None, rows=()):
        self.state = state
        self.row_exists = row_exists
        self.stream = _Stream(rows)
        self.flushed = False

    async def get(self, _model, _identifier):
        return self.state

    async def scalar(self, _query):
        return self.row_exists

    async def stream_scalars(self, _query):
        return self.stream

    async def flush(self):
        self.flushed = True


def _cursor() -> AuditSweepCursor:
    return AuditSweepCursor(id=1, verification_rows_checked=0, updated_at=utcnow())


def _state(
    owner: str,
    key: bytes,
    *,
    head_seq: int = 1,
    head_hash: str = "a" * 64,
    first_retained_seq: int | None = 1,
    first_retained_hash: str | None = None,
    head_at: datetime | None = None,
) -> AuditChainState:
    state = AuditChainState(
        user_id=owner,
        head_seq=head_seq,
        head_hash=head_hash,
        head_at=head_at or utcnow(),
        first_retained_seq=first_retained_seq,
        first_retained_hash=(
            head_hash
            if first_retained_hash is None and first_retained_seq is not None
            else first_retained_hash
        ),
        state_version=1,
        mac_key_version=1,
        updated_at=utcnow(),
    )
    state.state_mac = audit_mod.compute_chain_state_mac(key, state)
    return state


def _audit_row(
    owner: str,
    key: bytes,
    *,
    seq: int = 1,
    previous_hash: str | None = None,
) -> AccessLog:
    occurred = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    row = AccessLog(
        id=new_id(),
        actor_id=new_id(),
        actor_role="user",
        user_id=owner,
        action="coverage_check",
        at=occurred,
        chain_seq=seq,
        prev_hash=previous_hash,
        mac_key_version=1,
        record_version=2,
    )
    row.entry_hash = audit_mod.compute_entry_hash(
        previous_hash,
        row.actor_id,
        owner,
        row.action,
        occurred,
        actor_role=row.actor_role,
        record_version=row.record_version,
    )
    row.entry_mac = audit_mod.compute_entry_mac(key, owner, seq, row.entry_hash)
    return row


def test_audit_journal_parser_and_spooled_index_fail_closed(tmp_path, caplog):
    owner = "a" * 32
    other = "b" * 32
    occurred = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    valid = f"{owner} 1 {'1' * 64} {'2' * 64} {occurred}"

    assert audit_mod._parse_journal_line("   \n") is None
    assert audit_mod._parse_journal_line(valid) == (
        owner,
        1,
        "1" * 64,
        "2" * 64,
        occurred,
    )
    invalid_lines = (
        "too few fields",
        f"not-an-owner 1 {'1' * 64} {'2' * 64} {occurred}",
        f"{owner} 01 {'1' * 64} {'2' * 64} {occurred}",
        f"{owner} 1 bad {'2' * 64} {occurred}",
        f"{owner} 1 {'1' * 64} bad {occurred}",
        f"{owner} 1 {'1' * 64} {'2' * 64} 2026-01-01T00:00:00",
        f"{owner} 1 {'1' * 64} {'2' * 64} 2026-01-01T01:00:00+01:00",
    )
    for line in invalid_lines:
        with pytest.raises(ValueError):
            audit_mod._parse_journal_line(line)

    journal = tmp_path / "audit.journal"
    journal.write_text(
        "\n".join(
            (
                valid,
                f"{other} 2 {'3' * 64} {'4' * 64} {occurred}",
                f"{other} 2 {'5' * 64} {'6' * 64} {occurred}",
                "malformed evidence",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    caplog.set_level(logging.ERROR, logger="mindpattern.audit")
    index = audit_mod.build_journal_evidence_index(str(journal))
    assert index.corrupt
    assert index.get(owner) is not None
    assert index.get(other).conflict
    assert index.owner_ids_after(None, 10) == [owner, other]
    assert index.owner_ids_after(owner, 10) == [other]
    assert index.owner_ids_through(owner, 10) == [owner]
    assert audit_mod.JOURNAL_CORRUPTION_KEY in index.all_evidence()
    assert owner not in caplog.text and other not in caplog.text
    index.close()
    index.close()
    with pytest.raises(RuntimeError, match="closed"):
        index.apply_entries([(owner, 3, "7" * 64, "8" * 64, occurred)])

    assert audit_mod.journal_owner_status(str(tmp_path / "missing"), owner) == (False, True)


def test_audit_journal_configuration_and_checkpoint_key_validation(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="is empty"):
        audit_mod.validate_audit_journal_path("")
    with pytest.raises(RuntimeError, match="parent directory"):
        audit_mod.validate_audit_journal_path(str(tmp_path / "missing" / "journal"))

    closed = []
    monkeypatch.setattr(
        audit_mod, "close_reusable_journal_evidence_index", lambda: closed.append(1)
    )
    audit_mod.configure_audit_mac_key(b"k" * 32, str(tmp_path / "first"))
    audit_mod.configure_audit_mac_key(b"k" * 32, str(tmp_path / "second"))
    assert closed
    with pytest.raises(ApiError, match="current audit MAC key is unavailable"):
        audit_mod.seal_verification_checkpoint(_cursor(), {}, 1)


async def test_incremental_verifier_rejects_owner_and_missing_state_faults():
    key = b"k" * 32
    owner = new_id()

    with pytest.raises(ValueError, match="row budget"):
        await audit_mod.verify_access_log_chain_incremental(
            _AuditSession(),
            _cursor(),
            owner,
            mac_keys={1: key},
            current_mac_key_version=1,
            row_budget=0,
        )

    foreign_cursor = _cursor()
    foreign_cursor.verification_owner_id = new_id()
    audit_mod.seal_verification_checkpoint(foreign_cursor, {1: key}, 1)
    verdict = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(),
        foreign_cursor,
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not verdict.ok and "owner differs" in verdict.reason

    corrupt = {audit_mod.JOURNAL_CORRUPTION_KEY: audit_mod.JournalEvidence(0, "", "", "", True)}
    conflict = {owner: audit_mod.JournalEvidence(1, "a" * 64, "b" * 64, "at", True)}
    evidence = {owner: audit_mod.JournalEvidence(1, "a" * 64, "b" * 64, "at")}
    cases = (
        (_AuditSession(scalar_values=[None]), corrupt, "unavailable or malformed"),
        (_AuditSession(scalar_values=[None]), conflict, "sequence conflict"),
        (_AuditSession(scalar_values=[None, None]), evidence, "chain state is missing"),
        (_AuditSession(scalar_values=[None, new_id()]), {}, "chain state is missing"),
    )
    for session, journal, reason in cases:
        verdict = await audit_mod.verify_access_log_chain_incremental(
            session,
            _cursor(),
            owner,
            mac_keys={1: key},
            current_mac_key_version=1,
            journal_evidence=journal,
        )
        assert not verdict.ok and reason in verdict.reason

    cursor = _cursor()
    clean = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(scalar_values=[None, None]),
        cursor,
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert clean.ok and clean.complete and cursor.last_user_id == owner


async def test_incremental_verifier_rejects_state_tail_and_journal_discontinuities():
    key = b"s" * 32
    owner = new_id()

    invalid_state = _state(owner, key)
    invalid_state.state_mac = "0" * 64
    cases = [
        (
            _AuditSession(scalar_values=[invalid_state]),
            {},
            None,
            "state MAC does not verify",
        ),
        (
            _AuditSession(scalar_values=[_state(owner, key)]),
            {owner: audit_mod.JournalEvidence(2, "b" * 64, "c" * 64, "at")},
            None,
            "journal differs",
        ),
        (
            _AuditSession(scalar_values=[_state(owner, key)], tail=None),
            {},
            None,
            "expects retained rows",
        ),
        (
            _AuditSession(scalar_values=[_state(owner, key, first_retained_seq=None)], tail=None),
            {},
            None,
            "not explained",
        ),
        (
            _AuditSession(scalar_values=[_state(owner, key)], tail=(2, "a" * 64, "b" * 64)),
            {},
            None,
            "database tail differs",
        ),
        (
            _AuditSession(
                scalar_values=[_state(owner, key)],
                tail=(1, "a" * 64, "b" * 64),
            ),
            {owner: audit_mod.JournalEvidence(1, "a" * 64, "c" * 64, "at")},
            None,
            "journal differs",
        ),
    ]
    for session, journal, cutoff, reason in cases:
        verdict = await audit_mod.verify_access_log_chain_incremental(
            session,
            _cursor(),
            owner,
            mac_keys={1: key},
            current_mac_key_version=1,
            journal_evidence=journal,
            retention_cutoff=cutoff,
        )
        assert not verdict.ok and reason in verdict.reason

    old_state = _state(
        owner,
        key,
        first_retained_seq=None,
        head_at=utcnow() - timedelta(days=40),
    )
    cursor = _cursor()
    explained = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(scalar_values=[old_state], tail=None),
        cursor,
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
        retention_cutoff=utcnow() - timedelta(days=30),
    )
    assert explained.ok and explained.complete and cursor.last_user_id == owner


async def test_incremental_verifier_rejects_page_boundary_faults():
    key = b"p" * 32
    owner = new_id()

    row = _audit_row(owner, key)
    state = _state(owner, key, head_hash=row.entry_hash)
    tail = (1, row.entry_hash, row.entry_mac)
    empty = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(scalar_values=[state], tail=tail, page=[]),
        _cursor(),
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not empty.ok and "snapshot row is missing" in empty.reason

    gap_row = _audit_row(owner, key, seq=2, previous_hash="a" * 64)
    gap_state = _state(
        owner,
        key,
        head_seq=2,
        head_hash=gap_row.entry_hash,
        first_retained_hash="a" * 64,
    )
    gap = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(
            scalar_values=[gap_state],
            tail=(2, gap_row.entry_hash, gap_row.entry_mac),
            page=[gap_row],
        ),
        _cursor(),
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not gap.ok and "chain_seq gap" in gap.reason

    anchor_state = _state(owner, key, head_hash="f" * 64)
    anchor = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(
            scalar_values=[anchor_state],
            tail=(1, "f" * 64, row.entry_mac),
            page=[row],
        ),
        _cursor(),
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not anchor.ok and "retained-prefix anchor" in anchor.reason

    retained_row = _audit_row(owner, key, seq=2, previous_hash=None)
    retained_state = _state(
        owner,
        key,
        head_seq=2,
        head_hash=retained_row.entry_hash,
        first_retained_seq=2,
    )
    malformed = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(
            scalar_values=[retained_state],
            tail=(2, retained_row.entry_hash, retained_row.entry_mac),
            page=[retained_row],
        ),
        _cursor(),
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not malformed.ok and "predecessor is malformed" in malformed.reason

    linked_row = _audit_row(owner, key, seq=2, previous_hash="b" * 64)
    linked_state = _state(
        owner,
        key,
        head_seq=2,
        head_hash=linked_row.entry_hash,
        first_retained_hash="a" * 64,
    )
    linked_cursor = _cursor()
    linked_cursor.verification_owner_id = owner
    linked_cursor.verification_snapshot_head_seq = 2
    linked_cursor.verification_snapshot_head_hash = linked_row.entry_hash
    linked_cursor.verification_next_seq = 2
    linked_cursor.verification_previous_hash = "a" * 64
    audit_mod.seal_verification_checkpoint(linked_cursor, {1: key}, 1)
    unlinked = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(
            scalar_values=[linked_state],
            tail=(2, linked_row.entry_hash, linked_row.entry_mac),
            page=[linked_row],
        ),
        linked_cursor,
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not unlinked.ok and "does not link" in unlinked.reason

    tampered = _audit_row(owner, key)
    tampered.entry_hash = "e" * 64
    tampered.entry_mac = audit_mod.compute_entry_mac(key, owner, 1, tampered.entry_hash)
    tampered_state = _state(owner, key, head_hash=tampered.entry_hash)
    corrupt_row = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(
            scalar_values=[tampered_state],
            tail=(1, tampered.entry_hash, tampered.entry_mac),
            page=[tampered],
        ),
        _cursor(),
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not corrupt_row.ok and "entry_hash does not match" in corrupt_row.reason

    snapshot_cursor = _cursor()
    snapshot_cursor.verification_owner_id = owner
    snapshot_cursor.verification_snapshot_head_seq = 1
    snapshot_cursor.verification_snapshot_head_hash = "d" * 64
    snapshot_cursor.verification_next_seq = 1
    audit_mod.seal_verification_checkpoint(snapshot_cursor, {1: key}, 1)
    snapshot = await audit_mod.verify_access_log_chain_incremental(
        _AuditSession(scalar_values=[state], tail=tail, page=[row]),
        snapshot_cursor,
        owner,
        mac_keys={1: key},
        current_mac_key_version=1,
    )
    assert not snapshot.ok and "snapshot head hash" in snapshot.reason


async def test_full_audit_verifier_rejects_missing_or_unauthenticated_state():
    key = b"f" * 32
    owner = new_id()
    evidence = audit_mod.JournalEvidence(1, "a" * 64, "b" * 64, utcnow().isoformat())

    corrupt = await audit_mod.verify_access_log_chain(
        _VerifySession(),
        owner,
        mac_keys={1: key},
        journal_evidence={audit_mod.JOURNAL_CORRUPTION_KEY: evidence},
    )
    assert not corrupt.ok and "unavailable or malformed" in corrupt.reason
    conflict = await audit_mod.verify_access_log_chain(
        _VerifySession(),
        owner,
        mac_keys={1: key},
        journal_evidence={owner: audit_mod.JournalEvidence(1, "a", "b", "at", True)},
    )
    assert not conflict.ok and "sequence conflict" in conflict.reason

    for session, journal, reason in (
        (_VerifySession(), {owner: evidence}, "chain state is missing"),
        (_VerifySession(row_exists=new_id()), {}, "chain state is missing"),
    ):
        verdict = await audit_mod.verify_access_log_chain(
            session,
            owner,
            mac_keys={1: key},
            journal_evidence=journal,
        )
        assert not verdict.ok and reason in verdict.reason
    clean = await audit_mod.verify_access_log_chain(
        _VerifySession(), owner, mac_keys={1: key}, journal_evidence={}
    )
    assert clean.ok and clean.rows_checked == 0

    unsealed = _state(owner, key)
    unsealed.state_mac = None
    unknown_key = _state(owner, key)
    unknown_key.mac_key_version = 2
    invalid_mac = _state(owner, key)
    invalid_mac.state_mac = "0" * 64
    for state, reason in (
        (unsealed, "state is unsealed"),
        (unknown_key, "key version 2 is unavailable"),
        (invalid_mac, "state MAC does not verify"),
    ):
        verdict = await audit_mod.verify_access_log_chain(
            _VerifySession(state=state), owner, mac_keys={1: key}
        )
        assert not verdict.ok and reason in verdict.reason


async def test_full_audit_verifier_rejects_each_row_integrity_fault():
    key = b"r" * 32
    owner = new_id()

    def state_for(rows):
        return _state(
            owner,
            key,
            head_seq=rows[-1].chain_seq,
            head_hash=rows[-1].entry_hash or "0" * 64,
            first_retained_seq=rows[0].chain_seq,
            first_retained_hash=rows[0].entry_hash or "0" * 64,
        )

    genesis = _audit_row(owner, key, previous_hash="a" * 64)
    non_genesis = _audit_row(owner, key, seq=2, previous_hash=None)
    first_for_gap = _audit_row(owner, key)
    gap = _audit_row(owner, key, seq=3, previous_hash=first_for_gap.entry_hash)
    malformed_hash = _audit_row(owner, key)
    malformed_hash.entry_hash = None
    wrong_hash = _audit_row(owner, key)
    wrong_hash.entry_hash = "0" * 64
    first_for_link = _audit_row(owner, key)
    bad_link = _audit_row(owner, key, seq=2, previous_hash="b" * 64)
    missing_mac = _audit_row(owner, key)
    missing_mac.entry_mac = None
    unknown_key = _audit_row(owner, key)
    unknown_key.mac_key_version = 2
    bad_mac = _audit_row(owner, key)
    bad_mac.entry_mac = "0" * 64

    cases = (
        ([genesis], "genesis row carries"),
        ([non_genesis], "non-genesis row has no prev_hash"),
        ([first_for_gap, gap], "chain_seq gap"),
        ([malformed_hash], "malformed entry_hash"),
        ([wrong_hash], "entry_hash does not match"),
        ([first_for_link, bad_link], "prev_hash does not link"),
        ([missing_mac], "missing entry_mac"),
        ([unknown_key], "key version 2 is unavailable"),
        ([bad_mac], "entry_mac does not verify"),
    )
    for rows, reason in cases:
        verdict = await audit_mod.verify_access_log_chain(
            _VerifySession(state=state_for(rows), rows=rows),
            owner,
            mac_keys={1: key},
        )
        assert not verdict.ok and reason in verdict.reason


async def test_full_audit_verifier_enforces_empty_trail_anchors_and_journal_tail():
    key = b"t" * 32
    owner = new_id()
    cutoff = utcnow() - timedelta(days=30)

    retained = await audit_mod.verify_access_log_chain(
        _VerifySession(state=_state(owner, key)),
        owner,
        mac_keys={1: key},
        retention_cutoff=cutoff,
    )
    assert not retained.ok and "expects retained rows" in retained.reason
    recent = await audit_mod.verify_access_log_chain(
        _VerifySession(state=_state(owner, key, first_retained_seq=None)),
        owner,
        mac_keys={1: key},
        retention_cutoff=cutoff,
    )
    assert not recent.ok and "not explained" in recent.reason

    future_evidence = audit_mod.JournalEvidence(
        1, "a" * 64, "b" * 64, (utcnow() + timedelta(days=1)).isoformat()
    )
    journal_tail = await audit_mod.verify_access_log_chain(
        _VerifySession(),
        owner,
        mac_keys={},
        journal_evidence={owner: future_evidence},
        retention_cutoff=cutoff,
    )
    assert not journal_tail.ok and "tail truncation" in journal_tail.reason
    malformed_time = await audit_mod.verify_access_log_chain(
        _VerifySession(),
        owner,
        mac_keys={},
        journal_evidence={owner: audit_mod.JournalEvidence(1, "a", "b", "not-a-time")},
        retention_cutoff=cutoff,
    )
    assert malformed_time.ok

    row = _audit_row(owner, key)
    wrong_anchor = _state(owner, key, head_hash=row.entry_hash, first_retained_hash="a" * 64)
    anchor = await audit_mod.verify_access_log_chain(
        _VerifySession(state=wrong_anchor, rows=[row]), owner, mac_keys={1: key}
    )
    assert not anchor.ok and "retained-prefix anchor" in anchor.reason
    wrong_tail = _state(owner, key, head_seq=2, head_hash="c" * 64)
    wrong_tail.first_retained_seq = 1
    wrong_tail.first_retained_hash = row.entry_hash
    wrong_tail.state_mac = audit_mod.compute_chain_state_mac(key, wrong_tail)
    tail = await audit_mod.verify_access_log_chain(
        _VerifySession(state=wrong_tail, rows=[row]), owner, mac_keys={1: key}
    )
    assert not tail.ok and "database tail differs" in tail.reason

    for journal, legacy_head, reason in (
        (
            {owner: audit_mod.JournalEvidence(2, "c" * 64, "d" * 64, "at")},
            None,
            "journal is ahead",
        ),
        (
            {owner: audit_mod.JournalEvidence(1, row.entry_hash, "d" * 64, "at")},
            None,
            "journal seal conflicts",
        ),
        ({}, (2, "at"), "journal is ahead"),
    ):
        verdict = await audit_mod.verify_access_log_chain(
            _VerifySession(state=_state(owner, key, head_hash=row.entry_hash), rows=[row]),
            owner,
            mac_keys={1: key},
            journal_evidence=journal or None,
            journal_heads={owner: legacy_head} if legacy_head is not None else None,
        )
        assert not verdict.ok and reason in verdict.reason

    legacy = _audit_row(owner, key)
    legacy.entry_mac = None
    accepted = await audit_mod.verify_access_log_chain(
        _VerifySession(rows=[legacy]), owner, mac_keys={}
    )
    assert accepted.ok and accepted.legacy_rows == 1


async def test_legacy_audit_sealing_authenticates_rows_and_rejects_bad_or_oversized_chains(
    coverage_sessionmaker, monkeypatch
):
    key = b"l" * 32
    owner = new_id()
    row = _audit_row(owner, key)
    row.entry_mac = None
    state = _state(owner, key, head_hash=row.entry_hash)
    state.state_mac = None
    async with coverage_sessionmaker() as session:
        session.add_all([row, state])
        await session.commit()
        with pytest.raises(ApiError, match="current audit MAC key"):
            await audit_mod.seal_legacy_audit_states(
                session, mac_keys={}, current_mac_key_version=1
            )
        assert (
            await audit_mod.seal_legacy_audit_states(
                session, mac_keys={1: key}, current_mac_key_version=1
            )
            == 1
        )
        assert row.entry_mac == audit_mod.compute_entry_mac(key, owner, 1, row.entry_hash)
        assert state.state_mac == audit_mod.compute_chain_state_mac(key, state)
        await session.commit()

    empty_owner = new_id()
    empty_state = _state(empty_owner, key)
    empty_state.state_mac = None
    async with coverage_sessionmaker() as session:
        session.add(empty_state)
        await session.commit()
        with pytest.raises(ApiError, match="failed authenticated verification"):
            await audit_mod.seal_legacy_audit_states(
                session, mac_keys={1: key}, current_mac_key_version=1
            )
        await session.rollback()
        await session.delete(empty_state)
        await session.commit()

    large_owner = new_id()
    first = _audit_row(large_owner, key)
    second = _audit_row(large_owner, key, seq=2, previous_hash=first.entry_hash)
    first.entry_mac = None
    second.entry_mac = None
    large_state = _state(
        large_owner,
        key,
        head_seq=2,
        head_hash=second.entry_hash,
        first_retained_hash=first.entry_hash,
    )
    large_state.state_mac = None
    async with coverage_sessionmaker() as session:
        session.add_all([first, second, large_state])
        await session.commit()
        monkeypatch.setattr(audit_mod, "AUDIT_LEGACY_SEAL_ROW_BUDGET", 1)
        with pytest.raises(ApiError, match="exceeds the bounded online sealing budget"):
            await audit_mod.seal_legacy_audit_states(
                session, mac_keys={1: key}, current_mac_key_version=1
            )
        await session.rollback()


async def test_s3_inventory_is_bounded_ordered_and_requires_timestamps():
    modified = datetime(2026, 1, 1, tzinfo=timezone.utc)

    class Client:
        def __init__(self):
            self.kwargs = None
            self.response = {
                "Contents": [
                    {"Key": "audio/c.enc", "LastModified": modified},
                    {"Key": "audio/a.enc", "LastModified": modified},
                    {"Key": "audio/b.enc", "LastModified": modified},
                ],
                "IsTruncated": False,
            }

        def list_objects_v2(self, **kwargs):
            self.kwargs = kwargs
            return self.response

    client = Client()
    store = audio_store.S3AudioStore("private-bucket")
    store._client = client
    page, next_after = await store.inventory_page(after_key="audio/0.enc", limit=2)
    assert [key for key, _ in page] == ["audio/a.enc", "audio/b.enc"]
    assert next_after == "audio/b.enc"
    assert client.kwargs == {
        "Bucket": "private-bucket",
        "Prefix": "audio/",
        "MaxKeys": 2,
        "StartAfter": "audio/0.enc",
    }

    client.response = {"Contents": [{"Key": "audio/no-date.enc"}]}
    with pytest.raises(audio_store.AudioStoreError, match="inventory failed") as excinfo:
        await store.inventory_page(after_key=None, limit=1)
    assert isinstance(excinfo.value.__cause__, ValueError)
    with pytest.raises(ValueError, match="positive"):
        await store.inventory_page(after_key=None, limit=0)


async def test_local_inventory_recovers_corruption_and_rejects_symlink(tmp_path):
    corrupt_root = tmp_path / "corrupt"
    object_path = corrupt_root / "audio" / ("a" * 32) / "object.enc"
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(b"opaque")
    (corrupt_root / audio_store.LocalAudioStore._MANIFEST_NAME).write_bytes(b"not sqlite")
    store = audio_store.LocalAudioStore(str(corrupt_root))
    page, _ = await store.inventory_page(after_key=None, limit=10)
    assert [key for key, _ in page] == [f"audio/{'a' * 32}/object.enc"]
    assert object_path.read_bytes() == b"opaque"

    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir()
    target = tmp_path / "operator-file"
    target.write_text("preserve", encoding="utf-8")
    (unsafe_root / audio_store.LocalAudioStore._MANIFEST_NAME).symlink_to(target)
    unsafe = audio_store.LocalAudioStore(str(unsafe_root))
    with pytest.raises(audio_store.AudioStoreError, match="unsafe"):
        await unsafe.inventory_page(after_key=None, limit=10)
    assert target.read_text(encoding="utf-8") == "preserve"


async def test_local_inventory_repairs_stale_manifest_and_bounds_reads(tmp_path):
    store = audio_store.LocalAudioStore(str(tmp_path / "audio"))
    first = f"audio/{'a' * 32}/first.enc"
    second = f"audio/{'b' * 32}/second.enc"
    await store.put(first, b"first")
    await store.put(second, b"second")
    initial, _ = await store.inventory_page(after_key=None, limit=10)
    assert [key for key, _ in initial] == [first, second]

    store._path(first).unlink()
    future = (utcnow() + timedelta(seconds=2)).timestamp()
    os.utime(store._path(second), (future, future))
    repaired, _ = await store.inventory_page(after_key="audio/", limit=10)
    assert [key for key, _ in repaired] == [second]

    with pytest.raises(audio_store.AudioStoreError, match="local audio get failed") as excinfo:
        await store.get(second, max_bytes=3)
    assert isinstance(excinfo.value.__cause__, ValueError)
    with pytest.raises(audio_store.AudioStoreError, match="missing"):
        await store.get(first)
    with pytest.raises(audio_store.AudioStoreError, match="escapes"):
        await store.get("../../outside")
    with pytest.raises(ValueError, match="positive"):
        await store.inventory_page(after_key=None, limit=0)


async def test_audio_reconciliation_cursor_and_backlog_are_durable(
    coverage_sessionmaker,
):
    settings = Settings(environment="development")
    progress = []

    class NoInventory:
        backend = "adapter"

    async with coverage_sessionmaker() as session:
        assert (
            await audio_store.reconcile_audio_inventory(
                session,
                NoInventory(),
                settings,
                progress_observer=lambda **values: progress.append(values),
            )
            == 0
        )
    assert progress == [{"scanned": 0, "backlog": False, "cycle_completed": True}]

    class EmptyInventory:
        backend = "adapter"

        def __init__(self):
            self.calls = []

        async def inventory_page(self, *, after_key, limit):
            self.calls.append((after_key, limit))
            return [], "resume" if after_key is None else None

    store = EmptyInventory()
    async with coverage_sessionmaker() as session:
        assert await audio_store.reconcile_audio_inventory(session, store, settings) == 0
        assert await audio_store.reconcile_audio_inventory(session, store, settings) == 0
        cursor = await session.scalar(select(AudioInventoryCursor))
        assert cursor is not None and cursor.after_key is None
        session.add_all(
            [
                AudioDeletion(
                    id=new_id(),
                    owner_id=new_id(),
                    backend="adapter",
                    storage_key="audio/old.enc",
                    not_before=utcnow(),
                    created_at=utcnow() - timedelta(minutes=10),
                ),
                AudioDeletion(
                    id=new_id(),
                    owner_id=new_id(),
                    backend="adapter",
                    storage_key="audio/new.enc",
                    not_before=utcnow(),
                    created_at=utcnow(),
                ),
            ]
        )
        await session.commit()
        count, age = await audio_store.audio_deletion_backlog(session)
    assert store.calls[0][0] is None and store.calls[1][0] == "resume"
    assert count == 2 and age >= 590


async def test_audio_reconciliation_skips_live_and_young_objects_and_logs_safely(
    coverage_sessionmaker, caplog
):
    settings = Settings(environment="development")
    settings.audio_lifecycle_ceiling_days = 31
    owner = new_id()
    live_key = f"audio/{owner}/live.enc"
    young_key = f"audio/{owner}/young.enc"
    failed_key = f"audio/{owner}/secret-failed-object.enc"
    removed_key = f"audio/{owner}/removed.enc"
    old = utcnow() - timedelta(days=40)

    class Store:
        backend = "adapter"

        def __init__(self):
            self.deleted = []

        async def inventory_page(self, *, after_key, limit):
            assert after_key is None and limit == audio_store.INVENTORY_BATCH
            return [
                (live_key, old),
                (young_key, utcnow()),
                (failed_key, old),
                (removed_key, old),
            ], None

        async def delete(self, key):
            self.deleted.append(key)
            if key == failed_key:
                raise audio_store.AudioStoreError("provider leaked secret detail")

    store = Store()
    tombstone_id = new_id()
    async with coverage_sessionmaker() as session:
        session.add(_user(owner, "audio-owner"))
        await session.commit()
        session.add(
            AudioAttachment(
                id=new_id(),
                user_id=owner,
                client_entry_id="client-live",
                backend="adapter",
                storage_key=live_key,
                size_bytes=6,
                mime_type="audio/webm",
                duration_seconds=1,
                created_at=old,
                expires_at=utcnow() - timedelta(days=1),
            )
        )
        session.add(
            AudioDeletion(
                id=tombstone_id,
                owner_id=owner,
                backend="adapter",
                storage_key=removed_key,
                not_before=utcnow(),
                created_at=old,
            )
        )
        await session.commit()
        caplog.set_level(logging.WARNING, logger="mindpattern.audio_store")
        progress = []
        removed = await audio_store.reconcile_audio_inventory(
            session,
            store,
            settings,
            progress_observer=lambda **values: progress.append(values),
        )
        assert await session.get(AudioDeletion, tombstone_id) is None
    assert removed == 1
    assert store.deleted == [failed_key, removed_key]
    assert progress == [{"scanned": 4, "backlog": False, "cycle_completed": True}]
    assert "AudioStoreError" in caplog.text
    assert failed_key not in caplog.text and "provider leaked secret detail" not in caplog.text


def test_store_for_object_rejects_backend_and_locator_substitution(monkeypatch):
    settings = Settings(environment="development")
    row = SimpleNamespace(backend="s3", storage_locator=None)
    monkeypatch.setattr(audio_store, "get_audio_store_cached", lambda _settings: None)
    with pytest.raises(audio_store.AudioStoreError, match="backend is unavailable"):
        audio_store.store_for_object(settings, row)

    adapter = SimpleNamespace(backend="s3")
    monkeypatch.setattr(audio_store, "get_audio_store_cached", lambda _settings: adapter)
    row.storage_locator = "attacker-selected-locator"
    with pytest.raises(audio_store.AudioStoreError, match="target is unavailable"):
        audio_store.store_for_object(settings, row)


async def test_sharing_revision_failure_rolls_back_partial_active_update(
    coverage_sessionmaker,
):
    active_id = new_id()
    inactive_id = new_id()
    async with coverage_sessionmaker() as session:
        session.add_all(
            [
                _user(active_id, "active-patient"),
                _user(inactive_id, "deleted-patient", active=False),
            ]
        )
        await session.commit()
        with pytest.raises(ApiError, match="unable to advance sharing snapshot"):
            await sharing_state.advance_sharing_revisions(
                session, patient_ids=[active_id, inactive_id, active_id]
            )
        await session.rollback()

    async with coverage_sessionmaker() as session:
        active = await session.get(User, active_id)
        assert active is not None and active.consents_revision == 0


async def test_deletion_counterpart_fences_both_collection_directions(
    coverage_sessionmaker,
):
    patient_one, patient_two = new_id(), new_id()
    therapist_one, therapist_two = new_id(), new_id()
    async with coverage_sessionmaker() as session:
        session.add_all(
            [
                _user(patient_one, "patient-one"),
                _user(patient_two, "patient-two"),
                _user(therapist_one, "therapist-one", role=ROLE_THERAPIST),
                _user(therapist_two, "therapist-two", role=ROLE_THERAPIST),
            ]
        )
        await session.commit()
        session.add_all(
            [
                Consent(user_id=patient_one, therapist_id=therapist_one),
                Consent(user_id=patient_two, therapist_id=therapist_two),
            ]
        )
        await session.commit()
        await sharing_state.advance_counterpart_revisions_for_deletion(
            session, account_id=therapist_one, therapist=True
        )
        await sharing_state.advance_counterpart_revisions_for_deletion(
            session, account_id=patient_two, therapist=False
        )
        await session.commit()

    async with coverage_sessionmaker() as session:
        patient = await session.get(User, patient_one)
        therapist = await session.get(User, therapist_two)
        assert patient is not None and patient.consents_revision == 1
        assert therapist is not None and therapist.patients_revision == 1


async def test_account_deletion_rejects_invalid_phase_and_rewinds_for_late_child(
    coverage_sessionmaker,
):
    settings = Settings(environment="development")
    invalid_owner = new_id()
    late_owner = new_id()
    async with coverage_sessionmaker() as session:
        session.add(
            AccountDeletionJob(
                user_id=invalid_owner,
                role="user",
                phase="not-a-phase",
                requested_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        await session.commit()
        with pytest.raises(RuntimeError, match="invalid phase"):
            await account_deletion.purge_one_account_page(session, settings, owner_id=invalid_owner)
        await session.rollback()

        session.add(_user(late_owner, "logically-deleted", active=False))
        await session.commit()
        session.add(
            Entry(
                user_id=late_owner,
                client_entry_id="late-child",
                blob=b"opaque",
                entry_date=date.today(),
            )
        )
        session.add(
            AccountDeletionJob(
                user_id=late_owner,
                role="user",
                phase="user",
                requested_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        await session.commit()
        progress = await account_deletion.purge_one_account_page(
            session, settings, owner_id=late_owner
        )
        await session.commit()
        job = await session.get(AccountDeletionJob, late_owner)
        assert progress.backlog and progress.rows_deleted == 0
        assert job is not None and job.phase == "entries" and job.attempts == 1
        assert await session.get(User, late_owner) is not None


async def test_account_deletion_resumes_after_parent_was_already_removed(
    coverage_sessionmaker,
):
    owner = new_id()
    async with coverage_sessionmaker() as session:
        session.add(
            AccountDeletionJob(
                user_id=owner,
                role="user",
                phase="user",
                requested_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        await session.commit()
        progress = await account_deletion.purge_one_account_page(
            session,
            Settings(environment="development"),
            owner_id=owner,
        )
        await session.commit()
        assert progress.found and not progress.backlog and progress.rows_deleted == 0
        assert await session.get(AccountDeletionJob, owner) is None


class _Metrics:
    def __init__(self):
        self.audit_failures = 0
        self.deletion_failures = []
        self.storage_failures = 0
        self.retention = []

    def observe_audit_maintenance_failure(self):
        self.audit_failures += 1

    def observe_account_deletion_failure(self, category):
        self.deletion_failures.append(category)

    def observe_audio_storage_failure(self):
        self.storage_failures += 1

    def observe_audio_retention(self, **values):
        self.retention.append(values)


async def test_main_refuses_invalid_audit_ring_before_opening_a_session(caplog):
    from app import main as main_mod

    metrics = _Metrics()
    app = SimpleNamespace(
        state=SimpleNamespace(
            settings=SimpleNamespace(audit_mac_keyring={}, audit_mac_key_version=1),
            metrics=metrics,
            audit_maintenance_healthy=True,
            audit_maintenance_retry_needed=False,
        )
    )
    caplog.set_level(logging.ERROR, logger="mindpattern")
    with pytest.raises(RuntimeError, match="valid MAC key ring"):
        await main_mod._prune_access_log_once(app)
    assert not app.state.audit_maintenance_healthy
    assert app.state.audit_maintenance_retry_needed
    assert metrics.audit_failures == 1
    assert "MAC key ring is invalid" in caplog.text


def test_main_account_deletion_failure_categories_are_allowlisted():
    from app import main as main_mod

    assert (
        main_mod._account_deletion_failure_category(audio_store.AudioStoreError("provider secret"))
        == "object_store"
    )
    assert main_mod._account_deletion_failure_category(SQLAlchemyError("dsn secret")) == "database"
    assert (
        main_mod._account_deletion_failure_category(
            ApiError(503, "state detail", "service_unavailable")
        )
        == "state"
    )
    assert main_mod._account_deletion_failure_category(RuntimeError("state detail")) == "state"
    assert (
        main_mod._account_deletion_failure_category(ValueError("unexpected detail")) == "unexpected"
    )


async def test_account_deletion_sweep_uses_bounded_backoff_and_safe_logs(monkeypatch, caplog):
    from app import main as main_mod

    class Wakeup:
        def __init__(self):
            self.clears = 0

        async def wait(self):
            return True

        def clear(self):
            self.clears += 1

    attempts = 0

    async def purge(_app):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("secret account identifier")
        raise asyncio.CancelledError

    monkeypatch.setattr(main_mod, "_purge_deleted_account_once", purge)
    metrics = _Metrics()
    wakeup = Wakeup()
    app = SimpleNamespace(
        state=SimpleNamespace(
            account_deletion_wakeup=wakeup,
            account_deletion_backlog=False,
            account_deletion_failure_streak=0,
            metrics=metrics,
        )
    )
    caplog.set_level(logging.ERROR, logger="mindpattern")
    with pytest.raises(asyncio.CancelledError):
        await main_mod._account_deletion_sweep(app)
    assert metrics.deletion_failures == ["state"]
    assert app.state.account_deletion_backlog
    assert app.state.account_deletion_failure_streak == 1
    assert app.state.account_deletion_retry_delay_seconds == 2
    assert wakeup.clears == 2
    assert "category=state" in caplog.text
    assert "secret account identifier" not in caplog.text


class _SessionContext:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *_args):
        return None


async def test_audio_retention_sweep_reports_progress_and_normalizes_failures(monkeypatch, caplog):
    from app import main as main_mod

    real_asyncio = asyncio
    sleep_calls = 0

    async def one_cycle_then_cancel(_delay):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise real_asyncio.CancelledError

    monkeypatch.setattr(
        main_mod,
        "asyncio",
        SimpleNamespace(sleep=one_cycle_then_cancel, CancelledError=real_asyncio.CancelledError),
    )
    monkeypatch.setattr(audio_store, "get_audio_store_cached", lambda _settings: object())
    monkeypatch.setattr(audio_store, "sweep_expired_audio", _async_result(2))
    monkeypatch.setattr(audio_store, "drain_audio_deletions", _async_result(1))

    async def reconcile(_session, _store, _settings, *, progress_observer):
        progress_observer(scanned=7, backlog=True, cycle_completed=False)
        return 3

    monkeypatch.setattr(audio_store, "reconcile_audio_inventory", reconcile)
    monkeypatch.setattr(audio_store, "audio_deletion_backlog", _async_result((4, 12.5)))
    metrics = _Metrics()
    app = SimpleNamespace(
        state=SimpleNamespace(
            settings=SimpleNamespace(audio_sweep_interval_seconds=1),
            sessionmaker=lambda: _SessionContext(),
            metrics=metrics,
        )
    )
    caplog.set_level(logging.INFO, logger="mindpattern")
    with pytest.raises(real_asyncio.CancelledError):
        await main_mod._audio_retention_sweep(app)
    assert metrics.retention == [
        {
            "backlog": 4,
            "oldest_age_seconds": 12.5,
            "reconciled": 3,
            "inventory_scanned": 7,
            "inventory_backlog": True,
            "inventory_cycle_completed": False,
        }
    ]
    assert "removed 2 expired attachment" in caplog.text

    for failure in (
        audio_store.AudioStoreError("provider secret"),
        ValueError("unexpected secret"),
    ):
        sleep_calls = 0

        def raise_failure(_settings, failure=failure):
            raise failure

        monkeypatch.setattr(audio_store, "get_audio_store_cached", raise_failure)
        before = metrics.storage_failures
        with pytest.raises(real_asyncio.CancelledError):
            await main_mod._audio_retention_sweep(app)
        assert metrics.storage_failures == before + 1
    assert "provider secret" not in caplog.text and "unexpected secret" not in caplog.text


def _async_result(value):
    async def result(*_args, **_kwargs):
        return value

    return result


def test_audit_keyring_parser_rejects_ambiguous_rotation_material():
    settings = Settings(environment="development")
    current = "01" * 32
    previous = "02" * 32
    older = "03" * 32

    settings.audit_mac_secret_explicit = "not-hex"
    with pytest.raises(RuntimeError, match="32 bytes of hex"):
        settings.audit_mac_keyring
    settings.audit_mac_secret_explicit = "aa"
    with pytest.raises(RuntimeError, match="32 bytes of hex"):
        settings.audit_mac_keyring

    settings.audit_mac_secret_explicit = current
    settings.audit_mac_previous_secrets_explicit = f"2:{previous}, 3:{older}"
    assert settings.audit_mac_keyring == {
        1: bytes.fromhex(current),
        2: bytes.fromhex(previous),
        3: bytes.fromhex(older),
    }

    invalid_previous = (
        ("malformed", "version:64-hex-key entries"),
        (f"0:{previous}", "version\\(1..2147483647\\)"),
        ("2:aa", "version\\(1..2147483647\\)"),
        (f"1:{previous}", "versions must be unique"),
        (f"2:{current}", "distinct secrets"),
    )
    for raw, message in invalid_previous:
        settings.audit_mac_previous_secrets_explicit = raw
        with pytest.raises(RuntimeError, match=message):
            settings.audit_mac_keyring


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("audio_max_duration_seconds", 3_601, "must be <= 3600"),
        ("audio_retention_days", 3_651, "must be between 1 and 3650"),
        ("audio_lifecycle_ceiling_days", 30, "must exceed audio_retention_days"),
        ("audio_max_user_bytes", config_mod.MAX_USER_BLOB_BYTES + 1, "must be <= 8 GiB"),
        ("audio_max_body_bytes", config_mod.MAX_BODY_BYTES + 1, "must be <="),
        ("audio_sweep_interval_seconds", 86_401, "must be <= 86400"),
        ("stt_timeout_seconds", 0.5, "must be between 1 and 600 seconds"),
    ),
)
def test_voice_configuration_safety_ceilings_fail_at_boot(field, value, message):
    with pytest.raises(RuntimeError, match=message):
        Settings(environment="development", **{field: value})


async def test_step_up_store_bounds_per_user_global_capacity_and_input(monkeypatch):
    monkeypatch.setattr(step_up, "STEP_UP_MAX_PER_USER", 2)
    store = step_up.StepUpProofStore()
    oldest, _ = await store.issue(user_id="owner", action="delete", token_jti="a", token_epoch=1)
    _, _ = await store.issue(user_id="owner", action="delete", token_jti="b", token_epoch=1)
    newest, _ = await store.issue(user_id="owner", action="delete", token_jti="c", token_epoch=1)
    assert not await store.consume(
        oldest, user_id="owner", action="delete", token_jti="a", token_epoch=1
    )
    assert await store.consume(
        newest, user_id="owner", action="delete", token_jti="c", token_epoch=1
    )

    monkeypatch.setattr(step_up, "STEP_UP_MAX_PROOFS", 1)
    full = step_up.StepUpProofStore()
    await full.issue(user_id="first", action="delete", token_jti=None, token_epoch=1)
    with pytest.raises(RuntimeError, match="capacity exhausted"):
        await full.issue(user_id="second", action="delete", token_jti=None, token_epoch=1)
    assert not await full.consume(
        "snowman-☃", user_id="first", action="delete", token_jti=None, token_epoch=1
    )


def test_deletion_tombstone_rejects_version_mismatches_and_canonicalizes_naive_time():
    secret = "tombstone-test-secret"
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    row = deletion_tombstone.new_deletion_tombstone(
        _user(new_id(), "deleted-user"),
        secret=secret,
        auth_secret_version=1,
        now=now,
    )
    assert deletion_tombstone.verifies_deletion_tombstone(
        row, secret=secret, auth_secret_version=1, now=now
    )
    row.record_version = 2
    assert not deletion_tombstone.verifies_deletion_tombstone(
        row, secret=secret, auth_secret_version=1, now=now
    )
    row.record_version = 1
    assert not deletion_tombstone.verifies_deletion_tombstone(
        row, secret=secret, auth_secret_version=2, now=now
    )
    assert deletion_tombstone._canonical_timestamp(now.replace(tzinfo=None)) == str(
        int(now.timestamp())
    )


def test_audit_journal_io_failure_and_cleanup_seams(tmp_path, monkeypatch):
    target = tmp_path / "audit.journal"

    def deny_open(*_args, **_kwargs):
        raise PermissionError("simulated journal denial")

    with monkeypatch.context() as context:
        context.setattr(audit_mod, "open", deny_open, raising=False)
        with pytest.raises(RuntimeError, match="not writable"):
            audit_mod.validate_audit_journal_path(str(target))
    assert audit_mod.audit_journal_health() == (False, "io_failure")

    owner = "a" * 32
    occurred = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    target.write_text(
        f"{owner} 1 {'1' * 64} {'2' * 64} {occurred}\nmalformed evidence\n",
        encoding="utf-8",
    )
    assert audit_mod.journal_owner_status(str(target), owner) == (True, True)

    index = audit_mod.build_journal_evidence_index(str(tmp_path / "missing-journal"))
    os.unlink(index.path)
    index.close()
    audit_mod._stage_journal_entry(SimpleNamespace(), _audit_row(owner, b"k" * 32))
