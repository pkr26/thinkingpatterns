"""Interoperable audit encodings and durable journal behavior."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.api import _audit
from app.deps import ApiError
from app.models import AccessLog, AuditChainState, AuditSweepCursor

AT = datetime(2026, 10, 1, tzinfo=timezone.utc)
STAMP = "2026-10-01T00:00:00+00:00"
OWNER = "a" * 32
OTHER = "b" * 32
HASH = "c" * 64
MAC = "d" * 64
KEY = b"k" * 32


def test_row_integrity_checks_report_the_exact_failure():
    digest = hashlib.sha256(b'["","actor","owner","read","2026-10-01T00:00:00+00:00"]').hexdigest()
    row = AccessLog(
        actor_id="actor",
        actor_role="patient",
        user_id="owner",
        action="read",
        at=AT,
        chain_seq=1,
        prev_hash=None,
        record_version=1,
        entry_hash=digest,
        entry_mac=hmac.new(KEY, f"owner:1:{digest}".encode(), hashlib.sha256).hexdigest(),
        mac_key_version=1,
    )
    assert _audit._audit_row_integrity_error(row, {1: KEY}) is None
    assert _audit._audit_row_integrity_error(row, {}) is None
    row.record_version = None
    row.mac_key_version = None
    assert _audit._audit_row_integrity_error(row, {1: KEY}) is None
    for invalid in (None, "short"):
        row.entry_hash = invalid
        assert _audit._audit_row_integrity_error(row, {1: KEY}) == "missing or malformed entry_hash"
    row.entry_hash = "f" * 64
    assert (
        _audit._audit_row_integrity_error(row, {1: KEY})
        == "entry_hash does not match the row's contents"
    )
    row.entry_hash = digest
    row.entry_mac = None
    assert _audit._audit_row_integrity_error(row, {}) is None
    assert _audit._audit_row_integrity_error(row, {1: KEY}) == (
        "missing entry_mac (legacy rows require explicit offline review; MAC stripping is not accepted)"
    )
    row.entry_mac = "e" * 64
    assert (
        _audit._audit_row_integrity_error(row, {1: KEY})
        == "entry_mac does not verify (row rewritten without the chain key)"
    )
    row.mac_key_version = 7
    assert (
        _audit._audit_row_integrity_error(row, {1: KEY}) == "audit MAC key version 7 is unavailable"
    )
    row.mac_key_version = None
    assert (
        _audit._audit_row_integrity_error(row, {7: KEY}) == "audit MAC key version 1 is unavailable"
    )
    assert _audit._broken(9, "reason") == _audit.ChainVerification(
        ok=False,
        rows_checked=0,
        broken_at_seq=9,
        reason="reason",
        legacy_rows=0,
    )


def test_state_authentication_and_evidence_helpers_are_fail_closed():
    state = AuditChainState(
        state_version=1,
        mac_key_version=1,
        user_id="owner",
        head_seq=9,
        head_hash="head",
        head_at=AT,
        first_retained_seq=3,
        first_retained_hash="first",
        state_mac=None,
    )
    assert _audit._authenticated_state_error(state, {}) is None
    assert (
        _audit._authenticated_state_error(state, {1: KEY})
        == "durable audit chain state is unsealed"
    )
    state.state_mac = hmac.new(
        KEY,
        b'[1,1,"owner",9,"head","2026-10-01T00:00:00+00:00",3,"first"]',
        hashlib.sha256,
    ).hexdigest()
    assert _audit._authenticated_state_error(state, {1: KEY}) is None
    assert (
        _audit._authenticated_state_error(state, {7: KEY})
        == "audit MAC key version 1 is unavailable"
    )
    assert (
        _audit._authenticated_state_error(state, {1: b"x" * 32})
        == "durable audit chain state MAC does not verify"
    )
    state.mac_key_version = 7
    assert (
        _audit._authenticated_state_error(state, {1: KEY})
        == "audit MAC key version 7 is unavailable"
    )
    state.mac_key_version = None
    assert (
        _audit._authenticated_state_error(state, {7: KEY})
        == "audit MAC key version 1 is unavailable"
    )
    evidence = _audit.JournalEvidence(1, HASH, MAC, STAMP)
    assert evidence.conflict is False
    assert _audit._journal_evidence_for_owner(None, OWNER) is None
    assert _audit._journal_evidence_for_owner({OWNER: evidence}, OWNER) is evidence
    assert _audit._journal_evidence_for_owner({OWNER: evidence}, OTHER) is None


def test_audit_encodings_match_independent_wire_vectors():
    legacy = b'["","actor","owner","read","2026-10-01T00:00:00+00:00"]'
    versioned = b'["previous","actor","owner","read","2026-10-01T00:00:00+00:00","th\\u00e9rapist"]'
    assert (
        _audit.compute_entry_hash(None, "actor", "owner", "read", AT)
        == hashlib.sha256(legacy).hexdigest()
    )
    assert (
        _audit.compute_entry_hash(None, "actor", "owner", "read", AT, record_version=2)
        == hashlib.sha256(legacy[:-1] + b',""]').hexdigest()
    )
    assert (
        _audit.compute_entry_hash(
            "previous", "actor", "owner", "read", AT, actor_role="thérapist", record_version=2
        )
        == hashlib.sha256(versioned).hexdigest()
    )
    assert (
        _audit.compute_entry_hash(
            "previous", "actor", "owner", "read", AT, actor_role="thérapist", record_version=3
        )
        == hashlib.sha256(versioned).hexdigest()
    )
    assert (
        _audit.compute_entry_mac(KEY, "owner", 7, HASH)
        == hmac.new(KEY, f"owner:7:{HASH}".encode(), hashlib.sha256).hexdigest()
    )
    state = AuditChainState(
        state_version=1,
        mac_key_version=7,
        user_id="owner",
        head_seq=9,
        head_hash="head",
        head_at=AT,
        first_retained_seq=3,
        first_retained_hash="first",
    )
    wire = b'[1,7,"owner",9,"head","2026-10-01T00:00:00+00:00",3,"first"]'
    assert (
        _audit.compute_chain_state_mac(KEY, state)
        == hmac.new(KEY, wire, hashlib.sha256).hexdigest()
    )
    cursor = AuditSweepCursor(
        id="sweep",
        last_user_id="last",
        verification_owner_id="owner",
        verification_snapshot_head_seq=9,
        verification_snapshot_head_hash="head",
        verification_next_seq=3,
        verification_previous_hash="previous",
        verification_rows_checked=2,
        verification_mac_key_version=7,
    )
    wire = b'["mindpattern/audit-verification-checkpoint/v1","sweep","last","owner",9,"head",3,"previous",2,7]'
    assert (
        _audit.compute_verification_checkpoint_mac(KEY, cursor)
        == hmac.new(KEY, wire, hashlib.sha256).hexdigest()
    )
    cursor.verification_rows_checked = None
    assert (
        _audit.compute_verification_checkpoint_mac(KEY, cursor)
        == hmac.new(KEY, wire.replace(b",2,7]", b",0,7]"), hashlib.sha256).hexdigest()
    )


def test_checkpoint_restart_authentication_and_key_rotation():
    cursor = AuditSweepCursor(
        id="sweep",
        last_user_id="untrusted",
        verification_owner_id="owner",
        verification_snapshot_head_seq=9,
        verification_snapshot_head_hash="head",
        verification_next_seq=3,
        verification_previous_hash="previous",
        verification_rows_checked=2,
        verification_checkpoint_mac=None,
    )
    _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)
    assert cursor.last_user_id is None
    assert cursor.verification_owner_id is None
    assert cursor.verification_snapshot_head_seq is None
    assert cursor.verification_snapshot_head_hash is None
    assert cursor.verification_next_seq is None
    assert cursor.verification_previous_hash is None
    assert cursor.verification_rows_checked == 0
    assert cursor.verification_mac_key_version == 7
    assert cursor.verification_checkpoint_mac == _audit.compute_verification_checkpoint_mac(
        KEY, cursor
    )
    _audit.authenticate_verification_checkpoint(cursor, {7: KEY, 8: b"n" * 32}, 8)
    for keys in ({}, {7: b"short"}, {7: b"x" * 32}):
        with pytest.raises(ApiError) as caught:
            _audit.authenticate_verification_checkpoint(cursor, keys, 7)
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            "audit verification checkpoint does not authenticate",
            "audit_integrity_error",
        )
    cursor.verification_next_seq = 4
    with pytest.raises(ApiError) as caught:
        _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)
    assert caught.value.detail == "audit verification checkpoint does not authenticate"
    for keys in ({}, {7: b"short"}):
        with pytest.raises(ApiError) as caught:
            _audit.seal_verification_checkpoint(cursor, keys, 7)
        assert (caught.value.status_code, caught.value.detail, caught.value.code) == (
            500,
            "current audit MAC key is unavailable",
            "audit_integrity_error",
        )


def test_canonical_seals_escape_unicode_and_evidence_is_immutable():
    state = AuditChainState(
        state_version=1,
        mac_key_version=7,
        user_id="niño",
        head_seq=9,
        head_hash="head",
        head_at=AT,
        first_retained_seq=3,
        first_retained_hash="first",
    )
    wire = b'[1,7,"ni\\u00f1o",9,"head","2026-10-01T00:00:00+00:00",3,"first"]'
    assert (
        _audit.compute_chain_state_mac(KEY, state)
        == hmac.new(KEY, wire, hashlib.sha256).hexdigest()
    )
    cursor = AuditSweepCursor(
        id=1,
        last_user_id="niño",
        verification_owner_id=None,
        verification_snapshot_head_seq=None,
        verification_snapshot_head_hash=None,
        verification_next_seq=None,
        verification_previous_hash=None,
        verification_rows_checked=0,
        verification_mac_key_version=7,
    )
    wire = b'["mindpattern/audit-verification-checkpoint/v1",1,"ni\\u00f1o",null,null,null,null,null,0,7]'
    assert (
        _audit.compute_verification_checkpoint_mac(KEY, cursor)
        == hmac.new(KEY, wire, hashlib.sha256).hexdigest()
    )
    cursor.verification_mac_key_version = None
    cursor.verification_checkpoint_mac = _audit.compute_verification_checkpoint_mac(KEY, cursor)
    with pytest.raises(ApiError) as caught:
        _audit.authenticate_verification_checkpoint(cursor, {1: KEY}, 1)
    assert caught.value.detail == "audit verification checkpoint does not authenticate"
    evidence = _audit.JournalEvidence(1, HASH, MAC, STAMP)
    with pytest.raises(FrozenInstanceError):
        evidence.seq = 2


def journal_line(owner=OWNER, seq=1, entry_hash=HASH, mac=MAC, at=STAMP):
    return f"{owner} {seq} {entry_hash} {mac} {at}\n"


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("not a seal", "field count"),
        (journal_line(owner="A" * 32), "owner"),
        (journal_line(owner="a" * 31), "owner"),
        (journal_line(seq=0), "sequence"),
        (journal_line(seq="01"), "sequence"),
        (journal_line(seq="+1"), "sequence"),
        (journal_line(entry_hash="c" * 63), "entry hash"),
        (journal_line(entry_hash="C" * 64), "entry hash"),
        (journal_line(mac="d" * 63), "entry MAC"),
        (journal_line(mac="D" * 64), "entry MAC"),
        (journal_line(at="2026-10-01T00:00:00"), "timestamp"),
        (journal_line(at="2026-10-01T01:00:00+01:00"), "non-canonical timestamp"),
    ],
)
def test_journal_rejects_noncanonical_seals_with_precise_reasons(line, reason):
    with pytest.raises(ValueError) as caught:
        _audit._parse_journal_line(line)
    assert str(caught.value) == reason


def test_journal_accepts_blank_and_legacy_mac_and_preserves_fields():
    assert _audit._parse_journal_line(" \t\n") is None
    assert _audit._parse_journal_line(journal_line(seq=12)) == (OWNER, 12, HASH, MAC, STAMP)
    assert _audit._parse_journal_line(journal_line(mac="-")) == (OWNER, 1, HASH, "-", STAMP)


def test_journal_index_orders_heads_detects_conflicts_and_closes(tmp_path):
    journal = tmp_path / "journal"
    journal.write_text(
        journal_line(seq=3)
        + journal_line(seq=1)
        + journal_line(owner=OTHER, seq=2)
        + journal_line(seq=3)
        + "\n"
    )
    index = _audit.build_journal_evidence_index(str(journal))
    try:
        assert _audit.audit_journal_health() == (True, None)
        assert _audit.journal_owner_status(str(journal), OWNER) == (True, False)
        assert _audit.journal_owner_status(str(journal), "f" * 32) == (False, False)
        assert index.corrupt is False
        assert _audit.JournalEvidenceIndex(index.path).corrupt is False
        assert index.get(OWNER) == _audit.JournalEvidence(3, HASH, MAC, STAMP, False)
        assert index.get("f" * 32) is None
        assert index.owner_ids_after(None, 1) == [OWNER]
        assert index.owner_ids_after(OWNER, 5) == [OTHER]
        assert index.owner_ids_through(OTHER, 5) == [OWNER, OTHER]
        assert index.all_evidence() == {
            OWNER: _audit.JournalEvidence(3, HASH, MAC, STAMP, False),
            OTHER: _audit.JournalEvidence(2, HASH, MAC, STAMP, False),
        }
        index.apply_entries([(OWNER, 2, "e" * 64, MAC, AT)])
        assert index.get(OWNER).seq == 3
        assert index.get(OWNER).conflict is False
        index.apply_entries([(OWNER, 2, HASH, MAC, AT)])
        assert index.get(OWNER) == _audit.JournalEvidence(3, HASH, MAC, STAMP, True)
        index.apply_entries([(OWNER, 4, HASH, "e" * 64, AT)])
        assert index.get(OWNER) == _audit.JournalEvidence(4, HASH, "e" * 64, STAMP, True)
        index.apply_entries([(OWNER, 4, "f" * 64, MAC, AT)])
        assert index.get(OWNER) == _audit.JournalEvidence(4, HASH, "e" * 64, STAMP, True)
    finally:
        index.close()
    assert not Path(index.path).exists()
    index.close()
    with pytest.raises(RuntimeError, match=r"^audit journal evidence index is closed$"):
        index.apply_entries([(OWNER, 5, HASH, MAC, AT)])


def test_journal_corruption_and_missing_io_are_fail_closed(tmp_path, caplog):
    journal = tmp_path / "journal"
    journal.write_text("\n" + "bad evidence\n" + "\n" + journal_line())
    evidence = _audit.read_journal_evidence(str(journal))
    assert evidence == {
        OWNER: _audit.JournalEvidence(1, HASH, MAC, STAMP, False),
        _audit.JOURNAL_CORRUPTION_KEY: _audit.JournalEvidence(0, "", "", "", True),
    }
    assert _audit.audit_journal_health() == (False, "malformed_evidence")
    assert any(
        record.getMessage() == "audit journal contains malformed evidence at line 2"
        for record in caplog.records
    )
    assert _audit.read_journal_heads(str(journal)) == {OWNER: (1, STAMP)}
    assert _audit.read_journal_head(str(journal), OWNER) == (1, STAMP)
    assert _audit.read_journal_head(str(journal), OTHER) is None
    assert _audit.journal_owner_status(str(journal), OWNER) == (True, True)
    assert _audit.audit_journal_health() == (False, "malformed_evidence")
    assert _audit.journal_owner_status(str(journal), OTHER) == (False, True)
    missing = str(tmp_path / "missing")
    assert _audit.read_journal_evidence(missing) == {
        _audit.JOURNAL_CORRUPTION_KEY: _audit.JournalEvidence(0, "", "", "", True)
    }
    assert _audit.audit_journal_health() == (False, "io_failure")
    assert _audit.journal_owner_status(missing, OWNER) == (False, True)
    assert _audit.audit_journal_health() == (False, "io_failure")


async def test_flush_consumes_pending_seals_and_updates_reusable_cache(tmp_path):
    journal = tmp_path / "journal"
    journal.write_text("")
    index = _audit.reusable_journal_evidence_index(str(journal))
    assert _audit.reusable_journal_evidence_index(str(journal)) is index
    session = SimpleNamespace(info={})
    row = SimpleNamespace(user_id=OWNER, chain_seq=1, entry_hash=HASH, entry_mac=MAC, at=AT)
    _audit._stage_journal_entry(session, row)
    assert session.info == {"mindpattern_audit_journal_pending": [(OWNER, 1, HASH, MAC, AT)]}
    assert await _audit.flush_audit_journal(session, str(journal)) == 1
    assert session.info == {}
    assert journal.read_text() == journal_line()
    assert _audit.audit_journal_health() == (True, None)
    assert _audit.reusable_journal_evidence_index(str(journal)) is index
    assert index.get(OWNER) == _audit.JournalEvidence(1, HASH, MAC, STAMP, False)
    assert await _audit.flush_audit_journal(session, str(journal)) == 0
    assert journal.read_text() == journal_line()
    row.entry_hash = None
    row.entry_mac = None
    _audit._stage_journal_entry(session, row)
    assert session.info == {"mindpattern_audit_journal_pending": [(OWNER, 1, "", "-", AT)]}
    assert await _audit.flush_audit_journal(session, "") == 0
    assert session.info == {}
    _audit._stage_journal_entry(SimpleNamespace(), row)
    assert await _audit.flush_audit_journal(SimpleNamespace(), str(journal)) == 0
    _audit.close_reusable_journal_evidence_index()
    assert not Path(index.path).exists()
    _audit.close_reusable_journal_evidence_index()


async def test_flush_failure_observer_and_recovery_are_post_commit(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    failures = []
    session = SimpleNamespace(
        info={"mindpattern_audit_journal_pending": [(OWNER, 1, HASH, MAC, AT)]}
    )
    with monkeypatch.context() as fault:
        fault.setattr(_audit.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("disk")))
        assert (
            await _audit.flush_audit_journal(
                session, str(journal), failure_observer=lambda: failures.append("failed")
            )
            == 0
        )
    assert failures == ["failed"]
    assert session.info == {}
    assert _audit.audit_journal_health() == (False, "io_failure")
    session.info["mindpattern_audit_journal_pending"] = [(OWNER, 2, HASH, MAC, AT)]
    assert await _audit.flush_audit_journal(session, str(journal)) == 1
    assert _audit.audit_journal_health() == (True, None)
    assert journal.read_text() == journal_line() + journal_line(seq=2)


def test_compaction_preserves_heads_conflicts_cutoff_and_blank_lines(tmp_path):
    journal = tmp_path / "journal"
    at_cutoff = "2026-10-03T00:00:00+00:00"
    journal.write_text(
        journal_line(seq=1)
        + journal_line(seq=2)
        + journal_line(seq=3, at=at_cutoff)
        + journal_line(owner=OTHER, seq=1)
        + journal_line(owner=OTHER, seq=2)
        + journal_line(owner=OTHER, seq=1, entry_hash="e" * 64)
        + "\n"
    )
    index = _audit.reusable_journal_evidence_index(str(journal))
    assert _audit.compact_audit_journal(str(journal), at_cutoff) == (5, 2)
    assert journal.read_text() == (
        journal_line(seq=3, at=at_cutoff)
        + journal_line(owner=OTHER, seq=1)
        + journal_line(owner=OTHER, seq=2)
        + journal_line(owner=OTHER, seq=1, entry_hash="e" * 64)
        + "\n"
    )
    assert not Path(index.path).exists()
    assert _audit.audit_journal_health() == (True, None)
    assert not list(tmp_path.glob(".*.compact-*"))
    journal.write_text("broken\n")
    with pytest.raises(
        RuntimeError, match=r"^audit journal contains malformed or unavailable evidence$"
    ):
        _audit.compact_audit_journal(str(journal), at_cutoff)
    assert journal.read_text() == "broken\n"
    assert _audit.audit_journal_health() == (False, "malformed_evidence")


def test_journal_cache_tracks_file_generations_and_disposes_old_indexes(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(journal_line())
    status = journal.stat()
    assert _audit._journal_source_fingerprint(str(journal)) == (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )
    first = _audit.reusable_journal_evidence_index(str(journal))
    assert Path(first.path).stat().st_mode & 0o777 == 0o600
    assert _audit.reusable_journal_evidence_index(str(journal)) is first
    journal.write_text(journal_line(seq=2))
    second = _audit.reusable_journal_evidence_index(str(journal))
    assert second is not first
    assert not Path(first.path).exists()
    assert second.get(OWNER).seq == 2
    alternate = tmp_path / "alternate"
    alternate.write_text(journal_line(owner=OTHER))
    third = _audit.reusable_journal_evidence_index(str(alternate))
    assert not Path(second.path).exists()
    assert third.get(OTHER).seq == 1
    _audit.close_reusable_journal_evidence_index()
    assert not Path(third.path).exists()

    original_build = _audit._build_journal_evidence_index_unlocked

    def external_append_after_scan(path):
        index = original_build(path)
        with open(path, "a") as writer:
            writer.write(journal_line(seq=3))
        return index

    with monkeypatch.context() as race:
        race.setattr(_audit, "_build_journal_evidence_index_unlocked", external_append_after_scan)
        unstable = _audit.reusable_journal_evidence_index(str(journal))
        assert unstable.corrupt is True
        assert _audit.audit_journal_health() == (False, "source_changed_during_index")
    stable = _audit.reusable_journal_evidence_index(str(journal))
    assert stable is not unstable
    assert not Path(unstable.path).exists()
    assert stable.corrupt is False
    assert stable.get(OWNER).seq == 3
    assert _audit.audit_journal_health() == (True, None)
    _audit.close_reusable_journal_evidence_index()
