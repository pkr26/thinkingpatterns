"""Durable journal custody under I/O failure and changing file generations."""

from __future__ import annotations

import builtins
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.api import _audit

OWNER = "a" * 32
OTHER = "b" * 32
HASH = "c" * 64
MAC = "d" * 64
STAMP = "2026-10-01T00:00:00+00:00"
AT = datetime(2026, 10, 1, tzinfo=timezone.utc)


def line(owner=OWNER, seq=1, at=STAMP):
    return f"{owner} {seq} {HASH} {MAC} {at}\n"


def pending(owner=OWNER, seq=1):
    return SimpleNamespace(
        info={"mindpattern_audit_journal_pending": [(owner, seq, HASH, MAC, AT)]}
    )


def test_clean_owner_status_returns_explicit_boolean_custody(tmp_path):
    journal = tmp_path / "journal"
    journal.write_text(line())
    assert _audit.journal_owner_status(str(journal), OWNER) == (True, False)
    assert _audit.journal_owner_status(str(journal), OTHER) == (False, False)


def test_reconfiguring_the_same_disabled_journal_preserves_a_borrowed_diagnostic_index(tmp_path):
    journal = tmp_path / "journal"
    journal.write_text(line())
    _audit.configure_audit_mac_key(None)
    index = _audit.reusable_journal_evidence_index(str(journal))
    try:
        _audit.configure_audit_mac_key(None)
        assert index.get(OWNER) == _audit.JournalEvidence(1, HASH, MAC, STAMP, False)
        assert _audit.reusable_journal_evidence_index(str(journal)) is index
    finally:
        _audit.close_reusable_journal_evidence_index()


async def test_flush_to_new_source_closes_previous_generation_cache(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_text(line())
    second.write_text("")
    old = _audit.reusable_journal_evidence_index(str(first))
    try:
        assert await _audit.flush_audit_journal(pending(OTHER), str(second)) == 1
        assert not Path(old.path).exists()
        index = _audit.reusable_journal_evidence_index(str(second))
        assert index.get(OWNER) is None
        assert index.get(OTHER).seq == 1
        assert first.read_text() == line()
    finally:
        _audit.close_reusable_journal_evidence_index()


async def test_durable_append_survives_derived_cache_failure(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    index = _audit.reusable_journal_evidence_index(str(journal))

    def broken_cache(*args):
        raise sqlite3.OperationalError("derived index cannot write")

    monkeypatch.setattr(index, "apply_entries", broken_cache)
    try:
        assert await _audit.flush_audit_journal(pending(seq=2), str(journal)) == 1
        assert not Path(index.path).exists()
        assert journal.read_text() == line() + line(seq=2)
        assert _audit.audit_journal_health() == (True, None)
        rebuilt = _audit.reusable_journal_evidence_index(str(journal))
        assert rebuilt.get(OWNER).seq == 2
    finally:
        _audit.close_reusable_journal_evidence_index()


async def test_failed_append_records_operational_error_without_replaying_pending(
    tmp_path, monkeypatch, caplog
):
    journal = tmp_path / "journal"
    session = pending()

    def unavailable(*args):
        raise OSError("fsync unavailable")

    monkeypatch.setattr(_audit.os, "fsync", unavailable)
    assert await _audit.flush_audit_journal(session, str(journal)) == 0
    assert session.info == {}
    assert _audit.audit_journal_health() == (False, "io_failure")
    assert any(
        record.getMessage() == "audit journal append failed; readiness is now unhealthy"
        for record in caplog.records
    )


def test_compaction_keeps_aged_head_and_nonhead_at_exact_cutoff(tmp_path):
    journal = tmp_path / "journal"
    cutoff = "2026-10-03T00:00:00+00:00"
    later = "2026-10-04T00:00:00+00:00"
    journal.write_text(
        line() + line(seq=2) + line(OTHER) + line(OTHER, 2, cutoff) + line(OTHER, 3, later)
    )
    assert _audit.compact_audit_journal(str(journal), cutoff) == (3, 2)
    assert journal.read_text() == line(seq=2) + line(OTHER, 2, cutoff) + line(OTHER, 3, later)


def test_compaction_preserves_new_unindexed_owner_after_scan(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    original = _audit._build_journal_evidence_index_unlocked

    def append_after_scan(path):
        index = original(path)
        with open(path, "a") as handle:
            handle.write(line(OTHER))
        return index

    monkeypatch.setattr(_audit, "_build_journal_evidence_index_unlocked", append_after_scan)
    assert _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00") == (2, 0)
    assert journal.read_text() == line() + line(OTHER)


def test_compaction_reports_late_malformed_line_and_removes_scratch_files(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    original = _audit._build_journal_evidence_index_unlocked
    indexes = []

    def corrupt_after_scan(path):
        index = original(path)
        indexes.append(index.path)
        with open(path, "a") as handle:
            handle.write("malformed evidence\n")
        return index

    monkeypatch.setattr(_audit, "_build_journal_evidence_index_unlocked", corrupt_after_scan)
    with pytest.raises(RuntimeError) as failure:
        _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00")
    assert str(failure.value) == "audit journal contains malformed evidence at line 2"
    assert _audit.audit_journal_health() == (False, "malformed_evidence")
    assert journal.read_text() == line() + "malformed evidence\n"
    assert all(not Path(path).exists() for path in indexes)
    assert not list(tmp_path.glob(".*.compact-*"))


def test_compaction_io_failure_latches_health_and_preserves_published_source(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())

    def replace_unavailable(*args):
        raise OSError("directory entry cannot publish")

    monkeypatch.setattr(_audit.os, "replace", replace_unavailable)
    with pytest.raises(OSError, match="directory entry cannot publish"):
        _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00")
    assert journal.read_text() == line()
    assert _audit.audit_journal_health() == (False, "io_failure")
    assert not list(tmp_path.glob(".*.compact-*"))


def test_failed_fdopen_releases_descriptor_zero_and_all_scratch_custody(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    original_temp = _audit.tempfile.mkstemp
    original_close = _audit.os.close
    original_fdopen = _audit.os.fdopen
    closed = []

    def temporary(*args, **kwargs):
        descriptor, path = original_temp(*args, **kwargs)
        if ".compact-" in kwargs.get("prefix", ""):
            original_close(descriptor)
            return 0, path
        return descriptor, path

    def close(descriptor):
        if descriptor == 0:
            closed.append(0)
        else:
            original_close(descriptor)

    def fdopen(descriptor, *args, **kwargs):
        if descriptor == 0:
            raise OSError("fdopen refused a valid descriptor")
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(_audit.tempfile, "mkstemp", temporary)
    monkeypatch.setattr(_audit.os, "close", close)
    monkeypatch.setattr(_audit.os, "fdopen", fdopen)
    with pytest.raises(OSError, match="fdopen refused a valid descriptor"):
        _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00")
    assert closed == [0]
    assert journal.read_text() == line()
    assert not list(tmp_path.glob(".*.compact-*"))


def test_unstable_cache_forces_rescan_after_transient_stat_failures(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    original = _audit._journal_source_fingerprint
    calls = 0

    def fingerprint(path):
        nonlocal calls
        calls += 1
        if calls in (1, 3):
            raise OSError("source generation temporarily unavailable")
        return original(path)

    monkeypatch.setattr(_audit, "_journal_source_fingerprint", fingerprint)
    try:
        first = _audit.reusable_journal_evidence_index(str(journal))
        assert first.corrupt
        journal.write_text(line(seq=2))
        rebuilt = _audit.reusable_journal_evidence_index(str(journal))
        assert rebuilt is not first
        assert not Path(first.path).exists()
        assert rebuilt.get(OWNER).seq == 2
    finally:
        _audit.close_reusable_journal_evidence_index()


def test_owner_scan_reports_its_own_malformed_line_number(tmp_path, caplog):
    journal = tmp_path / "journal"
    journal.write_text("\nmalformed\n" + line())
    caplog.clear()
    assert _audit.journal_owner_status(str(journal), OWNER) == (True, True)
    assert [record.getMessage() for record in caplog.records] == [
        "audit journal contains malformed evidence at line 2"
    ]


def test_reconfiguration_closes_the_prior_enabled_journal_cache(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_text(line())
    second.write_text(line(OTHER))
    _audit.configure_audit_mac_key(b"k" * 32, str(first))
    prior = _audit.reusable_journal_evidence_index(str(first))
    try:
        _audit.configure_audit_mac_key(b"k" * 32, str(second))
        assert not Path(prior.path).exists()
        assert _audit.reusable_journal_evidence_index(str(second)).get(OWNER) is None
    finally:
        _audit.close_reusable_journal_evidence_index()


async def test_empty_or_disabled_flush_has_no_filesystem_effect(tmp_path):
    journal = tmp_path / "unused"
    _audit._set_journal_health(False, "io_failure")
    assert await _audit.flush_audit_journal(SimpleNamespace(info={}), str(journal)) == 0
    assert not journal.exists()
    assert _audit.audit_journal_health() == (False, "io_failure")
    _audit._set_journal_health(True)
    session = pending()
    assert await _audit.flush_audit_journal(session, "") == 0
    assert session.info == {}
    assert _audit.audit_journal_health() == (True, None)


def test_compaction_bounds_lookup_cache_and_reuses_recent_owner(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    first = "0" * 32
    journal.write_text(
        line(first)
        + "".join(line(f"{owner:032x}") for owner in range(1, 1025))
        + line(first, 2)
        + line(first, 3)
    )
    connect = _audit.sqlite3.connect
    first_lookups = 0

    class TracedConnection:
        def __init__(self, *args, **kwargs):
            self.connection = connect(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, statement, parameters=()):
            nonlocal first_lookups
            if statement.startswith(
                "SELECT head_seq, conflict FROM owner_heads"
            ) and parameters == (first,):
                first_lookups += 1
            return self.connection.execute(statement, parameters)

    monkeypatch.setattr(_audit.sqlite3, "connect", TracedConnection)
    assert _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00") == (1025, 2)
    assert first_lookups == 2, (
        "1024 cached owner decisions evict the oldest while reusing its immediate successor"
    )


def test_same_enabled_source_reconfiguration_preserves_reusable_generation(tmp_path):
    journal = tmp_path / "journal"
    journal.write_text(line())
    _audit.configure_audit_mac_key(b"k" * 32, str(journal))
    index = _audit.reusable_journal_evidence_index(str(journal))
    try:
        _audit.configure_audit_mac_key(b"m" * 32, str(journal))
        assert Path(index.path).exists()
        assert _audit.reusable_journal_evidence_index(str(journal)) is index
    finally:
        _audit.close_reusable_journal_evidence_index()


def test_successful_compaction_never_releases_process_standard_descriptors(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    close = _audit.os.close
    standard_descriptors = []

    def close_owned(descriptor):
        if descriptor in (0, 1, 2):
            standard_descriptors.append(descriptor)
        else:
            close(descriptor)

    monkeypatch.setattr(_audit.os, "close", close_owned)
    assert _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00") == (1, 0)
    assert standard_descriptors == [], "maintenance must release only its own file custody"


def test_missing_journal_generation_is_fail_closed_and_rebuilds_without_temp_leaks(
    tmp_path, monkeypatch
):
    known = tmp_path / "known"
    missing = tmp_path / "missing"
    known.write_text(line())
    created = []
    mkstemp = _audit.tempfile.mkstemp

    def tracked_temporary(*args, **kwargs):
        descriptor, path = mkstemp(*args, **kwargs)
        created.append(path)
        return descriptor, path

    monkeypatch.setattr(_audit.tempfile, "mkstemp", tracked_temporary)
    try:
        old = _audit.reusable_journal_evidence_index(str(known))
        unavailable = _audit.reusable_journal_evidence_index(str(missing))
        assert not Path(old.path).exists()
        assert unavailable.corrupt is True
        assert _audit.audit_journal_health() == (False, "io_failure")
        assert unavailable.all_evidence() == {
            _audit.JOURNAL_CORRUPTION_KEY: _audit.JournalEvidence(0, "", "", "", True)
        }
        unavailable.close()
        assert not Path(unavailable.path).exists()
        missing.write_text(line(seq=2))
        settled = _audit.reusable_journal_evidence_index(str(missing))
        assert settled is not unavailable and not settled.corrupt
        assert settled.get(OWNER).seq == 2
        assert _audit.audit_journal_health() == (True, None)
    finally:
        _audit.close_reusable_journal_evidence_index()
        for path in created:
            Path(path).unlink(missing_ok=True)


def test_unstatable_generation_keeps_corruption_evidence_and_releases_displaced_index(
    tmp_path, monkeypatch
):
    journal = tmp_path / "journal"
    journal.write_text(line())
    created = []
    mkstemp = _audit.tempfile.mkstemp

    def tracked_temporary(*args, **kwargs):
        descriptor, path = mkstemp(*args, **kwargs)
        created.append(path)
        return descriptor, path

    monkeypatch.setattr(_audit.tempfile, "mkstemp", tracked_temporary)

    def unstatable(path):
        raise OSError("generation metadata is unavailable")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(_audit, "_journal_source_fingerprint", unstatable)
            unavailable = _audit.reusable_journal_evidence_index(str(journal))
            assert unavailable.corrupt is True
            assert _audit.audit_journal_health() == (False, "io_failure")
            assert unavailable.all_evidence()[_audit.JOURNAL_CORRUPTION_KEY].conflict is True
            journal.write_text(line(seq=2))
            rebuilt = _audit.reusable_journal_evidence_index(str(journal))
            assert rebuilt is not unavailable
            assert not Path(unavailable.path).exists()
            assert rebuilt.corrupt is True and rebuilt.get(OWNER).seq == 2
            assert _audit.audit_journal_health() == (False, "io_failure")
        settled = _audit.reusable_journal_evidence_index(str(journal))
        assert settled is not rebuilt
        assert not Path(rebuilt.path).exists()
        assert not settled.corrupt and settled.get(OWNER).seq == 2
        assert _audit.audit_journal_health() == (True, None)
    finally:
        _audit.close_reusable_journal_evidence_index()
        for path in created:
            Path(path).unlink(missing_ok=True)


def test_compaction_persists_the_actual_journal_directory_entry(tmp_path, monkeypatch):
    journal = tmp_path / "journal"
    journal.write_text(line())
    open_descriptor = _audit.os.open
    observed_directory_entries = []
    temporary_directories = []
    temporary = _audit.tempfile.mkstemp

    def directory_descriptor(path, flags, *args, **kwargs):
        descriptor = open_descriptor(path, flags, *args, **kwargs)
        if flags == os.O_RDONLY:
            status = os.fstat(descriptor)
            observed_directory_entries.append((status.st_dev, status.st_ino))
        return descriptor

    def same_filesystem_temporary(*args, **kwargs):
        if ".compact-" in kwargs.get("prefix", ""):
            temporary_directories.append(Path(kwargs["dir"]).resolve())
        return temporary(*args, **kwargs)

    monkeypatch.setattr(_audit.os, "open", directory_descriptor)
    monkeypatch.setattr(_audit.tempfile, "mkstemp", same_filesystem_temporary)
    assert _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00") == (1, 0)
    status = journal.parent.stat()
    assert observed_directory_entries == [(status.st_dev, status.st_ino)]
    assert temporary_directories == [journal.parent.resolve()]
