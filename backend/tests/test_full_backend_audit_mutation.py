"""Audit configuration, cursor and timestamp contracts from the full campaign."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from app.api import _audit
from app.deps import ApiError


def test_audit_configuration_recovers_health_and_keeps_versioned_keys(tmp_path):
    key = b"a" * 32
    previous = {3: b"b" * 32}
    _audit._set_journal_health(False, "io_failure")
    _audit.configure_audit_mac_key(key, str(tmp_path / "journal"))
    assert _audit.audit_journal_health() == (True, None)
    assert _audit._effective_mac_keys(None, None, None) == ({1: key}, 1)

    _audit.configure_audit_mac_key(key, key_version=7, previous_keys=previous)
    assert _audit._effective_mac_keys(None, None, None) == ({3: b"b" * 32, 7: key}, 7)
    previous[9] = b"c" * 32
    assert _audit._effective_mac_keys(None, None, None) == ({3: b"b" * 32, 7: key}, 7)
    ring, version = _audit._effective_mac_keys(None, None, None)
    ring.clear()
    assert version == 7
    assert _audit._effective_mac_keys(None, None, None) == ({3: b"b" * 32, 7: key}, 7)

    _audit.configure_audit_mac_key(None, previous_keys={3: b"b" * 32})
    assert _audit._effective_mac_keys(None, None, None) == ({3: b"b" * 32}, 1)


@pytest.mark.parametrize("version", [None, 7])
def test_explicit_audit_keys_have_a_default_version_and_copy_the_ring(version):
    key = b"d" * 32
    ring = {2: key}
    resolved, selected = _audit._effective_mac_keys(None, ring, version)
    assert resolved == ring and resolved is not ring
    assert selected == (1 if version is None else 7)
    assert _audit._effective_mac_keys(key, None, version) == (
        {1: key},
        1 if version is None else 7,
    )


def test_audit_journal_startup_errors_are_exact_and_success_restores_health(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match=r"^MINDPATTERN_AUDIT_JOURNAL is empty$"):
        _audit.validate_audit_journal_path("")
    with pytest.raises(
        RuntimeError, match=r"^MINDPATTERN_AUDIT_JOURNAL parent directory does not exist$"
    ):
        _audit.validate_audit_journal_path(str(tmp_path / "missing" / "journal"))

    journal = tmp_path / "journal"
    with monkeypatch.context() as failed_io:

        def refuse_sync(_fd):
            raise OSError("disk unavailable")

        failed_io.setattr(_audit.os, "fsync", refuse_sync)
        with pytest.raises(RuntimeError, match=r"^MINDPATTERN_AUDIT_JOURNAL is not writable$"):
            _audit.validate_audit_journal_path(str(journal))
        assert _audit.audit_journal_health() == (False, "io_failure")

    _audit.validate_audit_journal_path(str(journal))
    assert journal.exists()
    assert _audit.audit_journal_health() == (True, None)


@pytest.mark.parametrize(
    "cursor",
    [
        "2026-10-05T12:00:00+00:00",
        "2026-10-05T12:00:00+00:00|bad",
        "2026-10-05T12:00:00+00:00|" + "a" * 32 + "|tail",
        "2026-10-05T12:00:00+00:00|" + "A" * 32,
        "2026-10-05T12:00:00|" + "a" * 32,
        "2026-10-05|" + "a" * 32,
        "garbage|" + "a" * 32,
    ],
)
def test_access_log_cursor_rejects_invalid_inputs_with_the_complete_envelope(cursor):
    with pytest.raises(ApiError) as caught:
        _audit.parse_access_log_cursor(cursor)
    assert caught.value.status_code == 422
    assert caught.value.detail == "malformed cursor"
    assert caught.value.code == "validation_error"


def test_access_log_cursor_preserves_a_valid_offset_and_row_id():
    instant = datetime(2026, 10, 5, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    row_id = "abcdef0123456789" * 2
    assert _audit.parse_access_log_cursor(f"{instant.isoformat()}|{row_id}") == (instant, row_id)


def test_audit_timestamp_canonicalization_uses_utc_independent_of_host_timezone(monkeypatch):
    instant = datetime(2026, 10, 5, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    try:
        with monkeypatch.context() as local_clock:
            local_clock.setenv("TZ", "EST5")
            time.tzset()
            assert _audit.canonical_occurred_at(instant) == "2026-10-05T07:00:00+00:00"
            naive = datetime(2026, 10, 5, 12, 30)
            assert _audit.canonical_occurred_at(naive) == "2026-10-05T12:30:00"
    finally:
        time.tzset()


@pytest.mark.parametrize("journal_enabled", [False, True])
async def test_retention_uses_the_configured_journal_and_default_configuration_disables_it(
    tmp_path, journal_enabled
):
    from sqlalchemy import func, select

    from app.db import build_engine, build_sessionmaker
    from app.models import AccessLog, Base

    key = b"e" * 32
    if journal_enabled:
        journal = tmp_path / "journal"
        journal.write_text("corrupted evidence\n")
        _audit.configure_audit_mac_key(key, str(journal))
    else:
        _audit.configure_audit_mac_key(key)

    engine = build_engine("sqlite+aiosqlite://")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = build_sessionmaker(engine)
        async with sessions() as session:
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
            cutoff = datetime(2026, 10, 4, tzinfo=timezone.utc)
            if journal_enabled:
                with pytest.raises(ApiError) as caught:
                    await _audit.prune_access_logs(session, cutoff=cutoff, mac_key=key)
                assert caught.value.status_code == 500
                assert caught.value.detail == "audit journal evidence is unavailable"
                assert caught.value.code == "audit_integrity_error"
                assert await session.scalar(select(func.count()).select_from(AccessLog)) == 1
            else:
                assert await _audit.prune_access_logs(session, cutoff=cutoff, mac_key=key) == 1
                assert await session.scalar(select(func.count()).select_from(AccessLog)) == 0
    finally:
        await engine.dispose()
