"""Bounded housekeeping, scheduling, and outage behavior using real storage."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"
AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)
KEY = b"k" * 32


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


@asynccontextmanager
async def maintenance(
    counts=(),
    *,
    retention=365,
    step=timedelta(days=1),
    database_url="sqlite+aiosqlite://",
):
    from app import main
    from app.api import _audit
    from app.db import build_engine, build_sessionmaker, init_models
    from app.metrics import MetricsRegistry
    from app.models import AccessLog, AuditChainState

    engine = build_engine(database_url)
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    settings = SimpleNamespace(
        audit_mac_keyring={7: KEY},
        audit_mac_key_version=7,
        audit_journal_path="",
        access_log_retention_days=retention,
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            settings=settings,
            engine=engine,
            sessionmaker=sessions,
            metrics=MetricsRegistry(),
            audit_maintenance_healthy=True,
            audit_maintenance_retry_needed=False,
            audit_maintenance_retry_delay_seconds=1,
        )
    )
    try:
        async with sessions() as session:
            for position, count in enumerate(counts):
                owner = "abcd"[position] * 32
                rows, previous = [], None
                for seq in range(1, count + 1):
                    row = AccessLog(
                        id=f"{position}{seq:031x}",
                        actor_id="actor",
                        actor_role="user",
                        user_id=owner,
                        action="read_entries",
                        at=AT + step * (seq - 1),
                        chain_seq=seq,
                        record_version=2,
                        mac_key_version=7,
                        prev_hash=previous,
                    )
                    row.entry_hash = _audit.compute_entry_hash(
                        previous,
                        row.actor_id,
                        owner,
                        row.action,
                        row.at,
                        actor_role=row.actor_role,
                        record_version=2,
                    )
                    row.entry_mac = _audit.compute_entry_mac(
                        KEY, owner, seq, row.entry_hash
                    )
                    previous = row.entry_hash
                    rows.append(row)
                    session.add(row)
                state = AuditChainState(
                    user_id=owner,
                    head_seq=count,
                    head_hash=previous,
                    head_at=rows[-1].at,
                    first_retained_seq=1,
                    first_retained_hash=rows[0].entry_hash,
                    state_version=1,
                    mac_key_version=7,
                    updated_at=rows[-1].at,
                )
                state.state_mac = _audit.compute_chain_state_mac(KEY, state)
                session.add(state)
            await session.commit()
        yield main, app
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_audit_maintenance_resumes_authenticated_bounded_pages_then_completes(
    monkeypatch,
):
    from app.api import _audit
    from app.models import AuditSweepCursor

    monkeypatch.setattr(_audit, "AUDIT_MAINTENANCE_OWNER_BATCH", 1)
    monkeypatch.setattr(_audit, "AUDIT_VERIFY_ROW_BATCH", 1)
    monkeypatch.setattr(_audit, "AUDIT_VERIFY_TOTAL_ROW_BATCH", 1)
    async with maintenance([3, 1]) as (main, app):
        observed = []
        for _ in range(8):
            backlog = await main._prune_access_log_once(app)
            async with app.state.sessionmaker() as session:
                cursor = await session.get(AuditSweepCursor, 1)
                observed.append(
                    (
                        backlog,
                        cursor.last_user_id,
                        cursor.verification_owner_id,
                        cursor.verification_next_seq,
                        cursor.verification_cycle_started_at,
                    )
                )
                _audit.authenticate_verification_checkpoint(cursor, {7: KEY}, 7)
            if not backlog:
                break
        assert len(observed) == 4, observed
        assert [item[0] for item in observed] == [True, True, True, False]
        assert observed[0][2:4] == ("a" * 32, 2)
        assert observed[1][2:4] == ("a" * 32, 3)
        assert observed[2][1] == "a" * 32
        assert observed[-1][1:] == (None, None, None, None)
        rendered = app.state.metrics.render(0)
        assert "mindpattern_audit_owners_verified_total 2\n" in rendered
        assert "mindpattern_audit_verification_backlog 0\n" in rendered
        assert (
            app.state.audit_maintenance_healthy
            and not app.state.audit_maintenance_retry_needed
        )
        assert app.state.audit_maintenance_retry_delay_seconds == 1


@pytest.mark.asyncio
async def test_corrupt_verification_rolls_back_tentative_cursor_and_closes_readiness(
    monkeypatch, caplog
):
    from app.models import AccessLog, AuditSweepCursor
    from sqlalchemy import select

    async with maintenance([2]) as (main, app):
        async with app.state.sessionmaker() as session:
            row = await session.scalar(
                select(AccessLog).where(AccessLog.chain_seq == 2)
            )
            row.entry_hash = "0" * 64
            await session.commit()
        with pytest.raises(RuntimeError, match=r"^audit chain verification failed$"):
            await main._prune_access_log_once(app)
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert cursor.verification_owner_id is None and cursor.last_user_id is None
        assert (
            not app.state.audit_maintenance_healthy
            and app.state.audit_maintenance_retry_needed
        )
        assert caplog.messages[-1] == "audit chain verification failed for 1 owner(s)"
        assert (
            "mindpattern_audit_maintenance_failures_total 1\n"
            in app.state.metrics.render(0)
        )


@pytest.mark.asyncio
async def test_verification_spends_one_shared_row_budget_across_multiple_owners(
    monkeypatch,
):
    from app import models
    from app.api import _audit
    from app.models import AuditSweepCursor

    monkeypatch.setattr(_audit, "AUDIT_MAINTENANCE_OWNER_BATCH", 3)
    monkeypatch.setattr(models, "utcnow", lambda: NOW)
    monkeypatch.setattr(_audit, "AUDIT_VERIFY_ROW_BATCH", 1)
    monkeypatch.setattr(_audit, "AUDIT_VERIFY_TOTAL_ROW_BATCH", 1)
    async with maintenance([1, 1, 1]) as (main, app):
        assert await main._prune_access_log_once(app) is True
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert cursor.last_user_id == "a" * 32
            assert cursor.verification_cycle_started_at is not None
        rendered = app.state.metrics.render(0)
        assert "mindpattern_audit_owners_verified_total 1\n" in rendered
        assert "mindpattern_audit_verification_pending_owners_probe 2\n" in rendered
        assert "mindpattern_audit_verification_cycle_age_seconds 0.000\n" in rendered
        assert app.state.audit_verification_backlog is True


@pytest.mark.asyncio
async def test_verification_stops_at_the_first_corrupt_owner(monkeypatch, caplog):
    from app.models import AccessLog
    from sqlalchemy import select

    async with maintenance([1, 1]) as (main, app):
        async with app.state.sessionmaker() as session:
            for row in await session.scalars(select(AccessLog)):
                row.entry_hash = "0" * 64
            await session.commit()
        with pytest.raises(RuntimeError, match=r"^audit chain verification failed$"):
            await main._prune_access_log_once(app)
        assert caplog.messages[-1] == "audit chain verification failed for 1 owner(s)"


@pytest.mark.parametrize(
    "failure", ["none", "malformed", "replace", "prune_backlog", "verify_backlog"]
)
@pytest.mark.asyncio
async def test_maintenance_uses_real_journal_evidence_and_exact_compaction_cushion(
    failure, tmp_path, monkeypatch, caplog
):
    from app import models
    from app.api import _audit
    from app.models import AccessLog
    from sqlalchemy import select

    clock = AT + timedelta(days=22)
    caplog.set_level("INFO", logger="mindpattern")
    monkeypatch.setattr(models, "utcnow", lambda: clock)
    path = tmp_path / "journal"
    if failure == "prune_backlog":
        monkeypatch.setattr(_audit, "AUDIT_PRUNE_ROW_BATCH", 1)
        monkeypatch.setattr(_audit, "AUDIT_PRUNE_TOTAL_ROW_BATCH", 1)
    if failure == "verify_backlog":
        monkeypatch.setattr(_audit, "AUDIT_VERIFY_ROW_BATCH", 1)
    async with maintenance(
        [3], retention=365 if failure == "verify_backlog" else 14
    ) as (main, app):
        app.state.settings.audit_journal_path = str(path)
        async with app.state.sessionmaker() as session:
            rows = list(
                await session.scalars(select(AccessLog).order_by(AccessLog.chain_seq))
            )
            lines = [
                f"{row.user_id} {row.chain_seq} {row.entry_hash} {row.entry_mac} {_audit.canonical_occurred_at(row.at)}\n"
                for row in rows
            ]
        path.write_text("malformed\n" if failure == "malformed" else "".join(lines))
        original_inode = path.stat().st_ino
        if failure == "replace":

            def fail_replace(*args, **kwargs):
                raise OSError("disk unavailable")

            monkeypatch.setattr(_audit.os, "replace", fail_replace)
        try:
            if failure == "malformed":
                with pytest.raises(
                    RuntimeError,
                    match=r"^audit journal evidence is unavailable or malformed$",
                ):
                    await main._prune_access_log_once(app)
                assert app.state.audit_maintenance_healthy is False
                assert app.state.audit_maintenance_retry_needed is True
                assert (
                    "mindpattern_audit_journal_failures_total 1\n"
                    in app.state.metrics.render(0)
                )
                return
            if failure in ("prune_backlog", "verify_backlog"):
                assert await main._prune_access_log_once(app) is True
                assert path.read_text() == "".join(lines)
                assert path.stat().st_ino == original_inode
                return
            assert await main._prune_access_log_once(app) is False
            async with app.state.sessionmaker() as session:
                assert list(await session.scalars(select(AccessLog))) == []
            if failure == "replace":
                assert path.read_text() == "".join(lines)
                assert (
                    caplog.messages[-1]
                    == "audit journal compaction failed; retrying next cycle"
                )
                assert (
                    "mindpattern_audit_journal_failures_total 1\n"
                    in app.state.metrics.render(0)
                )
            else:
                assert path.read_text() == "".join(lines[1:])
                assert (
                    caplog.messages[-1]
                    == "audit journal compacted: 2 lines kept, 1 older than 2026-09-02T00:00:00+00:00 dropped"
                )
        finally:
            _audit.close_reusable_journal_evidence_index()
            _audit._set_journal_health(True)


@pytest.mark.parametrize("invalid", [{}, {8: KEY}, None])
@pytest.mark.asyncio
async def test_maintenance_invalid_keyring_refusal_is_named_and_retryable(
    invalid, caplog
):
    async with maintenance() as (main, app):
        app.state.settings.audit_mac_keyring = invalid
        with pytest.raises(
            RuntimeError, match=r"^audit maintenance requires a valid MAC key ring$"
        ) as rejected:
            await main._prune_access_log_once(app)
        assert str(
            rejected.value.__cause__
        ) == "current audit MAC key is unavailable" or isinstance(
            rejected.value.__cause__, TypeError
        )
        assert (
            not app.state.audit_maintenance_healthy
            and app.state.audit_maintenance_retry_needed
        )
        assert (
            caplog.messages[-1] == "audit maintenance refused: MAC key ring is invalid"
        )


@pytest.mark.parametrize("expired", [2, 3])
@pytest.mark.asyncio
async def test_question_retention_exact_cutoff_batch_and_backlog(monkeypatch, expired):
    from app.api.insights import QUESTION_RETENTION_DAYS
    from app.models import Insight, User
    from sqlalchemy import select

    async with maintenance() as (main, app):
        monkeypatch.setattr(main, "QUESTION_RETENTION_BATCH", 2)
        cutoff = datetime.now(timezone.utc).date() - timedelta(
            days=QUESTION_RETENTION_DAYS
        )
        async with app.state.sessionmaker() as session:
            session.add(
                User(
                    id="owner",
                    username="owner",
                    salt="salt",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()
            for row_id, kind, for_date in [
                ("a", "question", cutoff - timedelta(days=3)),
                ("b", "question", cutoff - timedelta(days=2)),
                ("c", "question", cutoff - timedelta(days=1)),
                ("d", "question", cutoff),
                ("e", "brain", cutoff - timedelta(days=2)),
            ]:
                if row_id == "c" and expired == 2:
                    continue
                session.add(
                    Insight(
                        id=row_id,
                        user_id="owner",
                        kind=kind,
                        for_date=for_date,
                        blob=b"opaque",
                    )
                )
            await session.commit()
        assert await main._prune_expired_questions_once(app) is (expired == 3)
        async with app.state.sessionmaker() as session:
            assert list(
                (await session.scalars(select(Insight.id).order_by(Insight.id))).all()
            ) == (["c", "d", "e"] if expired == 3 else ["d", "e"])
        assert await main._prune_expired_questions_once(app) is False
        assert (
            f"mindpattern_question_insights_pruned_total {expired}\n"
            in app.state.metrics.render(0)
        )
        assert not app.state.question_retention_backlog


@pytest.mark.asyncio
async def test_auxiliary_retention_has_four_bounded_independent_expiry_policies(
    monkeypatch,
):
    from app.api.therapist import PAIRING_RETENTION
    from app.models import (
        AccountDeletionTombstone,
        PairingCode,
        RekeyJournal,
        TokenRevocation,
        User,
    )
    from sqlalchemy import select

    async with maintenance() as (main, app):
        monkeypatch.setattr(main, "AUXILIARY_RETENTION_BATCH", 1)
        async with app.state.sessionmaker() as session:
            session.add(
                User(
                    id="live",
                    username="live",
                    salt="salt",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()
            for i in range(3):
                expiry = NOW - PAIRING_RETENTION - timedelta(seconds=3 - i)
                session.add(
                    PairingCode(
                        id=f"p{i}",
                        therapist_id="live",
                        code_hash=f"h{i}",
                        expires_at=expiry,
                    )
                )
                session.add(
                    TokenRevocation(
                        jti=f"v{i}", expires_at=NOW - timedelta(seconds=3 - i)
                    )
                )
                session.add(
                    RekeyJournal(
                        id=f"r{i}",
                        user_id="orphan",
                        updated_at=NOW - timedelta(seconds=3 - i),
                    )
                )
                session.add(
                    AccountDeletionTombstone(
                        user_id=f"d{i}",
                        role="user",
                        token_epoch=1,
                        auth_secret_version=1,
                        deleted_at=NOW - timedelta(days=30),
                        expires_at=NOW - timedelta(seconds=3 - i),
                        record_mac="0" * 64,
                    )
                )
            session.add(
                PairingCode(
                    id="p-safe",
                    therapist_id="live",
                    code_hash="h-safe",
                    expires_at=NOW - PAIRING_RETENTION,
                )
            )
            session.add(TokenRevocation(jti="v-safe", expires_at=NOW))
            session.add(
                RekeyJournal(
                    id="r-safe", user_id="live", updated_at=NOW - timedelta(days=100)
                )
            )
            session.add(
                AccountDeletionTombstone(
                    user_id="d-edge",
                    role="user",
                    token_epoch=1,
                    auth_secret_version=1,
                    deleted_at=NOW - timedelta(days=30),
                    expires_at=NOW,
                    record_mac="0" * 64,
                )
            )
            await session.commit()
            first = await main._prune_auxiliary_retention_once(app, session, now=NOW)
            assert first == {
                "pairing": (True, PAIRING_RETENTION.total_seconds() + 2, 1),
                "revocations": (True, 2.0, 1),
                "rekeys": (True, 2.0, 1),
                "deletions": (True, 2.0, 1),
            }
            for _ in range(3):
                last = await main._prune_auxiliary_retention_once(app, session, now=NOW)
            assert last == {
                "pairing": (False, 0.0, 0),
                "revocations": (False, 0.0, 0),
                "rekeys": (False, 0.0, 0),
                "deletions": (False, 0.0, 1),
            }
            assert list((await session.scalars(select(PairingCode.id))).all()) == [
                "p-safe"
            ]
            assert list((await session.scalars(select(TokenRevocation.jti))).all()) == [
                "v-safe"
            ]
            assert list((await session.scalars(select(RekeyJournal.id))).all()) == [
                "r-safe"
            ]
            assert (
                list(
                    (
                        await session.scalars(select(AccountDeletionTombstone.user_id))
                    ).all()
                )
                == []
            )


@pytest.mark.parametrize(
    ("flags", "random_value", "delay", "operation"),
    [
        ({}, 0, 86400, "audit"),
        ({"question_retention_backlog": True}, 0, 1, "questions"),
        ({"audit_prune_backlog": True}, 0, 1, "audit"),
        ({"audit_verification_backlog": True}, 0, 1, "audit"),
        ({"auxiliary_retention_backlog": True}, 0, 1, "audit"),
        (
            {
                "audit_maintenance_retry_needed": True,
                "audit_maintenance_retry_delay_seconds": 30,
            },
            0.5,
            30,
            "audit",
        ),
        (
            {
                "audit_maintenance_retry_needed": True,
                "question_retention_backlog": True,
                "audit_maintenance_retry_delay_seconds": 30,
            },
            0,
            24,
            "audit",
        ),
        (
            {
                "audit_maintenance_retry_needed": True,
                "audit_maintenance_retry_delay_seconds": 30,
            },
            0,
            24,
            "audit",
        ),
        (
            {
                "audit_maintenance_retry_needed": True,
                "audit_maintenance_retry_delay_seconds": 200,
            },
            1,
            60,
            "audit",
        ),
        (
            {
                "audit_maintenance_retry_needed": True,
                "audit_maintenance_retry_delay_seconds": 0,
            },
            0,
            0.8,
            "audit",
        ),
    ],
)
@pytest.mark.asyncio
async def test_retention_scheduler_uses_catchup_and_bounded_retry_jitter(
    flags, random_value, delay, operation, monkeypatch
):
    import asyncio

    from app import main

    delays, calls = [], []
    app = SimpleNamespace(state=SimpleNamespace(**flags))

    async def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 2:
            raise asyncio.CancelledError

    async def audit(app):
        calls.append("audit")

    async def questions(app):
        calls.append("questions")

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main.random, "random", lambda: random_value)
    monkeypatch.setattr(main, "_prune_access_log_once", audit)
    monkeypatch.setattr(main, "_prune_expired_questions_once", questions)
    with pytest.raises(asyncio.CancelledError):
        await main._access_log_retention_sweep(app)
    assert delays[0] == pytest.approx(delay) and calls == [operation]


@pytest.mark.parametrize(("initial", "expected"), [(0, 1), (2, 4), (40, 60), (100, 60)])
@pytest.mark.asyncio
async def test_retention_failures_back_off_and_cancel_without_being_swallowed(
    initial, expected, monkeypatch, caplog
):
    import asyncio

    from app import main

    app = SimpleNamespace(
        state=SimpleNamespace(audit_maintenance_retry_delay_seconds=initial)
    )
    iterations = 0

    async def sleep(seconds):
        nonlocal iterations
        iterations += 1
        if iterations > 1:
            raise asyncio.CancelledError

    async def failed(app):
        raise RuntimeError("private exception details")

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main, "_prune_access_log_once", failed)
    with pytest.raises(asyncio.CancelledError):
        await main._access_log_retention_sweep(app)
    assert app.state.audit_maintenance_retry_needed is True
    assert app.state.audit_maintenance_retry_delay_seconds == expected
    assert caplog.messages == ["retention sweep failed; retrying shortly"]


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.asyncio
async def test_key_expiry_worker_runs_while_idle_and_recovers_without_leaking(
    failure, monkeypatch, caplog
):
    import asyncio

    from app import main

    calls, delays = [], []

    def purge():
        calls.append(True)
        if failure:
            raise RuntimeError("private key identifier")

    async def sleep(seconds):
        delays.append(seconds)
        raise asyncio.CancelledError

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    app = SimpleNamespace(
        state=SimpleNamespace(key_store=SimpleNamespace(purge_expired=purge))
    )
    with pytest.raises(asyncio.CancelledError):
        await main._processing_key_sweep(app)
    assert calls == [True] and delays == [1]
    assert caplog.messages == (
        ["processing-key expiry sweep failed; retrying shortly"] if failure else []
    )


def test_error_envelopes_keep_machine_codes_and_safe_human_defaults():
    from app.deps import ApiError
    from app.main import _account_deletion_failure_category, _error_envelope
    from app.services.audio_store import AudioStoreError
    from sqlalchemy.exc import SQLAlchemyError

    for detail in ("", None, [], {"input": "secret"}):
        assert _error_envelope(404, detail) == {
            "detail": "request failed",
            "code": "not_found",
        }
    assert _error_envelope(599, "custom") == {"detail": "custom", "code": "error"}
    assert _error_envelope(400, "refused", "custom") == {
        "detail": "refused",
        "code": "custom",
    }
    for error, expected in [
        (AudioStoreError("private"), "object_store"),
        (SQLAlchemyError("private"), "database"),
        (ApiError(400, "private", "private"), "state"),
        (RuntimeError("private"), "state"),
        (ValueError("private"), "unexpected"),
    ]:
        assert _account_deletion_failure_category(error) == expected


@pytest.mark.parametrize(
    "scenario", ["empty", "runnable", "recent", "waiting", "provider_failure"]
)
@pytest.mark.asyncio
async def test_account_purge_worker_commits_real_work_and_schedules_due_tombstones(
    scenario, tmp_path, monkeypatch
):
    from app import models
    from app.config import Settings

    if scenario == "recent":
        monkeypatch.setattr(models, "utcnow", lambda: NOW)
    from app.models import AccountDeletionJob, AudioDeletion, utcnow

    async with maintenance() as (main, app):
        app.state.settings = Settings(
            environment="development",
            database_url="sqlite+aiosqlite://",
            audio_local_dir=str(tmp_path / "audio"),
        )
        app.state.account_deletion_failure_streak = 4
        async with app.state.sessionmaker() as session:
            if scenario in ("runnable", "recent"):
                for owner in ("a", "b"):
                    session.add(
                        AccountDeletionJob(
                            user_id=owner,
                            role="user",
                            phase="complete",
                            requested_at=utcnow()
                            - timedelta(seconds=0.5 if scenario == "recent" else 10),
                            updated_at=AT,
                        )
                    )
            if scenario in ("waiting", "provider_failure"):
                session.add(
                    AccountDeletionJob(
                        user_id="owner",
                        role="user",
                        phase="audio_wait",
                        requested_at=utcnow() - timedelta(seconds=10),
                        updated_at=AT,
                    )
                )
                session.add(
                    AudioDeletion(
                        id="object",
                        owner_id="owner",
                        backend="local",
                        storage_key="../escape",
                        not_before=utcnow()
                        + timedelta(seconds=10 if scenario == "waiting" else -1),
                    )
                )
            await session.commit()
        backlog = await main._purge_deleted_account_once(app)
        assert backlog is (scenario != "empty")
        assert app.state.account_deletion_backlog is backlog
        assert app.state.account_deletion_failure_streak == 0
        rendered = app.state.metrics.render(0)
        expected_pending = 0 if scenario == "empty" else 1
        assert (
            f"mindpattern_account_deletion_pending_probe {expected_pending}\n"
            in rendered
        )
        if scenario == "empty":
            assert app.state.account_deletion_retry_delay_seconds == 60
            assert "mindpattern_account_deletion_oldest_seconds 0.000\n" in rendered
        if scenario in ("runnable", "recent"):
            assert app.state.account_deletion_retry_delay_seconds == 1
        if scenario == "recent":
            assert "mindpattern_account_deletion_oldest_seconds 0.500\n" in rendered
        if scenario == "waiting":
            assert 9 <= app.state.account_deletion_retry_delay_seconds <= 10
        if scenario == "provider_failure":
            assert (
                'mindpattern_account_deletion_failures_total{category="object_store"} 1\n'
                in rendered
            )
            async with app.state.sessionmaker() as session:
                row = await session.get(AudioDeletion, "object")
                assert row.attempts == 1


@pytest.mark.parametrize(
    ("initial", "backlog", "expected_delay", "expected_next"),
    [(0, False, 60, 2), (2, True, 3, 8), (8, True, 3, 60)],
)
@pytest.mark.asyncio
async def test_account_worker_wake_clear_and_failure_backoff_are_bounded(
    initial, backlog, expected_delay, expected_next, monkeypatch, caplog
):
    import asyncio

    from app import main
    from app.metrics import MetricsRegistry

    wake = asyncio.Event()
    wake.set()
    app = SimpleNamespace(
        state=SimpleNamespace(
            account_deletion_backlog=backlog,
            account_deletion_retry_delay_seconds=3,
            account_deletion_failure_streak=initial,
            account_deletion_wakeup=wake,
            metrics=MetricsRegistry(),
        )
    )
    delays = []

    async def wait(awaitable, timeout):
        awaitable.close()
        delays.append(timeout)
        if len(delays) == 2:
            raise asyncio.CancelledError
        raise TimeoutError

    async def failed(application):
        assert not wake.is_set()
        raise RuntimeError("private account identifier")

    monkeypatch.setattr(main.asyncio, "wait_for", wait)
    monkeypatch.setattr(main, "_purge_deleted_account_once", failed)
    with pytest.raises(asyncio.CancelledError):
        await main._account_deletion_sweep(app)
    assert delays == [expected_delay, expected_next]
    assert app.state.account_deletion_failure_streak == initial + 1
    assert app.state.account_deletion_backlog is True
    assert (
        caplog.messages[-1]
        == "account deletion sweep failed; category=state; retrying with bounded backoff"
    )
    assert (
        'mindpattern_account_deletion_failures_total{category="state"} 1\n'
        in app.state.metrics.render(0)
    )


@pytest.mark.parametrize("failure", ["none", "storage", "unexpected"])
@pytest.mark.asyncio
async def test_audio_worker_tracks_real_local_expiry_inventory_and_failure_classes(
    failure, tmp_path, monkeypatch, caplog
):
    import asyncio
    import logging

    from app.config import Settings
    from app.models import AudioAttachment, User, utcnow
    from app.services import audio_store
    from sqlalchemy import select

    async with maintenance() as (main, app):
        settings = Settings(
            environment="development",
            database_url="sqlite+aiosqlite://",
            audio_local_dir=str(tmp_path / "recordings"),
        )
        app.state.settings = settings
        store = audio_store.get_audio_store_cached(settings)
        owner, key = "a" * 32, f"audio/{'a' * 32}/{'b' * 32}.enc"
        await store.put(key, b"opaque recording")
        async with app.state.sessionmaker() as session:
            session.add(
                User(
                    id=owner,
                    username="owner",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()
            session.add(
                AudioAttachment(
                    id="recording",
                    user_id=owner,
                    client_entry_id="entry",
                    backend="local",
                    storage_key=key,
                    storage_locator=audio_store.storage_locator(store),
                    size_bytes=16,
                    mime_type="audio/mp4",
                    duration_seconds=3,
                    expires_at=utcnow() - timedelta(days=1),
                )
            )
            await session.commit()
        if failure != "none":

            def broken(settings):
                raise (
                    audio_store.AudioStoreError("private bucket")
                    if failure == "storage"
                    else RuntimeError("private identifier")
                )

            monkeypatch.setattr(audio_store, "get_audio_store_cached", broken)
        sleeps = []

        async def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 2:
                raise asyncio.CancelledError

        monkeypatch.setattr(main.asyncio, "sleep", sleep)
        with (
            caplog.at_level(logging.INFO, logger="mindpattern"),
            pytest.raises(asyncio.CancelledError),
        ):
            await main._audio_retention_sweep(app)
        assert sleeps == [settings.audio_sweep_interval_seconds] * 2
        rendered = app.state.metrics.render(0)
        if failure == "none":
            async with app.state.sessionmaker() as session:
                assert (await session.scalar(select(AudioAttachment.id))) is None
            assert not store._path(key).exists()
            assert (
                "audio retention sweep removed 1 expired attachment(s)"
                in caplog.messages
            )
            assert "mindpattern_audio_inventory_cycles_total 1\n" in rendered
        else:
            expected = (
                "audio retention sweep deferred after storage failure"
                if failure == "storage"
                else "audio retention sweep failed unexpectedly; retrying next cycle"
            )
            assert caplog.messages[-1] == expected
            assert "mindpattern_audio_storage_failures_total 1\n" in rendered


@pytest.mark.asyncio
async def test_recent_pending_rows_keep_subsecond_backlog_ages(monkeypatch):
    from app import models
    from app.api import _audit
    from app.models import TokenRevocation

    clock = AT + timedelta(days=14, milliseconds=100)
    monkeypatch.setattr(models, "utcnow", lambda: clock)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_ROW_BATCH", 1)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_TOTAL_ROW_BATCH", 1)
    async with maintenance([2], retention=14, step=timedelta(milliseconds=50)) as (
        main,
        app,
    ):
        monkeypatch.setattr(main, "AUXILIARY_RETENTION_BATCH", 1)
        async with app.state.sessionmaker() as session:
            session.add_all(
                [
                    TokenRevocation(
                        jti="first", expires_at=clock - timedelta(milliseconds=200)
                    ),
                    TokenRevocation(
                        jti="second", expires_at=clock - timedelta(milliseconds=100)
                    ),
                ]
            )
            await session.commit()
        assert await main._prune_access_log_once(app) is True
        assert app.state.audit_prune_backlog is True
        assert app.state.auxiliary_retention_backlog is True
        rendered = app.state.metrics.render(0)
        assert "mindpattern_audit_prune_oldest_overdue_seconds 0.050\n" in rendered
        assert (
            'mindpattern_auxiliary_retention_oldest_seconds{class="revocations"} 0.100\n'
            in rendered
        )


@pytest.mark.asyncio
async def test_prune_cursor_resumes_across_owners_and_question_housekeeping_runs(
    monkeypatch,
):
    from app import models
    from app.api import _audit
    from app.models import AuditSweepCursor, Insight, User
    from sqlalchemy import select

    monkeypatch.setattr(models, "utcnow", lambda: NOW)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_ROW_BATCH", 1)
    monkeypatch.setattr(_audit, "AUDIT_PRUNE_TOTAL_ROW_BATCH", 1)
    async with maintenance([2, 2], retention=14) as (main, app):
        monkeypatch.setattr(main, "QUESTION_RETENTION_BATCH", 2)
        async with app.state.sessionmaker() as session:
            session.add(
                User(
                    id="owner",
                    username="owner",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()
            session.add_all(
                [
                    Insight(
                        id=f"expired-{i}",
                        user_id="owner",
                        kind="question",
                        for_date=(AT - timedelta(days=500 + i)).date(),
                        blob=b"opaque",
                    )
                    for i in range(3)
                ]
            )
            await session.commit()
        assert await main._prune_access_log_once(app) is True
        assert app.state.question_retention_backlog
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert cursor.prune_last_user_id == "a" * 32
            assert cursor.prune_cycle_started_at == NOW
            assert len(list(await session.scalars(select(Insight)))) == 1
        assert await main._prune_access_log_once(app) is True
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert cursor.prune_last_user_id is None
            assert list(await session.scalars(select(Insight))) == []


@pytest.mark.parametrize("counts", [[], [1, 1]])
@pytest.mark.asyncio
async def test_completed_verification_resets_backlog_and_counts_each_owner(counts):
    async with maintenance(counts) as (main, app):
        assert await main._prune_access_log_once(app) is False
        rendered = app.state.metrics.render(0)
        assert f"mindpattern_audit_owners_verified_total {len(counts)}\n" in rendered
        assert "mindpattern_audit_verification_pending_owners_probe 0\n" in rendered
        assert "mindpattern_audit_verification_cycle_age_seconds 0.000\n" in rendered
        assert "mindpattern_audit_prune_oldest_overdue_seconds 0.000\n" in rendered


@pytest.mark.parametrize("kind", ["questions", "auxiliary"])
@pytest.mark.asyncio
async def test_native_retention_pages_remove_five_hundred_and_report_two_remaining(
    kind,
):
    from app.models import Insight, TokenRevocation, User
    from sqlalchemy import select

    async with maintenance() as (main, app):
        async with app.state.sessionmaker() as session:
            if kind == "questions":
                session.add(
                    User(
                        id="owner",
                        username="owner",
                        salt="s",
                        verifier=b"v",
                        scrypt_salt=b"s",
                    )
                )
                await session.flush()
                session.add_all(
                    [
                        Insight(
                            id=f"q-{i}",
                            user_id="owner",
                            kind="question",
                            for_date=(AT - timedelta(days=2000 + i)).date(),
                            blob=b"opaque",
                        )
                        for i in range(502)
                    ]
                )
            else:
                session.add_all(
                    [
                        TokenRevocation(
                            jti=f"v-{i}", expires_at=NOW - timedelta(seconds=1000 - i)
                        )
                        for i in range(502)
                    ]
                )
            await session.commit()
        if kind == "questions":
            assert await main._prune_expired_questions_once(app) is True
            async with app.state.sessionmaker() as session:
                assert len(list(await session.scalars(select(Insight)))) == 2
            assert (
                "mindpattern_question_insights_pruned_total 500\n"
                in app.state.metrics.render(0)
            )
        else:
            async with app.state.sessionmaker() as session:
                progress = await main._prune_auxiliary_retention_once(
                    app, session, now=NOW
                )
                assert progress["revocations"] == (True, 500.0, 500)
                assert len(list(await session.scalars(select(TokenRevocation)))) == 2


@pytest.mark.asyncio
async def test_incomplete_verification_does_not_move_to_the_next_owner(monkeypatch):
    from app.api import _audit
    from app.models import AuditSweepCursor

    monkeypatch.setattr(_audit, "AUDIT_VERIFY_ROW_BATCH", 1)
    async with maintenance([3, 1]) as (main, app):
        assert await main._prune_access_log_once(app) is True
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert cursor.verification_owner_id == "a" * 32
            assert cursor.verification_next_seq == 2
        assert (
            "mindpattern_audit_owners_verified_total 0\n" in app.state.metrics.render(0)
        )


@pytest.mark.asyncio
async def test_verification_reports_more_owners_beyond_the_first_page(monkeypatch):
    from app.api import _audit

    monkeypatch.setattr(_audit, "AUDIT_MAINTENANCE_OWNER_BATCH", 2)
    async with maintenance([1, 1, 1]) as (main, app):
        assert await main._prune_access_log_once(app) is True
        assert (
            "mindpattern_audit_owners_verified_total 2\n" in app.state.metrics.render(0)
        )
        assert await main._prune_access_log_once(app) is False
        assert (
            "mindpattern_audit_owners_verified_total 3\n" in app.state.metrics.render(0)
        )


@pytest.mark.asyncio
async def test_journal_only_earlier_owner_is_not_skipped_by_the_merged_page(
    tmp_path, monkeypatch
):
    from app.api import _audit

    monkeypatch.setattr(_audit, "AUDIT_MAINTENANCE_OWNER_BATCH", 1)
    path = tmp_path / "journal"
    path.write_text(
        f"{'0' * 32} 1 {'f' * 64} {'f' * 64} {_audit.canonical_occurred_at(NOW)}\n"
    )
    async with maintenance([1]) as (main, app):
        app.state.settings.audit_journal_path = str(path)
        try:
            with pytest.raises(
                RuntimeError, match=r"^audit chain verification failed$"
            ):
                await main._prune_access_log_once(app)
        finally:
            _audit.close_reusable_journal_evidence_index()
            _audit._set_journal_health(True)


@pytest.mark.asyncio
async def test_exactly_due_auxiliary_tombstones_keep_zero_age_backlog(monkeypatch):
    from app import models
    from app.models import AccountDeletionTombstone

    monkeypatch.setattr(models, "utcnow", lambda: NOW)
    async with maintenance() as (main, app):
        monkeypatch.setattr(main, "AUXILIARY_RETENTION_BATCH", 1)
        async with app.state.sessionmaker() as session:
            session.add_all(
                [
                    AccountDeletionTombstone(
                        user_id=owner,
                        role="user",
                        token_epoch=1,
                        auth_secret_version=1,
                        deleted_at=NOW - timedelta(days=30),
                        expires_at=NOW,
                        record_mac="0" * 64,
                    )
                    for owner in ("a", "b")
                ]
            )
            await session.commit()
        assert await main._prune_access_log_once(app) is True
        assert app.state.auxiliary_retention_backlog


@pytest.mark.asyncio
async def test_question_retention_metrics_count_rows_actually_deleted_after_a_concurrent_request(
    tmp_path, monkeypatch
):
    from app.models import Insight, User
    from sqlalchemy import delete, select
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select

    async with maintenance(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'retention.db'}"
    ) as (main, app):
        async with app.state.sessionmaker() as session:
            session.add(
                User(
                    id="owner",
                    username="owner",
                    salt="s",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.flush()
            session.add(
                Insight(
                    id="expired",
                    user_id="owner",
                    kind="question",
                    for_date=(AT - timedelta(days=2000)).date(),
                    blob=b"opaque",
                )
            )
            await session.commit()
        execute = AsyncSession.execute
        raced = False

        async def competing_delete(session, statement, *args, **kwargs):
            nonlocal raced
            result = await execute(session, statement, *args, **kwargs)
            if (
                not raced
                and isinstance(statement, Select)
                and any(
                    description.get("entity") is Insight
                    for description in statement.column_descriptions
                )
            ):
                raced = True
                async with app.state.sessionmaker() as competitor:
                    await competitor.execute(
                        delete(Insight).where(Insight.id == "expired")
                    )
                    await competitor.commit()
            return result

        monkeypatch.setattr(AsyncSession, "execute", competing_delete)
        assert await main._prune_expired_questions_once(app) is False
        assert raced
        assert (
            "mindpattern_question_insights_pruned_total 0\n"
            in app.state.metrics.render(0)
        )
        async with app.state.sessionmaker() as session:
            assert list(await session.scalars(select(Insight))) == []


@pytest.mark.asyncio
async def test_verification_finishes_the_active_owner_before_visiting_a_new_earlier_owner(
    monkeypatch,
):
    from app.api import _audit
    from app.models import AccessLog, AuditChainState, AuditSweepCursor

    monkeypatch.setattr(_audit, "AUDIT_VERIFY_ROW_BATCH", 2)
    async with maintenance([1, 3]) as (main, app):
        assert await main._prune_access_log_once(app) is True
        async with app.state.sessionmaker() as session:
            cursor = await session.get(AuditSweepCursor, 1)
            assert (
                cursor.verification_owner_id == "b" * 32
                and cursor.verification_next_seq == 3
            )
            owner = "a" + "f" * 31
            row = AccessLog(
                id="mid",
                actor_id="actor",
                actor_role="user",
                user_id=owner,
                action="read_entries",
                at=AT,
                chain_seq=1,
                record_version=2,
                mac_key_version=7,
            )
            row.entry_hash = _audit.compute_entry_hash(
                None,
                row.actor_id,
                owner,
                row.action,
                AT,
                actor_role="user",
                record_version=2,
            )
            row.entry_mac = _audit.compute_entry_mac(KEY, owner, 1, row.entry_hash)
            state = AuditChainState(
                user_id=owner,
                head_seq=1,
                head_hash=row.entry_hash,
                head_at=AT,
                first_retained_seq=1,
                first_retained_hash=row.entry_hash,
                state_version=1,
                mac_key_version=7,
                updated_at=AT,
            )
            state.state_mac = _audit.compute_chain_state_mac(KEY, state)
            session.add_all([row, state])
            await session.commit()
        assert await main._prune_access_log_once(app) is True
        assert (
            "mindpattern_audit_owners_verified_total 2\n" in app.state.metrics.render(0)
        )


@pytest.mark.asyncio
async def test_account_purge_keeps_a_retry_delay_when_a_waiting_tombstone_disappears_between_status_queries(
    tmp_path, monkeypatch
):
    from app.config import Settings
    from app.models import AccountDeletionJob, AudioDeletion
    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select

    async with maintenance(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'purge.db'}"
    ) as (main, app):
        app.state.settings = Settings(
            environment="development",
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'purge.db'}",
            audio_local_dir=str(tmp_path / "audio"),
        )
        async with app.state.sessionmaker() as session:
            session.add(
                AccountDeletionJob(
                    user_id="owner",
                    role="user",
                    phase="audio_wait",
                    requested_at=NOW,
                    updated_at=NOW,
                )
            )
            session.add(
                AudioDeletion(
                    id="waiting",
                    owner_id="owner",
                    backend="local",
                    storage_key="../escape",
                    not_before=NOW + timedelta(days=1000),
                )
            )
            await session.commit()
        scalar = AsyncSession.scalar
        raced = False

        async def competing_cleanup(session, statement, *args, **kwargs):
            nonlocal raced
            if (
                not raced
                and isinstance(statement, Select)
                and any(
                    description.get("entity") is AudioDeletion
                    and description.get("name") == "not_before"
                    for description in statement.column_descriptions
                )
            ):
                raced = True
                async with app.state.sessionmaker() as competitor:
                    await competitor.execute(
                        delete(AudioDeletion).where(AudioDeletion.id == "waiting")
                    )
                    await competitor.commit()
            return await scalar(session, statement, *args, **kwargs)

        monkeypatch.setattr(AsyncSession, "scalar", competing_cleanup)
        assert await main._purge_deleted_account_once(app) is True
        assert raced and app.state.account_deletion_retry_delay_seconds == 60
