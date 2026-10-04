"""Independent audit 2026-09-27 — remediation pins.

Every test here pins a fix from the post-audit remediation round:
durable jti revocation (restart, eviction, prune), the processing-session
mint-fence re-check, the keyed audit-chain MAC + journal tail anchor +
unique-seq retry + the daily verification sweep, the note create-channel
conflict contract, kdf_params re-store validation, the _secret_env strip
symmetry, the metrics-token file path, the limiter's 128-entry compression,
and the Settings knobs the fixes added.
"""

from __future__ import annotations

import asyncio
import base64
import os
import threading
import time
from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.api._audit import (
    ChainVerification,
    JournalEvidence,
    append_access_log,
    audit_journal_health,
    compact_audit_journal,
    compute_entry_hash,
    compute_entry_mac,
    flush_audit_journal,
    prune_access_logs,
    read_journal_evidence,
    read_journal_head,
    validate_audit_journal_path,
    verify_access_log_chain,
)
from app.cache import _MAX_LOG_ENTRIES, SlidingWindowCounter, TokenRevocationStore
from app.config import Settings, _secret_env
from app.deps import ApiError
from app.models import AccessLog, AuditChainState, TokenRevocation, utcnow
from app.security import tokens as token_mod
from tests.helpers import ClientEmulator, TherapistEmulator


def _mac_key() -> bytes:
    return bytes.fromhex(
        Settings(environment="development", token_secret="k" * 32).audit_mac_secret_hex
    )


def new_id_hex() -> str:
    return os.urandom(16).hex()


@pytest_asyncio.fixture
async def chain_sessionmaker():
    """A standalone engine for the chain unit tests.

    The app fixture's in-memory SQLite runs on ONE shared connection
    (StaticPool), and the background retention/verification sweep races
    any test that seeds rows through the app's sessionmaker — interleaved
    transactions on the single connection corrupt each other. The chain
    mechanics under test need no app; this engine is theirs alone.
    """
    from app.db import build_engine, build_sessionmaker
    from app.models import Base

    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    raw_sessionmaker = build_sessionmaker(engine)

    yield raw_sessionmaker
    await engine.dispose()


async def _seed_chain(sessionmaker, user_id: str, mac_key: bytes | None, n: int = 3) -> None:
    async with sessionmaker() as session:
        for i in range(n):
            await append_access_log(
                session,
                actor_id=new_id_hex(),
                actor_role="patient",
                user_id=user_id,
                action=f"read_insights{i}",
                mac_key=mac_key,
                allow_new_chain=i == 0,
            )
        await session.commit()


# ---------------------------------------------------------------------------
# Durable single-token revocation
# ---------------------------------------------------------------------------


async def test_logout_revocation_is_durable_across_a_restart(client, app, settings):
    """The 2026-09-27 audit: the jti revocation lived only in process
    memory, so any restart resurrected every logged-out bearer until its
    own exp. Logout now writes through to the token_revocation table and
    boot re-hydrates the cache from it — a fresh store (the restart
    model) still refuses the logged-out bearer."""
    emu = ClientEmulator("durablejti", "pw-durable-jti")
    await emu.register(client)
    payload = token_mod.verify_token(emu.token, settings.auth_token_secret)
    assert (await client.post("/api/auth/logout", headers=emu.headers)).status_code == 204

    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(TokenRevocation))).scalars().all()
    assert len(rows) == 1
    assert rows[0].jti == payload["jti"]

    # Restart model: brand-new in-memory cache hydrated from the table.
    fresh_store = TokenRevocationStore()
    async with app.state.sessionmaker() as session:
        assert await fresh_store.hydrate(session) == 1
        assert await fresh_store.is_revoked_checked(session, payload["jti"])


async def test_prune_sweep_removes_expired_revocations(client, app):
    emu = ClientEmulator("prunejti", "pw-prune-jti")
    await emu.register(client)
    await emu.login(client)
    assert (await client.post("/api/auth/logout", headers=emu.headers)).status_code == 204
    # Force the row expired, then run ONE housekeeping pass.
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(TokenRevocation))).scalars().one()
        row.expires_at = utcnow() - timedelta(seconds=1)
        await session.commit()
    from app import main as main_mod

    await main_mod._prune_access_log_once(app)
    async with app.state.sessionmaker() as session:
        assert (await session.execute(select(TokenRevocation))).scalars().all() == []


async def test_revocation_check_survives_cache_eviction(client, app):
    """Eviction pressure (a fleet of logouts pushing the cap) must not
    resurrect a victim's revocation: past the first eviction the checked
    lookup falls back to the durable point query."""
    store = TokenRevocationStore(max_entries=4)
    for i in range(6):
        store.revoke(f"attacker{i:028d}", time.time() + 3600)
    assert store._overflowed  # noqa: SLF001 — the pin IS the flag
    victim = "victim" + "0" * 28
    async with app.state.sessionmaker() as session:
        # Nothing durable: the point query runs and answers not-revoked.
        assert not await store.is_revoked_checked(session, victim)
        # A durable row wins even though memory evicted/never had it.
        session.add(TokenRevocation(jti=victim, expires_at=utcnow() + timedelta(hours=1)))
        await session.commit()
        assert await store.is_revoked_checked(session, victim)


async def test_processing_session_mint_fence_rechecks_revocation(client, app, monkeypatch):
    """A bearer revoked WHILE its request sat behind the lifecycle lock
    must not mint fresh key material: the fence re-checks the jti the
    dependency stashed. require_user ran before the lock; the flip is
    injected between the two checks."""
    emu = ClientEmulator("fencejti", "pw-fence-jti")
    await emu.register(client)
    payload = token_mod.verify_token(emu.token, app.state.settings.auth_token_secret)
    fence_jti = payload["jti"]

    real_check = app.state.token_revocations.is_revoked_checked
    calls = {"n": 0}

    async def flip_on_second_call(session, jti, now=None):
        calls["n"] += 1
        if calls["n"] >= 2 and jti == fence_jti:
            return True  # the "logout landed while we waited" world
        return await real_check(session, jti, now=now)

    monkeypatch.setattr(app.state.token_revocations, "is_revoked_checked", flip_on_second_call)
    response = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": emu.data_key_b64}
    )
    assert response.status_code == 401
    assert calls["n"] >= 2


# ---------------------------------------------------------------------------
# Keyed audit-chain MAC + journal tail anchor + seq-race retry + sweep
# ---------------------------------------------------------------------------


async def test_appended_rows_carry_a_verifying_mac(chain_sessionmaker):
    mac_key = _mac_key()
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac_key)
    async with chain_sessionmaker() as session:
        rows = (
            (await session.execute(select(AccessLog).order_by(AccessLog.chain_seq))).scalars().all()
        )
        assert len(rows) == 3
        for row in rows:
            assert row.entry_mac == compute_entry_mac(
                mac_key, row.user_id, row.chain_seq, row.entry_hash
            )
        verdict = await verify_access_log_chain(session, user_id, mac_key=mac_key)
    assert verdict.ok and verdict.legacy_rows == 0


async def test_runtime_appends_seal_with_the_configured_key(client, app):
    """Integration: create_app configures the module-level MAC key from
    settings, so app-driven writes seal automatically and verify against
    the SAME settings-derived key the daily sweep uses."""
    emu = ClientEmulator("runtime-mac", "configured-key-password")
    await emu.register(client)
    user_id = emu.user_id
    assert user_id is not None
    mac_key = bytes.fromhex(app.state.settings.audit_mac_secret_hex)
    async with app.state.sessionmaker() as session:
        verdict = await verify_access_log_chain(session, user_id, mac_key=mac_key)
    assert verdict.ok
    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == user_id)))
            .scalars()
            .all()
        )
    assert all(row.entry_mac is not None for row in rows)


async def test_rewritten_row_fails_the_mac_without_the_key(chain_sessionmaker):
    """The 2026-09-27 finding: entry_hash is over PUBLIC fields, so a
    DB-write attacker could recompute every link. The MAC (key held
    outside the DB) is what makes the full-rewrite attack fail."""
    mac_key = _mac_key()
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac_key, n=2)
    attacker_key = os.urandom(32)
    async with chain_sessionmaker() as session:
        row = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == user_id)))
            .scalars()
            .first()
        )
        row.action = "forged_action"
        row.entry_hash = compute_entry_hash(
            row.prev_hash,
            row.actor_id,
            row.user_id,
            row.action,
            row.at,
            actor_role=row.actor_role,
            record_version=row.record_version,
        )
        # The attacker recomputes the whole chain — under THEIR key.
        row.entry_mac = compute_entry_mac(attacker_key, row.user_id, row.chain_seq, row.entry_hash)
        await session.commit()
        verdict = await verify_access_log_chain(session, user_id, mac_key=mac_key)
    assert not verdict.ok
    assert "entry_mac" in verdict.reason


async def test_journal_detects_tail_truncation_and_tolerates_lag(chain_sessionmaker, tmp_path):
    mac_key = _mac_key()
    user_id = new_id_hex()
    journal = str(tmp_path / "audit.journal")
    await _seed_chain(chain_sessionmaker, user_id, mac_key, n=2)
    async with chain_sessionmaker() as session:
        rows = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == user_id)))
            .scalars()
            .all()
        )
        pending = session.info.setdefault("mindpattern_audit_journal_pending", [])
        for row in rows:  # both rows were journaled at their commits
            pending.append((row.user_id, row.chain_seq, row.entry_hash, row.entry_mac, row.at))
        assert await flush_audit_journal(session, journal) == 2
        assert read_journal_head(journal, user_id)[0] == 2

        # Benign lag: journal loses a line (crash window) — still ok.
        verdict = await verify_access_log_chain(
            session, user_id, mac_key=mac_key, journal_path=journal
        )
        assert verdict.ok

        # Tail truncation: the DB's newest rows vanish while the journal
        # still records them — the forward chain alone can't see this.
        for row in rows:
            await session.delete(row)
        await session.commit()
        verdict = await verify_access_log_chain(
            session,
            user_id,
            mac_key=mac_key,
            journal_path=journal,
            retention_cutoff=utcnow() - timedelta(days=1),
        )
    assert not verdict.ok
    assert "tail truncation" in verdict.reason


async def test_full_retention_prune_accepts_sealed_empty_then_appends(chain_sessionmaker):
    """A legitimate full-prefix prune keeps its sealed high-water mark and
    the next append continues at N+1 instead of looking like a new chain."""
    mac_key = _mac_key()
    user_id = new_id_hex()
    old = utcnow() - timedelta(days=10)
    async with chain_sessionmaker() as session:
        for index in range(2):
            await append_access_log(
                session,
                actor_id=user_id,
                actor_role="patient",
                user_id=user_id,
                action=f"old_{index}",
                at=old + timedelta(seconds=index),
                mac_key=mac_key,
                allow_new_chain=index == 0,
            )
        await session.commit()
        cutoff = utcnow() - timedelta(days=1)
        assert await prune_access_logs(session, cutoff=cutoff, mac_key=mac_key) == 2
        await session.commit()
        empty = await verify_access_log_chain(
            session, user_id, mac_key=mac_key, retention_cutoff=cutoff
        )
        assert empty.ok and empty.rows_checked == 0

        appended = await append_access_log(
            session,
            actor_id=user_id,
            actor_role="patient",
            user_id=user_id,
            action="after_prune",
            mac_key=mac_key,
        )
        await session.commit()
        assert appended.chain_seq == 3
        verified = await verify_access_log_chain(
            session, user_id, mac_key=mac_key, retention_cutoff=cutoff
        )
        assert verified.ok and verified.rows_checked == 1


async def test_prune_refuses_to_hide_deleted_current_middle_row(chain_sessionmaker):
    """Retention may advance an anchor only after authenticating the whole
    pre-prune trail.  Otherwise an expired seq-1 row could select an owner,
    a DB attacker could delete current seq-2, and pruning could anchor seq-3
    as though the gap had never existed."""
    mac_key = _mac_key()
    user_id = new_id_hex()
    old = utcnow() - timedelta(days=10)
    current = utcnow() - timedelta(hours=1)
    async with chain_sessionmaker() as session:
        for seq, at in enumerate((old, current, current + timedelta(seconds=1)), start=1):
            await append_access_log(
                session,
                actor_id=user_id,
                actor_role="patient",
                user_id=user_id,
                action=f"event_{seq}",
                at=at,
                mac_key=mac_key,
                allow_new_chain=seq == 1,
            )
        await session.commit()
        state = await session.get(AuditChainState, user_id)
        assert state is not None
        before = (
            state.head_seq,
            state.head_hash,
            state.first_retained_seq,
            state.first_retained_hash,
            state.state_mac,
        )
        await session.execute(
            delete(AccessLog).where(
                AccessLog.user_id == user_id,
                AccessLog.chain_seq == 2,
            )
        )
        await session.commit()

        with pytest.raises(ApiError) as excinfo:
            await prune_access_logs(
                session,
                cutoff=utcnow() - timedelta(days=1),
                mac_key=mac_key,
            )
        assert excinfo.value.code == "audit_integrity_error"
        assert "failed verification" in excinfo.value.detail

        await session.rollback()
        unchanged = await session.get(AuditChainState, user_id, populate_existing=True)
        assert unchanged is not None
        assert (
            unchanged.head_seq,
            unchanged.head_hash,
            unchanged.first_retained_seq,
            unchanged.first_retained_hash,
            unchanged.state_mac,
        ) == before
        remaining = (
            (
                await session.execute(
                    select(AccessLog.chain_seq)
                    .where(AccessLog.user_id == user_id)
                    .order_by(AccessLog.chain_seq)
                )
            )
            .scalars()
            .all()
        )
        assert remaining == [1, 3]


async def test_deleted_chain_state_and_actor_role_tamper_fail_closed(chain_sessionmaker):
    mac_key = _mac_key()
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac_key, n=1)
    async with chain_sessionmaker() as session:
        row = await session.scalar(select(AccessLog).where(AccessLog.user_id == user_id))
        row.actor_role = "therapist"
        await session.commit()
        tampered = await verify_access_log_chain(session, user_id, mac_key=mac_key)
        assert not tampered.ok and "entry_hash" in (tampered.reason or "")

        await session.execute(delete(AuditChainState).where(AuditChainState.user_id == user_id))
        await session.commit()
        missing = await verify_access_log_chain(session, user_id, mac_key=mac_key)
        assert not missing.ok and "state is missing" in (missing.reason or "")
        with pytest.raises(ApiError) as excinfo:
            await append_access_log(
                session,
                actor_id=user_id,
                actor_role="patient",
                user_id=user_id,
                action="must_not_reset",
                mac_key=mac_key,
            )
        assert excinfo.value.code == "audit_integrity_error"


async def test_audit_mac_rotation_verifies_history_and_missing_old_key_fails(
    chain_sessionmaker,
):
    user_id = new_id_hex()
    old_key = bytes.fromhex("11" * 32)
    new_key = bytes.fromhex("22" * 32)
    async with chain_sessionmaker() as session:
        first = await append_access_log(
            session,
            actor_id=user_id,
            actor_role="patient",
            user_id=user_id,
            action="under_v1",
            mac_keys={1: old_key},
            current_mac_key_version=1,
            allow_new_chain=True,
        )
        await session.commit()
        second = await append_access_log(
            session,
            actor_id=user_id,
            actor_role="patient",
            user_id=user_id,
            action="under_v2",
            mac_keys={1: old_key, 2: new_key},
            current_mac_key_version=2,
        )
        await session.commit()
        assert (first.mac_key_version, second.mac_key_version) == (1, 2)
        state = await session.get(AuditChainState, user_id)
        assert state is not None and state.mac_key_version == 2
        valid = await verify_access_log_chain(
            session,
            user_id,
            mac_keys={1: old_key, 2: new_key},
            current_mac_key_version=2,
        )
        assert valid.ok
        retired_too_early = await verify_access_log_chain(
            session,
            user_id,
            mac_keys={2: new_key},
            current_mac_key_version=2,
        )
        assert not retired_too_early.ok
        assert "version 1 is unavailable" in (retired_too_early.reason or "")


def test_journal_reduction_allows_out_of_order_but_rejects_conflicting_duplicate(tmp_path):
    owner = new_id_hex()
    journal = tmp_path / "audit.journal"
    journal.write_text(
        f"{owner} 2 {'2' * 64} {'b' * 64} 2026-09-27T00:00:02+00:00\n"
        f"{owner} 1 {'1' * 64} {'a' * 64} 2026-09-27T00:00:01+00:00\n"
    )
    evidence = read_journal_evidence(str(journal))[owner]
    assert evidence.seq == 2 and not evidence.conflict

    with journal.open("a", encoding="utf-8") as handle:
        handle.write(f"{owner} 2 {'f' * 64} {'e' * 64} 2026-09-27T00:00:03+00:00\n")
    evidence = read_journal_evidence(str(journal))[owner]
    assert evidence.conflict
    kept, dropped = compact_audit_journal(str(journal), "2030-01-01T00:00:00+00:00")
    assert (kept, dropped) == (3, 0), "conflicting evidence must survive compaction"


async def test_journal_compaction_serializes_with_append(chain_sessionmaker, tmp_path, monkeypatch):
    """An append opened on the old inode must not be lost by os.replace."""
    from app.api import _audit as audit_mod

    owner = new_id_hex()
    journal = tmp_path / "audit.journal"
    journal.write_text(f"{owner} 1 {'1' * 64} {'a' * 64} 2026-09-27T00:00:01+00:00\n")
    replacing = threading.Event()
    release_replace = threading.Event()
    real_replace = audit_mod.os.replace

    def blocking_replace(source, destination):
        replacing.set()
        assert release_replace.wait(timeout=5)
        return real_replace(source, destination)

    monkeypatch.setattr(audit_mod.os, "replace", blocking_replace)
    compact_task = asyncio.create_task(
        asyncio.to_thread(
            compact_audit_journal,
            str(journal),
            "2030-01-01T00:00:00+00:00",
        )
    )
    assert await asyncio.to_thread(replacing.wait, 5)

    async with chain_sessionmaker() as session:
        session.info["mindpattern_audit_journal_pending"] = [
            (owner, 2, "2" * 64, "b" * 64, utcnow())
        ]
        flush_task = asyncio.create_task(flush_audit_journal(session, str(journal)))
        await asyncio.sleep(0.05)
        assert not flush_task.done(), "append must wait for compaction's replace boundary"
        release_replace.set()
        await compact_task
        assert await flush_task == 1

    evidence = read_journal_evidence(str(journal))[owner]
    assert evidence.seq == 2
    assert not evidence.conflict


async def test_journal_failure_health_and_successful_recovery(chain_sessionmaker, tmp_path):
    missing = tmp_path / "missing" / "audit.journal"
    with pytest.raises(RuntimeError, match="parent directory does not exist"):
        validate_audit_journal_path(str(missing))

    directory_target = tmp_path / "directory-target"
    directory_target.mkdir()
    async with chain_sessionmaker() as session:
        session.info["mindpattern_audit_journal_pending"] = [
            (new_id_hex(), 1, "1" * 64, "a" * 64, utcnow())
        ]
        assert await flush_audit_journal(session, str(directory_target)) == 0
        healthy, error = audit_journal_health()
        assert not healthy and error == "io_failure"

        recovered = tmp_path / "recovered.journal"
        validate_audit_journal_path(str(recovered))
        session.info["mindpattern_audit_journal_pending"] = [
            (new_id_hex(), 1, "2" * 64, "b" * 64, utcnow())
        ]
        assert await flush_audit_journal(session, str(recovered)) == 1
        assert audit_journal_health() == (True, None)


async def test_durable_state_refuses_a_stale_head_read(chain_sessionmaker, monkeypatch):
    """A missing DB tail can never reset a sequence protected by state."""
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac_key=None, n=1)  # real seq-1 row
    async with chain_sessionmaker() as session:
        # Simulate the race once: the FIRST head read MISSES the committed
        # seq-1 row (READ COMMITTED — the concurrent winner had not landed
        # when this coroutine read), so the INSERT takes seq 1, collides on
        # the unique index, rolls back to its savepoint, and the retry's
        # fresh head read sees the winner and lands as seq 2.
        from sqlalchemy import select as sa_select

        real_execute = session.execute
        state = {"missed": False}
        empty_head_stmt = (
            sa_select(AccessLog.chain_seq, AccessLog.entry_hash)
            .where(AccessLog.user_id == "no-such-patient")
            .order_by(AccessLog.chain_seq.desc())
            .limit(1)
        )

        async def execute_missing_first_head(statement, *a, **kw):
            if (
                not state["missed"]
                and "chain_seq" in str(statement)
                and "access_log" in str(statement)
                and "SELECT" in str(statement).upper()
            ):
                state["missed"] = True
                # A REAL result object that simply matches no rows: the
                # session machinery (savepoints included) routes through
                # execute, so a hand-rolled stub breaks internals.
                return await real_execute(empty_head_stmt)
            return await real_execute(statement, *a, **kw)

        monkeypatch.setattr(session, "execute", execute_missing_first_head)
        with pytest.raises(ApiError) as exc:
            await append_access_log(
                session,
                actor_id=new_id_hex(),
                actor_role="patient",
                user_id=user_id,
                action="raced_action",
            )
        assert exc.value.code == "audit_integrity_error"
    assert state["missed"]


async def test_daily_sweep_verifies_chains_counts_failures_and_fails_readiness(
    client, app, monkeypatch, caplog
):
    """The chain verifier has a runtime caller now: the daily sweep walks
    recently-active patients and bumps a metrics counter on failure."""
    from app import main as main_mod

    emu = ClientEmulator("sweep-integrity", "sweep-password")
    await emu.register(client)
    user_id = emu.user_id
    assert user_id is not None
    async with app.state.sessionmaker() as session:
        row = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == user_id)))
            .scalars()
            .first()
        )
        row.action = "tampered"
        row.entry_hash = compute_entry_hash(
            row.prev_hash, row.actor_id, row.user_id, row.action, row.at
        )
        await session.commit()

    observed: list[int] = []
    monkeypatch.setattr(
        app.state.metrics, "observe_audit_chain", lambda *, failures: observed.append(failures)
    )
    caplog.set_level("ERROR", logger="mindpattern")
    with pytest.raises(RuntimeError, match="audit chain verification failed"):
        await main_mod._prune_access_log_once(app)
    assert sum(observed) >= 1
    assert app.state.audit_maintenance_healthy is False
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "audit chain verification failed for 1 owner(s)" in messages
    assert user_id not in messages
    assert all(record.exc_info is None for record in caplog.records)


async def test_daily_sweep_round_robins_past_500_and_includes_journal_only_owner(
    app, monkeypatch, tmp_path
):
    """The durable cursor reaches quiet/state-only and journal-only owners;
    the old recent-row LIMIT 500 could permanently starve both."""
    from app import main as main_mod
    from app.api import _audit as audit_mod

    mac_key = bytes.fromhex(app.state.settings.audit_mac_secret_hex)
    now = utcnow() - timedelta(days=2)
    state_ids = [f"{index:032x}" for index in range(501)]
    async with app.state.sessionmaker() as session:
        for user_id in state_ids:
            state = AuditChainState(
                user_id=user_id,
                head_seq=1,
                head_hash="a" * 64,
                head_at=now,
                first_retained_seq=None,
                first_retained_hash=None,
                state_version=1,
                mac_key_version=1,
                updated_at=now,
            )
            from app.api._audit import compute_chain_state_mac

            state.state_mac = compute_chain_state_mac(mac_key, state)
            session.add(state)
        await session.commit()

    journal_only = "f" * 32
    journal = tmp_path / "audit.journal"
    journal.write_text(f"{journal_only} 1 {'b' * 64} {'c' * 64} 2020-01-01T00:00:00+00:00\n")
    app.state.settings.audit_journal_path = str(journal)
    visited: list[str] = []

    async def capture(_session, cursor, user_id, **kwargs):
        from app.api._audit import (
            IncrementalChainVerification,
            seal_verification_checkpoint,
        )

        visited.append(user_id)
        cursor.last_user_id = user_id
        cursor.verification_owner_id = None
        cursor.verification_snapshot_head_seq = None
        cursor.verification_snapshot_head_hash = None
        cursor.verification_next_seq = None
        cursor.verification_previous_hash = None
        cursor.verification_rows_checked = 0
        seal_verification_checkpoint(
            cursor,
            kwargs["mac_keys"],
            kwargs["current_mac_key_version"],
        )
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)

    monkeypatch.setattr(audit_mod, "verify_access_log_chain_incremental", capture)
    await main_mod._prune_access_log_once(app)
    assert len(visited) == 500
    await main_mod._prune_access_log_once(app)
    assert set(state_ids).issubset(visited)
    assert journal_only in visited


# ---------------------------------------------------------------------------
# Note create-channel conflict contract
# ---------------------------------------------------------------------------


async def test_note_create_different_content_conflicts(client):
    """The create channel is idempotent for the same ciphertext BYTES only
    (what an offline queue re-sends); different content is a 409 the
    client resolves via PATCH + base_version — last-write-wins is gone
    from BOTH write channels."""
    therapist = TherapistEmulator("auditnoteth", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("auditnotep", "deep-password")
    await patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    first = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "c-id",
            "blob": therapist.encrypt_note(patient, "c-id", "first"),
        },
    )
    assert first.status_code == 201, first.text
    # Byte-identical replay (a fresh GCM encryption has different bytes,
    # so re-encrypting the same plaintext is NOT a replay).
    replay = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": "c-id", "blob": first.json()["blob"]},
    )
    assert replay.status_code == 201
    changed = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "c-id",
            "blob": therapist.encrypt_note(patient, "c-id", "second"),
        },
    )
    assert changed.status_code == 409
    assert changed.json()["code"] == "version_conflict"


# ---------------------------------------------------------------------------
# kdf_params re-store validation (fail-closed on a corrupt column)
# ---------------------------------------------------------------------------


async def test_password_change_refuses_a_corrupt_kdf_params_column(client, app):
    from tests.helpers import EnvelopeClientEmulator

    emu = EnvelopeClientEmulator("kdfcorrupt", "pw-kdf-corrupt")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        from app.models import User

        user = await session.get(User, emu.user_id)
        user.kdf_params = '{"scheme":"pbkdf2","iterations":99999999,"salt":"zz"}'  # garbage
        await session.commit()
    new_salt = os.urandom(16)
    old_auth = emu.auth_key_b64
    emu.rederive("pw-kdf-corrupt-next", new_salt)
    wrapped = emu.wrap_for("pw-kdf-corrupt-next", new_salt)
    response = await client.put(
        "/api/account/password",
        headers=emu.headers,
        json={
            "verifier": old_auth,
            "new_salt": base64.b64encode(new_salt).decode(),
            "new_verifier": emu.auth_key_b64,
            "wrapped_data_key": wrapped,
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "envelope_key_mismatch"


# ---------------------------------------------------------------------------
# Config: _secret_env symmetry, metrics _FILE, MAC secret pins
# ---------------------------------------------------------------------------


def test_secret_env_strips_both_sources(monkeypatch, tmp_path):
    monkeypatch.setenv("MINDPATTERN_PROBE_A", "  spaced-secret  ")
    monkeypatch.delenv("MINDPATTERN_PROBE_A_FILE", raising=False)
    assert _secret_env("MINDPATTERN_PROBE_A") == "spaced-secret"
    # File source and env source resolve IDENTICALLY for the same value —
    # the old asymmetry (file stripped, env verbatim) was a config trap.
    secret_file = tmp_path / "probe_a"
    secret_file.write_text("spaced-secret\n")
    monkeypatch.setenv("MINDPATTERN_PROBE_A", "")
    monkeypatch.setenv("MINDPATTERN_PROBE_A_FILE", str(secret_file))
    assert _secret_env("MINDPATTERN_PROBE_A") == "spaced-secret"
    # Empty both-sources falls back.
    monkeypatch.delenv("MINDPATTERN_PROBE_A_FILE", raising=False)
    assert _secret_env("MINDPATTERN_PROBE_A", "fallback") == "fallback"


def test_metrics_token_resolves_from_file(monkeypatch, tmp_path):
    token_file = tmp_path / "metrics_token"
    token_file.write_text("metrics-file-token\n")
    monkeypatch.delenv("MINDPATTERN_METRICS_TOKEN", raising=False)
    monkeypatch.setenv("MINDPATTERN_METRICS_TOKEN_FILE", str(token_file))
    assert Settings.from_env().metrics_token == "metrics-file-token"


def test_audit_mac_secret_explicit_must_be_hex32():
    with pytest.raises(RuntimeError, match="AUDIT_MAC_SECRET"):
        Settings(
            environment="development",
            token_secret="x" * 32,
            audit_mac_secret_explicit="not-hex",
        )


def test_audit_mac_key_derives_from_token_secret_and_explicit_wins():
    derived = Settings(environment="development", token_secret="k" * 32).audit_mac_secret_hex
    assert len(derived) == 64
    other = Settings(
        environment="development",
        token_secret="k" * 32,
        audit_mac_secret_explicit="ab" * 32,
    ).audit_mac_secret_hex
    assert other == "ab" * 32
    assert other != derived


# ---------------------------------------------------------------------------
# Limiter: the 128-entry compression keeps counts exact
# ---------------------------------------------------------------------------


def test_sliding_window_compression_keeps_counts_exact():
    counter = SlidingWindowCounter()
    # 130 hits with DISTINCT timestamps in one window: the per-key log
    # compresses past 128 entries (two oldest merge under the older
    # timestamp) but the COUNT must stay exact — this is the one branch
    # the 2026-09-27 audit found uncovered.
    for i in range(130):
        counter.hit("k1", 60, now=10.0 + i * 0.1)
    state = counter._hits["k1"]  # noqa: SLF001 — pinning the internal seam
    assert len(state.log) <= _MAX_LOG_ENTRIES
    result = counter.check("k1", 60, now=10.0 + 130 * 0.1)
    assert result.count == 130


def test_sliding_window_entries_age_out_at_the_boundary():
    counter = SlidingWindowCounter()
    counter.hit("k2", 60, now=100.0)
    # Just inside the window the entry still counts...
    assert counter.check("k2", 60, now=159.999).count == 1
    # ...and exactly at window age it is OUT (>= boundary, fail-closed).
    # check() prunes destructively, so this must run LAST.
    assert counter.check("k2", 60, now=160.0).count == 0


# ---------------------------------------------------------------------------
# Coverage addendum: the new code's error/boundary branches
# ---------------------------------------------------------------------------


def test_read_journal_head_missing_file_is_none(tmp_path):
    assert read_journal_head(str(tmp_path / "absent.journal"), "u1") is None


def test_read_journal_head_flags_malformed_lines_without_losing_valid_evidence(tmp_path):
    owner = new_id_hex()
    journal = tmp_path / "audit.journal"
    journal.write_text(
        "garbage line\n"
        f"{owner} 7 {'a' * 64} {'b' * 64} 2026-09-27T01:00:00+00:00\n"
        f"{owner} 3 {'c' * 64} {'d' * 64} 2026-09-27T02:00:00+00:00\n"
    )
    assert read_journal_head(str(journal), owner) == (7, "2026-09-27T01:00:00+00:00")
    assert audit_journal_health() == (False, "malformed_evidence")
    original = journal.read_bytes()
    with pytest.raises(RuntimeError, match="malformed.*evidence"):
        compact_audit_journal(str(journal), "2030-01-01T00:00:00+00:00")
    assert journal.read_bytes() == original


async def test_corrupt_journal_fails_verification_even_after_db_state_deletion(
    chain_sessionmaker, tmp_path
):
    mac_key = _mac_key()
    owner = new_id_hex()
    await _seed_chain(chain_sessionmaker, owner, mac_key, n=1)
    journal = tmp_path / "audit.journal"
    journal.write_text("truncated committed evidence")
    async with chain_sessionmaker() as session:
        await session.execute(delete(AccessLog).where(AccessLog.user_id == owner))
        await session.execute(delete(AuditChainState).where(AuditChainState.user_id == owner))
        await session.commit()
        verdict = await verify_access_log_chain(
            session,
            owner,
            mac_key=mac_key,
            journal_path=str(journal),
            retention_cutoff=utcnow() - timedelta(days=1),
        )
    assert not verdict.ok
    assert "journal evidence is unavailable or malformed" in (verdict.reason or "")


async def test_append_falls_back_to_bare_flush_without_savepoints(chain_sessionmaker, monkeypatch):
    """Session surfaces without begin_nested (narrow doubles) take the bare
    flush — the pre-audit behavior, no retry seam."""
    user_id = new_id_hex()
    async with chain_sessionmaker() as session:
        monkeypatch.setattr(session, "begin_nested", None, raising=False)
        row = await append_access_log(
            session,
            actor_id=new_id_hex(),
            actor_role="patient",
            user_id=user_id,
            action="bare_flush",
            allow_new_chain=True,
        )
        await session.commit()
        assert row.chain_seq == 1


async def test_append_exhausts_retries_and_fails_loud(chain_sessionmaker, monkeypatch):
    """A head read that persistently misses the committed row exhausts the
    retry budget: the audited action fails with an explicit 500 instead of
    forking the chain."""
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac_key=None, n=1)
    async with chain_sessionmaker() as session:
        from sqlalchemy import select as sa_select

        real_execute = session.execute
        empty_head_stmt = (
            sa_select(AccessLog.chain_seq, AccessLog.entry_hash)
            .where(AccessLog.user_id == "no-such-patient")
            .order_by(AccessLog.chain_seq.desc())
            .limit(1)
        )

        async def always_missing_head(statement, *a, **kw):
            if (
                "chain_seq" in str(statement)
                and "access_log" in str(statement)
                and "SELECT" in str(statement).upper()
            ):
                return await real_execute(empty_head_stmt)
            return await real_execute(statement, *a, **kw)

        monkeypatch.setattr(session, "execute", always_missing_head)
        with pytest.raises(Exception) as excinfo:
            await append_access_log(
                session,
                actor_id=new_id_hex(),
                actor_role="patient",
                user_id=user_id,
                action="doomed",
            )
        assert excinfo.value.status_code == 500


async def test_verifier_empty_db_journal_branches(chain_sessionmaker, tmp_path):
    """Empty trail with external evidence cannot pass without durable state;
    malformed evidence is an even earlier global integrity failure."""
    mac = _mac_key()
    user_id = new_id_hex()
    stale = tmp_path / "stale.journal"
    stale.write_text(f"{user_id} 4 {'a' * 64} {'b' * 64} 2020-01-01T00:00:00+00:00\n")
    fresh = tmp_path / "fresh.journal"
    fresh.write_text(f"{user_id} 4 {'a' * 64} {'b' * 64} {utcnow().isoformat()}\n")
    junk = tmp_path / "junk.journal"
    junk.write_text(f"{user_id} 4 {'a' * 64} {'b' * 64} not-a-date\n")
    async with chain_sessionmaker() as session:
        old_cutoff = utcnow() - timedelta(days=730)
        for path in (stale,):
            missing_state = await verify_access_log_chain(
                session,
                user_id,
                mac_key=mac,
                journal_path=str(path),
                retention_cutoff=old_cutoff,
            )
            assert not missing_state.ok
            assert "state is missing" in missing_state.reason
        corrupt = await verify_access_log_chain(
            session,
            user_id,
            mac_key=mac,
            journal_path=str(junk),
            retention_cutoff=old_cutoff,
        )
        assert not corrupt.ok
        assert "unavailable or malformed" in (corrupt.reason or "")
        verdict = await verify_access_log_chain(
            session, user_id, mac_key=mac, journal_path=str(fresh), retention_cutoff=old_cutoff
        )
    assert not verdict.ok
    assert "state is missing" in verdict.reason


async def test_verifier_flags_malformed_hash_and_journal_ahead_with_rows(
    chain_sessionmaker, tmp_path
):
    mac = _mac_key()
    user_id = new_id_hex()
    await _seed_chain(chain_sessionmaker, user_id, mac, n=2)
    journal = str(tmp_path / "audit.journal")
    with open(journal, "w", encoding="utf-8") as handle:
        handle.write(f"{user_id} 3 {'f' * 64} {'a' * 64} {utcnow().isoformat()}\n")
    async with chain_sessionmaker() as session:
        row = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == user_id)))
            .scalars()
            .first()
        )
        row.entry_hash = "short"
        await session.commit()
        verdict = await verify_access_log_chain(session, user_id, mac_key=mac)
        assert not verdict.ok and "malformed entry_hash" in verdict.reason

        row.entry_hash = None
        await session.commit()
        verdict = await verify_access_log_chain(session, user_id, mac_key=mac)
        assert not verdict.ok and "malformed entry_hash" in verdict.reason

        # Rows present + journal head BEYOND the db head -> truncation.
        await _seed_chain(chain_sessionmaker, user_id, mac, n=2)
        other = new_id_hex()
        await _seed_chain(chain_sessionmaker, other, mac, n=1)
        with open(journal, "a", encoding="utf-8") as handle:
            handle.write(f"{other} 9 {'e' * 64} {'b' * 64} {utcnow().isoformat()}\n")
        verdict = await verify_access_log_chain(session, other, mac_key=mac, journal_path=journal)
    assert not verdict.ok
    assert "tail truncation" in verdict.reason


async def test_journal_flush_failure_never_fails_the_request(client, app, monkeypatch, tmp_path):
    """deps.get_session flushes the journal post-commit; an unwritable
    journal path (a directory) must degrade to a logged non-event — the
    anchor contract is best-effort, never a 500."""
    import pathlib

    app.state.settings.audit_journal_path = str(tmp_path / "dir-as-file")
    pathlib.Path(app.state.settings.audit_journal_path).mkdir()
    emu = ClientEmulator("journalfail", "pw-journal-fail")
    await emu.register(client)
    # An audited, committing request through the real dependency stack:
    # grant pairing -> consent -> audit row staged + committed + flush
    # attempt against the directory -> OSError -> swallowed + logged.
    therapist = TherapistEmulator("journalth", "deep-password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await emu.pairing_lookup(client, code)
    granted = await emu.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted


async def test_sweep_fails_closed_on_an_unavailable_mac_keyring(client, app, monkeypatch):
    """Retention cannot fall back to unauthenticated link-only verification."""
    from types import SimpleNamespace

    from app import main as main_mod

    emu = ClientEmulator("missing-keyring", "keyring-password")
    await emu.register(client)
    owner = emu.user_id
    assert owner is not None
    async with app.state.sessionmaker() as session:
        before_rows = list(
            (
                await session.execute(
                    select(AccessLog.id, AccessLog.chain_seq, AccessLog.entry_hash)
                    .where(AccessLog.user_id == owner)
                    .order_by(AccessLog.chain_seq)
                )
            ).all()
        )
        before_state = await session.get(AuditChainState, owner)
        assert before_state is not None
        before_state_values = (
            before_state.head_seq,
            before_state.head_hash,
            before_state.first_retained_seq,
            before_state.first_retained_hash,
            before_state.state_mac,
        )
    real_settings = app.state.settings
    fake = SimpleNamespace(
        access_log_retention_days=730,
        audit_journal_path="",
        audit_mac_secret_hex="not-hex-at-all",
    )
    monkeypatch.setattr(app.state, "settings", fake)
    try:
        with pytest.raises(RuntimeError, match="requires a valid MAC key ring"):
            await main_mod._prune_access_log_once(app)
        assert app.state.audit_maintenance_healthy is False
        assert "mindpattern_audit_maintenance_failures_total 1" in app.state.metrics.render(0)
        async with app.state.sessionmaker() as session:
            after_rows = list(
                (
                    await session.execute(
                        select(AccessLog.id, AccessLog.chain_seq, AccessLog.entry_hash)
                        .where(AccessLog.user_id == owner)
                        .order_by(AccessLog.chain_seq)
                    )
                ).all()
            )
            after_state = await session.get(AuditChainState, owner)
            assert after_state is not None
            assert after_rows == before_rows
            assert (
                after_state.head_seq,
                after_state.head_hash,
                after_state.first_retained_seq,
                after_state.first_retained_hash,
                after_state.state_mac,
            ) == before_state_values
    finally:
        monkeypatch.setattr(app.state, "settings", real_settings)


def test_metrics_middleware_passes_non_http_scopes_through():
    from app.metrics import MetricsMiddleware, MetricsRegistry

    seen: list[str] = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    middleware = MetricsMiddleware(inner, MetricsRegistry())
    import asyncio

    asyncio.run(middleware({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_revocation_store_prune_and_empty_jti_semantics():
    store = TokenRevocationStore()
    assert store.prune(now=0.0) == 0
    store.revoke("j1" + "0" * 30, 100.0, now=10.0)
    assert store.prune(now=99.0) == 0  # still unexpired
    assert store.prune(now=100.0) == 1  # boundary: expired


async def test_checked_lookup_answers_false_for_empty_jti(chain_sessionmaker):
    store = TokenRevocationStore()
    async with chain_sessionmaker() as session:
        assert not await store.is_revoked_checked(session, None)
        assert not await store.is_revoked_checked(session, "")
