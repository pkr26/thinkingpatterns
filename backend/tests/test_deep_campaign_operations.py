"""Independent behavior oracles for backend operational mutation campaigns."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import cache
from app.config import DEFAULT_INSECURE_SECRET, Settings
from app.db import build_engine, build_sessionmaker, init_models
from app.locks import UserLocks
from app.metrics import MetricsRegistry
from app.middleware import HardeningMiddleware
from app.models import AccountDeletionJob, Entry, User
from app.services.account_deletion import stage_account_deletion

ROOT = Path(__file__).resolve().parents[2]


async def _request(headers=(), body=b"", method="POST", cap=1024):
    messages = []
    called = []
    received = False

    async def application(scope, receive, send):
        called.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    middleware = HardeningMiddleware(application, max_body_bytes=cap)
    await middleware(
        {
            "type": "http",
            "method": method,
            "path": "/api/v1/entries",
            "headers": list(headers),
            "client": ("192.0.2.1", 1234),
        },
        receive,
        send,
    )
    return messages, called


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"0"), (b"content-length", b"0")],
        [(b"content-length", b"0"), (b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"gzip, chunked")],
        [(b"content-length", b"+0")],
    ],
)
async def test_ambiguous_http_framing_never_dispatches(headers):
    messages, called = await _request(headers)
    assert messages[0]["status"] == 400
    assert not called


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST"])
async def test_unframed_body_limit_applies_to_every_method(method):
    messages, called = await _request(body=b"x" * 1025, method=method)
    assert messages[0]["status"] == 413
    assert not called
    valid, replay = await _request(body=b"x" * 1024, method=method)
    assert valid[0]["status"] == 204
    assert replay[0]["body"] == b"x" * 1024


def test_rate_counter_monotonic_expiry_and_read_only_checks(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(cache.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cache.time, "time", lambda: -1_000_000.0)
    counter = cache.SlidingWindowCounter()
    assert counter.hit("patient", 10).count == 1
    clock[0] = 104.0
    assert counter.hit("patient", 10).count == 2
    assert counter.check("patient", 10).count == 2
    assert counter.check("patient", 10).count == 2
    assert counter.hit("other", 10).count == 1
    clock[0] = 110.0
    assert counter.check("patient", 10).count == 1
    clock[0] = 114.0
    assert counter.check("patient", 10).count == 0


def test_rate_counter_compression_preserves_all_live_hits(monkeypatch):
    monkeypatch.setattr(cache, "_MAX_LOG_ENTRIES", 3)
    counter = cache.SlidingWindowCounter()
    for index in range(20):
        assert counter.hit("patient", 100, now=float(index)).count == index + 1
    assert counter.check("patient", 100, now=20).count == 20
    assert counter.check("patient", 100, now=120).count == 0


async def test_body_deadline_is_total_even_when_chunks_keep_arriving(monkeypatch):
    import app.middleware as middleware_module

    clock = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(
        middleware_module.asyncio,
        "get_running_loop",
        lambda: SimpleNamespace(time=lambda: next(clock)),
    )
    reads = []
    messages = []

    async def receive():
        reads.append(True)
        return {"type": "http.request", "body": b"x", "more_body": len(reads) == 1}

    async def send(message):
        messages.append(message)

    async def application(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})

    middleware = HardeningMiddleware(application, max_body_bytes=1024, body_read_timeout_seconds=30)
    await middleware(
        {"type": "http", "method": "POST", "path": "/", "headers": [], "client": ("192.0.2.1", 10)},
        receive,
        send,
    )
    assert messages[0]["status"] == 408
    assert len(reads) == 1


async def test_expired_deadline_refuses_even_an_already_buffered_receive_awaitable(monkeypatch):
    import app.middleware as middleware_module

    loop = asyncio.get_running_loop()
    clock = iter((0.0, 0.0, 30.5))
    monkeypatch.setattr(
        middleware_module.asyncio,
        "get_running_loop",
        lambda: SimpleNamespace(time=lambda: next(clock)),
    )
    reads = []
    messages = []

    def receive():
        # Starlette's Receive contract accepts any Awaitable[Message]. A
        # buffered transport can return an already fulfilled Future; negative
        # wait_for timeouts do not reject an awaitable that is already done.
        reads.append(True)
        pending = loop.create_future()
        pending.set_result({"type": "http.request", "body": b"x", "more_body": len(reads) == 1})
        return pending

    async def send(message):
        messages.append(message)

    async def application(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})

    middleware = HardeningMiddleware(application, max_body_bytes=1024, body_read_timeout_seconds=30)
    await middleware(
        {"type": "http", "method": "POST", "path": "/", "headers": [], "client": ("192.0.2.1", 10)},
        receive,
        send,
    )
    assert messages[0]["status"] == 408
    assert len(reads) == 1


async def test_untrusted_socket_peer_cannot_supply_forwarded_rate_identity():
    identities = []

    async def application(scope, receive, send):
        identities.append(cache.client_key_from_scope(scope, trust_proxy_headers=True))
        await send({"type": "http.response.start", "status": 204, "headers": []})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        pass

    middleware = HardeningMiddleware(
        application, max_body_bytes=1024, trust_proxy_headers=True, trusted_proxy_ips=["10.0.0.1"]
    )
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"203.0.113.9")],
            "client": ("192.0.2.1", 10),
        },
        receive,
        send,
    )
    assert identities == ["192.0.2.1"]


async def test_cancelled_lock_waiter_does_not_split_owner_lock():
    locks = UserLocks(max_keys=1)
    waiting = asyncio.Event()

    async def waiter():
        waiting.set()
        async with locks.hold("patient"):
            raise AssertionError("cancelled waiter entered critical section")

    async with locks.hold("patient") as first:
        task = asyncio.create_task(waiter())
        await waiting.wait()
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with locks.hold("other"):
            assert locks._locks["patient"].lock is first
            assert locks._locks["patient"].refs == 1
    async with locks.hold("patient"):
        pass
    assert locks._locks["patient"].refs == 0
    assert locks.total_overflow_refs() == 0


async def test_live_fallback_keeps_same_key_serialized_after_registry_space_opens():
    locks = UserLocks(max_keys=1)
    dedicated = locks.hold("dedicated")
    await dedicated.__aenter__()
    fallback = locks.hold("patient")
    await fallback.__aenter__()
    await dedicated.__aexit__(None, None, None)
    entered = asyncio.Event()

    async def contender():
        async with locks.hold("patient"):
            entered.set()

    task = asyncio.create_task(contender())
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not entered.is_set()
    finally:
        await fallback.__aexit__(None, None, None)
        await task
    assert entered.is_set()


async def test_saturated_admission_rejects_before_reading_and_does_not_hang():
    entered, release = asyncio.Event(), asyncio.Event()
    statuses = []

    async def application(scope, receive, send):
        entered.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 204, "headers": []})

    async def first_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def forbidden_receive():
        raise AssertionError("saturated admission read another request body")

    async def send(message):
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    middleware = HardeningMiddleware(application, max_body_bytes=1024, body_buffer_concurrency=1)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [],
        "client": ("192.0.2.1", 10),
    }
    first = asyncio.create_task(middleware(dict(scope), first_receive, send))
    await entered.wait()
    try:
        await middleware(dict(scope), forbidden_receive, send)
        assert statuses == [503]
    finally:
        release.set()
        await first
    assert statuses == [503, 204]


async def test_lost_database_lock_disables_admission_and_scrubs_resident_keys():
    from app.main import _guard_is_healthy

    erased = []

    class Connection:
        async def exec_driver_sql(self, query):
            return SimpleNamespace(scalar=lambda: False)

        async def commit(self):
            pass

    state = SimpleNamespace(
        guard_healthy=True,
        guard_connection=Connection(),
        guard_check_lock=asyncio.Lock(),
        key_store=SimpleNamespace(destroy_all=lambda: erased.append(True)),
        request_tasks=set(),
    )
    application = SimpleNamespace(state=state)
    assert not await _guard_is_healthy(application)
    assert not state.guard_healthy and erased == [True]
    assert not await _guard_is_healthy(application)
    assert erased == [True]


def test_production_default_secret_refusal_is_not_masked_by_other_faults(tmp_path):
    valid = dict(
        environment="production",
        database_url="postgresql+asyncpg://postgres@localhost/mindpattern_mutation_test",
        token_secret="synthetic-base-secret-material-123456789",
        auth_token_secret_explicit="a" * 32,
        totp_wrap_secret_explicit="b" * 32,
        pairing_secret_explicit="c" * 32,
        decoy_secret="d" * 32,
        audit_mac_secret_explicit="ab" * 32,
        audit_journal_path=str(tmp_path / "audit.jsonl"),
    )
    Settings(**valid)
    with pytest.raises(RuntimeError, match="TOKEN_SECRET is unset/insecure"):
        Settings(**{**valid, "token_secret": DEFAULT_INSECURE_SECRET})


def test_forwarding_trust_requires_an_actual_direct_peer_allowlist():
    accepted = Settings(
        environment="development", trust_proxy_headers=True, trusted_proxy_ips=["192.0.2.1"]
    )
    assert accepted.trusted_proxy_ips == ["192.0.2.1/32"]
    with pytest.raises(RuntimeError, match="requires a non-empty"):
        Settings(environment="development", trust_proxy_headers=True, trusted_proxy_ips=[])


def test_complete_body_memory_budget_includes_larger_audio_cap():
    limits = dict(
        environment="development",
        max_body_bytes=1024 * 1024,
        audio_max_body_bytes=2 * 1024 * 1024,
    )
    Settings(**limits, body_buffer_concurrency=256)
    with pytest.raises(RuntimeError, match="exceeds the edge body-buffer memory budget"):
        Settings(**limits, body_buffer_concurrency=257)


def test_metrics_histogram_and_fixed_failure_categories():
    metrics = MetricsRegistry()
    for duration in (0.25, 0.75, 3.0):
        metrics.observe_recompute(duration)
    metrics.observe_account_deletion_failure("private-account/provider-error")
    metrics.observe_request(422)
    output = metrics.render(0)
    assert 'mindpattern_recompute_seconds_bucket{le="0.25"} 1' in output
    assert 'mindpattern_recompute_seconds_bucket{le="1.0"} 2' in output
    assert 'mindpattern_recompute_seconds_bucket{le="+Inf"} 3' in output
    assert 'mindpattern_requests_total{status="4xx"} 1' in output
    assert 'category="unexpected"} 1' in output
    assert "private-account" not in output
    samples = [line.split(" ")[0] for line in output.splitlines() if not line.startswith("#")]
    assert len(samples) == len(set(samples))


def _backup_module():
    spec = importlib.util.spec_from_file_location("deep_backup", ROOT / "backup/backup_mac.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_backup_pruning_exact_boundary_and_scope(tmp_path, monkeypatch):
    backup = _backup_module()
    monkeypatch.setattr(backup.time, "time", lambda: 1_000_000.0)
    cutoff = 1_000_000.0 - 86_400
    for name, modified in [
        ("mindpattern-old.dump.enc", cutoff),
        ("mindpattern-old.dump.enc.hmac", cutoff - 1),
        ("mindpattern-new.dump.enc", cutoff + 1),
        ("unrelated.dump.enc", cutoff - 1),
    ]:
        path = tmp_path / name
        path.write_bytes(b"synthetic")
        os.utime(path, (modified, modified))
    assert backup._prune(tmp_path, "1") == 2
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "mindpattern-new.dump.enc",
        "unrelated.dump.enc",
    ]


def test_backup_real_roundtrip_and_tamper_no_plaintext(tmp_path):
    helper = ROOT / "backup/backup_mac.py"
    keyfile = tmp_path / "secret"
    keyfile.write_text("synthetic-backup-secret\n")
    ciphertext = tmp_path / "archive.enc"
    sidecar = tmp_path / "archive.enc.hmac"
    env = dict(os.environ, BACKUP_KEY="", BACKUP_KEY_FILE=str(keyfile))
    payload = b"synthetic restore probe\x00" * 64
    sealed = subprocess.run(
        [sys.executable, str(helper), "encrypt", str(ciphertext), str(sidecar)],
        input=payload,
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert sealed.returncode == 0, sealed.stderr
    opened = subprocess.run(
        [sys.executable, str(helper), "decrypt", str(ciphertext), str(sidecar)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert opened.returncode == 0 and opened.stdout == payload
    data = bytearray(ciphertext.read_bytes())
    data[-1] ^= 1
    ciphertext.write_bytes(data)
    rejected = subprocess.run(
        [sys.executable, str(helper), "decrypt", str(ciphertext), str(sidecar)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert rejected.returncode != 0 and rejected.stdout == b""


def test_decrypt_consumes_exact_authenticated_snapshot_despite_in_place_rewrite(
    tmp_path, monkeypatch
):
    backup = _backup_module()
    monkeypatch.setenv("BACKUP_KEY", "synthetic-secret")
    ciphertext = tmp_path / "cipher.enc"
    ciphertext.write_bytes(b"authenticated-original")
    sidecar = tmp_path / "cipher.enc.hmac"
    sidecar.write_bytes(backup._tag(ciphertext))
    compare = backup.hmac.compare_digest
    observed = []

    def authenticate_then_rewrite(actual, expected):
        valid = compare(actual, expected)
        ciphertext.write_bytes(b"unauthenticated-replacement")
        return valid

    def consume(secret, source, destination, *, decrypt):
        observed.append(source.read())
        return 0

    monkeypatch.setattr(backup.hmac, "compare_digest", authenticate_then_rewrite)
    monkeypatch.setattr(backup, "_openssl", consume)
    assert backup._crypt_file("decrypt", ciphertext, sidecar) == 0
    assert observed == [b"authenticated-original"]


async def test_entry_duplicate_identity_is_a_database_constraint():
    engine = build_engine("sqlite+aiosqlite://")
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    try:
        async with sessions() as session:
            user = User(
                id="owner", username="owner", salt="salt", verifier=b"v" * 32, scrypt_salt=b"s" * 16
            )
            session.add(user)
            await session.commit()
            for identifier in ("first", "second"):
                session.add(
                    Entry(
                        id=identifier,
                        user_id=user.id,
                        client_entry_id="same-client-id",
                        entry_date=user.created_at.date(),
                        blob=b"cipher",
                    )
                )
            with pytest.raises(IntegrityError):
                await session.commit()
    finally:
        await engine.dispose()


async def test_logical_retirement_clears_credentials_and_queues_persistent_erasure():
    engine = build_engine("sqlite+aiosqlite://")
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    try:
        async with sessions() as session:
            user = User(
                id="retiring",
                username="retiring",
                salt="salt",
                verifier=b"v" * 32,
                scrypt_salt=b"s" * 16,
                key_scheme="v2",
                wrapped_data_key=b"encrypted-key",
                recovery_verifier=b"r" * 32,
                recovery_wrapped_data_key=b"encrypted-recovery",
                voice_consent=True,
                llm_consent=True,
                entry_count=10,
                entry_blob_bytes=100,
            )
            session.add(user)
            await session.commit()
            stage_account_deletion(session, user)
            await session.commit()
        async with sessions() as session:
            user = await session.get(User, "retiring")
            assert not user.is_active and user.username != "retiring"
            assert user.verifier != b"v" * 32 and user.salt != "salt"
            assert user.wrapped_data_key is None and user.recovery_verifier is None
            assert user.recovery_wrapped_data_key is None
            assert not user.voice_consent and not user.llm_consent
            assert user.entry_count == 0 and user.entry_blob_bytes == 0
            job = await session.scalar(
                select(AccountDeletionJob).where(AccountDeletionJob.user_id == user.id)
            )
            assert job is not None and job.phase == "note_revisions"
    finally:
        await engine.dispose()


async def test_foreign_key_cascade_really_erases_child_rows():
    engine = build_engine("sqlite+aiosqlite://")
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    try:
        async with sessions() as session:
            user = User(
                id="cascade-owner",
                username="cascade-owner",
                salt="salt",
                verifier=b"v" * 32,
                scrypt_salt=b"s" * 16,
            )
            session.add(user)
            await session.commit()
            session.add(
                Entry(
                    id="cascade-child",
                    user_id=user.id,
                    client_entry_id="child",
                    entry_date=user.created_at.date(),
                    blob=b"cipher",
                )
            )
            await session.commit()
            await session.delete(user)
            await session.commit()
        async with sessions() as session:
            assert await session.get(Entry, "cascade-child") is None
    finally:
        await engine.dispose()


async def test_resumed_user_purge_phase_checks_dependents_before_bulk_cascade():
    from sqlalchemy import func

    from app.services.account_deletion import ACCOUNT_PURGE_ROW_BATCH, purge_one_account_page

    engine = build_engine("sqlite+aiosqlite://")
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    try:
        async with sessions() as session:
            user = User(
                id="resume-purge",
                username="resume-purge",
                salt="salt",
                verifier=b"v" * 32,
                scrypt_salt=b"s" * 16,
            )
            session.add(user)
            await session.commit()
            count = ACCOUNT_PURGE_ROW_BATCH + 5
            session.add_all(
                [
                    Entry(
                        id=f"remaining-{i}",
                        user_id=user.id,
                        client_entry_id=f"client-{i}",
                        entry_date=user.created_at.date(),
                        blob=b"cipher",
                    )
                    for i in range(count)
                ]
            )
            job = stage_account_deletion(session, user)
            job.phase = "user"
            await session.commit()
            progress = await purge_one_account_page(
                session, Settings(environment="development"), owner_id=user.id
            )
            await session.commit()
            assert progress.backlog and progress.rows_deleted == 0
            assert await session.get(User, user.id) is not None
            assert await session.scalar(select(func.count(Entry.id))) == count
            assert job.phase == "entries"
    finally:
        await engine.dispose()


async def test_purge_row_budget_is_shared_across_different_child_collections():
    from sqlalchemy import func

    from app.models import Measure
    from app.services.account_deletion import ACCOUNT_PURGE_ROW_BATCH, purge_one_account_page

    engine = build_engine("sqlite+aiosqlite://")
    await init_models(engine)
    sessions = build_sessionmaker(engine)
    try:
        async with sessions() as session:
            user = User(
                id="multi-phase-purge",
                username="multi-phase-purge",
                salt="salt",
                verifier=b"v" * 32,
                scrypt_salt=b"s" * 16,
            )
            session.add(user)
            await session.commit()
            entries = ACCOUNT_PURGE_ROW_BATCH // 2
            measures = ACCOUNT_PURGE_ROW_BATCH - entries + 7
            session.add_all(
                [
                    Entry(
                        user_id=user.id,
                        client_entry_id=f"entry-{i}",
                        entry_date=user.created_at.date(),
                        blob=b"cipher",
                    )
                    for i in range(entries)
                ]
                + [
                    Measure(
                        user_id=user.id,
                        client_measure_id=f"measure-{i}",
                        measure_date=user.created_at.date(),
                        blob=b"cipher",
                    )
                    for i in range(measures)
                ]
            )
            stage_account_deletion(session, user)
            await session.commit()
            progress = await purge_one_account_page(
                session, Settings(environment="development"), owner_id=user.id
            )
            await session.commit()
            assert progress.rows_deleted == ACCOUNT_PURGE_ROW_BATCH
            assert progress.backlog
            assert await session.get(User, user.id) is not None
            assert await session.scalar(select(func.count(Entry.id))) == 0
            assert await session.scalar(select(func.count(Measure.id))) == 7
    finally:
        await engine.dispose()


def test_real_postgresql_upgrade_persists_schema_and_head(monkeypatch):
    """Use only the campaign's dedicated disposable PostgreSQL database."""
    from alembic import command
    from alembic.config import Config

    from app.db import SCHEMA_HEAD

    url = os.environ.get("DEEP_MUTATION_POSTGRES_URL", "")
    if not url:
        pytest.skip("dedicated mutation PostgreSQL URL not supplied")
    assert "mindpattern_mutation_test" in url
    monkeypatch.setenv("MINDPATTERN_DB_URL", url)

    async def reset():
        engine = build_engine(url)
        try:
            async with engine.begin() as connection:
                await connection.exec_driver_sql("DROP SCHEMA public CASCADE")
                await connection.exec_driver_sql("CREATE SCHEMA public")
        finally:
            await engine.dispose()

    asyncio.run(reset())
    command.upgrade(Config(str(ROOT / "backend/alembic.ini")), "head")

    async def inspect():
        engine = build_engine(url)
        try:
            async with engine.connect() as connection:
                version = (
                    await connection.exec_driver_sql("SELECT version_num FROM alembic_version")
                ).scalar_one()
                assert version == SCHEMA_HEAD
                assert (
                    await connection.exec_driver_sql("SELECT COUNT(*) FROM entries")
                ).scalar_one() == 0
                assert (
                    await connection.exec_driver_sql(
                        "SELECT completed_at FROM entry_guard_bootstrap WHERE id=1"
                    )
                ).scalar_one() is None
        finally:
            await engine.dispose()

    asyncio.run(inspect())
