"""Focused behavioral coverage for infrastructure boundaries.

These tests deliberately exercise only configuration, request hardening,
in-process coordination, and application lifecycle plumbing.  They avoid the
router/service behavior owned by the feature suites.
"""

from __future__ import annotations

import asyncio
import uuid
from ipaddress import ip_network
from types import SimpleNamespace
from unittest.mock import AsyncMock

import anyio
import pytest

import app.main as main
import app.singleprocess as singleprocess
from app.api import auth
from app.cache import (
    FixedWindowCounter,
    _aggregate_host,
    check_keyed_limit_without_count,
    client_key,
    record_keyed_failure,
)
from app.config import (
    MAX_BODY_READ_TIMEOUT_SECONDS,
    Settings,
    _optional_bool_env,
    _validate_cors_origins,
)
from app.deps import ApiError
from app.locks import UserLocks, sharing_patient_lock_key, sharing_therapist_lock_key
from app.middleware import HardeningMiddleware, _forwarded_client


def _dev_settings(**overrides) -> Settings:
    values = {
        "environment": "development",
        "token_secret": "x" * 40,
        "database_url": "sqlite+aiosqlite://",
    }
    values.update(overrides)
    return Settings(**values)


def _prod_settings(**overrides) -> Settings:
    values = {
        "environment": "staging",
        "token_secret": "x" * 40,
        "database_url": "postgresql+asyncpg://u:p@db.example/mindpattern",
    }
    values.update(overrides)
    return Settings(**values)


# ---------------------------------------------------------------------------
# auth.py
# ---------------------------------------------------------------------------


async def test_auth_admission_rejects_when_all_kdf_slots_are_reserved():
    limiter = anyio.CapacityLimiter(1)
    other_borrower = object()
    await limiter.acquire_on_behalf_of(other_borrower)
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(auth_admission_limiter=limiter))
    )
    try:
        with pytest.raises(ApiError) as exc_info:
            async with auth.auth_work_slot(request):
                pytest.fail("a saturated admission limiter must not admit work")
    finally:
        limiter.release_on_behalf_of(other_borrower)

    assert exc_info.value.status_code == 503
    assert exc_info.value.headers == {"Retry-After": "1"}


async def test_auth_closes_read_transaction_with_rollback_on_commit_failure():
    session = SimpleNamespace(
        commit=AsyncMock(side_effect=RuntimeError("commit failed")),
        rollback=AsyncMock(),
    )

    with pytest.raises(RuntimeError, match="commit failed"):
        await auth._close_read_transaction(session)

    session.rollback.assert_awaited_once()


# ---------------------------------------------------------------------------
# cache.py
# ---------------------------------------------------------------------------


def test_cache_falls_back_safely_for_malformed_or_nonstring_forwarded_identity():
    assert _aggregate_host("not:an:ip") == "not:an:ip"
    request = SimpleNamespace(
        state=SimpleNamespace(
            mindpattern_trusted_proxy=True,
            mindpattern_forwarded_client=object(),
        ),
        client=SimpleNamespace(host="203.0.113.9"),
    )
    assert client_key(request, trust_proxy_headers=True) == "203.0.113.9"


def test_cache_keyed_limit_rejects_exactly_at_the_failure_budget():
    counter = FixedWindowCounter()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(rate_counter=counter)))
    record_keyed_failure(request, "register-name:alice", 60)
    record_keyed_failure(request, "register-name:alice", 60)

    with pytest.raises(ApiError) as exc_info:
        check_keyed_limit_without_count(request, "register-name:alice", limit=2, window=60)

    assert exc_info.value.status_code == 429


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------


def test_config_optional_boolean_keeps_explicit_false_distinct_from_absence(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_INFRA_FLAG", raising=False)
    assert _optional_bool_env("MINDPATTERN_INFRA_FLAG") is None
    monkeypatch.setenv("MINDPATTERN_INFRA_FLAG", "off")
    assert _optional_bool_env("MINDPATTERN_INFRA_FLAG") is False


def test_config_rejects_invalid_cors_authority_and_non_https_remote_origin():
    with pytest.raises(RuntimeError, match="invalid origin"):
        _validate_cors_origins(["https://browser.example:abc"], "development")
    with pytest.raises(RuntimeError, match="must contain exact https"):
        _validate_cors_origins(["ftp://browser.example"], "development")


def test_config_rejects_remaining_operational_upper_bounds():
    with pytest.raises(RuntimeError, match="body_read_timeout_seconds"):
        _dev_settings(body_read_timeout_seconds=MAX_BODY_READ_TIMEOUT_SECONDS + 1)
    with pytest.raises(RuntimeError, match="analysis_blob_budget"):
        _dev_settings(analysis_blob_budget=64 * 1024 * 1024 + 1)
    with pytest.raises(RuntimeError, match="access_log_retention_days"):
        _dev_settings(access_log_retention_days=3_651)


def test_config_requires_production_llm_policy_and_valid_authority():
    with pytest.raises(RuntimeError, match="MINDPATTERN_LLM_URL contains an invalid authority"):
        _dev_settings(llm_url="https://provider.example:abc")
    with pytest.raises(RuntimeError, match="requires explicit provider, retention, and policy"):
        _prod_settings(
            llm_url="https://provider.example/v1",
            llm_provider_name="",
            llm_data_retention="",
            llm_policy_version="",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("llm_policy_version", "p" * 65, "policy_version"),
        ("llm_provider_name", "p" * 121, "provider_name"),
        ("llm_data_retention", "p" * 501, "data_retention"),
    ],
)
def test_config_rejects_overlong_llm_disclosure_fields(field, value, message):
    with pytest.raises(RuntimeError, match=message):
        _dev_settings(**{field: value})


def test_config_production_pool_and_sharing_enrollment_gates():
    with pytest.raises(RuntimeError, match="db_pool_size"):
        _prod_settings(db_pool_size=1, db_max_overflow=0)
    with pytest.raises(RuntimeError, match="therapist sharing"):
        _prod_settings(therapist_sharing_enabled=True, therapist_enrollment_token="too-short")


# ---------------------------------------------------------------------------
# locks.py / singleprocess.py
# ---------------------------------------------------------------------------


def test_user_lock_constructor_and_sharing_key_helpers_are_explicit():
    with pytest.raises(ValueError, match="max_keys must be positive"):
        UserLocks(max_keys=0)
    assert sharing_therapist_lock_key("therapist-1") == "sharing-therapist:therapist-1"
    assert sharing_patient_lock_key("patient-1") == "sharing-patient:patient-1"


async def test_user_locks_keep_new_keys_on_live_overflow_lock_until_it_drains():
    locks = UserLocks(max_keys=1)
    overflow_entered = asyncio.Event()
    release_overflow = asyncio.Event()
    second_overflow_entered = asyncio.Event()

    async def first_overflow_user():
        async with locks.hold("overflow-a"):
            overflow_entered.set()
            await release_overflow.wait()

    async def second_overflow_user():
        await overflow_entered.wait()
        async with locks.hold("overflow-b"):
            second_overflow_entered.set()

    # A live dedicated lock fills the registry, forcing the first absent key
    # to fallback. While that fallback is live, all later absent keys must use
    # the same lock (rather than minting a potentially conflicting entry).
    async with locks.hold("dedicated"):
        first = asyncio.create_task(first_overflow_user())
        await overflow_entered.wait()
        second = asyncio.create_task(second_overflow_user())
        await asyncio.sleep(0)
        assert locks._overflow_refs == 2
        assert not second_overflow_entered.is_set()
        release_overflow.set()
        await asyncio.gather(first, second)


def test_single_process_guard_is_reentrant_and_handles_no_held_lock(monkeypatch):
    token = f"infra-{uuid.uuid4()}"
    database_url = f"sqlite+aiosqlite:///tmp/{uuid.uuid4()}.db"
    path = singleprocess.acquire_single_process_lock(token, database_url)
    try:
        assert singleprocess.acquire_single_process_lock(token, database_url) == path
    finally:
        singleprocess.release_single_process_lock(token, database_url)
    # Idempotent cleanup is important when a partially started lifespan exits.
    singleprocess.release_single_process_lock(token, database_url)

    def unavailable(*_args, **_kwargs):
        raise OSError("already locked")

    monkeypatch.setattr(singleprocess.fcntl, "flock", unavailable)
    with pytest.raises(singleprocess.MultipleWorkersError, match="another worker/process"):
        singleprocess.acquire_single_process_lock(f"infra-{uuid.uuid4()}", database_url)


# ---------------------------------------------------------------------------
# middleware.py
# ---------------------------------------------------------------------------


def _http_scope(headers=(), client=("127.0.0.1", 1234), state=None):
    return {
        "type": "http",
        "method": "POST",
        "path": "/infra",
        "headers": list(headers),
        "client": client,
        "state": {} if state is None else state,
    }


async def _call_asgi(app, scope, incoming):
    messages = list(incoming)
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def test_middleware_rejects_invalid_timeout_and_parses_only_safe_forwarding_values():
    with pytest.raises(ValueError, match="body_read_timeout_seconds must be positive"):
        HardeningMiddleware(lambda *_: None, max_body_bytes=10, body_read_timeout_seconds=0)

    trusted = (ip_network("10.0.0.0/8"),)
    assert (
        _forwarded_client([(b"x-forwarded-for", b"opaque, 198.51.100.7, 10.1.1.1")], trusted)
        == "198.51.100.7"
    )
    assert _forwarded_client([(b"x-forwarded-for", b"10.1.1.1")], trusted) is None
    middleware = HardeningMiddleware(
        lambda *_: None, max_body_bytes=10, trusted_proxy_ips=["10.0.0.0/8"]
    )
    assert middleware._direct_peer_is_trusted(_http_scope(client=("not-an-ip", 1))) is False


async def test_middleware_clears_unusable_forwarding_state_and_replays_unknown_asgi_message():
    seen = {}

    async def inner(scope, receive, send):
        seen["forwarded"] = scope["state"].get("mindpattern_forwarded_client")
        seen["message"] = await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = HardeningMiddleware(
        inner,
        max_body_bytes=10,
        trust_proxy_headers=True,
        trusted_proxy_ips=["10.0.0.0/8"],
    )
    scope = _http_scope(
        headers=[(b"x-forwarded-for", b"opaque")],
        client=("10.1.1.1", 443),
        state={"mindpattern_forwarded_client": "stale"},
    )
    sent = await _call_asgi(wrapped, scope, [{"type": "unexpected.asgi.message"}])

    assert seen == {"forwarded": None, "message": {"type": "unexpected.asgi.message"}}
    assert sent[0]["status"] == 200


async def test_middleware_never_replaces_an_already_started_response_after_an_exception():
    async def starts_then_fails(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})
        raise RuntimeError("late failure")

    wrapped = HardeningMiddleware(starts_then_fails, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope(),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert [message["status"] for message in sent if message["type"] == "http.response.start"] == [
        204
    ]


# ---------------------------------------------------------------------------
# main.py
# ---------------------------------------------------------------------------


class _GuardResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _GuardConnection:
    def __init__(self, acquired=True, failure: Exception | None = None):
        self.acquired = acquired
        self.failure = failure
        self.sql = []
        self.committed = False
        self.closed = False

    async def exec_driver_sql(self, statement):
        self.sql.append(statement)
        if self.failure is not None:
            raise self.failure
        return _GuardResult(self.acquired)

    async def commit(self):
        self.committed = True

    async def close(self):
        self.closed = True


class _GuardEngine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, connection):
        self.connection = connection

    async def connect(self):
        return self.connection


async def test_main_cross_host_guard_acquires_releases_and_fails_closed():
    assert (
        await main._acquire_cross_host_guard(
            SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
        )
        is None
    )

    acquired = _GuardConnection(acquired=True)
    assert await main._acquire_cross_host_guard(_GuardEngine(acquired)) is acquired
    assert acquired.committed and not acquired.closed
    await main._release_cross_host_guard(acquired)
    assert acquired.closed
    assert any("pg_advisory_unlock" in statement for statement in acquired.sql)

    denied = _GuardConnection(acquired=False)
    with pytest.raises(RuntimeError, match="another host"):
        await main._acquire_cross_host_guard(_GuardEngine(denied))
    assert denied.closed

    broken = _GuardConnection(failure=RuntimeError("database unavailable"))
    with pytest.raises(RuntimeError, match="database unavailable"):
        await main._acquire_cross_host_guard(_GuardEngine(broken))
    assert broken.closed

    unlock_broken = _GuardConnection(failure=RuntimeError("unlock unavailable"))
    await main._release_cross_host_guard(unlock_broken)
    assert unlock_broken.closed


async def test_main_processing_key_sweep_retries_failures_but_propagates_cancellation(monkeypatch):
    attempts = []

    class BrokenStore:
        def purge_expired(self):
            attempts.append("purge")
            raise RuntimeError("transient")

    async def stop_after_one_cycle(_seconds):
        raise asyncio.CancelledError

    monkeypatch.setattr(main.asyncio, "sleep", stop_after_one_cycle)
    app = SimpleNamespace(state=SimpleNamespace(key_store=BrokenStore()))
    with pytest.raises(asyncio.CancelledError):
        await main._processing_key_sweep(app)
    assert attempts == ["purge"]

    class CancelledStore:
        def purge_expired(self):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await main._processing_key_sweep(
            SimpleNamespace(state=SimpleNamespace(key_store=CancelledStore()))
        )


async def test_main_readyz_fails_closed_when_production_schema_is_not_at_head():
    class Result:
        def scalar_one_or_none(self):
            return "old-revision"

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, _statement):
            return Result()

    application = main.create_app(_dev_settings())
    try:
        readyz = next(
            route.endpoint
            for route in application.routes
            if getattr(route, "path", None) == "/readyz"
        )
        request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    sessionmaker=Session,
                    settings=SimpleNamespace(environment="production"),
                )
            )
        )
        response = await readyz(request)
    finally:
        await application.state.engine.dispose()

    assert response.status_code == 503
    assert b"database unavailable" in response.body
