"""Released infrastructure protocols, exercised without ASGI import side effects."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

FIXTURES = Path(__file__).with_name("fixtures")
BACKEND = Path(__file__).resolve().parents[2] / "backend"


@pytest.fixture(autouse=True)
def backend_imports(monkeypatch):
    monkeypatch.syspath_prepend(str(BACKEND))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")


def observed_metrics():
    from app.metrics import MetricsRegistry

    registry = MetricsRegistry()
    for status in (200, 201, 301, 404, 503):
        registry.observe_request(status)
    for duration in (0.0, 0.25, 0.251, 0.5, 1.0, 2.0, 5.0, 15.0, 60.0, 60.01):
        registry.observe_recompute(duration)
    for failed in (True, False, False):
        registry.observe_llm(failed)
    registry.observe_audit_chain(2)
    registry.observe_audit_chain(3)
    registry.observe_audit_journal_failure()
    registry.observe_audit_maintenance_failure()
    registry.observe_audit_progress(
        prune_backlog=True,
        verification_backlog=False,
        rows_pruned=2,
        owners_verified=3,
        prune_pending_rows_probe=4,
        prune_oldest_overdue_seconds=2.25,
        verification_pending_owners_probe=6,
        verification_cycle_age_seconds=1.5,
    )
    registry.observe_audit_progress(
        prune_backlog=False,
        verification_backlog=True,
        rows_pruned=5,
        owners_verified=7,
        prune_pending_rows_probe=-3,
        prune_oldest_overdue_seconds=-2.0,
        verification_pending_owners_probe=-5,
        verification_cycle_age_seconds=-1.0,
    )
    registry.observe_auxiliary_retention(
        {
            "deletions": (True, 2.25, 3),
            "pairing": (False, 0.5, 4),
            "revocations": (False, 1.25, 5),
            "rekeys": (True, 3.5, 6),
        }
    )
    registry.observe_auxiliary_retention(
        {
            "deletions": (False, 1.0, 2),
            "pairing": (True, 1.5, 1),
            "revocations": (True, 2.0, 3),
            "rekeys": (False, 0.0, 2),
        }
    )
    registry.observe_retention(question_insights=2, question_backlog=True)
    registry.observe_retention(question_insights=3)
    registry.observe_audio_retention(
        backlog=2,
        oldest_age_seconds=1.25,
        reconciled=3,
        inventory_scanned=4,
        inventory_backlog=True,
        inventory_cycle_completed=True,
    )
    registry.observe_audio_retention(backlog=1, oldest_age_seconds=0.5)
    registry.observe_audio_storage_failure()
    registry.observe_account_deletion(pending_probe=-2, oldest_seconds=-1.0)
    registry.observe_account_deletion(pending_probe=3, oldest_seconds=4.25)
    for category in (
        "database",
        "object_store",
        "state",
        "unexpected",
        "sensitive-user-data",
    ):
        registry.observe_account_deletion_failure(category)
    return registry


def test_prometheus_wire_preserves_empty_and_observed_registry_protocol():
    from app.metrics import MetricsRegistry

    assert (
        MetricsRegistry().render(0)
        == (FIXTURES / "backend-metrics-empty.prom").read_text()
    )
    rendered = observed_metrics().render(9)
    assert rendered == (FIXTURES / "backend-metrics-observed.prom").read_text()
    assert 'mindpattern_requests_total{status="2xx"} 2\n' in rendered
    assert 'mindpattern_recompute_seconds_bucket{le="0.25"} 2\n' in rendered
    assert 'mindpattern_recompute_seconds_bucket{le="+Inf"} 10\n' in rendered
    assert "mindpattern_audit_rows_pruned_total 7\n" in rendered
    assert "mindpattern_audit_owners_verified_total 10\n" in rendered
    assert (
        'mindpattern_account_deletion_failures_total{category="unexpected"} 2\n'
        in rendered
    )
    assert "sensitive-user-data" not in rendered


@pytest.mark.asyncio
async def test_metrics_asgi_observes_http_status_only_and_forwards_every_message():
    from app.metrics import MetricsMiddleware, MetricsRegistry

    registry = MetricsRegistry()
    delivered = []
    receive = object()
    messages = [
        {"type": "http.response.start", "status": 418, "headers": []},
        {"type": "http.response.body", "body": b"private", "more_body": False},
    ]

    async def app(scope, received, send):
        assert received is receive
        for message in messages:
            await send(message)

    async def send(message):
        delivered.append(message)

    middleware = MetricsMiddleware(app, registry)
    await middleware({"type": "http"}, receive, send)
    assert delivered == messages
    assert 'mindpattern_requests_total{status="4xx"} 1\n' in registry.render(0)
    delivered.clear()
    await middleware({"type": "websocket"}, receive, send)
    assert delivered == messages
    assert 'mindpattern_requests_total{status="4xx"} 1\n' in registry.render(0)


def test_rate_window_boundaries_retries_and_immutable_results():
    from app.cache import HitResult, SlidingWindowCounter

    counter = SlidingWindowCounter()
    for invalid in (0, -1):
        for operation in (counter.hit, counter.check):
            with pytest.raises(ValueError, match=r"^window_seconds must be positive$"):
                operation("peer", invalid, now=10.0)
    assert counter.check("peer", 1, now=0.0) == HitResult(0, 1)
    assert counter.hit("peer", 1, now=0.0) == HitResult(1, 2)
    assert counter.hit("peer", 1, now=0.5) == HitResult(2, 1)
    assert counter.hit("peer", 1, now=0.5) == HitResult(3, 1)
    assert counter.check("peer", 1, now=1.0) == HitResult(2, 1)
    assert counter.check("peer", 1, now=1.5) == HitResult(0, 1)
    result = counter.hit("other", 1, now=10.0)
    with pytest.raises(FrozenInstanceError):
        result.count = 0


def test_rate_limit_refusals_keep_complete_status_detail_code_and_retry_envelopes():
    from app.cache import _limit_response, _no_identity_response

    for retry, expected in ((-2, "1"), (0, "1"), (1, "1"), (3, "3")):
        error = _limit_response(retry)
        assert (error.status_code, error.detail, error.code, error.headers) == (
            429,
            "rate limit exceeded",
            "rate_limited",
            {"Retry-After": expected},
        )
    error = _no_identity_response()
    assert (error.status_code, error.detail, error.code) == (
        429,
        "no client identity available for rate limiting",
        "rate_limited",
    )


@pytest.mark.parametrize("forwarded", ["", None, 3, "2001:db8:1234:5678::9"])
@pytest.mark.parametrize("trusted", [False, True])
def test_rate_client_identity_requires_trusted_forwarding_and_has_request_scope_parity(
    forwarded, trusted
):
    from app.cache import client_key, client_key_from_scope

    state = {
        "mindpattern_trusted_proxy": trusted,
        "mindpattern_forwarded_client": forwarded,
    }
    request = SimpleNamespace(
        state=SimpleNamespace(**state), client=SimpleNamespace(host="127.0.0.1")
    )
    scope = {"state": state, "client": ("127.0.0.1", 443)}
    expected = (
        "2001:db8:1234:5678::/64"
        if trusted and isinstance(forwarded, str) and forwarded
        else "127.0.0.1"
    )
    assert client_key(request, True) == client_key_from_scope(scope, True) == expected
    request.client = None
    scope["client"] = None
    expected = expected if expected != "127.0.0.1" else None
    assert client_key(request, True) == client_key_from_scope(scope, True) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("sqlite+aiosqlite:///./mindpattern.db", "sqlite+aiosqlite:///mindpattern.db"),
        ("sqlite+aiosqlite:///:memory:", "sqlite+aiosqlite:///:memory:"),
        ("sqlite+aiosqlite://", "sqlite+aiosqlite://"),
        (
            "postgresql+asyncpg://name:password@localhost/db?z=2&a=1",
            "postgresql+asyncpg://name:password@127.0.0.1:5432/db?a=1&z=2",
        ),
        (
            "postgresql+asyncpg://name:password@[::1]:55488/db",
            "postgresql+asyncpg://name:password@127.0.0.1:55488/db",
        ),
        (
            "postgresql+asyncpg://name:password@remote:55488/db",
            "postgresql+asyncpg://name:password@remote:55488/db",
        ),
        ("invalid-url", "invalid-url"),
    ],
)
def test_guard_database_identity_normalizes_only_supported_aliases(source, expected):
    from app.singleprocess import _normalized_database_url

    assert _normalized_database_url(source) == expected


def test_single_process_guard_has_private_files_pid_payload_and_exact_reentrant_custody(
    tmp_path, monkeypatch
):
    from app import singleprocess

    directory = tmp_path / "private"
    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(directory))
    secret, url = "deployment-secret", "sqlite+aiosqlite:///database.db"
    expected_digest = hashlib.sha256(
        f"mindpattern:{secret}:{url}".encode()
    ).hexdigest()[:24]
    expected_path = directory / f"mindpattern-single-{expected_digest}.lock"
    with singleprocess.single_process_guard(secret, url) as guard:
        assert guard is not None
        original_descriptor = singleprocess._held[str(expected_path)][0]
        assert singleprocess.acquire_single_process_lock(secret, url) == str(
            expected_path
        )
        descriptor, references = singleprocess._held[str(expected_path)]
        assert descriptor == original_descriptor
        assert references == 2
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(expected_path.stat().st_mode) == 0o600
        assert expected_path.read_text() == f"pid={os.getpid()}\n"
        singleprocess.release_single_process_lock(secret, url)
        assert singleprocess._held[str(expected_path)] == (descriptor, 1)
        os.fstat(descriptor)
    assert str(expected_path) not in singleprocess._held
    with pytest.raises(OSError):
        os.fstat(descriptor)
    singleprocess.release_single_process_lock(secret, url)


@pytest.mark.asyncio
async def test_application_ops_routes_read_live_settings_and_fail_closed(
    tmp_path, caplog
):
    import httpx
    import tomllib
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from app import main
    from app.api import _audit
    from app.config import Settings
    from app.db import init_models
    from sqlalchemy import text

    settings = Settings(environment="development", database_url="sqlite+aiosqlite://")
    migration_config = Config()
    migration_config.set_main_option("script_location", str(BACKEND / "alembic"))
    schema_head = ScriptDirectory.from_config(migration_config).get_current_head()
    settings.ops_rate_limit = 1000
    app = main.create_app(settings)
    version = tomllib.loads((BACKEND / "pyproject.toml").read_text())["project"][
        "version"
    ]
    previous_health = _audit.audit_journal_health()
    try:
        await init_models(app.state.engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200 and health.json() == {
                "status": "ok",
                "version": version,
            }
            refused_method = await client.post("/healthz")
            assert refused_method.status_code == 405
            assert refused_method.headers["allow"] == "GET"
            ready = await client.get("/readyz")
            assert ready.status_code == 200 and ready.json() == {
                "status": "ready",
                "version": version,
            }
            metrics = await client.get("/metrics")
            assert metrics.status_code == 200
            assert "mindpattern_keystore_sessions 0\n" in metrics.text
            assert (
                metrics.headers["content-type"]
                == "text/plain; version=0.0.4; charset=utf-8"
            )
            for field, detail in [
                ("guard_healthy", "instance ownership unavailable"),
                ("audit_maintenance_healthy", "audit maintenance unavailable"),
            ]:
                setattr(app.state, field, False)
                response = await client.get("/readyz")
                assert response.status_code == 503 and response.json() == {
                    "detail": detail,
                    "code": "service_unavailable",
                }
                setattr(app.state, field, True)
            settings.audit_journal_path = str(tmp_path / "journal")
            _audit._set_journal_health(False, "io_failure")
            response = await client.get("/readyz")
            assert response.status_code == 503 and response.json() == {
                "detail": "audit journal unavailable",
                "code": "service_unavailable",
            }
            _audit._set_journal_health(True)
            settings.audit_journal_path = ""
            settings.metrics_token = "sécurité"
            denied = await client.get("/metrics")
            assert denied.status_code == 401 and denied.json() == {
                "detail": "metrics token required",
                "code": "unauthorized",
            }
            allowed = await client.get(
                "/metrics",
                headers={"Authorization": "Bearer sécurité".encode("latin1")},
            )
            assert allowed.status_code == 200
            replacement = Settings(
                environment="development",
                database_url="sqlite+aiosqlite://",
                metrics_token="rotated",
            )
            replacement.ops_rate_limit = 1000
            app.state.settings = replacement
            replacement.max_body_bytes = 4
            assert (await client.post("/unknown", content=b"12345")).status_code == 413
            assert (
                await client.get(
                    "/metrics",
                    headers={"Authorization": b"Bearer s\xc3\xa9curit\xc3\xa9"},
                )
            ).status_code == 401
            assert (
                await client.get(
                    "/metrics", headers={"Authorization": "Bearer rotated"}
                )
            ).status_code == 200
            replacement.metrics_token = ""
            replacement.environment = "production"
            disabled = await client.get("/metrics")
            assert disabled.status_code == 404 and disabled.json() == {
                "detail": "not found",
                "code": "not_found",
            }
            missing_schema = await client.get("/readyz")
            assert missing_schema.status_code == 503 and missing_schema.json() == {
                "detail": "database unavailable",
                "code": "service_unavailable",
            }
            assert (
                caplog.messages[-1]
                == "readiness check failed: database or schema unavailable"
            )
            async with app.state.engine.begin() as connection:
                await connection.execute(
                    text("CREATE TABLE alembic_version (version_num TEXT)")
                )
                await connection.execute(
                    text("INSERT INTO alembic_version VALUES (:version)"),
                    {"version": schema_head},
                )
            assert (await client.get("/readyz")).json() == {
                "status": "ready",
                "version": version,
            }
    finally:
        _audit._set_journal_health(*previous_health)
        await app.state.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("errors", "detail", "parse_failed"),
    [
        ([], "request validation failed", False),
        (
            [
                {
                    "type": "missing",
                    "loc": ("body", "username"),
                    "msg": "Field required",
                    "input": "secret",
                }
            ],
            "username: Field required",
            False,
        ),
        (
            [{"type": "missing", "loc": ("body",), "input": "secret"}],
            "invalid value",
            False,
        ),
        (
            [
                {
                    "type": "json_invalid",
                    "loc": ("body", 0),
                    "msg": "JSON decode error",
                    "input": "secret",
                }
            ],
            "0: JSON decode error",
            True,
        ),
        (
            [
                {"type": "missing", "loc": ("query", "x"), "msg": "required"},
                {"type": "missing", "loc": (), "msg": "invalid"},
            ],
            "query.x: required; invalid",
            False,
        ),
        ([{"type": "value_error", "loc": (), "msg": "x" * 501}], "x" * 500, False),
    ],
)
async def test_validation_handler_emits_bounded_complete_details_without_echoing_inputs(
    errors, detail, parse_failed
):
    from app import main
    from app.config import Settings
    from fastapi.exceptions import RequestValidationError
    from starlette.requests import Request

    app = main.create_app(
        Settings(environment="development", database_url="sqlite+aiosqlite://")
    )
    request = Request({"type": "http", "state": {}})
    try:
        response = await app.exception_handlers[RequestValidationError](
            request, RequestValidationError(errors)
        )
        import json

        assert response.status_code == 422
        assert json.loads(response.body) == {
            "detail": detail,
            "code": "validation_error",
        }
        assert "secret" not in response.body.decode()
        assert (
            bool(request.scope["state"].get("mindpattern_body_parse_failed"))
            is parse_failed
        )
    finally:
        await app.state.engine.dispose()


def test_metrics_defaults_and_repeated_failure_counters_are_cumulative():
    from app.metrics import MetricsRegistry

    registry = MetricsRegistry()
    registry.observe_audit_progress(prune_backlog=False, verification_backlog=False)
    registry.observe_retention()
    registry.observe_account_deletion(pending_probe=0, oldest_seconds=0)
    assert registry.render(0) == (FIXTURES / "backend-metrics-empty.prom").read_text()
    for _ in range(3):
        registry.observe_llm(True)
        registry.observe_audit_journal_failure()
        registry.observe_audit_maintenance_failure()
        registry.observe_audio_storage_failure()
    rendered = registry.render(0)
    for metric in (
        "audit_journal_failures",
        "audit_maintenance_failures",
        "audio_storage_failures",
    ):
        assert f"mindpattern_{metric}_total 3\n" in rendered
    assert 'mindpattern_llm_calls_total{outcome="failure"} 3\n' in rendered


def test_rate_counter_compression_eviction_and_default_proxy_policy(monkeypatch):
    from app import cache

    counter = cache.SlidingWindowCounter()
    for instant in range(128):
        counter.hit("busy", 1000, now=float(instant))
    assert len(counter._hits["busy"].log) == 128
    counter.hit("busy", 1000, now=128.0)
    assert len(counter._hits["busy"].log) == 128
    assert counter.check("busy", 1000, now=1000.0).count == 127
    # Changing a key's window updates its idleness policy during eviction.
    counter = cache.SlidingWindowCounter()
    counter.hit("old", 100, now=0.0)
    counter.hit("old", 1, now=0.0)
    counter.hit("victim", 100, now=0.0)
    counter.hit("victim", 100, now=0.0)
    for index in range(49997):
        counter.hit(f"filler-{index}", 100, now=0.0)
    counter.hit("fresh", 100, now=1.0)
    assert len(counter._hits) == 50000
    counter.hit("new", 100, now=1.0)
    assert len(counter._hits) == 45000
    assert "old" not in counter._hits
    assert "victim" in counter._hits and "new" in counter._hits
    assert counter.check("victim", 100, now=1.0).count == 2
    # An empty retained bucket is reclaimable without inspecting a timestamp.
    counter._hits["empty"] = cache._WindowLog(window_seconds=100)
    counter._evict_locked(1.0)
    assert "empty" not in counter._hits
    request = SimpleNamespace(
        state=SimpleNamespace(
            mindpattern_trusted_proxy=True, mindpattern_forwarded_client="203.0.113.1"
        ),
        client=SimpleNamespace(host="127.0.0.1"),
    )
    assert cache.client_key(request) == "127.0.0.1"
    request.state = SimpleNamespace(mindpattern_forwarded_client="203.0.113.1")
    assert cache.client_key(request, True) == "127.0.0.1"
    assert (
        cache.client_key_from_scope(
            {
                "state": {
                    "mindpattern_trusted_proxy": True,
                    "mindpattern_forwarded_client": "203.0.113.1",
                },
                "client": ("127.0.0.1", 0),
            }
        )
        == "127.0.0.1"
    )


def test_rate_counter_evicts_the_last_one_over_its_post_prune_target():
    from app.cache import SlidingWindowCounter

    counter = SlidingWindowCounter()
    for index in range(5000):
        counter.hit(f"expired-{index}", 1, now=0.0)
    for index in range(45000):
        counter.hit(f"live-{index}", 100, now=0.0)
    assert len(counter._hits) == 50000
    counter.hit("new", 100, now=1.0)
    assert len(counter._hits) == 45000
    assert "new" in counter._hits
    assert all(not key.startswith("expired-") for key in counter._hits)


@pytest.mark.asyncio
async def test_rate_dependencies_share_buckets_and_read_live_limits(monkeypatch):
    from app import cache

    monkeypatch.setattr(cache.time, "monotonic", lambda: 10.0)
    counter = cache.SlidingWindowCounter()
    settings = SimpleNamespace(
        login_limit=2, login_window=30, trust_proxy_headers=False
    )
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(settings=settings, rate_counter=counter)
        ),
        state=SimpleNamespace(),
        client=SimpleNamespace(host="127.0.0.1"),
    )
    gate = cache.make_rate_limiter("login", "login_limit", "login_window")
    await gate(request)
    await gate(request)
    assert counter.check("login:127.0.0.1", 30, now=10.0).count == 2
    with pytest.raises(cache.ApiError) as rejected:
        await gate(request)
    assert rejected.value.status_code == 429
    settings.login_limit = 4
    await gate(request)
    cache.check_keyed_limit_without_count(request, "registration:name", 1, 30)
    cache.record_keyed_failure(request, "registration:name", 30)
    with pytest.raises(cache.ApiError):
        cache.check_keyed_limit_without_count(request, "registration:name", 1, 30)
    assert counter.check("registration:name", 30, now=10.0).count == 1


def test_revocation_exact_expiry_capacity_and_refusal_details(monkeypatch):
    from app import cache

    monkeypatch.setattr(cache.time, "time", lambda: 100.0)
    for invalid in (0, -1):
        with pytest.raises(ValueError, match=r"^max_entries must be positive$"):
            cache.TokenRevocationStore(invalid)
    store = cache.TokenRevocationStore(1)
    with pytest.raises(ValueError, match=r"^jti must be non-empty$"):
        store.revoke("", 200)
    store.revoke("a", 110)
    assert store.is_revoked("a") and not store.is_revoked(None)
    assert not store._overflowed
    store.revoke("b", 120)
    assert store._overflowed and not store.is_revoked("a") and store.is_revoked("b")
    assert not store.is_revoked("b", now=120)
    store.revoke("expired", 90)
    assert store.prune(100) == 1 and len(store) == 0
    store.revoke("boundary", 110)
    assert not store.is_revoked("boundary", now=110)


@pytest.mark.asyncio
async def test_durable_revocation_hydration_limits_and_exact_fallback_queries(
    monkeypatch,
):
    from datetime import datetime, timezone

    from app import cache
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import TokenRevocation
    from sqlalchemy import event

    monkeypatch.setattr(cache.time, "time", lambda: 100.0)
    engine = build_engine("sqlite+aiosqlite://")
    queries = []
    event.listen(
        engine.sync_engine,
        "before_cursor_execute",
        lambda conn, cursor, statement, parameters, context, many: queries.append(
            statement
        ),
    )
    try:
        await init_models(engine)
        sessions = build_sessionmaker(engine)
        async with sessions() as session:
            for jti, expires in [("exact", 100), ("older", 110), ("newer", 120)]:
                session.add(
                    TokenRevocation(
                        jti=jti,
                        expires_at=datetime.fromtimestamp(expires, timezone.utc),
                    )
                )
            await session.commit()
            store = cache.TokenRevocationStore(1)
            assert not await store.is_revoked_checked(session, None)
            assert await store.is_revoked_checked(session, "older")
            assert await store.hydrate(session) == 1
            assert store._by_expiry == {"newer": 120.0}
            assert await store.is_revoked_checked(session, "older")
            assert not await store.is_revoked_checked(session, "exact")
            assert not await store.is_revoked_checked(session, "unknown")
            complete = cache.TokenRevocationStore(5)
            assert await complete.hydrate(session, now=100) == 2
            before = len(queries)
            assert not await complete.is_revoked_checked(session, "unknown", now=100)
            assert len(queries) == before
            assert await complete.is_revoked_checked(session, "newer", now=100)
            assert len(queries) == before
            await complete.revoke_durable(session, "persisted", 150)
            await session.commit()
        async with sessions() as session:
            fresh = cache.TokenRevocationStore(10)
            assert await fresh.hydrate(session, now=100) == 3
            assert await fresh.is_revoked_checked(session, "persisted", now=100)
            assert not await fresh.is_revoked_checked(session, "persisted", now=150)
    finally:
        await engine.dispose()


def test_guard_default_directory_and_permission_failure_diagnostics(
    tmp_path, monkeypatch, caplog
):
    import logging

    from app import singleprocess

    monkeypatch.delenv("MINDPATTERN_LOCK_DIR", raising=False)
    monkeypatch.setattr(singleprocess.tempfile, "gettempdir", lambda: str(tmp_path))
    expected = tmp_path / f"mindpattern-{os.getuid()}"
    with caplog.at_level(logging.WARNING, logger="mindpattern"):

        def denied(*args, **kwargs):
            raise PermissionError("chmod refused")

        monkeypatch.setattr(singleprocess.os, "chmod", denied)
        assert singleprocess._lock_dir() == str(expected)
        assert stat.S_IMODE(expected.stat().st_mode) == 0o700
        assert caplog.records[-1].name == "mindpattern"
        assert (
            caplog.messages[-1]
            == f"could not tighten permissions on lock dir {str(expected)!r}"
        )
        assert singleprocess._lock_dir() == str(expected)
        override = tmp_path / "override"
        monkeypatch.setenv("MINDPATTERN_LOCK_DIR", f" {override} ")
        assert singleprocess._lock_dir() == str(override)
        assert stat.S_IMODE(override.stat().st_mode) == 0o700


def test_guard_symlink_and_competing_descriptor_refusals_preserve_custody(
    tmp_path, monkeypatch
):
    import fcntl

    from app import singleprocess

    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path))
    secret, url = "refusal-secret", "sqlite+aiosqlite:///guard.db"
    path = Path(singleprocess._lock_path(secret, url))
    target = tmp_path / "do-not-truncate"
    target.write_text("precious original bytes")
    path.symlink_to(target)
    with pytest.raises(singleprocess.LockPathError) as rejected:
        singleprocess.acquire_single_process_lock(secret, url)
    assert (
        str(rejected.value)
        == f"single-process lock path {str(path)!r} is a symlink; refusing to lock or truncate it. Remove the symlink (or set MINDPATTERN_LOCK_DIR to a private directory) and restart."
    )
    assert target.read_text() == "precious original bytes"
    path.unlink()
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(singleprocess.MultipleWorkersError) as rejected:
            singleprocess.acquire_single_process_lock(secret, url)
        assert (
            str(rejected.value)
            == "another worker/process is already serving this deployment: the rate limiter, per-user locks, and processing-session keystore are all in-process (see locks.py / cache.py / enclave.py). Run ONE worker per instance; put shared counters/locks in Redis &c. before ever scaling horizontally."
        )
        assert str(path) not in singleprocess._held
    finally:
        os.close(descriptor)


def test_guard_warns_on_inode_replacement_and_keeps_live_descriptor(
    tmp_path, monkeypatch, caplog
):
    import logging

    from app import singleprocess

    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path))
    original_stat = os.stat
    secret, url = "inode-secret", "sqlite+aiosqlite:///inode.db"
    path = singleprocess._lock_path(secret, url)

    def replaced(candidate, *args, **kwargs):
        result = original_stat(candidate, *args, **kwargs)
        return (
            SimpleNamespace(st_ino=result.st_ino + 1) if candidate == path else result
        )

    monkeypatch.setattr(singleprocess.os, "stat", replaced)
    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        singleprocess.acquire_single_process_lock(secret, url)
        try:
            assert (
                caplog.messages[-1]
                == f"single-process lock path {path!r} no longer names the locked inode; an external unlinked it — a second boot could now fragment in-process guarantees. Point MINDPATTERN_LOCK_DIR at a persistent directory."
            )
            os.fstat(singleprocess._held[path][0])
        finally:
            singleprocess.release_single_process_lock(secret, url)


@pytest.mark.asyncio
async def test_database_pools_and_foreign_keys_match_real_sqlite_topologies(tmp_path):
    from app.db import build_engine, rowcount
    from sqlalchemy import text
    from sqlalchemy.pool import NullPool, StaticPool

    assert rowcount(SimpleNamespace()) == 0
    assert rowcount(SimpleNamespace(rowcount=3)) == 3
    for url, expected_pool, expected_mode in [
        ("sqlite+aiosqlite://", StaticPool, "memory"),
        ("sqlite+aiosqlite:///:memory:", StaticPool, "memory"),
        (f"sqlite+aiosqlite:///{tmp_path / 'file.db'}", NullPool, "wal"),
    ]:
        engine = build_engine(url)
        try:
            assert isinstance(engine.pool, expected_pool)
            async with engine.connect() as connection:
                assert (await connection.scalar(text("PRAGMA foreign_keys"))) == 1
                assert (
                    await connection.scalar(text("PRAGMA journal_mode"))
                ) == expected_mode
                if expected_mode == "wal":
                    assert (
                        await connection.scalar(text("PRAGMA busy_timeout"))
                    ) == 30000
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_locks_retain_waiter_custody_and_bound_live_overflow():
    import asyncio

    from app import locks

    for invalid in (0, -1):
        with pytest.raises(ValueError):
            locks.UserLocks(invalid)
    for shared in (locks.lifecycle_locks, locks.sharing_locks):
        async with shared.hold("cross-router") as lock:
            assert lock.locked()
    registry = locks.UserLocks(1)
    entered, release = asyncio.Event(), asyncio.Event()

    async def waiter():
        async with registry.hold("owner"):
            entered.set()
            await release.wait()

    async with registry.hold("owner") as dedicated:
        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        assert registry._locks["owner"].refs == 2
        assert not entered.is_set()
        async with registry.hold("overflow") as fallback:
            assert fallback is not dedicated and len(registry._locks) == 1
            assert registry.total_overflow_refs() == 1
        assert registry.total_overflow_refs() == 0
    await asyncio.wait_for(entered.wait(), 1)
    assert registry._locks["owner"].refs == 1
    release.set()
    await task
    assert registry._locks["owner"].refs == 0
    async with registry.hold("next"):
        assert set(registry._locks) == {"next"}
    # Explicit capacity bounds remain meaningful independently of default tuning.
    bounded = locks.UserLocks(max_keys=3)
    for index in range(4):
        async with bounded.hold(str(index)):
            pass
    assert len(bounded._locks) == 3


@pytest.mark.parametrize(
    ("pool_size", "overflow", "expected"), [(1, 0, 1), (1, 1, 1), (2, 1, 2), (5, 10, 2)]
)
@pytest.mark.asyncio
async def test_app_capacity_policies_and_cors_are_exposed_at_the_request_boundary(
    pool_size, overflow, expected
):
    import httpx
    from app import main
    from app.config import Settings
    from app.db import init_models

    settings = Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        db_pool_size=pool_size,
        db_max_overflow=overflow,
        cors_origins=["https://client.example"],
    )
    settings.ops_rate_limit = 1000
    app = main.create_app(settings)
    try:
        assert app.state.analyze_limiter.total_tokens == 4
        assert app.state.auth_limiter.total_tokens == 4
        assert app.state.auth_admission_limiter.total_tokens == 4
        assert app.state.export_limiter.total_tokens == expected
        await init_models(app.state.engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
                preflight = await client.options(
                    "/healthz",
                    headers={
                        "Origin": "https://client.example",
                        "Access-Control-Request-Method": method,
                        "Access-Control-Request-Headers": "Authorization, Content-Type, X-Processing-Token, X-New-Processing-Token, X-Account-Verifier, X-Step-Up-Proof, X-Therapist-Enrollment-Token, X-Pairing-Code",
                    },
                )
                assert preflight.status_code == 200
                assert (
                    preflight.headers["access-control-allow-origin"]
                    == "https://client.example"
                )
            response = await client.get(
                "/healthz", headers={"Origin": "https://client.example"}
            )
            assert (
                response.headers["access-control-expose-headers"]
                == "X-Next-Offset, X-Entries-Revision, X-Notes-Revision, X-Measures-Revision, X-Next-Cursor"
            )
            # Health and readiness intentionally share one operations bucket.
            assert (
                app.state.rate_counter.check(
                    "ops-health:127.0.0.1", settings.ops_rate_window
                ).count
                == 1
            )
            await client.get("/readyz")
            await client.get("/metrics")
            assert (
                app.state.rate_counter.check(
                    "ops-health:127.0.0.1", settings.ops_rate_window
                ).count
                == 3
            )
            settings.ops_rate_limit = 3
            assert (await client.get("/healthz")).status_code == 429
    finally:
        await app.state.engine.dispose()


@pytest.mark.asyncio
async def test_router_rate_discovery_covers_both_mounts_and_deduplicates_dependencies():
    import httpx
    from app import main
    from app.cache import make_rate_limiter
    from app.config import Settings
    from app.db import init_models

    settings = Settings(
        environment="development", database_url="sqlite+aiosqlite://", auth_rate_limit=1
    )
    app = main.create_app(settings)
    try:
        await init_models(app.state.engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            first = await client.post(
                "/api/v1/auth/register",
                content="{",
                headers={"Content-Type": "application/json"},
            )
            assert (
                first.status_code == 422 and first.json()["code"] == "validation_error"
            )
            second = await client.post(
                "/api/auth/register",
                content="{",
                headers={"Content-Type": "application/json"},
            )
            assert second.status_code == 429 and second.json() == {
                "detail": "rate limit exceeded",
                "code": "rate_limited",
            }
        # De-duplication is observable: a single malformed body consumes one
        # budget even when the same limiter is reachable by both dependency paths.
        from fastapi import Depends

        check = make_rate_limiter("duplicate", "auth_rate_limit", "auth_rate_window")

        async def nested(dependency=Depends(check)):  # noqa: B008 - FastAPI dependency declaration
            pass

        @app.post("/duplicate", dependencies=[Depends(check), Depends(nested)])
        async def target(value: dict):
            return value

        rules = main._rate_limit_rules(app)
        matching = [
            checks
            for methods, pattern, checks in rules
            if "POST" in methods and pattern.fullmatch("/duplicate")
        ]
        assert len(matching) == 1 and len(matching[0]) == 1
    finally:
        await app.state.engine.dispose()


@pytest.mark.asyncio
async def test_factory_keeps_old_audit_mac_keys_available_for_existing_chains():
    from app import main
    from app.api import _audit
    from app.config import Settings
    from test_full_backend_maintenance_contracts import KEY, maintenance

    settings = Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        audit_mac_key_version=8,
        audit_mac_previous_secrets_explicit=f"7:{KEY.hex()}",
    )
    app = main.create_app(settings)
    try:
        async with (
            maintenance([1]) as (_, stored),
            stored.state.sessionmaker() as session,
        ):
            verdict = await _audit.verify_access_log_chain(session, "a" * 32)
            assert verdict.ok and verdict.rows_checked == 1
    finally:
        await app.state.engine.dispose()


@pytest.mark.asyncio
async def test_overflow_waiters_keep_the_same_lock_and_correct_live_reference_count():
    import asyncio

    from app.locks import UserLocks

    registry = UserLocks(1)
    first_entered, second_entered = asyncio.Event(), asyncio.Event()
    first_release, second_release = asyncio.Event(), asyncio.Event()

    async def hold(entered, release):
        async with registry.hold("overflow"):
            entered.set()
            await release.wait()

    holders = []
    try:
        async with registry.hold("dedicated"):
            holders.append(asyncio.create_task(hold(first_entered, first_release)))
            await asyncio.wait_for(first_entered.wait(), 1)
            holders.append(asyncio.create_task(hold(second_entered, second_release)))
            await asyncio.sleep(0)
            assert registry.total_overflow_refs() == 2
            assert not second_entered.is_set()
            first_release.set()
            await holders[0]
            await asyncio.wait_for(second_entered.wait(), 1)
            assert registry.total_overflow_refs() == 1
    finally:
        first_release.set()
        second_release.set()
        await asyncio.gather(*holders)
    assert registry.total_overflow_refs() == 0


@pytest.mark.asyncio
async def test_native_overflow_registry_reuses_its_bounded_preallocated_pool():
    from app.locks import UserLocks

    registry = UserLocks(1)
    preallocated = {shard.lock for shard in registry._overflow_shards}
    observed = set()
    async with registry.hold("dedicated"):
        for index in range(300):
            async with registry.hold(f"overflow-{index}") as lock:
                observed.add(lock)
        assert len(registry._locks) == 1
    assert observed == preallocated
    assert registry.total_overflow_refs() == 0
    assert all(not lock.locked() for lock in preallocated)


@pytest.mark.asyncio
async def test_default_revocation_hydration_enforces_the_native_hundred_thousand_cap():
    from datetime import datetime, timedelta, timezone

    from app.cache import TokenRevocationStore
    from app.db import build_engine, build_sessionmaker, init_models
    from app.models import TokenRevocation
    from sqlalchemy import insert

    instant = datetime(2026, 10, 5, tzinfo=timezone.utc)
    engine = build_engine("sqlite+aiosqlite://")
    try:
        await init_models(engine)
        async with build_sessionmaker(engine)() as session:
            for offset in range(0, 100001, 1000):
                await session.execute(
                    insert(TokenRevocation),
                    [
                        {
                            "jti": f"native-{i}",
                            "expires_at": instant + timedelta(seconds=i + 1),
                        }
                        for i in range(offset, min(offset + 1000, 100001))
                    ],
                )
            await session.commit()
            store = TokenRevocationStore()
            assert await store.hydrate(session, now=instant.timestamp()) == 100000
            assert store.is_revoked("native-100000", now=instant.timestamp())
            assert not store.is_revoked("native-0", now=instant.timestamp())
    finally:
        await engine.dispose()


@pytest.mark.parametrize("operation", ["truncate", "write", "short_write"])
def test_failed_guard_identity_io_releases_kernel_custody(
    operation, tmp_path, monkeypatch
):
    import errno
    import fcntl

    from app import singleprocess

    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path / "locks"))
    secret, url = "guard-io", "sqlite+aiosqlite:///guard-io.db"
    path = Path(singleprocess._lock_path(secret, url))
    path.write_bytes(b"pid=old\n")
    path.chmod(0o600)
    descriptors = []
    truncate, write = os.ftruncate, os.write

    def failing_truncate(fd, length):
        descriptors.append(fd)
        if operation == "truncate":
            raise OSError(errno.ENOSPC, "identity storage unavailable")
        return truncate(fd, length)

    def failing_write(fd, payload):
        if not payload.startswith(b"pid="):
            return write(fd, payload)
        if operation == "write":
            raise OSError(errno.ENOSPC, "identity storage unavailable")
        if operation == "short_write":
            return write(fd, payload[:2])
        return write(fd, payload)

    monkeypatch.setattr(singleprocess.os, "ftruncate", failing_truncate)
    monkeypatch.setattr(singleprocess.os, "write", failing_write)
    try:
        with pytest.raises(OSError) as rejected:
            singleprocess.acquire_single_process_lock(secret, url)
        if operation == "short_write":
            assert (
                str(rejected.value)
                == "could not write complete single-process lock identity"
            )
        assert str(path) not in singleprocess._held
        if operation == "write":
            assert path.read_bytes() == b""
        competing = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(competing)
    finally:
        singleprocess.release_single_process_lock(secret, url)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
