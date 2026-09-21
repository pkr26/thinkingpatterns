"""Regression pins for the 2026-09-20 audit remediation wave.

Findings covered here (behavioral surface only — doc-only fixes such as
L-3's pairing-alphabet comment are pinned by the vectors themselves):

* M-1  — malformed-JSON bodies are counted into the route's own rate-limit
         bucket by HardeningMiddleware, so a garbage flood draws 429s after
         the limit instead of unlimited 422s.
* M-26 — crash-class 500s (and the deep-nesting 400, and the middleware's
         flood 429) are visible in mindpattern_requests_total via the
         status observer; the pre-parse 413 exclusion is unchanged.
* M-27 — the single-process flock is released only when the OUTERMOST
         overlapping scope exits (refcounted re-entrancy).
* M-28 — deployment identity normalizes URL spellings (make_url) before
         hashing, so alias spellings of one database share one lock.
* M-29 — access_log_retention_days is bounded to 1..3650 at startup.
* L-2  — (endpoint shape pinned in test_tokens.py; the 401-not-500
         behavior is pinned by the existing auth suites).
* L-4  — middleware-generated 4xx/5xx responses mirror the CORS allow-list.
* L-13 — repr(Settings) embeds no secret-bearing field values.
* L-31 — /meta's llm_* fields are None whenever llm_available is false.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app import cache, singleprocess
from app.config import Settings
from app.main import _rate_limit_rules, create_app
from app.metrics import MetricsRegistry
from app.middleware import HardeningMiddleware

BACKEND_DIR = Path(__file__).resolve().parents[1]

MALFORMED = {"content": b"{not-json", "headers": {"content-type": "application/json"}}


def _settings(**overrides) -> Settings:
    """Settings whose overrides go through the CONSTRUCTOR, so __post_init__
    validation (the thing several pins below exercise) actually runs."""
    kwargs = dict(
        environment="development",
        database_url="sqlite+aiosqlite://",
        token_secret="test-secret-not-for-production",
    )
    kwargs.update(overrides)
    return Settings(**kwargs)


# ---------------------------------------------------------------------------
# M-1: malformed-JSON floods are rate limited
# ---------------------------------------------------------------------------


class TestMalformedJsonRateLimiting:
    async def test_malformed_json_flood_gets_429_after_limit(self):
        settings = _settings(auth_rate_limit=3, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                statuses = [
                    (await c.post("/api/auth/salt", **MALFORMED)).status_code for _ in range(8)
                ]
        # Exactly `limit` parse failures are admitted (422); everything
        # past that is a cheap 429 — never 422×8 again.
        assert statuses == [422, 422, 422, 429, 429, 429, 429, 429], statuses

    async def test_flood_429_carries_envelope_and_retry_after(self):
        settings = _settings(auth_rate_limit=1, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                await c.post("/api/auth/salt", **MALFORMED)
                r = await c.post("/api/auth/salt", **MALFORMED)
        assert r.status_code == 429
        assert r.json() == {"detail": "rate limit exceeded", "code": "rate_limited"}
        assert int(r.headers["retry-after"]) >= 1
        # The middleware's own responses carry the same security-header
        # stamp everything else gets.
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cache-control"] == "no-store"

    async def test_malformed_and_valid_requests_share_one_bucket(self):
        """The parse failures count into the SAME bucket the route's limiter
        dependency uses — a mixed flood cannot outvote valid traffic."""
        settings = _settings(auth_rate_limit=3, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                assert (await c.post("/api/auth/salt", **MALFORMED)).status_code == 422
                assert (await c.post("/api/auth/salt", **MALFORMED)).status_code == 422
                # Two garbage requests consumed 2 of 3; one valid request
                # fits, the next valid one is over.
                assert (await c.post("/api/auth/salt", json={"username": "x"})).status_code == 200
                r = await c.post("/api/auth/salt", json={"username": "x"})
                assert r.status_code == 429

    async def test_parseable_schema_failures_are_not_double_counted(self):
        """A 422 for a body that DID parse flows through the dependency
        (which counts it once); the middleware must not add a second hit —
        double counting would halve every client's effective allowance."""
        settings = _settings(auth_rate_limit=3, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                statuses = [
                    (await c.post("/api/auth/salt", json={"wrong": 1})).status_code
                    for _ in range(4)
                ]
        assert statuses == [422, 422, 422, 429], statuses

    async def test_both_mounts_share_the_bucket(self):
        """/api and /api/v1 name the same route object family with the same
        bucket names — alternating mounts must not double the allowance."""
        settings = _settings(auth_rate_limit=3, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                statuses = [
                    (await c.post(path, **MALFORMED)).status_code
                    for path in (
                        "/api/auth/salt",
                        "/api/v1/auth/salt",
                        "/api/auth/salt",
                        "/api/v1/auth/salt",
                    )
                ]
        assert statuses == [422, 422, 422, 429], statuses

    async def test_over_limit_check_does_not_grow_the_bucket(self):
        """The pre-dispatch gate reads without counting (check(), not hit()):
        an unlimited flood must not keep inflating the bucket once full."""
        settings = _settings(auth_rate_limit=2, auth_rate_window=3600)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                for _ in range(6):
                    await c.post("/api/auth/salt", **MALFORMED)
        counter = app.state.rate_counter
        bucket_keys = [k for k in counter._hits if k.startswith("auth-salt:")]
        assert len(bucket_keys) == 1
        count, _start, window = counter._hits[bucket_keys[0]]
        # The two admitted parse failures are the only recorded events; the
        # four flood 429s beyond them added nothing (and restarted nothing).
        assert count == 2, (count, window)

    async def test_route_rules_are_built_from_the_live_router(self):
        """The edge counter's route→bucket map comes from the registered
        dependencies themselves, covering both mounts and parameterized
        paths."""
        app = create_app(_settings())
        rules = _rate_limit_rules(app)
        assert rules, "no rate-limit rules resolved — the edge gate is inert"
        # Aggregate across rules: PUT and DELETE on /entries/{id} compile to
        # the SAME path pattern but are distinct rules (matched by method).
        by_pattern: dict[str, set[str]] = {}
        for methods, pattern, checks in rules:
            by_pattern.setdefault(pattern.pattern, set()).update(c.bucket for c in checks)
        assert "auth-salt" in by_pattern["^/api/auth/salt$"]
        assert "auth-salt" in by_pattern["^/api/v1/auth/salt$"]
        # A parameterized route resolves with its converter pattern intact.
        entry_buckets = by_pattern["^/api/v1/entries/(?P<client_entry_id>[^/]+)$"]
        assert {"entries-replace", "entries-delete"} <= entry_buckets


# ---------------------------------------------------------------------------
# M-26: crash-class statuses are visible to the metrics registry
# ---------------------------------------------------------------------------


class TestCrashMetricsVisibility:
    @staticmethod
    async def _request_asgi(app, method: str, path: str, **kwargs):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.request(method, path, **kwargs)

    async def test_last_ditch_500_is_observed(self):
        registry = MetricsRegistry()

        async def boom(scope, receive, send):
            raise RuntimeError("crash-class failure")

        app = HardeningMiddleware(
            boom, max_body_bytes=1024, status_observer=registry.observe_request
        )
        r = await self._request_asgi(app, "GET", "/anything")
        assert r.status_code == 500
        assert 'mindpattern_requests_total{status="5xx"} 1' in registry.render(0)

    async def test_recursion_400_is_observed(self):
        registry = MetricsRegistry()

        async def too_deep(scope, receive, send):
            raise RecursionError("deeply nested JSON")

        app = HardeningMiddleware(
            too_deep, max_body_bytes=1024, status_observer=registry.observe_request
        )
        r = await self._request_asgi(app, "POST", "/anything", **MALFORMED)
        assert r.status_code == 400
        assert 'mindpattern_requests_total{status="4xx"} 1' in registry.render(0)

    async def test_pre_parse_413_stays_excluded(self):
        """The documented exclusion is unchanged: oversize-body rejections
        never entered the application and are not counted."""
        registry = MetricsRegistry()

        async def unreachable(scope, receive, send):
            raise AssertionError("must not be reached")

        app = HardeningMiddleware(
            unreachable, max_body_bytes=16, status_observer=registry.observe_request
        )
        r = await self._request_asgi(app, "POST", "/anything", content=b"x" * 64)
        assert r.status_code == 413
        # render() always emits the TYPE header line; the pin is that no
        # status SAMPLE line exists.
        assert "mindpattern_requests_total{status=" not in registry.render(0)

    async def test_flood_429_is_observed_in_the_real_app(self):
        settings = _settings(auth_rate_limit=1, auth_rate_window=60)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                await c.post("/api/auth/salt", **MALFORMED)
                for _ in range(3):
                    assert (await c.post("/api/auth/salt", **MALFORMED)).status_code == 429
                # /metrics is open in development: one admitted parse
                # failure (4xx) plus three edge 429s.
                rendered = app.state.metrics.render(0)
        assert 'mindpattern_requests_total{status="4xx"} 4' in rendered, rendered


# ---------------------------------------------------------------------------
# M-27 / M-28: single-process guard — refcounted re-entrancy, URL identity
# ---------------------------------------------------------------------------


class TestSingleProcessGuard2026_09_20:
    @staticmethod
    def _second_process_refused(secret: str, url: str, lock_dir: Path) -> bool:
        probe = (
            "import sys; sys.path.insert(0, '.');"
            "from app import singleprocess;"
            "singleprocess.acquire_single_process_lock(%r, %r)" % (secret, url)
        )
        done = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            cwd=BACKEND_DIR,
            timeout=60,
            env={**os.environ, singleprocess.LOCK_DIR_ENV: str(lock_dir)},
        )
        return done.returncode != 0

    def test_inner_release_keeps_the_flock(self, tmp_path, monkeypatch):
        """M-27: with overlapping same-identity scopes, the INNER exit must
        not drop the flock — a real second process stays refused until the
        OUTERMOST scope releases."""
        monkeypatch.setenv(singleprocess.LOCK_DIR_ENV, str(tmp_path))
        secret, url = "refcount-secret-2026-09-20", "sqlite+aiosqlite:///refcount"
        singleprocess.acquire_single_process_lock(secret, url)
        try:
            with singleprocess.single_process_guard(secret, url):
                pass  # inner scope acquires (refs 2) and releases (refs 1)
            assert singleprocess._held[singleprocess._lock_path(secret, url)][1] == 1
            assert self._second_process_refused(secret, url, tmp_path)
        finally:
            singleprocess.release_single_process_lock(secret, url)
        assert singleprocess._lock_path(secret, url) not in singleprocess._held
        assert not self._second_process_refused(secret, url, tmp_path)

    def test_release_is_idempotent_at_depth_zero(self, tmp_path, monkeypatch):
        monkeypatch.setenv(singleprocess.LOCK_DIR_ENV, str(tmp_path))
        secret, url = "idempotent-secret", "sqlite+aiosqlite:///idempotent"
        singleprocess.acquire_single_process_lock(secret, url)
        singleprocess.release_single_process_lock(secret, url)
        singleprocess.release_single_process_lock(secret, url)  # extra: no-op
        assert singleprocess._lock_path(secret, url) not in singleprocess._held

    def test_url_spellings_share_one_lock_identity(self, tmp_path, monkeypatch):
        """M-28: alias spellings of one database derive the SAME lock path,
        and a second process using the other spelling is refused."""
        monkeypatch.setenv(singleprocess.LOCK_DIR_ENV, str(tmp_path))
        secret = "identity-secret"
        spelling_a = "postgresql+asyncpg://u:p@localhost:5432/prod"
        spelling_b = "postgresql+asyncpg://u:p@127.0.0.1/prod"
        assert singleprocess._lock_path(secret, spelling_a) == singleprocess._lock_path(
            secret, spelling_b
        )
        singleprocess.acquire_single_process_lock(secret, spelling_a)
        try:
            assert self._second_process_refused(secret, spelling_b, tmp_path)
        finally:
            singleprocess.release_single_process_lock(secret, spelling_a)

    def test_distinct_databases_stay_distinct(self, tmp_path, monkeypatch):
        monkeypatch.setenv(singleprocess.LOCK_DIR_ENV, str(tmp_path))
        secret = "identity-secret"
        base = "postgresql+asyncpg://u:p@db.example:5432/prod"
        # Different credentials, host, port, or database are genuinely
        # different deployments and must not collapse together.
        for variant in (
            "postgresql+asyncpg://u2:p@db.example:5432/prod",
            "postgresql+asyncpg://u:p@other.example:5432/prod",
            "postgresql+asyncpg://u:p@db.example:5433/prod",
            "postgresql+asyncpg://u:p@db.example:5432/staging",
        ):
            assert singleprocess._lock_path(secret, base) != singleprocess._lock_path(
                secret, variant
            ), variant

    def test_query_parameter_order_and_sqlite_dot_paths_collapse(self):
        norm = singleprocess._normalized_database_url
        assert norm("postgresql://u:p@h/db?sslmode=require&connect_timeout=5") == norm(
            "postgresql://u:p@h/db?connect_timeout=5&sslmode=require"
        )
        assert norm("sqlite+aiosqlite:///./mindpattern.db") == norm(
            "sqlite+aiosqlite:///mindpattern.db"
        )
        # An unparseable URL falls back to the raw string (identity
        # unchanged rather than a boot refusal).
        assert norm("::::not-a-url") == "::::not-a-url"


# ---------------------------------------------------------------------------
# M-29: access-log retention bounds
# ---------------------------------------------------------------------------


class TestAccessLogRetentionBounds:
    def test_zero_and_negative_refuse_to_boot(self):
        for bad in (0, -1, -365):
            with pytest.raises(RuntimeError, match="access_log_retention_days"):
                _settings(access_log_retention_days=bad)

    def test_above_ten_years_refuses_to_boot(self):
        with pytest.raises(RuntimeError, match="access_log_retention_days"):
            _settings(access_log_retention_days=3651)

    def test_bounds_are_inclusive(self):
        assert _settings(access_log_retention_days=1).access_log_retention_days == 1
        assert _settings(access_log_retention_days=3650).access_log_retention_days == 3650


# ---------------------------------------------------------------------------
# L-4: CORS headers on middleware-generated responses
# ---------------------------------------------------------------------------


class TestCorsOnMiddlewareResponses:
    ORIGIN = "https://portal.example"

    def _app_settings(self) -> Settings:
        # 1024 is the configured floor for byte-count settings; a 2 KiB body
        # then trips the 413 content-length short-circuit deterministically.
        return _settings(
            cors_origins=[self.ORIGIN],
            max_body_bytes=1024,
        )

    async def test_413_mirrors_allowed_origin(self):
        app = create_app(self._app_settings())
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                r = await c.post(
                    "/api/auth/salt",
                    content=b"x" * 2048,
                    headers={"content-type": "application/json", "origin": self.ORIGIN},
                )
        assert r.status_code == 413
        assert r.headers["access-control-allow-origin"] == self.ORIGIN
        # The app's expose list is mirrored so a browser client can read
        # the same custom headers the inner CORS layer would expose.
        assert "x-next-offset" in r.headers.get("access-control-expose-headers", "").lower()
        assert r.headers["x-content-type-options"] == "nosniff"

    async def test_disallowed_origin_gets_no_cors_headers(self):
        app = create_app(self._app_settings())
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                r = await c.post(
                    "/api/auth/salt",
                    content=b"x" * 2048,
                    headers={"content-type": "application/json", "origin": "https://evil.example"},
                )
        assert r.status_code == 413
        assert "access-control-allow-origin" not in r.headers

    async def test_no_origin_gets_no_cors_headers(self):
        app = create_app(self._app_settings())
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                r = await c.post(
                    "/api/auth/salt",
                    content=b"x" * 2048,
                    headers={"content-type": "application/json"},
                )
        assert r.status_code == 413
        assert "access-control-allow-origin" not in r.headers

    async def test_last_ditch_500_mirrors_allowed_origin(self):
        registry = MetricsRegistry()

        async def boom(scope, receive, send):
            raise RuntimeError("crash")

        app = HardeningMiddleware(
            boom,
            max_body_bytes=1024,
            cors_origins=(self.ORIGIN,),
            cors_expose_headers=("X-Next-Offset",),
            status_observer=registry.observe_request,
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get("/anything", headers={"origin": self.ORIGIN})
        assert r.status_code == 500
        assert r.headers["access-control-allow-origin"] == self.ORIGIN


# ---------------------------------------------------------------------------
# L-13: settings repr must not leak secrets
# ---------------------------------------------------------------------------


class TestSettingsReprHidesSecrets:
    def test_repr_contains_no_secret_values(self):
        token_secret = "T" * 40
        db_password = "db-password-do-not-log"
        metrics_token = "metrics-bearer-secret"
        llm_key = "sk-live-abcdef0123456789"
        enrollment = "E" * 33
        s = _settings(
            database_url=f"postgresql+asyncpg://svc:{db_password}@db.internal:5432/mindpattern",
            token_secret=token_secret,
            metrics_token=metrics_token,
            llm_api_key=llm_key,
            therapist_enrollment_token=enrollment,
        )
        rendered = repr(s)
        for secret in (token_secret, db_password, metrics_token, llm_key, enrollment):
            assert secret not in rendered, secret[:6] + "..."
        # Non-secret tuning stays visible: the repr remains useful.
        assert "development" in rendered
        assert "730" in rendered  # access_log_retention_days default

    def test_secret_fields_are_individually_masked(self):
        import dataclasses

        hidden = {f.name for f in dataclasses.fields(Settings) if f.repr is False}
        assert hidden == {
            "database_url",
            "token_secret",
            "metrics_token",
            "llm_api_key",
            "therapist_enrollment_token",
        }


# ---------------------------------------------------------------------------
# L-31: /meta llm contract coherence
# ---------------------------------------------------------------------------


class TestMetaLlmContract:
    async def test_llm_fields_none_when_llm_unavailable(self):
        # Operator leftover declarations with no URL configured: they are
        # only validated (and only meaningful) when a URL exists.
        settings = _settings(
            llm_url="",
            llm_provider_name="Acme External LLM",
            llm_data_retention="30 days",
        )
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                body = (await c.get("/api/meta")).json()
        assert body["llm_available"] is False
        assert body["llm_provider_name"] is None
        assert body["llm_data_retention"] is None
        assert body["llm_policy_fingerprint"] is None

    async def test_llm_fields_populated_when_configured(self):
        settings = _settings(
            llm_url="https://llm.example/v1/chat",
            llm_provider_name="Acme External LLM",
            llm_data_retention="30 days",
        )
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as c:
                body = (await c.get("/api/meta")).json()
        assert body["llm_available"] is True
        assert body["llm_provider_name"] == "Acme External LLM"
        assert body["llm_data_retention"] == "30 days"
        fingerprint = body["llm_policy_fingerprint"]
        assert isinstance(fingerprint, str) and len(fingerprint) == 64


# ---------------------------------------------------------------------------
# Edge/dependency parity pins the M-1 machinery leans on
# ---------------------------------------------------------------------------


class TestRateLimitIdentityParity:
    def test_scope_and_request_client_key_agree(self):
        """The middleware's pre-dispatch key must equal the dependency's
        request-time key, or the two counters would split one client's
        budget into two buckets."""
        scope = {"type": "http", "client": ("2001:db8:1:2:3:4:5:6", 4242), "state": {}}
        request = Request(scope)
        assert cache.client_key(request) == cache.client_key_from_scope(scope)
        # IPv6 aggregates to /64 in both.
        assert cache.client_key_from_scope(scope).endswith("/64")

    def test_proxy_trust_decision_is_respected_from_scope(self):
        scope = {
            "type": "http",
            "client": ("10.0.0.9", 5),
            "state": {
                "mindpattern_trusted_proxy": True,
                "mindpattern_forwarded_client": "203.0.113.7",
            },
        }
        assert cache.client_key_from_scope(scope, trust_proxy_headers=True) == "203.0.113.7"
        # Trust flag off: the forged-friendly header is ignored.
        assert cache.client_key_from_scope(scope, trust_proxy_headers=False) == "10.0.0.9"

    def test_limiter_spec_is_introspectable(self):
        check = cache.make_rate_limiter("pin-bucket", "auth_rate_limit", "auth_rate_window")
        assert (check.bucket, check.limit_attr, check.window_attr) == (
            "pin-bucket",
            "auth_rate_limit",
            "auth_rate_window",
        )
