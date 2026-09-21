"""Mutation-campaign pin corpus.

Every test here kills a mutant that survived a mutation campaign against
the backend (the original 2026-09-15 mutmut campaign plus the behavioral
rounds of 2026-09-18/19); each test's docstring names the mutant it pins.
If one starts failing, a pinned behavior changed -- the mutant it guards
against is live again. Campaign reports are preserved in git history.
"""
from __future__ import annotations
from app import cache as cache_module
from app.api import account as account_api, auth as auth_api, entries as entries_api, insights as insights_api, meta as meta_api
from app.cache import FixedWindowCounter, HitResult, MAX_TRACKED_KEYS, RateLimitCheck, client_key, make_rate_limiter
from app.config import DEFAULT_INSECURE_SECRET, Settings, _bool_env, _cors_origins
from app.locks import UserLocks
from app.main import create_app, app as module_level_app
from app.middleware import HardeningMiddleware, SECURITY_HEADERS
from app.models import Insight
from app.schemas import InsightOut
from app.security import crypto as crypto_module, tokens as tokens_module
from app.security.enclave import InMemoryKeyStore, KeyStoreFull
from app.security.tokens import TokenError, issue_token, verify_token
from app.services import brain, crisis, llm, patterns as patterns_module, questions, questions as questions_module
from app.services.brain import JournalEntry, StoredPattern, dump_state, load_state
from app.services.llm import LLMAnalyzer, get_enricher, sanitize_pattern
from app.services.patterns import Pattern
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime, timedelta, timezone
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, insert, select
from sqlalchemy.exc import IntegrityError
from tests.helpers import ClientEmulator, TherapistEmulator, daterange
from types import SimpleNamespace
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import pytest
import random
import re


# ---------------------------------------------------------------------------
# Pins from test_mutation_pins.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
TODAY = date.today()

# ---------------------------------------------------------------------------
# Configuration: defaults, env wiring, parsing, production validation
# ---------------------------------------------------------------------------

ALL_MINDPATTERN_ENV_VARS = [
    "MINDPATTERN_ENV",
    "MINDPATTERN_TOKEN_SECRET",
    "MINDPATTERN_TOKEN_TTL",
    "MINDPATTERN_PROCESSING_TTL",
    "MINDPATTERN_UNLOCK_DAYS",
    "MINDPATTERN_AUTH_RATE_LIMIT",
    "MINDPATTERN_AUTH_RATE_WINDOW",
    "MINDPATTERN_ENTRIES_RATE_LIMIT",
    "MINDPATTERN_ENTRIES_RATE_WINDOW",
    "MINDPATTERN_PROCESSING_RATE_LIMIT",
    "MINDPATTERN_PROCESSING_RATE_WINDOW",
    "MINDPATTERN_READ_RATE_LIMIT",
    "MINDPATTERN_READ_RATE_WINDOW",
    "MINDPATTERN_BODY_READ_TIMEOUT",
    "MINDPATTERN_MAX_BODY_BYTES",
    "MINDPATTERN_MAX_ENTRIES_PER_USER",
    "MINDPATTERN_MAX_USER_BLOB_BYTES",
    "MINDPATTERN_RECOMPUTE_ENTRY_LIMIT",
    "MINDPATTERN_EXPORT_RATE_LIMIT",
    "MINDPATTERN_EXPORT_RATE_WINDOW",
    "MINDPATTERN_DB_POOL_SIZE",
    "MINDPATTERN_DB_MAX_OVERFLOW",
    "MINDPATTERN_DB_POOL_TIMEOUT",
    "MINDPATTERN_LLM_URL",
    "MINDPATTERN_LLM_API_KEY",
    "MINDPATTERN_LLM_MODEL",
    "MINDPATTERN_LLM_PROVIDER_NAME",
    "MINDPATTERN_LLM_DATA_RETENTION",
    "MINDPATTERN_LLM_POLICY_VERSION",
    "MINDPATTERN_ACCESS_LOG_RETENTION_DAYS",
    "MINDPATTERN_THERAPIST_SHARING_ENABLED",
    "MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN",
    "MINDPATTERN_TRUST_PROXY_HEADERS",
    "MINDPATTERN_TRUSTED_PROXY_IPS",
    "MINDPATTERN_CORS_ORIGINS",
    "MINDPATTERN_DB_URL",
]


@pytest.fixture
def clean_env(monkeypatch):
    for name in ALL_MINDPATTERN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_settings_defaults_are_pinned(clean_env):
    """Every default is a documented contract: rate budgets, TTLs, caps."""
    # Fail closed: a bare Settings() is production + the dev secret and
    # refuses to boot — that RuntimeError pins the environment default.
    with pytest.raises(RuntimeError) as excinfo:
        Settings()
    assert str(excinfo.value) == (
        "MINDPATTERN_TOKEN_SECRET is unset/insecure: refuse to start. "
        "Set a strong random value (e.g. openssl rand -hex 32). "
        "(The built-in dev secret is only allowed with "
        "MINDPATTERN_ENV=development exactly.)"
    )
    defaults = asdict(Settings(environment="development"))
    assert defaults == {
        "environment": "development",
        "database_url": "sqlite+aiosqlite:///./mindpattern.db",
        "token_secret": "dev-insecure-secret-change-me",
        "token_ttl_seconds": 86_400,
        "processing_session_ttl": 300,
        "unlock_threshold_days": 30,
        "auth_rate_limit": 10,
        "auth_rate_window": 60,
        "entries_rate_limit": 120,
        "entries_rate_window": 60,
        "processing_rate_limit": 10,
        "processing_rate_window": 60,
        "read_rate_limit": 300,
        "read_rate_window": 60,
        "body_read_timeout_seconds": 30,
        "max_body_bytes": 2 * 1024 * 1024,
        "max_entries_per_user": 10_000,
        "max_user_blob_bytes": 256 * 1024 * 1024,
        "recompute_entry_limit": 2_000,
        "analysis_blob_budget": 8 * 1024 * 1024,
        "metrics_token": "",
        # Added 2026-09-07: dedicated export bucket + env-sized PG pool.
        "export_rate_limit": 5,
        "export_rate_window": 60,
        # Added 2026-09-20 (L-2): the shared ops bucket for /healthz+/readyz.
        "ops_rate_limit": 240,
        "ops_rate_window": 60,
        "access_log_retention_days": 730,
        "db_pool_size": 5,
        "db_max_overflow": 10,
        "db_pool_timeout": 30,
        "llm_url": "",
        "llm_api_key": "",
        "llm_model": "gpt-4o-mini",
        "llm_provider_name": "",
        "llm_data_retention": "",
        "llm_policy_version": "v1",
        "therapist_sharing_enabled": True,
        "therapist_enrollment_token": "",
        "cors_origins": [],
        "trust_proxy_headers": False,
        "trusted_proxy_ips": [],
    }


def test_from_env_defaults_are_pinned(clean_env, monkeypatch):
    """The inline fallbacks in from_env() equal the dataclass defaults."""
    # Bare from_env() fails closed: environment defaults to production, which
    # rejects the dev secret/SQLite defaults — development must be opted in.
    with pytest.raises(RuntimeError, match=r"MINDPATTERN_TOKEN_SECRET is unset/insecure"):
        Settings.from_env()
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    assert asdict(Settings.from_env()) == asdict(Settings(environment="development"))


def test_insecure_default_secret_value_is_pinned():
    assert DEFAULT_INSECURE_SECRET == "dev-insecure-secret-change-me"


def test_from_env_wires_every_variable(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.setenv("MINDPATTERN_DB_URL", "sqlite+aiosqlite://")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 45)
    monkeypatch.setenv("MINDPATTERN_TOKEN_TTL", "1234")
    monkeypatch.setenv("MINDPATTERN_PROCESSING_TTL", "123")
    monkeypatch.setenv("MINDPATTERN_UNLOCK_DAYS", "21")
    monkeypatch.setenv("MINDPATTERN_AUTH_RATE_LIMIT", "5")
    monkeypatch.setenv("MINDPATTERN_AUTH_RATE_WINDOW", "55")
    monkeypatch.setenv("MINDPATTERN_ENTRIES_RATE_LIMIT", "6")
    monkeypatch.setenv("MINDPATTERN_ENTRIES_RATE_WINDOW", "56")
    monkeypatch.setenv("MINDPATTERN_PROCESSING_RATE_LIMIT", "7")
    monkeypatch.setenv("MINDPATTERN_PROCESSING_RATE_WINDOW", "57")
    monkeypatch.setenv("MINDPATTERN_READ_RATE_LIMIT", "8")
    monkeypatch.setenv("MINDPATTERN_READ_RATE_WINDOW", "58")
    monkeypatch.setenv("MINDPATTERN_BODY_READ_TIMEOUT", "17")
    monkeypatch.setenv("MINDPATTERN_MAX_BODY_BYTES", str(1024 * 1024))
    monkeypatch.setenv("MINDPATTERN_MAX_ENTRIES_PER_USER", "99")
    monkeypatch.setenv("MINDPATTERN_MAX_USER_BLOB_BYTES", str(1024 * 1024))
    monkeypatch.setenv("MINDPATTERN_RECOMPUTE_ENTRY_LIMIT", "42")
    monkeypatch.setenv("MINDPATTERN_LLM_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("MINDPATTERN_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("MINDPATTERN_LLM_MODEL", "mini-latest")
    monkeypatch.setenv("MINDPATTERN_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("MINDPATTERN_TRUSTED_PROXY_IPS", "10.0.0.9, 2001:db8::/64")
    monkeypatch.setenv("MINDPATTERN_CORS_ORIGINS", "https://a.example, https://b.example")

    settings = Settings.from_env()
    assert settings.environment == "development"
    assert settings.database_url == "sqlite+aiosqlite://"
    assert settings.token_secret == "x" * 45
    assert settings.token_ttl_seconds == 1234
    assert settings.processing_session_ttl == 123
    assert settings.unlock_threshold_days == 21
    assert settings.auth_rate_limit == 5
    assert settings.auth_rate_window == 55
    assert settings.entries_rate_limit == 6
    assert settings.entries_rate_window == 56
    assert settings.processing_rate_limit == 7
    assert settings.processing_rate_window == 57
    assert settings.read_rate_limit == 8
    assert settings.read_rate_window == 58
    assert settings.body_read_timeout_seconds == 17
    assert settings.max_body_bytes == 1024 * 1024
    assert settings.max_entries_per_user == 99
    assert settings.max_user_blob_bytes == 1024 * 1024
    assert settings.recompute_entry_limit == 42
    assert settings.llm_url == "https://llm.example.com/v1"
    assert settings.llm_api_key == "sk-test"
    assert settings.llm_model == "mini-latest"
    assert settings.trust_proxy_headers is True
    assert settings.trusted_proxy_ips == ["10.0.0.9/32", "2001:db8::/64"]
    assert settings.cors_origins == ["https://a.example", "https://b.example"]


def test_from_env_rejects_non_integer(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_AUTH_RATE_LIMIT", "ten")
    with pytest.raises(
        ValueError,
        match=r"^environment variable MINDPATTERN_AUTH_RATE_LIMIT='ten' is not an integer$",
    ):
        Settings.from_env()


def test_proxy_header_mode_requires_valid_direct_peer_allowlist(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.setenv("MINDPATTERN_TRUST_PROXY_HEADERS", "1")
    with pytest.raises(RuntimeError, match="MINDPATTERN_TRUSTED_PROXY_IPS"):
        Settings.from_env()

    monkeypatch.setenv("MINDPATTERN_TRUSTED_PROXY_IPS", "not-an-ip")
    with pytest.raises(RuntimeError, match="invalid IP/CIDR"):
        Settings.from_env()


def test_bool_env_accepts_every_spelling(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_TEST_BOOL", raising=False)
    assert _bool_env("MINDPATTERN_TEST_BOOL") is False  # unset -> default False
    assert _bool_env("MINDPATTERN_TEST_BOOL", True) is True  # explicit default
    for truthy in ("1", "true", "yes", "on"):
        monkeypatch.setenv("MINDPATTERN_TEST_BOOL", truthy)
        assert _bool_env("MINDPATTERN_TEST_BOOL") is True
    for falsy in ("0", "false", "no", "off", "anything-else"):
        monkeypatch.setenv("MINDPATTERN_TEST_BOOL", falsy)
        assert _bool_env("MINDPATTERN_TEST_BOOL") is False


def test_cors_origins_parsing(clean_env, monkeypatch):
    monkeypatch.delenv("MINDPATTERN_CORS_ORIGINS", raising=False)
    assert _cors_origins() == []  # empty default = NO cross-origin access
    monkeypatch.setenv("MINDPATTERN_CORS_ORIGINS", " https://a.example , https://b.example , , ")
    assert _cors_origins() == ["https://a.example", "https://b.example"]


def test_production_refuses_weak_token_secret_at_the_exact_boundary(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")

    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 31)
    with pytest.raises(
        RuntimeError, match=r"MINDPATTERN_TOKEN_SECRET must be at least 32 characters"
    ):
        Settings.from_env()

    # Exactly 32 characters is the accepted minimum.
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 32)
    assert Settings.from_env().token_secret == "x" * 32


def test_production_refuses_dev_secret_and_sqlite(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 45)
    monkeypatch.setenv("MINDPATTERN_DB_URL", "sqlite+aiosqlite://")
    with pytest.raises(RuntimeError) as excinfo:
        Settings.from_env()
    assert str(excinfo.value) == (
        "MINDPATTERN_DB_URL must point at PostgreSQL (or another shared "
        "database) outside development; SQLite is dev/test only"
    )

    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", DEFAULT_INSECURE_SECRET)
    with pytest.raises(RuntimeError) as excinfo:
        Settings.from_env()
    assert str(excinfo.value) == (
        "MINDPATTERN_TOKEN_SECRET is unset/insecure: refuse to start. "
        "Set a strong random value (e.g. openssl rand -hex 32). "
        "(The built-in dev secret is only allowed with "
        "MINDPATTERN_ENV=development exactly.)"
    )


def test_development_env_allows_the_dev_secret(clean_env, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_TOKEN_SECRET", raising=False)
    assert Settings.from_env().token_secret == DEFAULT_INSECURE_SECRET


# ---------------------------------------------------------------------------
# Route wiring: prefixes, tags, methods, rate-limiter buckets
# ---------------------------------------------------------------------------

EXPECTED_ROUTES = {
    # (module router, path, method): (tags, limiter bucket or None)
    (meta_api, "/meta", "GET"): ({"meta"}, None),
    (auth_api, "/auth/register", "POST"): ({"auth"}, "auth-register"),
    (auth_api, "/auth/salt", "POST"): ({"auth"}, "auth-salt"),
    (auth_api, "/auth/login", "POST"): ({"auth"}, "auth-login"),
    (auth_api, "/auth/logout", "POST"): ({"auth"}, "auth-logout"),
    (entries_api, "/entries", "POST"): ({"entries"}, "entries-create"),
    (entries_api, "/entries", "GET"): ({"entries"}, "entries-read"),
    (entries_api, "/entries/{client_entry_id}", "DELETE"): ({"entries"}, "entries-delete"),
    (insights_api, "/processing/sessions", "POST"): ({"insights"}, "processing-sessions"),
    (insights_api, "/insights/recompute", "POST"): ({"insights"}, "insights-recompute"),
    (insights_api, "/insights", "GET"): ({"insights"}, "insights-read"),
    (insights_api, "/questions/today", "GET"): ({"insights"}, "questions-read"),
    # Dedicated export bucket since 2026-09-07 (was "account-read"): one
    # export streams up to the whole blob quota.
    (account_api, "/account/export", "GET"): ({"account"}, "account-export"),
    (account_api, "/account/llm-consent", "GET"): ({"account"}, "account-consent-read"),
    (account_api, "/account/llm-consent", "PUT"): ({"account"}, "account-consent"),
    (account_api, "/account", "DELETE"): ({"account"}, "account-delete"),
}


def _limiter_bucket(route: APIRoute) -> str | None:
    """The bucket name of a make_rate_limiter dependency.

    Pin updated 2026-09-20 (M-1): make_rate_limiter now returns a
    RateLimitCheck callable OBJECT carrying (bucket, limit_attr,
    window_attr) as attributes — the introspection HardeningMiddleware's
    malformed-body edge counting is built on — instead of a closure named
    ``check`` with cells. Same pinned fact, readable surface.
    """
    for depends in route.dependencies:
        if isinstance(depends.dependency, RateLimitCheck):
            return depends.dependency.bucket
    return None


def test_route_wiring_prefixes_tags_and_limiter_buckets():
    from app.api import api_router

    assert api_router.prefix == "/api"  # every module router mounts under /api
    seen = set()
    for (module, path, method), (tags, bucket) in EXPECTED_ROUTES.items():
        route = next(
            r
            for r in module.router.routes
            if isinstance(r, APIRoute) and r.path == path and method in r.methods
        )
        seen.add((path, method))
        assert set(route.tags) == tags, f"{method} {path} tags: {route.tags}"
        assert _limiter_bucket(route) == bucket, f"{method} {path} limiter bucket"
    assert len(seen) == len(EXPECTED_ROUTES)
    # healthz is declared straight on the app factory.
    health = next(
        r for r in module_level_app.routes if isinstance(r, APIRoute) and r.path == "/healthz"
    )
    assert set(health.tags) == {"ops"}


def test_limiter_composite_key_shape():
    """The counter key is bucket:client — pinned so buckets never collide.

    Pin updated 2026-09-20 (M-1): the spec rides the RateLimitCheck
    attributes instead of closure cells (see _limiter_bucket above).
    """
    route = next(
        r
        for r in entries_api.router.routes
        if isinstance(r, APIRoute) and r.path == "/entries" and "POST" in r.methods
    )
    check = next(
        d.dependency for d in route.dependencies if isinstance(d.dependency, RateLimitCheck)
    )
    assert check.bucket == "entries-create"
    assert (check.limit_attr, check.window_attr) == ("entries_rate_limit", "entries_rate_window")


# ---------------------------------------------------------------------------
# Constants that are cost/deployment contracts
# ---------------------------------------------------------------------------


def test_crypto_and_auth_constants_are_pinned():
    assert auth_api.SCRYPT_N == 2**16
    assert auth_api.SCRYPT_R == 8
    assert auth_api.SCRYPT_P == 1
    assert auth_api.SCRYPT_MAXMEM == 256 * 1024 * 1024
    assert auth_api.SALT_BYTES == 16
    assert auth_api.AUTH_KEY_SIZE == 32
    assert crypto_module.KEY_SIZE == 32
    assert crypto_module.MIN_BLOB_SIZE == 28
    assert entries_api.BACKDATE_GRACE_DAYS == 1
    assert cache_module.MAX_TRACKED_KEYS == 10_000
    assert patterns_module.MAX_PATTERNS == 20
    assert patterns_module.MIN_THEME_OCCURRENCES == 4
    assert patterns_module.TEMPORAL_DAY_FRACTION == 0.5
    assert patterns_module.MOOD_DELTA_THRESHOLD == 0.3
    assert patterns_module.PHRASE_MIN_OCCURRENCES == 3
    assert patterns_module.PHRASE_MIN_SPAN_DAYS == 7
    assert SECURITY_HEADERS == (
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cache-control", b"no-store"),
        (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
    )


def test_build_aad_escapes_non_ascii_exactly_like_the_backend_vectors():
    """ensure_ascii=True is the wire contract: every non-ASCII code unit is
    \\u-escaped (astral chars as surrogate pairs), matching shared/vectors.json."""
    assert crypto_module.build_aad("ünïcode", "🧠", "del\u007f") == (
        b'["\\u00fcn\\u00efcode","\\ud83e\\udde0","del\\u007f"]'
    )
    # ASCII passes through byte-identically.
    assert crypto_module.build_aad("plain", "ids") == b'["plain","ids"]'


def test_hitresult_is_frozen():
    with pytest.raises(Exception):  # FrozenInstanceError (AttributeError subclass)
        HitResult(count=1, retry_after=2).count = 5


def test_counter_window_boundary_semantics():
    counter = FixedWindowCounter()
    # Fresh window: retry_after covers the whole window (exact value pinned).
    first = counter.hit("k", window_seconds=10, now=100.0)
    assert (first.count, first.retry_after) == (1, 11)
    # Half a second before expiry: retry_after floors to exactly 1 second.
    late = counter.hit("k", window_seconds=10, now=109.5)
    assert (late.count, late.retry_after) == (2, 1)
    with pytest.raises(ValueError, match=r"^window_seconds must be positive$"):
        counter.hit("k", window_seconds=0)


def test_counter_evicts_at_the_exact_cap_and_by_window_start():
    counter = FixedWindowCounter()
    # Fill exactly MAX keys with DIFFERENT window sizes: eviction ranks
    # active victims by (count, window_start), not by window size.
    for i in range(MAX_TRACKED_KEYS):
        counter.hit(f"k{i}", window_seconds=10_000 + i, now=1_000.0 + i)
    assert len(counter._hits) == MAX_TRACKED_KEYS
    counter.hit("newcomer", window_seconds=1, now=2_000.0)
    # Eviction is batched: one pass clears down to MAX - EVICTION_BATCH so
    # the next over-cap hits do not each pay a full scan.
    assert len(counter._hits) == MAX_TRACKED_KEYS - cache_module.EVICTION_BATCH
    # Every key ties on count=1, so the oldest window STARTS go first; k0's
    # start is strictly the oldest so its eviction is certain, while the
    # exact identity of the remaining tied victims is unspecified.
    assert "k0" not in counter._hits
    assert "newcomer" in counter._hits


def test_counter_drops_exactly_expired_windows():
    counter = FixedWindowCounter()
    # now - start == window EXACTLY: the window is stale (>= semantics).
    for i in range(MAX_TRACKED_KEYS):
        counter.hit(f"k{i}", window_seconds=1_000, now=0.0)
    result = counter.hit("fresh", window_seconds=2_000, now=1_000.0)
    assert result.count == 1
    # All exactly-expired windows were reclaimed; only the fresh key remains.
    assert len(counter._hits) == 1
    assert "fresh" in counter._hits


def test_client_key_uses_only_middleware_authorized_forwarding_state():
    from starlette.requests import Request

    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"9.9.9.9, 8.8.8.8")],
        "client": ("1.2.3.4", 5),
        "method": "GET",
        "path": "/",
    }
    request = Request(scope)
    # Default: do NOT trust the spoofable header.
    assert client_key(request) == "1.2.3.4"
    # A raw boolean alone never grants a direct client authority over XFF.
    assert client_key(request, trust_proxy_headers=True) == "1.2.3.4"
    # HardeningMiddleware supplies this state only after the direct socket
    # peer matches MINDPATTERN_TRUSTED_PROXY_IPS and it sanitizes the chain.
    request.state.mindpattern_trusted_proxy = True
    request.state.mindpattern_forwarded_client = "8.8.8.8"
    assert client_key(request, trust_proxy_headers=True) == "8.8.8.8"


async def test_unlimited_endpoints_create_no_rate_buckets(settings):
    """key=None style mutants would collapse every client into one bucket.

    (This test and test_rate_limiter_buckets_clients_independently below
    accidentally shared one name for years — the first definition was
    shadowed and never ran until the 2026-09-17 audit un-shadowed it.)
    """
    settings.auth_rate_limit = 1
    settings.auth_rate_window = 60
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        sent = []
        for host in ("1.1.1.1", "2.2.2.2"):
            transport = ASGITransport(app=application, client=(host, 1234))
            async with AsyncClient(transport=transport, base_url="http://t") as c:
                r1 = await c.get("/healthz")
                r2 = await c.get("/healthz")
                sent.append((r1.status_code, r2.status_code))
        # L-2 (2026-09-20) reversed the old contract: /healthz and /readyz
        # now share ONE generous ops bucket ("ops-health") — they used to be
        # the only DB-touching endpoints with no limiter at all. The limiter
        # shape is still asserted via the counter: exactly that one bucket,
        # per-client keys, nothing else.
        counter: FixedWindowCounter = application.state.rate_counter
        assert sent == [(200, 200)] * 2
        buckets = {k.split(":", 1)[0] for k in counter._hits}
        assert buckets == {"ops-health"}
        assert {k.rsplit(":", 1)[1] for k in counter._hits} == {"1.1.1.1", "2.2.2.2"}


async def test_keyed_limit_429_shape(settings):
    """429 shape: exact detail and a Retry-After of at least 1 second."""
    settings.auth_rate_limit = 1
    settings.auth_rate_window = 60
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            first = await c.post("/api/auth/salt", json={"username": "ratelimit-pin"})
            second = await c.post("/api/auth/salt", json={"username": "ratelimit-pin"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "rate limit exceeded"
    assert int(second.headers["Retry-After"]) >= 1
    counter: FixedWindowCounter = application.state.rate_counter
    assert any(key.startswith("auth-salt:") for key in counter._hits)


async def test_rate_limiter_buckets_clients_independently(settings):
    """A collapsed client key would put every caller in ONE bucket."""
    settings.auth_rate_limit = 1
    settings.auth_rate_window = 60
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        firsts = []
        for host in ("1.1.1.1", "2.2.2.2"):
            transport = ASGITransport(app=application, client=(host, 1234))
            async with AsyncClient(transport=transport, base_url="http://t") as c:
                response = await c.post("/api/auth/salt", json={"username": f"client-{host}"})
                firsts.append(response.status_code)
    # With a limit of 1 per window, each DISTINCT client's first request is
    # allowed; a collapsed key would 429 the second client immediately.
    assert firsts == [200, 200]


# ---------------------------------------------------------------------------
# main.py: app metadata, CORS wiring, healthz, module-level app
# ---------------------------------------------------------------------------


async def test_app_metadata_and_healthz(app, client):
    assert app.title == "MindPattern API"
    assert app.version == "1.0.0"
    assert app.description == "Zero-knowledge personal pattern recognition for mental state."

    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "1.0.0"}

    health_route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == "/healthz")
    assert set(health_route.tags) == {"ops"}


async def test_cors_middleware_contract(settings):
    application = create_app(settings)
    cors = next(m for m in application.user_middleware if m.cls.__name__ == "CORSMiddleware")
    # PATCH joined the allowlist with the therapist portal (note updates).
    assert cors.kwargs["allow_methods"] == ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    # Pin updated 2026-09-08: X-Account-Verifier joined the list — it is the
    # preferred DELETE /account re-auth transport and a browser client must
    # be allowed to send it cross-origin (origins themselves stay opt-in).
    assert cors.kwargs["allow_headers"] == [
        "Authorization",
        "Content-Type",
        "X-Processing-Token",
        "X-Account-Verifier",
        "X-Therapist-Enrollment-Token",
    ]
    assert cors.kwargs["expose_headers"] == [
        "X-Next-Offset",
        "X-Entries-Revision",
        "X-Notes-Revision",
    ]
    assert cors.kwargs["allow_origins"] == []


async def test_validation_errors_expose_only_loc_and_msg(app, client):
    # Envelope unification (2026-09-07): detail is now ONE human string that
    # names the failed fields and pydantic's reasons — never the input, never
    # the old list-of-dicts shape (mobile parses detail as a string).
    response = await client.post("/api/auth/register", json={})
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert isinstance(body["detail"], str)
    assert "username" in body["detail"]
    assert "salt" in body["detail"]
    assert "verifier" in body["detail"]
    assert "Field required" in body["detail"]
    assert "input" not in body  # the echo channel stays closed


async def test_module_level_app_is_a_real_app():
    assert module_level_app is not None
    assert module_level_app.title == "MindPattern API"


async def test_lifespan_context_is_an_async_context_manager(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        # Entering must have initialized the app state uvicorn relies on.
        assert application.state.engine is not None
        assert application.state.sessionmaker is not None
        assert application.state.rate_counter is not None


# ---------------------------------------------------------------------------
# Base64 strictness: whitespace must be rejected, not silently stripped
# ---------------------------------------------------------------------------

SPACEY_SALT = base64.b64encode(b"x" * 16).decode() + " "


async def test_register_rejects_whitespace_in_base64_salt(client):
    emu = ClientEmulator("b64strict", "pw-b64-strict")
    response = await client.post(
        "/api/auth/register",
        json={"username": emu.username, "salt": SPACEY_SALT, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "salt and verifier must be base64"


async def test_register_rejects_whitespace_in_base64_verifier(client):
    emu = ClientEmulator("b64strict2", "pw-b64-strict-2")
    response = await client.post(
        "/api/auth/register",
        json={
            "username": emu.username,
            "salt": emu.salt_b64,
            "verifier": emu.auth_key_b64 + " ",
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "salt and verifier must be base64"


async def test_register_rejects_wrongly_sized_salt_and_verifier(client):
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "sizing",
            "salt": base64.b64encode(b"short").decode(),
            "verifier": base64.b64encode(b"y" * 32).decode(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "salt must be exactly 16 bytes"

    response = await client.post(
        "/api/auth/register",
        json={
            "username": "sizing",
            "salt": base64.b64encode(b"x" * 16).decode(),
            "verifier": base64.b64encode(b"y" * 31).decode(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "verifier must be 32 bytes"


async def test_entries_rejects_whitespace_in_base64_blob(client):
    emu = ClientEmulator("b64blob", "pw-b64-blob")
    await emu.register(client)
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-spacey",
            "blob": base64.b64encode(b"z" * 40).decode() + " ",
            "entry_date": TODAY.isoformat(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "blob must be base64"


async def test_processing_session_rejects_whitespace_in_base64_key(client):
    emu = ClientEmulator("b64key", "pw-b64-key")
    await emu.register(client)
    # Same length as a valid key (44 chars, the schema cap) but with a space
    # inside: length validation passes, the HANDLER's strict b64 must reject.
    # (The old payload appended a space to a valid key; with the cap now
    # exactly 44 that variant is rejected by length instead — also fine, but
    # it stops pinning the base64 branch.)
    key_with_space = base64.b64encode(b"k" * 32).decode()[:-1] + " "
    response = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": key_with_space},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "data_key must be base64"


async def test_processing_session_rejects_wrongly_sized_key(client):
    emu = ClientEmulator("b64key2", "pw-b64-key-2")
    await emu.register(client)
    response = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": base64.b64encode(b"k" * 31).decode()},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "data_key must be 32 bytes"


# ---------------------------------------------------------------------------
# Exact user-facing error details
# ---------------------------------------------------------------------------


async def test_entry_validation_details_are_exact(client):
    emu = ClientEmulator("details", "pw-details")
    await emu.register(client)

    too_small = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-small",
            "blob": base64.b64encode(b"x" * 27).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert too_small.status_code == 422
    assert too_small.json()["detail"] == "blob must be at least 28 bytes"

    future = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-future",
            "blob": base64.b64encode(b"x" * 40).decode(),
            # Two days out: one day of FORWARD grace absorbs device-local
            # dates east of UTC (added 2026-09-07), so the rejection pin
            # moved past the grace window.
            "entry_date": (TODAY + timedelta(days=2)).isoformat(),
        },
    )
    assert future.status_code == 422
    assert future.json()["detail"] == "entry_date cannot be in the future"

    ancient = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-old",
            "blob": base64.b64encode(b"x" * 40).decode(),
            "entry_date": (TODAY - timedelta(days=400)).isoformat(),
        },
    )
    assert ancient.status_code == 422
    assert ancient.json()["detail"] == "entry_date is before this account existed"

    created = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-dup",
            "blob": base64.b64encode(b"x" * 40).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert created.status_code == 201
    duplicate = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-dup",
            "blob": base64.b64encode(b"x" * 40).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "entry already exists"

    missing = await client.delete("/api/entries/never-created", headers=emu.headers)
    assert missing.status_code == 404
    assert missing.json()["detail"] == "entry not found"


async def test_entry_quota_details_are_exact(client, app):
    emu = ClientEmulator("quotadetails", "pw-quota-details")
    await emu.register(client)
    app.state.settings.max_entries_per_user = 1
    blob = base64.b64encode(b"x" * 40).decode()
    await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": "q-1", "blob": blob, "entry_date": TODAY.isoformat()},
    )
    second = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": "q-2", "blob": blob, "entry_date": TODAY.isoformat()},
    )
    assert second.status_code == 413
    assert second.json()["detail"] == "storage quota reached (1 entries)"


async def test_byte_quota_boundary_admits_an_exactly_full_account(client, app):
    emu = ClientEmulator("quotabound", "pw-quota-bound")
    await emu.register(client)
    raw = b"x" * 40
    app.state.settings.max_user_blob_bytes = len(raw)  # exactly the incoming blob
    created = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "qb-1",
            "blob": base64.b64encode(raw).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert created.status_code == 201


async def test_min_blob_size_boundary(client):
    emu = ClientEmulator("blobbound", "pw-blob-bound")
    await emu.register(client)
    exactly = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "mb-1",
            "blob": base64.b64encode(b"x" * 28).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert exactly.status_code == 201


async def test_entries_pagination_bounds(client):
    emu = ClientEmulator("paging", "pw-paging")
    await emu.register(client)
    await emu.backdate_account(client, days=160)
    for day in daterange(150, TODAY):
        await emu.create_entry(client, "note", day, client_entry_id=f"p-{day.isoformat()}")

    default_page = await client.get("/api/entries", headers=emu.headers)
    assert default_page.status_code == 200
    assert len(default_page.json()) == 100  # default limit

    max_limit = await client.get("/api/entries?limit=500", headers=emu.headers)
    assert max_limit.status_code == 200
    over_limit = await client.get("/api/entries?limit=501", headers=emu.headers)
    assert over_limit.status_code == 422
    min_limit = await client.get("/api/entries?limit=0", headers=emu.headers)
    assert min_limit.status_code == 422

    max_offset = await client.get("/api/entries?offset=100000", headers=emu.headers)
    assert max_offset.status_code == 200
    over_offset = await client.get("/api/entries?offset=100001", headers=emu.headers)
    assert over_offset.status_code == 422


async def test_entry_ids_are_per_account(client):
    alice = ClientEmulator("idsalice", "pw-ids-alice")
    bob = ClientEmulator("idsbob", "pw-ids-bob")
    await alice.register(client)
    await bob.register(client)
    await alice.create_entry(client, "alice note", TODAY, client_entry_id="shared-id")
    # The same client_entry_id under another account is NOT a duplicate.
    bob_entry = await bob.create_entry(client, "bob note", TODAY, client_entry_id="shared-id")
    assert bob_entry["client_entry_id"] == "shared-id"


async def test_salt_lookup_returns_the_real_salt_for_active_accounts(client):
    emu = ClientEmulator("realsalt", "pw-real-salt")
    await emu.register(client)
    salt = await emu.salt_for(client)
    assert salt["salt"] == emu.salt_b64


async def test_processing_session_errors_are_exact(client):
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator("perr", "pw-p-errors")
    await emu.register(client)
    # The token checks sit behind the threshold gate: only a post-threshold
    # account reaches them.
    await seed_corpus(client, emu, days=35)

    empty_token = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": ""}
    )
    assert empty_token.status_code == 401
    assert empty_token.json()["detail"] == "missing processing session token"

    bad_token = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": "not-a-session"},
    )
    assert bad_token.status_code == 403
    assert bad_token.json()["detail"] == "processing session missing or expired"


async def test_recompute_without_entries_is_rejected_exactly(client):
    emu = ClientEmulator("noentries", "pw-no-entries")
    await emu.register(client)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "no entries to analyze"


async def test_question_404_detail_is_exact(client):
    emu = ClientEmulator("noq", "pw-no-q")
    await emu.register(client)
    response = await client.get("/api/questions/today", headers=emu.headers)
    assert response.status_code == 404
    assert response.json()["detail"] == (
        "no question for today; open a processing session and run /insights/recompute"
    )


async def test_baseline_recompute_stores_nothing(client):
    emu = ClientEmulator("basepin", "pw-base-pin")
    await emu.register(client)
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=29)
    token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    body = recompute.json()
    assert body["phase"] == "baseline"
    assert body["question_stored"] is False
    assert body["patterns_stored"] == 0

    insights = await client.get("/api/insights", headers=emu.headers)
    assert insights.json()["blob"] is None


async def test_insights_payload_declares_version_two(client):
    emu = ClientEmulator("vtwo", "pw-v-two")
    await emu.register(client)
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=35)
    await emu.recompute(client)
    payload = await emu.decrypt_insights(client)
    assert payload["v"] == 2
    assert payload["phase"] == "insight"


async def test_recompute_accepts_numeric_client_sentiment(client):
    emu = ClientEmulator("numsent", "pw-num-sent")
    await emu.register(client)
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=35)
    await emu.create_entry(client, "scored day", TODAY, client_entry_id="sent-1", sentiment=0.5)
    result = await emu.recompute(client)
    assert result["phase"] == "insight"


async def test_stale_insight_rows_are_replaced_for_the_same_kind_only(client, app):
    emu = ClientEmulator("staleins", "pw-stale-ins")
    await emu.register(client)
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=35)
    await emu.recompute(client)

    async with app.state.sessionmaker() as session:
        # A foreign-kind row and a stale same-kind row for another date.
        session.add(
            Insight(
                user_id=emu.user_id,
                kind="other-kind",
                for_date=TODAY - timedelta(days=3),
                blob=b"keep-me",
            )
        )
        session.add(
            Insight(
                user_id=emu.user_id,
                kind="patterns",
                for_date=TODAY - timedelta(days=9),
                blob=b"stale",
            )
        )
        session.add(
            Insight(
                user_id=emu.user_id,
                kind="question",
                for_date=TODAY - timedelta(days=9),
                blob=b"stale-q",
            )
        )
        await session.commit()

    await emu.recompute(client)

    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(Insight).where(Insight.user_id == emu.user_id)))
            .scalars()
            .all()
        )
    kinds = sorted((r.kind, r.for_date) for r in rows)
    pattern_rows = [r for r in rows if r.kind == "patterns"]
    # The foreign-kind row is untouched, exactly ONE fresh patterns row
    # remains (the stale one was replaced), and today's question is stored.
    assert ("other-kind", TODAY - timedelta(days=3)) in kinds
    assert len(pattern_rows) == 1
    assert ("question", TODAY) in kinds
    assert ("patterns", TODAY - timedelta(days=9)) not in kinds


# ---------------------------------------------------------------------------
# auth: server salt size, decoy determinism, register 409 detail
# ---------------------------------------------------------------------------


async def test_register_stores_a_16_byte_server_scrypt_salt(client, app):
    from app.models import User

    emu = ClientEmulator("srvsalt", "pw-srv-salt")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        row = (
            await session.execute(select(User).where(User.username == emu.username))
        ).scalar_one()
    assert len(bytes(row.scrypt_salt)) == 16


async def test_decoy_salt_is_deterministic_and_domain_separated(settings):
    from app.api.auth import DECOY_SALT_INFO, decoy_salt
    from app.security.kdf import hkdf_sha256

    secret = settings.token_secret
    assert decoy_salt("alice", secret) == decoy_salt("alice", secret)  # stable
    assert decoy_salt("alice", secret) != decoy_salt("bob", secret)  # per-name
    assert decoy_salt("alice", secret) != decoy_salt("alice", "other-secret")
    # Domain separation: the decoy HMAC runs under an HKDF subkey derived
    # from the token secret — base64(HMAC(HKDF(secret, None, info),
    # b"decoy:<name>")[:16]) exactly, never HMAC(raw_secret, ...).
    decoy_key = hkdf_sha256(secret.encode("utf-8"), None, DECOY_SALT_INFO)
    digest = hmac.new(decoy_key, b"decoy:alice", hashlib.sha256).digest()
    assert decoy_salt("alice", secret) == base64.b64encode(digest[:16]).decode("ascii")


async def test_register_conflict_detail_is_exact(client):
    emu = ClientEmulator("conflict", "pw-conflict")
    await emu.register(client)
    response = await client.post(
        "/api/auth/register",
        json={"username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "username already taken"


async def test_login_failure_detail_is_exact(client):
    emu = ClientEmulator("badlogin", "pw-bad-login")
    await emu.register(client)
    response = await client.post(
        "/api/auth/login",
        json={"username": emu.username, "verifier": base64.b64encode(b"w" * 32).decode()},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"


async def test_unknown_user_login_burns_cpu_and_fails_flat(client):
    response = await client.post(
        "/api/auth/login",
        json={"username": "ghost-user", "verifier": base64.b64encode(b"w" * 32).decode()},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"


# ---------------------------------------------------------------------------
# tokens: missing-field payloads and error messages
# ---------------------------------------------------------------------------


def _signed_token(payload: dict, secret: str) -> str:
    body = tokens_module._b64url_encode(json.dumps(payload).encode("utf-8"))
    signature = tokens_module._b64url_encode(
        hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"


def test_token_with_payload_missing_uid_is_rejected():
    token = _signed_token({"exp": 9999999999}, "secret")
    with pytest.raises(TokenError, match=r"^malformed payload$"):
        verify_token(token, "secret")


def test_token_with_payload_missing_exp_is_rejected():
    token = _signed_token({"uid": "u"}, "secret")
    with pytest.raises(TokenError, match=r"^malformed payload$"):
        verify_token(token, "secret")


def test_issue_token_rejects_non_positive_ttl():
    with pytest.raises(ValueError, match=r"^ttl_seconds must be positive$"):
        issue_token("u", "s", 0)


def test_verify_token_error_messages_are_pinned():
    with pytest.raises(TokenError, match=r"^malformed token$"):
        verify_token("no-dot-here", "secret")
    with pytest.raises(TokenError, match=r"^bad signature$"):
        verify_token(".......", "secret")  # empty pieces: signature cannot match


async def test_token_without_epoch_claim_is_accepted_for_epoch_one(client, app):
    """Legacy tokens issued without an 'ep' claim must keep working against
    an account still at epoch 1 (the default in the check)."""
    emu = ClientEmulator("epochless", "pw-epoch-less")
    await emu.register(client)
    legacy = _signed_token({"uid": emu.user_id, "exp": 9999999999}, app.state.settings.token_secret)
    response = await client.get("/api/entries", headers={"Authorization": f"Bearer {legacy}"})
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# account export: exact bundle header and streaming shape
# ---------------------------------------------------------------------------


async def test_export_bundle_header_is_exact(client):
    emu = ClientEmulator("exportpin", "pw-export-pin")
    await emu.register(client)
    await emu.create_entry(client, "exported note", TODAY, client_entry_id="x-1")
    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    lines = [line for line in response.text.splitlines() if line.strip()]
    head = json.loads(lines[0])
    assert head["version"] == 1
    assert head["llm_consent"] is False
    # 2026-09-16 (finding H2): no cleartext username in the export bundle.
    assert "username" not in head
    parsed_at = datetime.fromisoformat(head["exported_at"])
    assert parsed_at.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - parsed_at).total_seconds()) < 300


# ---------------------------------------------------------------------------
# middleware: exact boundaries and header semantics
# ---------------------------------------------------------------------------


def _http_scope(headers=None, method="POST"):
    return {
        "type": "http",
        "asgi": {"version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "path": "/x",
        "headers": headers or [],
    }


async def _call_asgi(app, scope, incoming):
    sent = []
    queue = list(incoming)

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def test_body_exactly_at_the_cap_is_allowed():
    async def echo(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapped = HardeningMiddleware(echo, max_body_bytes=10)
    # Declared content-length exactly at the cap: allowed.
    sent = await _call_asgi(wrapped, _http_scope([(b"content-length", b"10")]), [])
    assert sent[0]["status"] == 200

    # Streamed body exactly at the cap: allowed (strictly greater rejects).
    sent = await _call_asgi(
        wrapped, _http_scope([]), [{"type": "http.request", "body": b"0" * 10, "more_body": False}]
    )
    assert sent[0]["status"] == 200

    # One byte over, streamed: the app sees the converted disconnect and
    # gives up silently -> the middleware produces the 413.
    async def silent_reader(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return

    wrapped = HardeningMiddleware(silent_reader, max_body_bytes=10)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [
            {"type": "http.request", "more_body": True},
            {"type": "http.request", "body": b"0" * 11, "more_body": False},
        ],
    )
    assert sent[0]["status"] == 413

    # A message with NO body key contributes exactly zero bytes.
    async def exact_reader(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    exact = HardeningMiddleware(exact_reader, max_body_bytes=3)
    sent = await _call_asgi(
        exact,
        _http_scope([]),
        [
            {"type": "http.request", "more_body": True},
            {"type": "http.request", "body": b"123", "more_body": False},
        ],
    )
    assert sent[0]["status"] == 200


async def test_overflow_is_rejected_before_the_app_can_observe_it():
    seen_types = []

    async def reader_app(scope, receive, send):
        while True:
            message = await receive()
            seen_types.append(message["type"])
            if message["type"] != "http.request":
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapped = HardeningMiddleware(reader_app, max_body_bytes=4)
    sent = await _call_asgi(
        wrapped,
        _http_scope([]),
        [{"type": "http.request", "body": b"toolarge", "more_body": False}],
    )
    assert seen_types == []
    assert sent[0]["status"] == 413


async def test_silent_app_without_overflow_gets_no_synthesized_response():
    async def silent(scope, receive, send):
        return  # never answers, never overflows

    wrapped = HardeningMiddleware(silent, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([]), [])
    assert sent == []  # nothing synthesized when nothing was rejected


async def test_no_second_response_after_the_app_already_answered():
    async def answer_then_raise(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})
        raise RuntimeError("late failure")

    wrapped = HardeningMiddleware(answer_then_raise, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([]), [])
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]


async def test_app_provided_security_headers_are_not_duplicated():
    async def headered(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"cache-control", b"no-store"), (b"x-custom", b"x-frame-options")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    wrapped = HardeningMiddleware(headered, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([], method="GET"), [])
    headers = sent[0]["headers"]
    names = [name for name, _ in headers]
    # The app's own header is respected (no duplicate), and a header whose
    # VALUE equals a security-header NAME must not suppress the real one.
    assert names.count(b"cache-control") == 1
    assert (b"x-frame-options", b"DENY") in headers
    assert (b"x-custom", b"x-frame-options") in headers


async def test_middleware_generated_errors_carry_exact_content_type():
    async def exploding(scope, receive, send):
        raise RuntimeError("boom")

    wrapped = HardeningMiddleware(exploding, max_body_bytes=100)
    sent = await _call_asgi(wrapped, _http_scope([], method="GET"), [])
    assert (b"content-type", b"application/json") in sent[0]["headers"]


async def test_unhandled_exceptions_are_logged_on_the_mindpattern_logger(caplog):
    async def exploding(scope, receive, send):
        raise RuntimeError("boom")

    wrapped = HardeningMiddleware(exploding, max_body_bytes=100)
    with caplog.at_level(logging.ERROR, logger="mindpattern"):
        await _call_asgi(wrapped, _http_scope([], method="GET"), [])
    matching = [r for r in caplog.records if "unhandled error serving method=GET" in r.message]
    assert matching, "expected an unhandled-error record"
    assert matching[0].name == "mindpattern"
    assert matching[0].message == "unhandled error serving method=GET"


# ---------------------------------------------------------------------------
# llm: prompt, payload shape, boundaries, analyzer selection
# ---------------------------------------------------------------------------


def test_llm_constants_are_cost_contracts():
    from app.services.llm import MAX_LABEL_CHARS, MAX_OCCURRENCES

    assert MAX_LABEL_CHARS == 80
    assert MAX_OCCURRENCES == 100_000
    assert LLMAnalyzer.MAX_ENTRIES == 200
    assert LLMAnalyzer.MAX_TOTAL_CHARS == 150_000


def test_llm_analyzer_defaults_and_url_normalization():
    analyzer = LLMAnalyzer("https://llm.example.com/v1/", "key")
    assert analyzer.model == "gpt-4o-mini"
    assert analyzer.url == "https://llm.example.com/v1"
    # rstrip("/"): a URL that merely ends in other characters is untouched.
    assert LLMAnalyzer("https://llm.example.com/v1X", "k").url == "https://llm.example.com/v1X"


def test_get_enricher_requires_explicit_consent_argument():
    settings = Settings(environment="development")
    settings.llm_url = "https://llm.example.com/v1"
    # Default parameter: no consent argument -> None (deterministic-only),
    # never the LLM. There is no rule-based analyzer to fall back to.
    assert get_enricher(settings) is None


def test_mood_correlation_kind_is_accepted():
    kept = sanitize_pattern(
        {"kind": "mood_correlation", "label": "money", "occurrences": 5, "confidence": 0.4},
        ["money worries today"],
    )
    assert kept is not None
    assert kept.kind == "mood_correlation"


def test_label_of_exactly_80_chars_is_kept():
    kept = sanitize_pattern({"kind": "temporal", "label": "x" * 80}, ["x" * 80])
    assert kept is not None and len(kept.label) == 80


def test_sanitize_defaults_for_missing_occurrences_and_confidence():
    kept = sanitize_pattern({"kind": "temporal", "label": "work"}, ["a work day"])
    assert kept is not None
    assert kept.occurrences == 0
    assert kept.confidence == 0.5


def test_sanitize_keeps_numeric_span_days():
    kept = sanitize_pattern(
        {"kind": "temporal", "label": "work", "detail": {"span_days": 12.0}}, ["a work day"]
    )
    assert kept is not None
    assert kept.detail["span_days"] == 12.0


def _entry(n, text="work", sentiment=0.1):
    from app.services.patterns import JournalEntry

    return JournalEntry(
        text=text, entry_date=date(2026, 7, 1) + timedelta(days=n), sentiment=sentiment
    )


def test_llm_prompt_and_payload_shape_are_pinned():
    analyzer = LLMAnalyzer("https://llm.example.com/v1", "key", model="mini")
    posted = []
    analyzer._post = lambda payload: (
        posted.append(payload)
        or {"choices": [{"message": {"content": json.dumps({"patterns": []})}}]}
    )
    analyzer.extract_patterns([_entry(0, "a work day", sentiment=-0.25)])

    payload = posted[0]
    # 2026-09-16 remediation (D2): generation is bounded.
    assert set(payload) == {"model", "max_tokens", "temperature", "messages"}
    assert payload["max_tokens"] == 512
    assert payload["temperature"] == 0.0
    assert payload["model"] == "mini"
    system, user = payload["messages"]
    assert system["role"] == "system"
    # Tracks the engine round's llm.py: the kind list grew "mood_shift"
    # (2026-09-08, engine agent's _ALLOWED_KINDS). The pin stays an exact
    # string so a prompt mutation still kills a mutant.
    # 2026-09-17 inversion: the prompt now forbids discovery (label-
    # restricted narration of the brain's findings only).
    assert system["content"].startswith("You REFINE deterministic statistical findings")
    assert "never discover new ones" in system["content"]
    assert user["role"] == "user"
    wire = json.loads(user["content"])
    assert wire["findings"] == []
    assert wire["recent_entries"] == [
        {"date": "2026-07-01", "sentiment": -0.25, "text": "a work day"}
    ]


def test_llm_budget_boundary_is_exact():
    """Two entries of 75k chars fill the budget exactly: nothing more is sent,
    and an exhausted budget never appends empty-text entries."""
    analyzer = LLMAnalyzer("https://llm.example.com/v1", "key")
    analyzer._post = lambda payload: {"choices": [{"message": {"content": '{"patterns": []}'}}]}
    corpus = [_entry(i, "w" * 75_000) for i in range(4)]

    posted = []
    analyzer._post = lambda payload: (
        posted.append(payload) or {"choices": [{"message": {"content": '{"patterns": []}'}}]}
    )
    analyzer.extract_patterns(corpus)

    sent_entries = json.loads(posted[0]["messages"][1]["content"])["recent_entries"]
    assert len(sent_entries) == 2
    assert all(item["text"] for item in sent_entries)
    assert sum(len(item["text"]) for item in sent_entries) == 150_000


def test_llm_sends_the_last_entries_within_the_slice_and_budget():
    analyzer = LLMAnalyzer("https://llm.example.com/v1", "key")
    posted = []
    analyzer._post = lambda payload: (
        posted.append(payload) or {"choices": [{"message": {"content": '{"patterns": []}'}}]}
    )
    corpus = [_entry(i, f"entry {i} " + "x" * 700) for i in range(250)]
    analyzer.extract_patterns(corpus)
    sent_entries = json.loads(posted[0]["messages"][1]["content"])["recent_entries"]
    assert len(sent_entries) == 200  # the MAX_ENTRIES slice
    total = sum(len(item["text"]) for item in sent_entries)
    assert total <= 150_000
    # Only the LAST 200 entries (the most recent ones) are considered.
    assert sent_entries[0]["text"].startswith("entry 50 ")


# ---------------------------------------------------------------------------
# patterns: sentence-scan ordering; questions: pool dedup
# ---------------------------------------------------------------------------


def test_recurring_phrase_detection_survives_earlier_short_sentences():
    """The sentence scanner must SKIP sub-minimum sentences and keep scanning,
    not abandon the entry (continue vs break)."""
    from app.services.patterns import analyze as analyze_patterns
    from app.services.patterns import JournalEntry

    long_sentence = "I keep worrying about the same deadline every single week"
    entries = [
        JournalEntry(
            text=f"ok then. {long_sentence}.",  # short sentence first
            entry_date=date(2026, 6, 1) + timedelta(days=i),
        )
        for i in range(9)
    ]
    analysis = analyze_patterns(entries)
    phrases = [p for p in analysis.patterns if p.kind == "recurring_phrase"]
    assert any(long_sentence.lower() == p.label.lower() for p in phrases)


def test_question_pool_dedups_duplicates():
    """build_pool must keep only the FIRST occurrence of any question."""
    from app.services.patterns import Pattern

    temporal = Pattern(
        kind="temporal", label="work", occurrences=6, confidence=0.8, detail={"day": "Sunday"}
    )
    pool = questions_module.build_pool([temporal])
    assert len(pool) == len(set(pool))  # no duplicates survive

    # A pattern kind with no templates contributes nothing; generics fill in.
    unknown = Pattern(kind="mystery", label="x", occurrences=1, confidence=0.1, detail={})
    assert questions_module.build_pool([unknown]) == list(questions_module.GENERIC_QUESTIONS)


# ---------------------------------------------------------------------------
# Schema validation boundaries (schemas.py). Since the 2026-09-07 error
# envelope unification, EVERY error detail is a string with a machine code;
# the pydantic-vs-handler layer distinction is now carried by the message
# text, which the exact-string pins below still assert (a min_length mutant
# still changes which message answers).
# ---------------------------------------------------------------------------


def _is_validation_shaped(detail) -> bool:
    # Envelope shape: a non-empty human string. (Was: isinstance(detail,
    # list) — FastAPI's default list-of-objects detail, removed by the
    # unified {"detail": str, "code": str} envelope.)
    return isinstance(detail, str) and bool(detail)


async def test_register_schema_boundaries(client):
    good_salt = base64.b64encode(b"s" * 16).decode()
    good_verifier = base64.b64encode(b"v" * 32).decode()

    # A short-but-decodable salt passes pydantic (min_length=1) and fails
    # in the handler with the size message; "A" alone is not decodable b64.
    one_char = await client.post(
        "/api/auth/register",
        json={
            "username": "bounds",
            "salt": base64.b64encode(b"s").decode(),
            "verifier": good_verifier,
        },
    )
    assert one_char.status_code == 422
    assert one_char.json()["detail"] == "salt must be exactly 16 bytes"

    one_char_v = await client.post(
        "/api/auth/register",
        json={"username": "bounds", "salt": good_salt, "verifier": base64.b64encode(b"v").decode()},
    )
    assert one_char_v.status_code == 422
    assert one_char_v.json()["detail"] == "verifier must be 32 bytes"

    # At exactly 128 b64 chars the pydantic cap passes and the HANDLER
    # answers (string detail); at 129 the pydantic cap fires (list detail).
    long_salt = base64.b64encode(b"s" * 96).decode()  # 128 chars exactly
    assert len(long_salt) == 128
    at_cap = await client.post(
        "/api/auth/register",
        json={"username": "bounds129a", "salt": long_salt, "verifier": good_verifier},
    )
    assert at_cap.status_code == 422
    assert at_cap.json()["detail"] == "salt must be exactly 16 bytes"
    too_long = await client.post(
        "/api/auth/register",
        json={"username": "bounds129b", "salt": long_salt + "A", "verifier": good_verifier},
    )
    assert too_long.status_code == 422
    assert _is_validation_shaped(too_long.json()["detail"])

    # A 65-char verifier trips the cap; 64 is fine at the pydantic layer.
    v64 = base64.b64encode(b"v" * 48).decode()  # 64 chars
    assert len(v64) == 64
    v65 = v64 + "A"
    over_v = await client.post(
        "/api/auth/register",
        json={"username": "boundsv", "salt": good_salt, "verifier": v65},
    )
    assert over_v.status_code == 422
    assert _is_validation_shaped(over_v.json()["detail"])

    # Username: pattern-anchored, 1..128 chars.
    bad_name = await client.post(
        "/api/auth/register",
        json={"username": "!!not-a-user!!", "salt": good_salt, "verifier": good_verifier},
    )
    assert bad_name.status_code == 422
    assert _is_validation_shaped(bad_name.json()["detail"])

    # Register usernames follow the 3..64 pattern.
    min_ok = await client.post(
        "/api/auth/register",
        json={"username": "abc", "salt": good_salt, "verifier": good_verifier},
    )
    assert min_ok.status_code == 201
    too_short = await client.post(
        "/api/auth/register",
        json={"username": "ab", "salt": good_salt, "verifier": good_verifier},
    )
    assert too_short.status_code == 422
    assert _is_validation_shaped(too_short.json()["detail"])

    # Salt LOOKUP deliberately accepts any 1..128-char probe (no pattern):
    # a 422 for hostile strings would be an account-existence oracle.
    short_lookup = await client.post("/api/auth/salt", json={"username": "a"})
    assert short_lookup.status_code == 200
    long_lookup = await client.post("/api/auth/salt", json={"username": "u" * 128})
    assert long_lookup.status_code == 200
    over_lookup = await client.post("/api/auth/salt", json={"username": "u" * 129})
    assert over_lookup.status_code == 422
    assert _is_validation_shaped(over_lookup.json()["detail"])


async def test_entry_schema_boundaries(client):
    emu = ClientEmulator("entrybounds", "pw-entry-bounds")
    await emu.register(client)

    # 1-char blob reaches the handler's base64 branch.
    one_char = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": "eb-1", "blob": "A", "entry_date": TODAY.isoformat()},
    )
    assert one_char.status_code == 422
    assert one_char.json()["detail"] == "blob must be base64"

    # client_entry_id pattern: 1-64 chars of [A-Za-z0-9_-].
    bad_id = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "!!bad!!",
            "blob": base64.b64encode(b"z" * 40).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert bad_id.status_code == 422
    assert _is_validation_shaped(bad_id.json()["detail"])

    ok_64 = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "a" * 64,
            "blob": base64.b64encode(b"z" * 40).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert ok_64.status_code == 201
    over_64 = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "a" * 65,
            "blob": base64.b64encode(b"z" * 40).decode(),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert over_64.status_code == 422
    assert _is_validation_shaped(over_64.json()["detail"])

    # The blob b64 cap is inclusive: 1_500_000 chars is accepted...
    huge = base64.b64encode(b"b" * 1_125_000).decode()
    assert len(huge) == 1_500_000
    at_cap = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": "eb-huge", "blob": huge, "entry_date": TODAY.isoformat()},
    )
    assert at_cap.status_code == 201
    # ...and one character over is a pydantic 422 (list-shaped detail).
    capped = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={"client_entry_id": "eb-huge2", "blob": huge + "A", "entry_date": TODAY.isoformat()},
    )
    assert capped.status_code == 422
    assert _is_validation_shaped(capped.json()["detail"])


async def test_single_character_fields_reach_the_handlers(client):
    """A 1-char field passes pydantic (min_length=1) everywhere; the handler
    then answers with its own STRING detail — under min_length=2 mutants the
    answer becomes a pydantic LIST instead."""
    from tests.test_insights_api import seed_corpus  # noqa: F401  (ordering)

    # Register: salt and verifier.
    r1 = await client.post(
        "/api/auth/register",
        json={
            "username": "singlechar",
            "salt": "A",
            "verifier": base64.b64encode(b"v" * 32).decode(),
        },
    )
    assert r1.status_code == 422
    assert r1.json()["detail"] == "salt and verifier must be base64"

    emu = ClientEmulator("singlechar2", "pw-single-char-2")
    await emu.register(client)
    r2 = await client.post(
        "/api/auth/register",
        json={
            "username": "singlechar2b",
            "salt": emu.salt_b64,
            "verifier": "A",
        },
    )
    assert r2.status_code == 422
    assert r2.json()["detail"] == "salt and verifier must be base64"

    # Login verifier: the handler deliberately swallows the decode error and
    # burns CPU -> flat 401 (never 422; a shape change betrays a min_length
    # mutant).
    r3 = await client.post(
        "/api/auth/login",
        json={
            "username": emu.username,
            "verifier": "A",
        },
    )
    assert r3.status_code == 401
    assert r3.json()["detail"] == "invalid credentials"

    # Account deletion and LLM consent verifiers: authenticated requests with
    # a bad proof are 403 (since 2026-09-07; 401 means "session expired").
    r4 = await client.request(
        "DELETE",
        "/api/account",
        headers=emu.headers,
        json={"verifier": "A"},
    )
    assert r4.status_code == 403
    assert r4.json()["detail"] == "invalid credentials"

    r5 = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": "A"},
    )
    assert r5.status_code == 403
    assert r5.json()["detail"] == "invalid credentials"

    # Register username: 1 char passes pydantic? No — the pattern (3..64)
    # rejects it, list-shaped; a 3-char name is accepted.
    r6 = await client.post(
        "/api/auth/register",
        json={
            "username": "a",
            "salt": emu.salt_b64,
            "verifier": base64.b64encode(b"v" * 32).decode(),
        },
    )
    assert r6.status_code == 422
    assert _is_validation_shaped(r6.json()["detail"])


async def test_verifier_and_username_caps_on_every_schema(client):
    emu = ClientEmulator("vcaps", "pw-v-caps")
    await emu.register(client)
    v65 = base64.b64encode(b"v" * 48).decode() + "A"  # 65 chars, valid b64

    # Login: pattern-anchored username and capped verifier.
    bad_format = await client.post(
        "/api/auth/login",
        json={"username": "!!bad!!", "verifier": emu.auth_key_b64},
    )
    assert bad_format.status_code == 422
    assert _is_validation_shaped(bad_format.json()["detail"])

    long_login = await client.post(
        "/api/auth/login",
        json={"username": emu.username, "verifier": v65},
    )
    assert long_login.status_code == 422
    assert _is_validation_shaped(long_login.json()["detail"])

    # LLM consent PUT: capped verifier.
    long_consent = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": v65},
    )
    assert long_consent.status_code == 422
    assert _is_validation_shaped(long_consent.json()["detail"])

    # Account deletion: capped verifier.
    long_delete = await client.request(
        "DELETE",
        "/api/account",
        headers=emu.headers,
        json={"verifier": v65},
    )
    assert long_delete.status_code == 422
    assert _is_validation_shaped(long_delete.json()["detail"])


async def test_processing_key_schema_boundaries(client):
    emu = ClientEmulator("keybounds", "pw-key-bounds")
    await emu.register(client)

    one_char = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": "A"},
    )
    assert one_char.status_code == 422
    assert one_char.json()["detail"] == "data_key must be base64"

    # 65-char data key: the pydantic cap (exactly 44 since 2026-09-07 —
    # b64(32 bytes)) fires before the size handler.
    k48 = base64.b64encode(b"k" * 48).decode()
    assert len(k48) == 64
    over = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": k48 + "A"},
    )
    assert over.status_code == 422
    assert _is_validation_shaped(over.json()["detail"])


async def test_entries_limit_of_one_is_valid(client):
    emu = ClientEmulator("limitone", "pw-limit-one")
    await emu.register(client)
    await emu.create_entry(client, "single", TODAY, client_entry_id="lo-1")
    page = await client.get("/api/entries?limit=1", headers=emu.headers)
    assert page.status_code == 200
    assert len(page.json()) == 1


def test_insights_response_default_blob_is_none():
    from app.schemas import InsightsResponse

    payload = InsightsResponse(phase="baseline", active_days=1, streak=0, days_remaining=29)
    assert payload.blob is None


# ---------------------------------------------------------------------------
# Rate limiter internals: bucket names and the Retry-After floor
# ---------------------------------------------------------------------------


async def test_keyed_limit_buckets_use_the_username_namespaced_keys(client, app):
    emu = ClientEmulator("keyednames", "pw-keyed-names")
    response = await client.post(
        "/api/auth/register",
        json={"username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 201
    counter: FixedWindowCounter = app.state.rate_counter
    # A SUCCESSFUL register does NOT consume the per-username bucket — only
    # 409 conflicts count, so probing a free name cannot 429 its legitimate
    # first registrant.
    keys = set(counter._hits)
    assert not any(k.startswith(f"register-name:{emu.username}") for k in keys), keys

    # Login has no per-username deny bucket: an attacker rotating source IPs
    # must not be able to spend a victim's failure budget and lock them out.
    await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": emu.auth_key_b64}
    )
    keys = set(counter._hits)
    assert not any(k.startswith(f"login-name:{emu.username}") for k in keys), keys

    # A FAILED verification also must not create a name-scoped lockout.
    wrong = base64.b64encode(b"\x11" * 32).decode()
    await client.post("/api/auth/login", json={"username": emu.username, "verifier": wrong})
    keys = set(counter._hits)
    assert not any(k.startswith(f"login-name:{emu.username}") for k in keys), keys

    # And a 409 register conflict does consume the register-name bucket.
    response = await client.post(
        "/api/auth/register",
        json={"username": emu.username, "salt": emu.salt_b64, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 409
    keys = set(counter._hits)
    assert any(k.startswith(f"register-name:{emu.username}") for k in keys), keys


def test_retry_after_header_floors_at_exactly_one_second():
    from app.cache import _limit_response

    assert _limit_response(1).headers["Retry-After"] == "1"
    assert _limit_response(7).headers["Retry-After"] == "7"


# ---------------------------------------------------------------------------
# Baseline storage isolation: nothing is persisted pre-threshold
# ---------------------------------------------------------------------------


async def test_baseline_recompute_writes_no_insight_rows(client, app):
    emu = ClientEmulator("norows", "pw-no-rows")
    await emu.register(client)
    from tests.test_insights_api import seed_corpus

    await seed_corpus(client, emu, days=29)
    token = await emu.open_processing_session(client)
    await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(Insight).where(Insight.user_id == emu.user_id)))
            .scalars()
            .all()
        )
    assert rows == []


async def test_threshold_recompute_without_patterns_stores_nothing(client, app):
    """Post-threshold but no qualifying pattern: question_stored False,
    patterns_stored 0, and nothing written."""
    emu = ClientEmulator("nopatterns", "pw-no-patterns")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    # 31 distinct one-off texts: no theme hits 4 mentions, no repeats.
    for i, day in enumerate(daterange(31, TODAY)):
        await emu.create_entry(client, f"unique day {i}", day, client_entry_id=f"np-{i}")

    result = await emu.recompute(client)
    assert result["phase"] == "insight"
    assert result["question_stored"] is False
    assert result["patterns_stored"] == 0

    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(Insight).where(Insight.user_id == emu.user_id)))
            .scalars()
            .all()
        )
    assert not any(r.kind == "question" for r in rows)


async def test_old_question_rows_survive_a_new_recompute(client, app):
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator("oldq", "pw-old-q")
    await emu.register(client)
    await seed_corpus(client, emu, days=35)
    await emu.recompute(client)

    stale_date = TODAY - timedelta(days=5)
    async with app.state.sessionmaker() as session:
        session.add(
            Insight(user_id=emu.user_id, kind="question", for_date=stale_date, blob=b"history")
        )
        await session.commit()

    await emu.recompute(client)

    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(Insight).where(Insight.user_id == emu.user_id)))
            .scalars()
            .all()
        )
    dates = {(r.kind, r.for_date) for r in rows}
    assert ("question", stale_date) in dates  # history is not deleted
    assert ("question", TODAY) in dates


# ---------------------------------------------------------------------------
# LLM budget boundary: exactly one char of budget left
# ---------------------------------------------------------------------------


def test_llm_budget_exhausts_mid_entry_with_one_char_left():
    analyzer = LLMAnalyzer("https://llm.example.com/v1", "key")
    posted = []
    analyzer._post = lambda payload: (
        posted.append(payload) or {"choices": [{"message": {"content": '{"patterns": []}'}}]}
    )
    # 74_999 + 75_000 = 149_999; one char of budget remains for entry 3.
    corpus = [
        _entry(0, "a" * 74_999),
        _entry(1, "b" * 75_000),
        _entry(2, "cccccccccc"),
        _entry(3, "dddddddddd"),
    ]
    analyzer.extract_patterns(corpus)
    sent = json.loads(posted[0]["messages"][1]["content"])["recent_entries"]
    assert len(sent) == 3
    assert len(sent[2]["text"]) == 1  # exactly the remaining budget
    assert sent[2]["text"] == "c"


# ---------------------------------------------------------------------------
# Tokens, enclave, account, meta, questions: final message pins
# ---------------------------------------------------------------------------


def test_non_ascii_token_body_is_malformed():
    with pytest.raises(TokenError, match=r"^malformed token$"):
        verify_token("césar.sig", "secret")


async def test_delete_account_with_wrong_but_valid_verifier_detail(client):
    emu = ClientEmulator("wrongver", "pw-wrong-ver")
    await emu.register(client)
    wrong = base64.b64encode(b"w" * 32).decode()
    response = await client.request(
        "DELETE", "/api/account", headers=emu.headers, json={"verifier": wrong}
    )
    # 403 verification_failed since 2026-09-07: the session is valid, the
    # password proof is not — 401 means "session expired" to clients.
    assert response.status_code == 403
    assert response.json()["detail"] == "invalid credentials"


async def test_meta_payload_is_exact(client):
    response = await client.get("/api/meta")
    assert response.status_code == 200
    assert response.json() == {
        # api_version added with the /api/v1 mount (2026-09-07).
        "version": "1.0.0",
        "api_version": "v1",
        "unlock_days": 30,
        "llm_available": False,
        "llm_provider_name": None,
        "llm_data_retention": None,
        "llm_policy_fingerprint": None,
        "sharing_available": True,
        # v2 (2026-09-20, audit H-14): the disclosure copy now names
        # measures + caseload summaries.
        "sharing_disclosure_version": "v2",
        "sharing_access_log_retention_days": 730,
    }


def test_enclave_key_mismatch_message_is_pinned():
    from app.security.enclave import InMemoryKeyStore, KeyNotFound

    store = InMemoryKeyStore()
    token = store.create(b"k" * 32, ttl_seconds=60, owner="alice", now=0.0)
    with pytest.raises(KeyNotFound, match=r"^processing session belongs to another user$"):
        store.get(token, owner="bob", now=1.0)


def test_question_pool_dedups_identically_rendered_patterns():
    from app.services.patterns import Pattern

    same_a = Pattern(
        kind="temporal", label="work", occurrences=6, confidence=0.9, detail={"day": "Sunday"}
    )
    same_b = Pattern(
        kind="temporal", label="work", occurrences=5, confidence=0.8, detail={"day": "Sunday"}
    )
    pool = questions_module.build_pool([same_a, same_b])
    assert len(pool) == len(set(pool))
    single = questions_module.build_pool([same_a])
    assert pool == single  # the duplicate contributed nothing


# ---------------------------------------------------------------------------
# Middleware: body-count boundaries observed through a SILENT app (a
# responding app masks the 413 — its answer wins).
# ---------------------------------------------------------------------------


async def _silent_call(max_body: int, incoming) -> list:
    async def silent(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return

    wrapped = HardeningMiddleware(silent, max_body_bytes=max_body)
    return await _call_asgi(wrapped, _http_scope([]), incoming)


async def test_streamed_body_exactly_at_cap_is_never_rejected():
    sent = await _silent_call(10, [{"type": "http.request", "body": b"0" * 10, "more_body": False}])
    assert sent == []  # no overflow, so no synthesized response


async def test_bodyless_chunks_count_zero_bytes():
    sent = await _silent_call(
        3,
        [
            {"type": "http.request", "more_body": True},
            {"type": "http.request", "body": b"123", "more_body": False},
        ],
    )
    assert sent == []


async def test_streamed_body_one_over_cap_is_rejected():
    sent = await _silent_call(10, [{"type": "http.request", "body": b"0" * 11, "more_body": False}])
    assert sent and sent[0]["status"] == 413


# ---------------------------------------------------------------------------
# Patterns: skip-but-keep-scanning (continue, not break)
# ---------------------------------------------------------------------------


def test_phrase_scan_skips_rare_sentences_and_finds_later_ones():
    from app.services.patterns import JournalEntry
    from app.services.patterns import analyze as analyze_patterns

    rare = "this sentence shows up twice only"
    recurring = "the same long deadline worry keeps returning every week"
    entries = [
        JournalEntry(
            text=f"{rare}. {recurring}." if i < 2 else f"{recurring}.",
            entry_date=date(2026, 6, 1) + timedelta(days=i),
        )
        for i in range(8)
    ]
    analysis = analyze_patterns(entries)
    labels = [p.label.lower() for p in analysis.patterns if p.kind == "recurring_phrase"]
    assert recurring in labels


def test_theme_scan_skips_rare_themes_and_finds_later_ones():
    from app.services.patterns import JournalEntry
    from app.services.patterns import analyze as analyze_patterns

    """'food' (alphabetically before 'work') appears only twice and must be
    SKIPPED, not abort the scan that later finds the Sunday-work pattern."""
    entries = []
    for i, day in enumerate(daterange(35, TODAY)):
        if day.weekday() == 6:  # Sunday: work mentions
            text = "busy shift at work with a deadline"
        else:
            text = "quiet day reading outside"
        if i < 2:
            text += " and feeling hungry"  # rare 'food' theme, 2 mentions
        entries.append(JournalEntry(text=text, entry_date=day))
    analysis = analyze_patterns(entries)
    temporal = [p for p in analysis.patterns if p.kind == "temporal"]
    assert any(p.label == "work" for p in temporal)



# ---------------------------------------------------------------------------
# Pins from test_mutation_pins_2026_09_18.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
CALM = "felt calm and grateful today"
T0_R1 = date(2026, 9, 4)


def _trivial_effect_corpus() -> tuple[list[JournalEntry], JournalEntry]:
    """Sundays carry 'work' with a tight, low mood tag; every other day is
    calm text with a wide, noisy tag. Result (measured, deterministic seed):
    reported mood_delta ≈ 0.25 (clears MOOD_MIN_DELTA) while |d| ≈ 0.42
    (under the 0.5 floor) — a statistically detectable but practically
    trivial separation that ONLY the effect-size gate refuses."""
    rng = random.Random(5)
    days = [T0_R1 - timedelta(days=279 - i) for i in range(280)]

    def mood(theme_day: bool) -> float:
        center, width = (-0.25, 0.12) if theme_day else (0.03, 0.65)
        return max(-1.0, min(1.0, rng.gauss(center, width)))

    entries = [
        JournalEntry(
            "anxious about work" if d.weekday() == 6 else CALM,
            d,
            sentiment=mood(d.weekday() == 6),
        )
        for d in days
    ]
    extra = JournalEntry("anxious about work", T0_R1 + timedelta(days=1), sentiment=mood(True))
    return entries, extra


def _surface_after_two_qualification_days(
    entries: list[JournalEntry], extra: JournalEntry
) -> list[Pattern]:
    first = brain.update(brain.load_state(None), entries, T0_R1)
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        entries + [extra],
        T0_R1 + timedelta(days=1),
    )
    return list(second.surfaced)


class TestEffectSizeFloor:
    def test_trivial_standardized_effect_never_surfaces(self):
        """A5: MOOD_MIN_EFFECT = 0.0 survived the ENTIRE suite. The only
        prior pin (test_effect_and_significance_gates) asserts the card's
        detail against the constant itself — true for any constant. This
        corpus clears the delta gate with a |d| well under the floor and
        must earn no mood_correlation card, even after a second,
        independently-qualifying day."""
        entries, extra = _trivial_effect_corpus()
        surfaced = _surface_after_two_qualification_days(entries, extra)
        assert all(not (p.kind == "mood_correlation" and p.label == "work") for p in surfaced)

    def test_trivial_effect_corpus_canary(self):
        """Same corpus with the floor relaxed to 0.0 MUST surface the card —
        this is what proves the corpus still discriminates (and what the
        A5 mutant does to production code)."""
        entries, extra = _trivial_effect_corpus()
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(brain, "MOOD_MIN_EFFECT", 0.0)
            surfaced = _surface_after_two_qualification_days(entries, extra)
        work = [p for p in surfaced if p.kind == "mood_correlation" and p.label == "work"]
        assert work, "corpus lost its discriminating power — recalibrate it"
        assert work[0].detail["mood_delta"] >= brain.MOOD_MIN_DELTA
        assert abs(work[0].detail["cohens_d"]) < 0.5

    def test_floor_value_is_pinned(self):
        """The 0.5 Cohen's d floor is a product decision (RESEARCH.md):
        smaller effects are honest noise at journal scale. Changes must be
        deliberate, not a silent constant edit — which is exactly mutant A5."""
        assert brain.MOOD_MIN_EFFECT == 0.5


class TestNarrativeClinicalBoundary:
    def test_narrative_rejects_diagnosis_language(self):
        """D1: deleting the diagnosis words from _CLINICAL_TERMS survived —
        every existing narrative input overlapped another rule
        ('medication', domains, phones). These inputs trip ONLY the
        clinical-term check: no digits, no contacts, no crisis echo."""
        clean = llm._clean_narrative
        assert clean("a doctor would diagnose this pattern quickly") is None
        assert clean("you are clearly diagnosed with something common") is None
        assert clean("this reads like a textbook diagnosis of low mood") is None

    def test_narrative_rejects_digits_alone(self):
        """D2: the digit ban was only exercised through inputs that also
        contained phones/domains/medication wording. A bare minted statistic
        must die on the digit rule alone."""
        clean = llm._clean_narrative
        assert clean("your darker Saturdays came to 87 percent of them") is None
        assert clean("mood dipped for 14 of the last 30 days") is None


class TestQuestionInterlockLayers:
    def test_label_tripwire_fires_without_the_sensitive_flag(self):
        """E3: disabling the label tripwire of pattern_is_sensitive survived
        the full suite — the composite outcome stayed safe through the
        'sensitive' flag (brain-side) and the belt-and-braces filter on
        rendered questions. But the label tripwire is the layer that covers
        patterns arriving WITHOUT the flag (LLM extras, legacy payloads);
        it earns its own pin. Defense in depth only counts if every layer
        is individually testable."""
        unflagged = Pattern("recurring_phrase", "want to disappear", 4, 0.4, {})
        assert questions.pattern_is_sensitive(unflagged) is True

    def test_unflagged_crisis_label_never_renders_a_question(self):
        """End-to-end form of the same pin: an unflagged crisis-adjacent
        pattern must contribute no rendered question to the pool."""
        unflagged = Pattern("recurring_phrase", "want to disappear", 4, 0.4, {})
        pool = questions.build_pool([unflagged])
        assert all("disappear" not in q for q in pool)



# ---------------------------------------------------------------------------
# Pins from test_mutation_pins_2026_09_18b.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
T0_R2 = date(2026, 6, 1)


def _days(n: int, start: date = T0_R2) -> list[date]:
    return [start + timedelta(days=i) for i in range(n)]


# ---------------------------------------------------------------------------
# G4/G5: the EWMA control chart's honesty parameters
# ---------------------------------------------------------------------------


class TestEwmaChartPins:
    def _update_twice(self, sentiments: list[float], start: date = T0_R2):
        """mood_shift is a WINDOW_STAT kind: it surfaces only after a second
        qualification day >= 2 calendar days out (the replication gate), so
        every chart pin recomputes twice."""
        first = [
            JournalEntry("ordinary day notes", d, sentiment=s)
            for d, s in zip(_days(len(sentiments), start), sentiments)
        ]
        res1 = brain.update(brain.fresh_state(), first, start + timedelta(days=len(sentiments)))
        tail_days = _days(2, start + timedelta(days=len(sentiments) + 1))
        second = first + [
            JournalEntry("ordinary day notes", d, sentiment=sentiments[-1]) for d in tail_days
        ]
        res2 = brain.update(res1.new_state, second, tail_days[-1] + timedelta(days=1))
        return res2

    def test_autocorrelated_stationary_series_does_not_fire(self):
        """G4 pin: a stationary AR-like series with strong carryover must not
        fire the chart — the limits are inflated by (1+phi)/(1-phi) precisely
        so ordinary autocorrelated mood is not a 'shift'.

        Corpus (tuned and verified discriminating): a single smooth hump
        baseline (lag-1 phi ~= 0.81, well above the 0.35 inflation trigger,
        sigma ~= 0.26), a quiet continuation, then a moderate elevated run
        (+0.5, ~1.6 sigma). Without the inflation the run clears the limits
        at p ~= 1e-6 and surfaces; the honest chart must stay silent.
        """
        hump = [0.10, 0.25, 0.40, 0.30, 0.15, -0.05, -0.25, -0.40, -0.25, -0.05]
        continuation = [0.05, 0.20, 0.05, -0.15, 0.05]
        elevated = [0.5] * 8
        result = self._update_twice(hump + continuation + elevated)
        shifts = [p for p in result.surfaced if p.kind == "mood_shift"]
        assert shifts == [], [s.detail for s in shifts]

    def test_single_beyond_limit_spike_is_not_a_shift(self):
        """G5 pin: MOOD_SHIFT_RUN is 3 — one beyond-limit point in the recent
        tail (a transient spike at the very end) must not surface a card.

        Corpus: flat baseline (sigma from mild variation), quiet run, one
        large spike on the final day. The spike's EWMA crosses the limit for
        exactly one point; the spike is repeated on the replication days so
        the second qualification is not what silences it — the run rule is.
        """
        baseline = [
            0.1,
            -0.1,
            0.2,
            -0.2,
            0.05,
            -0.05,
            0.15,
            -0.15,
            0.1,
            -0.1,
            0.2,
            -0.2,
            0.0,
            0.1,
            -0.1,
        ] + [0.0] * 8
        result = self._update_twice(baseline + [2.5])
        shifts = [p for p in result.surfaced if p.kind == "mood_shift"]
        assert shifts == [], [s.detail for s in shifts]


# ---------------------------------------------------------------------------
# G14/G15: lifecycle boundaries are exact
# ---------------------------------------------------------------------------


def _store_with_pattern(last_qualified: str, state_name: str) -> dict:
    store = brain.fresh_state()
    record = StoredPattern(
        pid="temporal:work",
        kind="temporal",
        label="work",
        first_seen=last_qualified,
        last_seen=last_qualified,
        first_qualified=last_qualified,
        last_qualified=last_qualified,
        occurrences=12,
        state=state_name,
        qualification_days=[last_qualified],
        evidence_dates=[last_qualified],
        feedback={},
        detail={"day": "Sunday"},
    )
    store["patterns"][record.pid] = record
    # Round-trip so _merge_lifecycle sees a normalized store, exactly as a
    # recompute would after loading the encrypted blob.
    return load_state(dump_state(store))


class TestLifecycleBoundaries:
    def test_active_pattern_survives_exactly_seven_stale_days(self):
        """G14 pin: GRACE_DAYS is 7 — at exactly 7 stale days the pattern is
        still active; fading starts only past 7 (a ->6 mutant fades early)."""
        last = "2026-08-01"
        for stale, expect_fading in ((7, False), (8, True)):
            store = _store_with_pattern(last, "confirmed")
            brain._merge_lifecycle(store, [], date.fromisoformat(last) + timedelta(days=stale))
            assert store["patterns"]["temporal:work"].state == (
                "fading" if expect_fading else "confirmed"
            ), f"stale={stale}"

    def test_fading_pattern_archives_only_past_forty_five_days(self):
        """G15 pin: ARCHIVE_DAYS is 45 — at exactly 45 stale days the pattern
        is still fading; archival starts only past 45 (a ->44 mutant
        archives a day early)."""
        last = "2026-08-01"
        for stale, expect_archived in ((45, False), (46, True)):
            store = _store_with_pattern(last, "fading")
            brain._merge_lifecycle(store, [], date.fromisoformat(last) + timedelta(days=stale))
            assert store["patterns"]["temporal:work"].state == (
                "archived" if expect_archived else "fading"
            ), f"stale={stale}"


# ---------------------------------------------------------------------------
# J2: crisis-adjacent surfaced cards carry detail.sensitive
# ---------------------------------------------------------------------------


class TestSensitiveFlagPin:
    def test_suppress_tier_rumination_surfaces_non_quoting(self):
        """J2 pin: a recurring negative cluster whose label is suppress-tier
        crisis language must surface with detail.sensitive — the mobile app
        and portal render the non-quoting card keyed off this flag."""
        phrase = "i can't go on anymore"  # dialog tier (therefore suppress tier)
        assert crisis.matches_suppress(phrase)
        days = _days(12)  # direct-measurement kinds surface at STRONG_EVIDENCE=10 occurrences
        entries = [
            JournalEntry(
                f"{phrase} and everything feels heavy and hopeless and unbearable",
                d,
                sentiment=-0.8,
            )
            for d in days
        ]
        result = brain.update(brain.fresh_state(), entries, days[-1] + timedelta(days=1))
        surfaced = [p for p in result.surfaced if p.kind in ("rumination", "recurring_phrase")]
        assert surfaced, "corpus must surface the recurring cluster"
        flagged = [p for p in surfaced if p.detail.get("sensitive")]
        assert flagged, [(p.kind, p.label, p.detail.get("sensitive")) for p in surfaced]

    def test_label_branch_of_sensitivity_flag(self):
        """J2 pin (the label branch): a record whose LABEL is suppress-tier
        is sensitive even when the stored variant list cannot catch it —
        the representative must not be the only unchecked copy. The variants
        check subsumes the label check whenever the representative survives
        the variants[:3] cap; this is the record shape where only the label
        branch sees it."""
        record = StoredPattern(
            pid="rumination:x",
            kind="rumination",
            label="i can't go on anymore",
            first_seen="2026-08-01",
            last_seen="2026-08-12",
            first_qualified="2026-08-12",
            last_qualified="2026-08-12",
            occurrences=12,
            state="emerging",
            qualification_days=["2026-08-12"],
            evidence_dates=["2026-08-01"],
            feedback={},
            # Benign variants only: the variants branch cannot fire here.
            detail={"variants": ["everything feels heavy and slow", "so tired of everything"]},
        )
        assert crisis.matches_suppress(record.label)
        assert not any(crisis.matches_suppress(v) for v in record.detail["variants"])
        assert brain._record_is_sensitive(record) is True


# ---------------------------------------------------------------------------
# K1/K4: fail-closed boot gates
# ---------------------------------------------------------------------------


class TestBootGates:
    def test_uppercase_environment_hits_production_gates(self):
        """K1 pin: environment values normalize before any comparison. The
        security direction is the DEV side — 'DEVELOPMENT'/' Development '
        are the developer's OPT-IN to dev gates; without normalization a
        case typo silently hits the production gates instead (fail-closed,
        but it means normalization is dead code and the next check built on
        the comparison inherits the typo)."""
        for env in ("DEVELOPMENT", " Development ", "development"):
            s = Settings(environment=env)  # dev secret allowed exactly here
            assert s.environment == "development", env
        # ...and no production-adjacent spelling may reach the dev gates.
        for env in ("PRODUCTION", " Production ", "prod", "staging"):
            with pytest.raises(RuntimeError, match="MINDPATTERN_TOKEN_SECRET"):
                Settings(environment=env)

    def test_production_app_mounts_no_docs(self):
        """K4 pin: /docs and /openapi.json exist only in development. The
        FastAPI attributes are set at construction, before any lifespan
        work, so construction alone is the honest pin."""
        settings = Settings(
            environment="production",
            token_secret="x" * 48,
            database_url="postgresql+asyncpg://u:p@localhost:5432/mindpattern_test",
        )
        app = create_app(settings)  # no lifespan: construction must not touch the DB
        assert app.docs_url is None
        assert app.openapi_url is None


# ---------------------------------------------------------------------------
# L2: the poor-sleep split is against the user's OWN median
# ---------------------------------------------------------------------------


class TestOwnMedianSleepSplit:
    def test_split_is_strictly_below_the_users_own_median(self):
        """L2 pin: a user rating every night 1 or 2 (median 1.5) has poor
        nights ONLY on the 1s. A fixed 3.0 population norm would mark every
        night poor — the within-person promise, pinned at the theme-day set
        (the candidate mood-correlation record's evidence dates)."""
        days = _days(20)  # the mood tie needs >=8 entries per side (poor vs not)
        entries = []
        for i, d in enumerate(days):
            rating = 1 if i % 2 == 0 else 2
            # Poor nights read lower, decent nights fine — the mood tie the
            # channel exists to find (and the reason the record lands in the
            # store at all: unqualified candidates are never merged).
            mood = -0.8 if rating == 1 else 0.5
            entries.append(
                JournalEntry("quiet notes and tea", d, sentiment=mood, sleep_quality=rating)
            )
        result = brain.update(brain.fresh_state(), entries, days[-1] + timedelta(days=1))
        record = result.new_state["patterns"].get("mood_correlation:poor sleep")
        assert record is not None, "the poor-sleep theme must be analyzed"
        expected = {d.isoformat() for d in days[0::2]}  # the rating-1 nights
        assert set(record.evidence_dates) == expected, (
            "poor-sleep days must be exactly the nights rated strictly below "
            "THIS user's median (1.5), not below any population norm"
        )



# ---------------------------------------------------------------------------
# Pins from test_mutation_pins_2026_09_19.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
# --- O2: suspended account must be refused on routes without a fresh re-check


async def test_suspended_account_is_refused_on_insights_reads(client, app):
    """The /entries routes re-check is_active under their lifecycle fence;
    GET /insights has no such re-check — require_user itself must refuse a
    deactivated account there. (Kills mutant O2.)"""
    from sqlalchemy import update

    from app.models import User

    emu = ClientEmulator("pins-o2", "pw-pins-o2")
    await emu.register(client)
    await emu.create_entry(client, "an ordinary day", TODAY, client_entry_id="pins-o2-e1")

    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()

    response = await client.get("/api/insights", headers=emu.headers)
    assert response.status_code == 401
    assert response.json()["code"] == "unauthorized"


# --- O10: therapist registration honors the enrollment-token gate


async def test_therapist_registration_requires_the_enrollment_token(client, settings):
    """When an enrollment token is configured, a wrong or absent
    X-Therapist-Enrollment-Token must answer a flat 404; the right one
    registers. (Kills mutant O10.)"""
    settings.therapist_sharing_enabled = True
    settings.therapist_enrollment_token = "t" * 32

    def payload(emu: TherapistEmulator) -> dict:
        return {
            "username": emu.username,
            "salt": emu.salt_b64,
            "verifier": emu.auth_key_b64,
            "display_name": emu.display_name,
            "wrap_pub_key": emu.wrap_pub_key,
            "wrap_key_blob": emu.wrap_key_blob_b64(),
        }

    wrong = TherapistEmulator("pins-o10-wrong", "pw")
    no_header = await client.post("/api/therapist/register", json=payload(wrong))
    assert no_header.status_code == 404
    assert no_header.json()["code"] == "not_found"

    bad_header = await client.post(
        "/api/therapist/register",
        json=payload(TherapistEmulator("pins-o10-bad", "pw")),
        headers={"X-Therapist-Enrollment-Token": "wrong-token-of-at-least-some-length"},
    )
    assert bad_header.status_code == 404

    right = TherapistEmulator("pins-o10-right", "pw")
    accepted = await client.post(
        "/api/therapist/register",
        json=payload(right),
        headers={"X-Therapist-Enrollment-Token": "t" * 32},
    )
    assert accepted.status_code == 201, accepted.text


# --- P5: paginated entry order must be fully deterministic


async def test_entry_page_ordering_carries_the_id_tiebreak(client, app):
    """The page METADATA query (the one that sizes rows with LENGTH and
    paginates) must order by (entry_date, received_at, id): without the id
    tiebreak, rows sharing date+receipt time can swap across pages. The
    later blob-fetch query keeps its own full ordering, so only the
    metadata query distinguishes the mutant. (Kills mutant P5.)"""
    emu = ClientEmulator("pins-p5", "pw-pins-p5")
    await emu.register(client)
    await emu.create_entry(client, "one", TODAY, client_entry_id="pins-p5-a")
    await emu.create_entry(client, "two", TODAY, client_entry_id="pins-p5-b")

    statements: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    response = await client.get("/api/entries", headers=emu.headers)
    assert response.status_code == 200

    lowered = [s.lower() for s in statements]
    metadata_queries = [
        q for q in lowered if "length(" in q and "from entries" in q and "order by" in q
    ]
    assert metadata_queries, statements
    for query in metadata_queries:
        ordering = query.split("order by", 1)[1]
        assert "entry_date" in ordering and "received_at" in ordering and "id" in ordering, query


# --- P6 (REPURPOSED 2026-09-20, audit H-12): a same-day recompute must
# NOT rewrite the stored question blob. The old pin asserted the opposite
# (fresh ciphertext on every same-day recompute) and the audit proved that
# behavior breaks "one question per day, stable within the day" — a
# recompute after an evening entry served a different question than the one
# the user may already have answered. The day's question is now pinned on
# first write; the pin asserts byte-identical stability.


async def test_same_day_recompute_preserves_the_question_blob(client):
    """Audit H-12: recompute with an extra pattern -> SAME question for the
    same day. The rotation pool changing underneath must never change an
    already-served (possibly already-answered) question."""
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator("pins-p6", "pw-pins-p6")
    await emu.register(client)
    await seed_corpus(client, emu, days=32)
    await emu.recompute(client)
    first = (await client.get("/api/questions/today", headers=emu.headers)).json()["blob"]
    assert first

    await emu.create_entry(
        client, "a late evening note about sleep", TODAY, client_entry_id="pins-p6-extra"
    )
    await emu.recompute(client)
    second = (await client.get("/api/questions/today", headers=emu.headers)).json()["blob"]

    assert second == first, "same-day recompute changed the pinned daily question"


# --- Q1: the legacy entry-page byte budget is exactly 2 MiB (independent of
#     the code under test — the existing test imported the constant, so the
#     mutant scaled the test along with the budget).


async def test_legacy_entry_page_budget_is_two_mebibytes(client, app):
    """2 x ~1.05 MiB entries exceed the 2 MiB legacy response budget: an
    unpaged request must 413. Constants here are independent literals by
    design. (Kills mutant Q1.)"""
    from app.models import Entry

    emu = ClientEmulator("pins-q1", "pw-pins-q1")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Entry(
                    user_id=emu.user_id,
                    client_entry_id=f"pins-q1-{index}",
                    blob=bytes([index + 1]) * 1_100_000,
                    entry_date=TODAY,
                )
                for index in range(2)
            ]
        )
        await session.commit()

    legacy = await client.get("/api/entries", headers=emu.headers, params={"limit": 25})
    assert legacy.status_code == 413
    assert legacy.json()["code"] == "payload_too_large"

    paged = await client.get(
        "/api/entries", headers=emu.headers, params={"limit": 25, "page_bytes": 2 * 1024 * 1024}
    )
    assert paged.status_code == 200
    assert len(paged.json()) == 1  # only ONE ~1.05 MiB entry fits per budgeted page


# --- Q9: the therapist caseload cap is enforced at grant time


async def test_grant_rejects_when_the_therapist_caseload_is_full(client, app):
    """100 existing consent rows (any status) cap the therapist's caseload;
    the 101st pair must 413 without burning the pairing code. The filler
    count is an independent literal: reading MAX_PATIENTS_PER_THERAPIST
    here would scale the pin with the mutant. (Kills mutant Q9.)"""
    from app.models import Consent, User, new_id

    therapist = TherapistEmulator("pins-q9-th", "pw")
    patient = ClientEmulator("pins-q9-pt", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)

    async with app.state.sessionmaker() as session:
        filler = [
            User(
                id=new_id(),
                username=f"pins-q9-filler-{index}",
                salt="s" * 24,
                verifier=b"v" * 64,
                scrypt_salt=b"k" * 16,
            )
            for index in range(100)
        ]
        session.add_all(filler)
        await session.flush()
        session.add_all(
            Consent(
                user_id=row.id,
                therapist_id=therapist.user_id,
                status="revoked",
            )
            for row in filler
        )
        await session.commit()

    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )
    assert result["status"] == 413
    assert result["body"]["code"] == "payload_too_large"


# --- R8: a losing concurrent same-pair grant answers the 409 contract


class _GrantRaceSession:
    """Proxy over a real session whose commit fails with a unique violation
    the moment the pairing-code claim UPDATE has run (the commit-time race
    the 409 mapping exists for)."""

    def __init__(self, inner, error: Exception):
        self._inner = inner
        self._error = error
        self._armed = False

    async def execute(self, statement, *args, **kwargs):
        if "update pairing_codes" in str(statement).lower():
            self._armed = True
        return await self._inner.execute(statement, *args, **kwargs)

    async def commit(self):
        if self._armed:
            raise self._error
        return await self._inner.commit()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def __aenter__(self):
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)


async def test_concurrent_pair_grant_answers_conflict_not_500(client, app, monkeypatch):
    """The grant commit's IntegrityError must map to the retryable 409
    envelope, never leak as a 500. (Kills mutant R8.)"""
    patient = ClientEmulator("pins-r8", "pw-pins-r8")
    therapist = TherapistEmulator("pins-r8-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)

    original_factory = app.state.sessionmaker
    boom = IntegrityError(
        "INSERT INTO consents ...",
        {},
        RuntimeError("UNIQUE constraint failed: uq_consents_user_therapist"),
    )

    def factory():
        return _GrantRaceSession(original_factory(), boom)

    monkeypatch.setattr(app.state, "sessionmaker", factory)

    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )
    assert result["status"] == 409
    assert result["body"]["code"] == "conflict"


# --- R10: only unique violations are retried during pairing-code allocation


async def test_pairing_code_creation_only_retries_unique_violations():
    """A non-unique IntegrityError during code creation must propagate
    immediately, never be retried. Direct route call with fakes: the clean
    handler re-raises on the FIRST non-unique failure, while the
    retry-everything mutant grinds through all five attempts and answers its
    503 ApiError instead. (Kills mutant R10.)"""
    from app.api import therapist as therapist_api
    from app.deps import ApiError

    boom = IntegrityError(
        "INSERT INTO pairing_codes ...",
        {},
        RuntimeError("FOREIGN KEY constraint failed"),
    )

    class FakeSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        async def execute(self, statement, *args, **kwargs):
            return SimpleNamespace(rowcount=0)

        async def commit(self):
            raise boom

        async def rollback(self):
            return None

        def add(self, obj):
            return None

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(token_secret="s" * 40, access_log_retention_days=730)
            )
        )
    )
    user = SimpleNamespace(id="therapist-r10")

    with pytest.raises(IntegrityError):
        await therapist_api.create_pairing_code(
            request=request,
            user=user,
            session=FakeSession(),  # type: ignore[arg-type]
        )

    # Positive control: a UNIQUE violation is retried (bounded), surfacing
    # as the 503 allocation error rather than a raw leak.
    unique_boom = IntegrityError(
        "INSERT INTO pairing_codes ...",
        {},
        RuntimeError("UNIQUE constraint failed: uq_pairing_codes_code_hash"),
    )

    class RetryingSession(FakeSession):
        async def commit(self):
            raise unique_boom

    with pytest.raises(ApiError) as info:
        await therapist_api.create_pairing_code(
            request=request,
            user=user,
            session=RetryingSession(),  # type: ignore[arg-type]
        )
    assert info.value.status_code == 503


# --- S3: the per-owner processing-session cap


def test_keystore_per_owner_session_cap():
    """Four live sessions per account; the fifth is refused without evicting
    anyone else's. (Kills mutant S3.)"""
    store = InMemoryKeyStore(max_sessions=64, max_sessions_per_owner=4)
    key = bytes(range(32))
    for _ in range(4):
        store.create(key, ttl_seconds=60, owner="user-a")
    with pytest.raises(KeyStoreFull, match="for account"):
        store.create(key, ttl_seconds=60, owner="user-a")
    # The cap is per owner: another account is unaffected.
    store.create(key, ttl_seconds=60, owner="user-b")


# --- C3 (round 1, re-pinned 2026-09-19): pop() consumes the token


def test_keystore_pop_is_single_use_by_mechanism():
    """A second pop of the same token must fail: pop() is an atomic consume
    under the store lock. Re-pinned by the round-3 campaign after the PR
    gate found the round-1 pin had rotted (no suite still exercised a
    double-pop)."""
    from app.security.enclave import KeyNotFound

    store = InMemoryKeyStore()
    key = bytes(range(32))
    token = store.create(key, ttl_seconds=60, owner="user-a")

    popped = store.pop(token, owner="user-a")
    assert bytes(popped) == key
    with pytest.raises(KeyNotFound):
        store.pop(token, owner="user-a")


# --- S5: a snapshot marker AHEAD of the server is still a conflict


async def test_ahead_of_server_snapshot_marker_also_conflicts(client):
    """expected_revision diverging in EITHER direction must 409: a client
    holding a marker from a future/rolled-back state must not receive a
    silently wrong page. (Kills mutant S5.)"""
    emu = ClientEmulator("pins-s5", "pw-pins-s5")
    await emu.register(client)
    await emu.create_entry(client, "day one", TODAY, client_entry_id="pins-s5-e1")

    current = await client.get("/api/entries", headers=emu.headers)
    assert current.status_code == 200
    revision = int(current.headers["X-Entries-Revision"])

    ahead = await client.get(
        "/api/entries", headers=emu.headers, params={"expected_revision": str(revision + 5)}
    )
    assert ahead.status_code == 409
    assert ahead.json()["code"] == "collection_changed"


# --- S6/S7: a threshold regression must stop serving the stored blob


async def _regressed_account(client, app, username: str) -> ClientEmulator:
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator(username, f"pw-{username}")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    ids_by_day = {}
    for day in daterange(32, TODAY):
        entry_id = f"{username}-{day.isoformat()}"
        ids_by_day[day] = entry_id
        await emu.create_entry(
            client, "a day with work and some sleep", day, client_entry_id=entry_id
        )
    await emu.recompute(client)
    blob = (await client.get("/api/insights", headers=emu.headers)).json()["blob"]
    assert blob is not None  # insight phase: the blob is legitimately served
    # Delete 3 days: 29 distinct active days — back below the threshold.
    for day in sorted(ids_by_day)[:3]:
        response = await client.delete(f"/api/entries/{ids_by_day[day]}", headers=emu.headers)
        assert response.status_code == 204
    return emu


async def test_insights_blob_not_served_after_threshold_regression(client, app):
    """Baseline reveals nothing — not even a blob stored while the account
    WAS in the insight phase. (Kills mutant S6.)"""
    emu = await _regressed_account(client, app, "pins-s6")

    summary = await client.get("/api/insights", headers=emu.headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["phase"] == "baseline"
    assert body["blob"] is None


async def test_therapist_insights_read_phase_gates_the_blob(client, app):
    """The therapist's view of a regressed account must match the patient's:
    no blob in baseline. (Kills mutant S7.)"""
    from tests.helpers import patient_wrap_for

    emu = await _regressed_account(client, app, "pins-s7")
    therapist = TherapistEmulator("pins-s7-th", "pw")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    wrap = patient_wrap_for(emu, therapist.wrap_pub_key, therapist.user_id or "")
    from app.api.consents import SHARING_DISCLOSURE_VERSION

    granted = await client.post(
        "/api/consents",
        headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64},
        json={"code": code, **wrap, "disclosure": SHARING_DISCLOSURE_VERSION},
    )
    assert granted.status_code == 201, granted.text

    response = await client.get(
        f"/api/therapist/patients/{emu.user_id}/insights", headers=therapist.headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["phase"] == "baseline"
    assert body["blob"] is None


# --- S10 (recompute-lock keying) is NOT pinned: the per-user recompute lock
# sits nested inside the per-user lifecycle fence the route takes first, so
# two recomputes for one account serialize at the OUTER lock today and the
# inner-lock mutant (S10) is API-unobservable. It guards a future refactor
# that drops the fence, not the current shape — see the campaign report.


# --- T6: a forwarded identity is only trusted for an allowlisted peer


class _FakeRequest:
    def __init__(self, state: dict, client_host: str):
        self.state = SimpleNamespace(**state)
        self.client = SimpleNamespace(host=client_host)


def test_forwarded_identity_requires_the_trusted_peer_decision():
    """trust_proxy_headers=True is NOT sufficient: the middleware's
    authenticated peer decision (state.mindpattern_trusted_proxy) gates the
    forwarded value. A direct client must stay keyed on its socket address
    even when it forges X-Forwarded-For. (Kills mutant T6.)"""
    forged = _FakeRequest(
        {"mindpattern_trusted_proxy": False, "mindpattern_forwarded_client": "2001:db8::9"},
        client_host="203.0.113.7",
    )
    assert client_key(forged, trust_proxy_headers=True) == "203.0.113.7"
    assert client_key(forged, trust_proxy_headers=False) == "203.0.113.7"

    authenticated = _FakeRequest(
        {"mindpattern_trusted_proxy": True, "mindpattern_forwarded_client": "2001:db8::9"},
        client_host="10.0.0.8",
    )
    assert client_key(authenticated, trust_proxy_headers=True) == "2001:db8::/64"


# --- T8: absent keys stay on the overflow lock until it drains


async def test_absent_keys_stay_on_the_overflow_lock_until_it_drains():
    """While the overflow lock is live, an absent key must JOIN it (even if a
    stale registry slot could be evicted): otherwise the same key can hold a
    fresh dedicated lock concurrently with its own earlier overflow-held
    section. (Kills mutant T8.)"""
    locks = UserLocks(max_keys=1)

    k1_acquired = asyncio.Event()
    k1_release = asyncio.Event()

    async def hold_k1():
        async with locks.hold("K1"):
            k1_acquired.set()
            await k1_release.wait()

    k1_task = asyncio.create_task(hold_k1())
    await k1_acquired.wait()

    overflow_started = asyncio.Event()
    observed = []

    async def hold_k2_first():
        async with locks.hold("K2"):  # registry full with live K1 -> overflow
            overflow_started.set()
            await asyncio.sleep(0.5)

    first = asyncio.create_task(hold_k2_first())
    await overflow_started.wait()
    k1_release.set()
    await k1_task  # K1's slot is now a STALE registry entry

    async def hold_k2_second():
        async with locks.hold("K2"):  # same key, overflow still live
            observed.append(first.done())

    second = asyncio.create_task(hold_k2_second())
    await asyncio.gather(first, second)

    assert observed == [True], "the same key ran concurrently with its overflow-held section"

