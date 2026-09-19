"""Production-hardening regressions.

Each test here pins a specific failure mode found in the audit:
malformed tokens crashing instead of 401ing, request-size ceilings,
rate limits on expensive/unauthenticated endpoints, processing-session
owner binding, keystore memory hygiene, config fail-fast, and the
fixed-window counter's cross-window correctness.
"""

from __future__ import annotations

import base64
from datetime import date

import pytest

from app.cache import FixedWindowCounter
from app.config import Settings
from app.security import crypto
from app.security.enclave import InMemoryKeyStore, KeyNotFound
from app.security.tokens import TokenError, verify_token
from tests.helpers import ClientEmulator

TODAY = date.today()


# --- tokens: hostile input must 401, never 500 -------------------------------


def test_verify_token_rejects_non_ascii():
    with pytest.raises(TokenError):
        verify_token("nøn-åscii-body.sig", "secret")


def test_verify_token_rejects_non_ascii_signature():
    with pytest.raises(TokenError):
        verify_token("body.\uffff", "secret")


async def test_hostile_bearer_tokens_are_401_not_500(client):
    # httpx rejects non-ASCII header values client-side, so hostile tokens
    # that can actually arrive over the wire are ASCII: oversized, padded,
    # dotted garbage. All must 401 cleanly, never 500.
    for bad in ("a" * 100_000, "....", "===.===", "...."):
        response = await client.get("/api/entries", headers={"Authorization": f"Bearer {bad}"})
        assert response.status_code == 401


# --- request-size ceilings ----------------------------------------------------


async def test_oversized_blob_rejected_by_schema(client):
    emu = ClientEmulator("bigblob", "p")
    await emu.register(client)
    # 1,125,001 raw bytes -> 1,500,004 b64 chars: over the per-field cap but
    # under the 2 MiB whole-body cap, so this pins the SCHEMA rejection.
    huge = base64.b64encode(b"x" * 1_125_001).decode()
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "big",
            "blob": huge,
            "entry_date": TODAY.isoformat(),
        },
    )
    assert response.status_code == 422


async def test_oversized_data_key_rejected_by_schema(client):
    emu = ClientEmulator("bigkey", "p")
    await emu.register(client)
    huge = base64.b64encode(b"k" * 2_000).decode()
    response = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": huge}
    )
    assert response.status_code == 422


async def test_oversized_register_fields_rejected(client):
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "saltbomb",
            "salt": base64.b64encode(b"s" * 200).decode(),
            "verifier": base64.b64encode(b"v" * 32).decode(),
        },
    )
    assert response.status_code == 422


# --- disabled accounts --------------------------------------------------------


async def test_inactive_user_cannot_login_or_use_api(client, app):
    emu = ClientEmulator("suspended", "p")
    await emu.register(client)

    from sqlalchemy import update
    from app.models import User

    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()

    login = await client.post(
        "/api/auth/login",
        json={
            "username": "suspended",
            "verifier": emu.auth_key_b64,
        },
    )
    assert login.status_code == 401

    stale = await client.get("/api/entries", headers=emu.headers)
    assert stale.status_code == 401


# --- rate limits on the newly protected endpoints -----------------------------


async def test_salt_lookup_rate_limited(client, settings):
    settings.auth_rate_limit = 3
    statuses = [
        (await client.post("/api/auth/salt", json={"username": "whoever"})).status_code
        for _ in range(5)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]


async def test_recompute_rate_limited(client, settings):
    settings.processing_rate_limit = 2
    emu = ClientEmulator("hammer", "p")
    await emu.register(client)
    await emu.create_entry(client, "one calm day", TODAY)
    token = await emu.open_processing_session(client)
    statuses = [
        (
            await client.post(
                "/api/insights/recompute",
                headers={**emu.headers, "X-Processing-Token": token},
            )
        ).status_code
        for _ in range(4)
    ]
    assert statuses[:2] == [200, 200]
    assert statuses[2:] == [429, 429]


# --- keystore: owner binding + memory hygiene ---------------------------------


def test_keystore_binds_owner():
    store = InMemoryKeyStore()
    key_a = crypto.generate_key()
    token = store.create(key_a, 60, owner="user-a")
    assert store.get(token, owner="user-a") == key_a
    with pytest.raises(KeyNotFound):
        store.get(token, owner="user-b")
    # Unbound reads (ops/tooling) still work.
    assert store.get(token) == key_a


def test_keystore_purges_expired_on_create():
    store = InMemoryKeyStore()
    store.create(crypto.generate_key(), ttl_seconds=10, now=0.0, owner='unbound-test')
    store.create(crypto.generate_key(), ttl_seconds=500, now=0.0, owner='unbound-test')
    store.create(crypto.generate_key(), ttl_seconds=500, now=100.0, owner='unbound-test')  # triggers purge
    assert len(store) == 2


# --- FixedWindowCounter: time-based windows -----------------------------------


def test_counter_resets_after_window():
    counter = FixedWindowCounter()
    assert counter.hit("k", 60, now=100.0).count == 1
    assert counter.hit("k", 60, now=100.5).count == 2
    assert counter.hit("k", 60, now=159.9).count == 3  # still inside the first window
    assert counter.hit("k", 60, now=160.0).count == 1  # window elapsed -> fresh count


def test_counter_keys_are_independent_across_window_sizes():
    counter = FixedWindowCounter()
    assert counter.hit("a:short", 10, now=0.0).count == 1
    assert counter.hit("a:short", 10, now=9.0).count == 2
    assert counter.hit("a:short", 10, now=10.0).count == 1  # short window rolled over
    assert counter.hit("b:long", 60, now=10.0).count == 1  # different key unaffected


def test_counter_reports_usable_retry_after():
    counter = FixedWindowCounter()
    result = counter.hit("k", 60, now=100.0)
    assert result.retry_after >= 1
    # While limited, Retry-After must point at when THIS window resets,
    # not blindly restate the full window length.
    late = counter.hit("k", 60, now=150.0)
    assert late.retry_after <= 11


def test_counter_rejects_bad_window():
    with pytest.raises(ValueError):
        FixedWindowCounter().hit("k", 0)


# --- config: production fail-fast ----------------------------------------------


def test_production_refuses_insecure_secret(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "dev-insecure-secret-change-me")
    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings.from_env()


@pytest.mark.parametrize("env", ["staging", "prod", "PRODUCTION", "Production ", "eu-west"])
def test_non_dev_environments_refuse_insecure_secret(monkeypatch, env):
    # Fail closed: only the literal "development" may boot with the
    # repo-committed dev secret — a typo'd or unexpected env value must not
    # silently sign tokens with a public constant.
    monkeypatch.setenv("MINDPATTERN_ENV", env)
    monkeypatch.delenv("MINDPATTERN_TOKEN_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings.from_env()


def test_production_refuses_short_secret(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "too-short")
    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings.from_env()


def test_production_refuses_sqlite(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 48)
    with pytest.raises(RuntimeError, match="DB_URL"):
        Settings.from_env()


@pytest.mark.parametrize("env", ["staging", "prod", "PRODUCTION", "Production ", "eu-west"])
def test_any_non_development_env_refuses_sqlite(env):
    # Fail closed on the URL too: a typo'd MINDPATTERN_ENV must not boot
    # against a throwaway local file database.
    with pytest.raises(RuntimeError, match="DB_URL"):
        Settings(environment=env, token_secret="x" * 48)


def test_development_allows_sqlite():
    s = Settings(environment="development", database_url="sqlite+aiosqlite:///./dev.db")
    assert s.database_url.startswith("sqlite")


def test_production_accepts_real_config(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "production")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "x" * 48)
    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")
    s = Settings.from_env()
    assert s.environment == "production"


def test_garbage_int_env_is_loud(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_TOKEN_TTL", "8O000")  # letter O, not zero
    with pytest.raises(ValueError, match="MINDPATTERN_TOKEN_TTL"):
        Settings.from_env()


def test_missing_env_fails_closed(monkeypatch):
    # No MINDPATTERN_ENV at all: the default is production, so the committed
    # dev secret must refuse to boot rather than silently sign tokens with a
    # public constant.
    for var in ("MINDPATTERN_ENV", "MINDPATTERN_TOKEN_SECRET"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings.from_env()


def test_development_boots_only_when_explicit(monkeypatch):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.delenv("MINDPATTERN_TOKEN_SECRET", raising=False)
    s = Settings.from_env()
    assert s.environment == "development"


def test_settings_default_environment_is_production():
    # The dataclass default itself fails closed: Settings() with no explicit
    # environment is production, so the committed dev secret is rejected.
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings()


# --- config: LLM endpoint must be TLS ------------------------------------------


def test_llm_url_http_rejected_in_production():
    with pytest.raises(RuntimeError, match="LLM_URL"):
        Settings(
            environment="production",
            database_url="postgresql+asyncpg://u:p@h/db",
            token_secret="x" * 48,
            llm_url="http://llm.internal/v1",
        )


def test_llm_url_http_rejected_in_staging():
    # Not just production: ANY non-development environment sends journal
    # plaintext over TLS or not at all.
    with pytest.raises(RuntimeError, match="LLM_URL"):
        Settings(
            environment="staging",
            token_secret="x" * 45,
            database_url="postgresql+asyncpg://u:p@h/db",
            llm_url="http://llm.internal/v1",
        )


def test_llm_url_https_accepted():
    s = Settings(
        environment="production",
        database_url="postgresql+asyncpg://u:p@h/db",
        token_secret="x" * 48,
        llm_url="https://llm.example.com/v1",
        llm_provider_name="Example LLM",
        llm_data_retention="30 days",
        llm_policy_version="2026-09",
    )
    assert s.llm_url == "https://llm.example.com/v1"


def test_llm_url_loopback_http_allowed_only_in_development():
    for url in (
        "http://localhost:11434/v1",
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8080/v1",
    ):
        s = Settings(environment="development", llm_url=url)
        assert s.llm_url == url
    # Exact-host match: a lookalike host or a LAN address is not loopback.
    for url in ("http://localhost.evil.com/v1", "http://192.168.1.10/v1"):
        with pytest.raises(RuntimeError, match="LLM_URL"):
            Settings(environment="development", llm_url=url)
    # Loopback http does NOT leak into other environments.
    with pytest.raises(RuntimeError, match="LLM_URL"):
        Settings(
            environment="staging",
            token_secret="x" * 45,
            database_url="postgresql+asyncpg://u:p@h/db",
            llm_url="http://localhost:11434/v1",
        )


@pytest.mark.parametrize(
    "url",
    (
        "https://",
        "https://provider.example:abc/v1",
        "https://user:pass@provider.example/v1",
        "https://provider.example/v1?alternate=1",
        "https://provider.example/v1#fragment",
    ),
)
def test_llm_url_rejects_malformed_or_ambiguous_endpoint_urls(url):
    # The LLM target carries decrypted journal text. Fail during boot for a
    # malformed authority or URL component that would otherwise make the
    # configured /chat/completions target ambiguous.
    with pytest.raises(RuntimeError, match="LLM_URL"):
        Settings(environment="development", llm_url=url)


# --- config: CORS defaults to no origins ---------------------------------------


def test_cors_origins_default_to_empty():
    assert Settings(environment="development").cors_origins == []


def test_cors_origins_require_exact_secure_origins():
    # A wildcard or a URL with userinfo/path/query is not an explicit Origin
    # allowlist entry. Remote plaintext origins are equally unsafe; only
    # exact local development hosts may use http.
    for origins in (
        ["*"],
        ["http://web.example"],
        ["https://user:pass@web.example"],
        ["https://web.example/portal"],
        ["https://web.example?next=bad"],
        ["https://web.example:abc"],
    ):
        with pytest.raises(RuntimeError, match="cors_origins"):
            Settings(environment="development", cors_origins=origins)

    for origin in ("https://web.example", "http://localhost:5173", "http://[::1]:5173"):
        assert Settings(environment="development", cors_origins=[origin]).cors_origins == [origin]

    with pytest.raises(RuntimeError, match="cors_origins"):
        Settings(
            environment="production",
            database_url="postgresql+asyncpg://u:p@h/db",
            token_secret="x" * 48,
            cors_origins=["http://localhost:5173"],
        )


async def test_no_cors_headers_by_default(client):
    # A cross-origin browser request must get no allow header when no
    # allowlist is configured (the mobile app never sends Origin anyway).
    response = await client.get("/healthz", headers={"Origin": "https://attacker.example"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


async def test_configured_cors_origin_is_echoed(settings):
    settings.cors_origins = ["https://web.example"]
    from httpx import ASGITransport, AsyncClient
    from app.main import create_app

    transport = ASGITransport(app=create_app(settings))
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        allowed = await c.get("/healthz", headers={"Origin": "https://web.example"})
        denied = await c.get("/healthz", headers={"Origin": "https://attacker.example"})
    assert allowed.headers.get("access-control-allow-origin") == "https://web.example"
    assert "access-control-allow-origin" not in denied.headers


# --- app factory: create_all is a development-only convenience -----------------


async def test_create_all_only_runs_in_development(monkeypatch):
    # Outside development the schema comes from `alembic upgrade head` (image
    # entrypoint); startup must NOT create_all an unstamped schema.
    import app.main as main_mod

    class _Engine:
        async def dispose(self):
            pass

    inited: list = []

    async def _init(engine):
        inited.append(engine)

    monkeypatch.setattr(main_mod, "build_engine", lambda url, **_: _Engine())
    monkeypatch.setattr(main_mod, "init_models", _init)

    prod = main_mod.create_app(
        Settings(
            environment="staging",
            database_url="postgresql+asyncpg://u:p@h/db",
            token_secret="x" * 48,
        )
    )
    async with prod.router.lifespan_context(prod):
        pass
    assert inited == []

    dev = main_mod.create_app(
        Settings(environment="development", database_url="sqlite+aiosqlite://")
    )
    async with dev.router.lifespan_context(dev):
        pass
    assert len(inited) == 1


# --- app factory: docs/schema hidden outside development ----------------------


@pytest.mark.parametrize("env", ["production", "staging", "prod"])
async def test_docs_hidden_in_any_non_development_env(monkeypatch, env):
    # The docs gate must match the config gates: any MINDPATTERN_ENV value
    # other than the exact "development" serves no API map.
    import httpx
    from app.main import create_app

    monkeypatch.setattr(
        "app.main.build_engine", lambda url, **_: None
    )  # pool kwargs accepted, engine unused
    settings = Settings(
        environment=env,
        database_url="postgresql+asyncpg://u:p@h/db",
        token_secret="x" * 48,
    )
    app = create_app(settings)
    async with httpx.ASGITransport(app=app) as transport:
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.get("/docs")).status_code == 404
            assert (await c.get("/openapi.json")).status_code == 404


# --- cache: eviction is batched, semantics unchanged ----------------------------


def test_counter_eviction_is_batched_under_cap_pressure():
    from app.cache import EVICTION_BATCH, MAX_TRACKED_KEYS

    counter = FixedWindowCounter()
    for i in range(MAX_TRACKED_KEYS + 1):
        counter.hit(f"attacker-{i}", 60)
    # One eviction event clears a whole batch below the cap instead of
    # trimming a single key per over-cap hit.
    assert len(counter._hits) <= MAX_TRACKED_KEYS - EVICTION_BATCH + 1  # noqa: SLF001


# --- offline-queue duplicate race: second sync is a 409, not a 500 ------------


async def test_duplicate_entry_after_queue_flush_is_409(client):
    emu = ClientEmulator("queuedup", "p")
    await emu.register(client)
    created = await emu.create_entry(client, "queued entry", TODAY, client_entry_id="dup-1")
    replay = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "dup-1",
            "blob": created["blob"],
            "entry_date": TODAY.isoformat(),
        },
    )
    assert replay.status_code == 409
