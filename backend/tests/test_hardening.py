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
        response = await client.get(
            "/api/entries", headers={"Authorization": f"Bearer {bad}"}
        )
        assert response.status_code == 401


# --- request-size ceilings ----------------------------------------------------


async def test_oversized_blob_rejected_by_schema(client):
    emu = ClientEmulator("bigblob", "p")
    await emu.register(client)
    # 1,125,001 raw bytes -> 1,500,004 b64 chars: over the per-field cap but
    # under the 2 MiB whole-body cap, so this pins the SCHEMA rejection.
    huge = base64.b64encode(b"x" * 1_125_001).decode()
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "big", "blob": huge, "entry_date": TODAY.isoformat(),
    })
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
    response = await client.post("/api/auth/register", json={
        "username": "saltbomb",
        "salt": base64.b64encode(b"s" * 200).decode(),
        "verifier": base64.b64encode(b"v" * 32).decode(),
    })
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

    login = await client.post("/api/auth/login", json={
        "username": "suspended", "verifier": emu.auth_key_b64,
    })
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
        (await client.post(
            "/api/insights/recompute",
            headers={**emu.headers, "X-Processing-Token": token},
        )).status_code
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
    store.create(crypto.generate_key(), ttl_seconds=10, now=0.0)
    store.create(crypto.generate_key(), ttl_seconds=500, now=0.0)
    store.create(crypto.generate_key(), ttl_seconds=500, now=100.0)  # triggers purge
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
    assert counter.hit("b:long", 60, now=10.0).count == 1   # different key unaffected


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


def test_development_defaults_still_boot(monkeypatch):
    for var in ("MINDPATTERN_ENV", "MINDPATTERN_TOKEN_SECRET"):
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    assert s.environment == "development"


# --- offline-queue duplicate race: second sync is a 409, not a 500 ------------


async def test_duplicate_entry_after_queue_flush_is_409(client):
    emu = ClientEmulator("queuedup", "p")
    await emu.register(client)
    created = await emu.create_entry(client, "queued entry", TODAY, client_entry_id="dup-1")
    replay = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "dup-1",
        "blob": created["blob"],
        "entry_date": TODAY.isoformat(),
    })
    assert replay.status_code == 409
