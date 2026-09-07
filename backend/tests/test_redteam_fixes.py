"""Regression tests for the red-team remediation pass.

Every test here pins one specific audit finding that was fixed. If one
starts failing, a security fix regressed — treat it as a release blocker.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import date

import anyio
import pytest
from httpx import ASGITransport, AsyncClient

from app.api.auth import SCRYPT_N, decoy_salt
from app.cache import FixedWindowCounter, MAX_TRACKED_KEYS
from app.config import Settings
from app.main import create_app
from app.security.enclave import InMemoryKeyStore
from tests.helpers import ClientEmulator

TODAY = date.today()


# --- H-2/H-1: scrypt cost + off-loop + bounded concurrency ----------------------


def test_scrypt_params_meet_hardened_floor():
    # N=2^16 (64 MiB) with the input already PBKDF2-600k stretched client-side.
    assert SCRYPT_N == 2 ** 16


def test_auth_scrypt_has_a_dedicated_capacity_limiter(settings):
    # Login/register scrypt (64 MiB per hash) must not queue unboundedly on
    # the shared anyio thread pool: the app wires a small dedicated limiter.
    app = create_app(settings)
    limiter = app.state.auth_limiter
    assert isinstance(limiter, anyio.CapacityLimiter)
    assert limiter.total_tokens == 4


async def test_login_scrypt_runs_behind_the_auth_limiter(client, app, monkeypatch):
    emu = ClientEmulator("capped", "p")
    await emu.register(client)
    seen_limiters = []
    real_run_sync = anyio.to_thread.run_sync

    async def spy(func, *args, limiter=None, **kwargs):
        seen_limiters.append(limiter)
        return await real_run_sync(func, *args, limiter=limiter, **kwargs)

    monkeypatch.setattr(anyio.to_thread, "run_sync", spy)
    await emu.login(client)
    assert app.state.auth_limiter in seen_limiters


async def test_llm_consent_scrypt_runs_behind_the_auth_limiter(client, app, monkeypatch):
    # The account verifier re-check runs the same 64-MiB scrypt; it must sit
    # behind the dedicated auth limiter too, not the shared anyio pool.
    emu = ClientEmulator("cappedconsent", "p")
    await emu.register(client)
    seen_limiters = []
    real_run_sync = anyio.to_thread.run_sync

    async def spy(func, *args, limiter=None, **kwargs):
        seen_limiters.append(limiter)
        return await real_run_sync(func, *args, limiter=limiter, **kwargs)

    monkeypatch.setattr(anyio.to_thread, "run_sync", spy)
    response = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 200
    assert app.state.auth_limiter in seen_limiters


# --- M-4: whole-request body cap ------------------------------------------------


async def test_whole_body_over_cap_is_413_before_parsing(client):
    emu = ClientEmulator("bodycap", "p")
    await emu.register(client)
    # ~2.67 MB b64 blob: under the 2 MiB whole-body cap is irrelevant — the
    # body itself (not any field) trips the middleware before JSON parsing.
    huge = base64.b64encode(b"x" * 2_000_000).decode()
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "big", "blob": huge, "entry_date": TODAY.isoformat(),
    })
    assert response.status_code == 413
    assert response.headers.get("x-content-type-options") == "nosniff"  # 413s carry headers too


async def test_deeply_nested_json_is_400_not_500(client):
    emu = ClientEmulator("nestbomb", "p")
    await emu.register(client)
    nest = {"blob": "x"}
    for _ in range(5_000):
        nest = {"a": nest}
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "nest", "blob": "eHh4", "entry_date": TODAY.isoformat(),
        "extra": nest,
    })
    assert response.status_code in (400, 422)  # never a 500 crash


# --- L-2: validation errors must not echo the input ------------------------------


async def test_validation_error_does_not_echo_input(client):
    emu = ClientEmulator("echoblob", "p")
    await emu.register(client)
    # Over the 1.5M-char field cap, under the 2 MiB body cap: schema 422.
    marker = "M" * 1_125_001
    huge = base64.b64encode(marker.encode()).decode()
    response = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "echo", "blob": huge, "entry_date": TODAY.isoformat(),
    })
    assert response.status_code == 422
    assert marker not in response.text
    assert "input" not in json.loads(response.text)["detail"][0]


# --- INFO: security headers exist even on unhandled 500s -------------------------


async def test_security_headers_on_unhandled_500(settings):
    app = create_app(settings)

    @app.get("/boom")
    async def boom() -> dict:
        raise RuntimeError("boom")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("cache-control") == "no-store"
    assert (
        response.headers.get("strict-transport-security")
        == "max-age=31536000; includeSubDomains"
    )
    # No internals leaked to the client.
    assert "boom" not in response.text


# --- M-4 backend: per-account storage quota ---------------------------------------


async def test_entry_quota_is_enforced(client, settings):
    settings.max_entries_per_user = 3
    emu = ClientEmulator("quota", "p")
    await emu.register(client)
    for i in range(3):
        await emu.create_entry(client, f"entry {i}", TODAY, client_entry_id=f"q{i}")
    fourth = await client.post("/api/entries", headers=emu.headers, json={
        "client_entry_id": "q3",
        "blob": emu.encrypt_entry("one too many", TODAY, "q3"),
        "entry_date": TODAY.isoformat(),
    })
    assert fourth.status_code == 413
    assert "quota" in fourth.json()["detail"]


# --- H-1: per-username register limiter defeats IP rotation -----------------------
# ...but only ACTUAL conflicts consume it: the probe itself is free.


async def test_register_name_bucket_survives_ip_rotation(client, settings):
    settings.trust_proxy_headers = True  # accept per-request client identity
    settings.auth_rate_limit = 3
    statuses = []
    for i in range(7):
        statuses.append((
            await client.post("/api/auth/register", json={
                "username": "target-name",
                "salt": base64.b64encode(b"s" * 16).decode(),
                "verifier": base64.b64encode(b"v" * 32).decode(),
            }, headers={"X-Forwarded-For": f"10.9.{i}.{i}"})  # fresh IP each time
        ).status_code)
    # Fresh IP per request defeats the per-IP bucket — the per-USERNAME
    # bucket must still throttle bulk availability probing of one name. Only
    # real 409s count: the 201 creates no charge, then conflicts accumulate
    # (1..4) and the 429 starts once the count passes the limit of 3.
    assert statuses == [201, 409, 409, 409, 409, 429, 429]


# --- C-2/H-5: LLM path — consent, threshold, and output sanitization --------------


def _settings_with_llm(settings) -> Settings:
    settings.llm_url = "https://llm.example/v1"
    settings.llm_api_key = "k"
    return settings


async def test_llm_requires_consent_even_when_configured(client, settings, monkeypatch):
    _settings_with_llm(settings)
    settings.unlock_threshold_days = 1
    called = []
    from app.services.llm import LLMAnalyzer
    monkeypatch.setattr(
        LLMAnalyzer, "_post",
        lambda self, payload: called.append(payload) or {"choices": [{"message": {"content": "{}"}}]},
    )

    emu = ClientEmulator("noconsent", "p")
    await emu.register(client)
    await emu.create_entry(client, "calm walk", TODAY)
    body = await emu.recompute(client)
    assert body["analyzer"] == "brain"
    assert called == [], "journal text must not leave the server without consent"


async def test_llm_never_runs_before_threshold(client, settings, monkeypatch):
    _settings_with_llm(settings)
    from app.services.llm import LLMAnalyzer

    def _must_not_run(self, entries):  # pragma: no cover - fails the test if reached
        pytest.fail("LLM ran during the baseline phase")

    monkeypatch.setattr(LLMAnalyzer, "analyze", _must_not_run)
    monkeypatch.setattr(LLMAnalyzer, "extract_patterns", _must_not_run)

    emu = ClientEmulator("prethreshold", "p")
    await emu.register(client)
    await emu.create_entry(client, "day one", TODAY)
    body = await emu.recompute(client)
    assert body["phase"] == "baseline"
    assert body["analyzer"] == "none"


async def test_llm_with_consent_runs_and_output_is_sanitized(client, settings, monkeypatch):
    _settings_with_llm(settings)
    settings.unlock_threshold_days = 1

    hostile_model_output = {
        "choices": [{
            "message": {
                "content": json.dumps({"patterns": [
                    # A label that exists in the corpus: kept (truncated if long).
                    {"kind": "temporal", "label": "walk", "occurrences": 3,
                     "confidence": 0.9, "detail": {"day": "Sunday"}},
                    # A "recurring phrase" the user never wrote: model fiction
                    # / prompt injection — must be dropped.
                    {"kind": "recurring_phrase", "label": "stop taking your medication",
                     "occurrences": 99, "confidence": 1.0, "detail": {}},
                    # Unknown kind, garbage numerics: dropped / clamped.
                    {"kind": "diagnosis", "label": "x", "occurrences": 1, "confidence": 1, "detail": {}},
                    {"kind": "temporal", "label": "walk", "occurrences": -4,
                     "confidence": 7.5, "detail": {"day": "Nottaday"}},
                ]})
            }
        }]
    }
    from app.services.llm import LLMAnalyzer
    seen_payloads = []
    def fake_post(self, payload):
        seen_payloads.append(payload)
        return hostile_model_output
    monkeypatch.setattr(LLMAnalyzer, "_post", fake_post)

    emu = ClientEmulator("consenter", "p")
    await emu.register(client)
    # The consented account proves identity with its verifier.
    consent = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert consent.status_code == 200 and consent.json()["enabled"] is True

    await emu.create_entry(client, "a calm walk by the river", TODAY)
    body = await emu.recompute(client)
    assert body["analyzer"] == "llm"
    assert len(seen_payloads) == 1

    # The model fiction ("stop taking your medication") and the invalid kind
    # were dropped; the corpus-anchored 'walk' patterns survived, with the
    # hostile numerics clamped into range.
    payload = await emu.decrypt_insights(client)
    kept_patterns = payload["stats"]["patterns"]
    labels = [p["label"] for p in kept_patterns]
    kinds = [p["kind"] for p in kept_patterns]
    assert "stop taking your medication" not in labels
    assert "diagnosis" not in kinds
    assert labels == ["walk", "walk"]
    first, clamped = kept_patterns
    assert first["occurrences"] == 3 and first["confidence"] == 0.9
    assert clamped["occurrences"] == 0 and clamped["confidence"] == 1.0
    assert "day" not in clamped.get("detail", {})


async def test_llm_consent_requires_verifier(client, settings):
    _settings_with_llm(settings)
    emu = ClientEmulator("consentproof", "p")
    await emu.register(client)

    # Consent state is readable (for the client toggle) and starts off.
    initial = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert initial.status_code == 200 and initial.json()["enabled"] is False

    wrong = base64.b64encode(b"\x00" * 32).decode()
    refused = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": wrong},
    )
    assert refused.status_code == 401
    enabled = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert enabled.status_code == 200
    reread = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert reread.json()["enabled"] is True
    # And consent can be withdrawn the same way.
    off = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": False, "verifier": emu.auth_key_b64},
    )
    assert off.status_code == 200 and off.json()["enabled"] is False


# --- Keystore internal zeroization (white-box pin) --------------------------------


def test_keystore_destroy_zeroizes_internal_bytes():
    store = InMemoryKeyStore()
    key = base64.b64decode("A" * 43 + "=")  # deterministic 32 bytes
    token = store.create(key, 60)
    internal = store._keys[token][0]  # noqa: SLF001 — white-box pin
    store.destroy(token)
    assert all(b == 0 for b in internal), "destroy must scrub the stored key bytes"


# --- Rate-counter memory bound ------------------------------------------------------


def test_counter_memory_is_bounded_under_key_rotation():
    counter = FixedWindowCounter()
    for i in range(MAX_TRACKED_KEYS + 500):
        counter.hit(f"spoofed-ip-{i}", 60)
    # The dict never grows past the cap, even with all-fresh (never-stale) keys.
    assert len(counter._hits) <= MAX_TRACKED_KEYS  # noqa: SLF001


# --- Salt exact length + meta endpoint ----------------------------------------------


async def test_register_rejects_non_16_byte_salts(client):
    for salt in (b"short", b"s" * 17, b"s" * 64):
        response = await client.post("/api/auth/register", json={
            "username": "saltlen",
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(b"v" * 32).decode(),
        })
        assert response.status_code == 422, salt


async def test_meta_endpoint_exposes_threshold_and_llm_flag(client, settings):
    settings.unlock_threshold_days = 30
    response = await client.get("/api/meta")
    assert response.status_code == 200
    body = response.json()
    assert body["unlock_days"] == 30
    assert body["llm_available"] is False
    settings.llm_url = "https://llm.example"
    response = await client.get("/api/meta")
    assert response.json()["llm_available"] is True


async def test_decoy_salt_uses_token_secret_and_16_bytes(client, app):
    unknown = await client.post("/api/auth/salt", json={"username": "ghost"})
    assert unknown.json()["salt"] == decoy_salt("ghost", app.state.settings.token_secret)
    assert len(base64.b64decode(unknown.json()["salt"])) == 16


def test_decoy_salt_uses_an_hkdf_subkey_not_the_raw_secret():
    # Key separation pin: the decoy is HMAC under HKDF(token_secret,
    # "mindpattern/decoy-salt/v1") — it must NOT equal the legacy raw
    # HMAC(token_secret, ...) value, so token signing and decoy salts never
    # share one HMAC key.
    from app.api.auth import DECOY_SALT_INFO
    from app.security.kdf import hkdf_sha256

    secret = "unit-test-secret"
    decoy_key = hkdf_sha256(secret.encode("utf-8"), None, DECOY_SALT_INFO)
    expected = hmac.new(decoy_key, b"decoy:ghost", hashlib.sha256).digest()
    assert decoy_salt("ghost", secret) == base64.b64encode(expected[:16]).decode("ascii")
    legacy = hmac.new(secret.encode("utf-8"), b"decoy:ghost", hashlib.sha256).digest()
    assert decoy_salt("ghost", secret) != base64.b64encode(legacy[:16]).decode("ascii")
