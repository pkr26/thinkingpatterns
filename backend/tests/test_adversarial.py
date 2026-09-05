"""Adversarial red-team suite.

Every test here simulates a specific attack against the running API:
cross-account token abuse, rate-limit evasion via spoofed forwarding
headers, config drift between endpoints, OpenAPI surface exposure,
unbounded authenticated reads, injection-style input, and data isolation
at every boundary. If any of these start failing, someone broke a
security property — find out who before shipping.
"""

from __future__ import annotations

import base64
from datetime import date

from starlette.requests import Request

from app.cache import client_key
from app.config import Settings
from app.main import create_app
from app.security import crypto, tokens
from tests.helpers import ClientEmulator

TODAY = date.today()


# --- rate limiting vs. spoofed X-Forwarded-For --------------------------------


def test_xff_uses_rightmost_entry_when_trusted():
    # A single trusted reverse proxy appends the IP it actually saw to
    # X-Forwarded-For; client-supplied (leftmost) entries are spoofable.
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"1.2.3.4, 5.6.7.8")],
        "client": ("10.0.0.9", 5000),
    }
    assert client_key(Request(scope), trust_proxy_headers=True) == "5.6.7.8"


def test_xff_rightmost_across_multiple_header_lines():
    # Starlette's Headers.get() returns only the FIRST line. A proxy that
    # appends its observation as a SEPARATE header line (HAProxy
    # add-header style) must not let the client's spoofed first line win —
    # the rightmost entry across the whole message is the proxy's.
    scope = {
        "type": "http",
        "headers": [
            (b"x-forwarded-for", b"1.1.1.1"),
            (b"x-forwarded-for", b"2.2.2.2, 3.3.3.3"),
        ],
        "client": ("10.0.0.9", 5000),
    }
    assert client_key(Request(scope), trust_proxy_headers=True) == "3.3.3.3"


def test_xff_ignored_completely_when_proxy_not_trusted():
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"6.6.6.6")],
        "client": ("10.0.0.9", 5000),
    }
    assert client_key(Request(scope), trust_proxy_headers=False) == "10.0.0.9"


async def test_rotating_spoofed_xff_cannot_evade_rate_limit(client, settings):
    # trust off (the default): every request counts against the real peer
    # no matter what the client claims in X-Forwarded-For.
    settings.auth_rate_limit = 3
    statuses = [
        (await client.post(
            "/api/auth/salt",
            json={"username": "anyone"},
            headers={"X-Forwarded-For": f"10.1.{i}.{i}"},
        )).status_code
        for i in range(5)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]


# --- cross-account abuse -------------------------------------------------------


async def test_processing_token_is_bound_to_its_owner_at_api_level(client, settings):
    settings.unlock_threshold_days = 1  # reach the key-consuming path
    alice = ClientEmulator("alice-x", "pw-one")
    bob = ClientEmulator("bob-x", "pw-two")
    await alice.register(client)
    await bob.register(client)
    await alice.create_entry(client, "alice private thought", TODAY)

    alice_session = await alice.open_processing_session(client)
    # Bob needs at least one entry so his recompute reaches the key check
    # (an empty account answers 400 "no entries" before session validation).
    await bob.create_entry(client, "bob filler", TODAY)

    stolen = await client.post(
        "/api/insights/recompute",
        headers={**bob.headers, "X-Processing-Token": alice_session},
    )
    assert stolen.status_code == 403
    assert "missing or expired" in stolen.json()["detail"]


async def test_signed_token_for_unknown_user_is_rejected(client, app):
    ghost = tokens.issue_token(
        "no-such-user-id", app.state.settings.token_secret, 3600
    )
    response = await client.get(
        "/api/entries", headers={"Authorization": f"Bearer {ghost}"}
    )
    assert response.status_code == 401


async def test_login_with_another_users_verifier_fails(client):
    alice = ClientEmulator("alice-v", "pw-one")
    mallory = ClientEmulator("mallory-v", "pw-two")
    await alice.register(client)
    await mallory.register(client)

    response = await client.post(
        "/api/auth/login",
        json={"username": alice.username, "verifier": mallory.auth_key_b64},
    )
    assert response.status_code == 401


async def test_deleting_a_foreign_entry_id_is_404_not_silent_success(client):
    alice = ClientEmulator("alice-del", "pw-one")
    bob = ClientEmulator("bob-del", "pw-two")
    await alice.register(client)
    await bob.register(client)
    await alice.create_entry(client, "mine", TODAY, client_entry_id="shared-id")

    attempted = await client.delete(
        "/api/entries/shared-id", headers=bob.headers
    )
    assert attempted.status_code == 404

    listing = await client.get("/api/entries", headers=alice.headers)
    assert [e["client_entry_id"] for e in listing.json()] == ["shared-id"]


async def test_export_is_isolated_per_user(client):
    alice = ClientEmulator("alice-exp", "pw-one")
    bob = ClientEmulator("bob-exp", "pw-two")
    await alice.register(client)
    await bob.register(client)
    await alice.create_entry(client, "alice secret one", TODAY, client_entry_id="a1")
    await bob.create_entry(client, "bob secret one", TODAY, client_entry_id="b1")

    alice_bundle = (await client.get("/api/account/export", headers=alice.headers)).json()
    bob_bundle = (await client.get("/api/account/export", headers=bob.headers)).json()

    assert [e["client_entry_id"] for e in alice_bundle["entries"]] == ["a1"]
    assert [e["client_entry_id"] for e in bob_bundle["entries"]] == ["b1"]

    # Bob's key must not open Alice's ciphertext (key separation + AAD).
    alice_blob = base64.b64decode(alice_bundle["entries"][0]["blob"])
    aad = crypto.build_aad("entry", alice.user_id, "a1")
    try:
        crypto.decrypt(bob.data_key, alice_blob, aad)
        raise AssertionError("bob's data key decrypted alice's entry!")
    except crypto.TamperError:
        pass


async def test_deleted_account_bearer_token_is_dead(client):
    emu = ClientEmulator("gone", "pw")
    await emu.register(client)
    response = await client.request("DELETE", "/api/account", headers=emu.headers,
                                    json={"verifier": emu.auth_key_b64})
    assert response.status_code == 204
    stale = await client.get("/api/entries", headers=emu.headers)
    assert stale.status_code == 401


# --- consistency between endpoints (config drift) ------------------------------


async def test_get_insights_respects_configured_threshold(client, settings):
    # recompute honours MINDPATTERN_UNLOCK_DAYS; GET /insights must agree,
    # or the client UI and the stored blob tell different stories.
    settings.unlock_threshold_days = 2
    emu = ClientEmulator("threshold-drift", "pw")
    await emu.register(client)
    from datetime import timedelta

    await emu.create_entry(client, "day one calm", TODAY)
    await emu.create_entry(client, "day two calm", TODAY - timedelta(days=1), client_entry_id="e2")

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert recompute.status_code == 200
    assert recompute.json()["phase"] == "insight"

    summary = await client.get("/api/insights", headers=emu.headers)
    assert summary.status_code == 200
    assert summary.json()["phase"] == "insight", (
        "GET /api/insights ignored MINDPATTERN_UNLOCK_DAYS"
    )


async def test_wrong_key_recompute_leaves_previous_insights_intact(client, settings):
    settings.unlock_threshold_days = 1  # single entry must reach the decrypt path
    emu = ClientEmulator("intact", "pw")
    await emu.register(client)
    await emu.create_entry(client, "one calm entry", TODAY)

    good = await emu.open_processing_session(client)
    ok = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": good},
    )
    assert ok.status_code == 200

    # Attacker (or a buggy client) recomputes with a garbage key.
    garbage = base64.b64encode(crypto.generate_key()).decode()
    bad_session = (
        await client.post(
            "/api/processing/sessions",
            headers=emu.headers,
            json={"data_key": garbage},
        )
    ).json()["session_token"]
    sabotaged = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": bad_session},
    )
    assert sabotaged.status_code == 400

    # The previously stored insight must survive, still decryptable.
    payload = await emu.decrypt_insights(client)
    assert payload["stats"]["total_entries"] == 1


# --- API surface + transport hardening -----------------------------------------


def _production_app(monkeypatch) -> object:
    # asyncpg is not installed in the unit-test venv; the engine is never
    # used without the lifespan, so substitute a placeholder.
    monkeypatch.setattr("app.main.build_engine", lambda url: None)
    settings = Settings(
        environment="production",
        database_url="postgresql+asyncpg://u:p@h/db",
        token_secret="x" * 48,
    )
    return create_app(settings)


async def test_production_hides_openapi_and_docs(monkeypatch):
    import httpx

    app = _production_app(monkeypatch)
    async with httpx.ASGITransport(app=app) as transport:
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.get("/docs")).status_code == 404
            assert (await c.get("/redoc")).status_code == 404
            assert (await c.get("/openapi.json")).status_code == 404


async def test_docs_available_in_development(client):
    assert (await client.get("/docs")).status_code == 200


async def test_security_headers_on_every_response(client):
    response = await client.get("/healthz")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    # Private per-user material must not be cached by intermediaries.
    assert response.headers.get("cache-control") == "no-store"


async def test_authenticated_reads_are_rate_limited(client, settings):
    # Unbounded export/list loops are a self-service DoS: each export reads
    # every row the user owns.
    settings.read_rate_limit = 2
    emu = ClientEmulator("reader", "pw")
    await emu.register(client)
    statuses = [
        (await client.get("/api/account/export", headers=emu.headers)).status_code
        for _ in range(4)
    ]
    assert statuses[:2] == [200, 200]
    assert statuses[2:] == [429, 429]


# --- hostile input ------------------------------------------------------------


async def test_injection_style_usernames_are_inert(client, app):
    # SQLAlchemy parameterizes everything, but prove it: a classic injection
    # string in the salt-lookup path must produce a normal decoy response —
    # never a 500, never a validation error that differs from the known-user
    # shape.
    hostile = "x' OR '1'='1'; DROP TABLE users; --"

    response = await client.post("/api/auth/salt", json={"username": hostile})
    assert response.status_code == 200
    expected = app.state.settings.token_secret
    from app.api.auth import decoy_salt

    assert response.json()["salt"] == decoy_salt(hostile, expected)


async def test_decoy_salt_is_deterministic_and_well_formed(client):
    import re

    first = (await client.post("/api/auth/salt", json={"username": "ghost-user-42"})).json()["salt"]
    second = (await client.post("/api/auth/salt", json={"username": "ghost-user-42"})).json()["salt"]
    assert first == second
    assert re.fullmatch(r"[A-Za-z0-9+/=]+", first)
    assert 8 <= len(base64.b64decode(first)) <= 64


async def test_deactivated_account_gets_decoy_salt(client, app):
    # A suspended account must not hand out its real salt — the account is
    # not usable, so the lookup must look exactly like an unknown user.
    from sqlalchemy import update

    from app.models import User

    emu = ClientEmulator("suspended-salt", "pw")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()

    response = await client.post("/api/auth/salt", json={"username": emu.username})
    assert response.status_code == 200
    from app.api.auth import decoy_salt

    assert response.json()["salt"] == decoy_salt(emu.username, app.state.settings.token_secret)
    assert response.json()["salt"] != emu.salt_b64
