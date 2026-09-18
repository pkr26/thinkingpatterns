"""Auth API: register, login, salt lookup (anti-enumeration), token gate."""

from __future__ import annotations

import base64

import pytest

from tests.helpers import ClientEmulator


async def test_register_and_login_roundtrip(client):
    emu = ClientEmulator("alice", "hunter2-strong-pass")
    registered = await emu.register(client)
    assert registered["token"] and registered["user_id"]

    fresh = ClientEmulator("alice", "hunter2-strong-pass", salt=emu.salt)
    logged_in = await fresh.login(client)
    assert logged_in["user_id"] == registered["user_id"]


async def test_register_duplicate_username_conflicts(client):
    await ClientEmulator("bob", "pass-one").register(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "bob",
            "salt": base64.b64encode(b"0" * 16).decode(),
            "verifier": base64.b64encode(b"1" * 32).decode(),
        },
    )
    assert response.status_code == 409


async def test_login_wrong_password_rejected(client):
    emu = ClientEmulator("carol", "right-password")
    await emu.register(client)
    imposter = ClientEmulator("carol", "wrong-password", salt=emu.salt)
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "carol",
            "verifier": imposter.auth_key_b64,
        },
    )
    assert response.status_code == 401
    assert "credentials" in response.json()["detail"]


async def test_login_unknown_user_rejected(client):
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "ghost",
            "verifier": base64.b64encode(b"\x00" * 32).decode(),
        },
    )
    assert response.status_code == 401


async def test_register_rejects_bad_verifier_length(client):
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "dave",
            "salt": base64.b64encode(b"0" * 16).decode(),
            "verifier": base64.b64encode(b"wrong-size").decode(),
        },
    )
    assert response.status_code == 422


async def test_register_rejects_bad_salt_and_b64(client):
    for salt, verifier in [
        (
            base64.b64encode(b"tiny").decode(),
            base64.b64encode(b"1" * 32).decode(),
        ),  # salt < 8 bytes
        ("!!!not-b64!!!", base64.b64encode(b"1" * 32).decode()),
        (base64.b64encode(b"0" * 16).decode(), "%%%not-b64%%%"),
    ]:
        response = await client.post(
            "/api/auth/register",
            json={
                "username": "erin",
                "salt": salt,
                "verifier": verifier,
            },
        )
        assert response.status_code == 422


async def test_register_rejects_bad_usernames(client):
    for username in ("ab", "has space", "x" * 65, "ünïcode-user"):
        response = await client.post(
            "/api/auth/register",
            json={
                "username": username,
                "salt": base64.b64encode(b"0" * 16).decode(),
                "verifier": base64.b64encode(b"1" * 32).decode(),
            },
        )
        assert response.status_code == 422, username


async def test_salt_lookup_never_reveals_existence(client):
    emu = ClientEmulator("frank", "some-password")
    await emu.register(client)

    real = await client.post("/api/auth/salt", json={"username": "frank"})
    unknown = await client.post("/api/auth/salt", json={"username": "nobody-here"})
    unknown_again = await client.post("/api/auth/salt", json={"username": "nobody-here"})

    assert real.status_code == unknown.status_code == 200
    # Decoy is deterministic (same unknown user -> same salt)...
    assert unknown.json()["salt"] == unknown_again.json()["salt"]
    # ...and never collides with the real user's salt.
    assert unknown.json()["salt"] != real.json()["salt"]
    # Both decode to 16 plausible bytes — lengths cannot distinguish them.
    assert len(base64.b64decode(unknown.json()["salt"])) == 16
    assert len(base64.b64decode(real.json()["salt"])) == 16


async def test_logout_revokes_every_token(client):
    emu = ClientEmulator("revoker", "some-password")
    await emu.register(client)
    old_token = emu.token

    response = await client.post("/api/auth/logout", headers=emu.headers)
    assert response.status_code == 204

    # The pre-logout bearer token is dead (epoch bumped)...
    stale = await client.get("/api/entries", headers={"Authorization": f"Bearer {old_token}"})
    assert stale.status_code == 401
    assert stale.json()["detail"] == "invalid token"  # flat reason, no oracle

    # ...and a fresh login works, minting an epoch-current token.
    relogged = await emu.login(client)
    ok = await client.get("/api/entries", headers={"Authorization": f"Bearer {relogged['token']}"})
    assert ok.status_code == 200


async def test_protected_routes_require_token(client):
    for method, path in [
        ("get", "/api/entries"),
        ("post", "/api/insights/recompute"),
        ("get", "/api/insights"),
        ("get", "/api/questions/today"),
        ("get", "/api/account/export"),
        ("delete", "/api/account"),
    ]:
        response = await getattr(client, method)(path)
        assert response.status_code == 401, path


async def test_garbage_token_rejected(client):
    for bad in ("Bearer garbage", "Bearer a.b.c", "Basic abc", "Bearer "):
        response = await client.get("/api/entries", headers={"Authorization": bad})
        assert response.status_code == 401


async def test_token_from_wrong_secret_rejected(client, app):
    from app.security.tokens import issue_token

    forged = issue_token("someone", "attacker-knows-other-secret", 60)
    response = await client.get("/api/entries", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401
