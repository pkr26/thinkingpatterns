"""Fixed-window rate limiting on auth and processing endpoints."""

from __future__ import annotations

import base64

from tests.helpers import ClientEmulator


async def test_login_rate_limited(client, settings):
    settings.auth_rate_limit = 3
    emu = ClientEmulator("flood", "p")
    await emu.register(client)  # register bucket is separate

    statuses = []
    for _ in range(5):
        response = await client.post("/api/auth/login", json={
            "username": "flood", "verifier": emu.auth_key_b64,
        })
        statuses.append(response.status_code)

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]
    limited = await client.post("/api/auth/login", json={
        "username": "flood", "verifier": emu.auth_key_b64,
    })
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers


async def test_register_rate_limited(client, settings):
    settings.auth_rate_limit = 10
    statuses = []
    for i in range(12):
        response = await client.post("/api/auth/register", json={
            "username": f"user-{i}",
            "salt": base64.b64encode(b"0" * 16).decode(),
            "verifier": base64.b64encode(b"1" * 32).decode(),
        })
        statuses.append(response.status_code)
    assert 429 in statuses
    assert statuses[-1] == 429


async def test_register_probes_do_not_lock_out_a_legitimate_registrant(client, settings):
    # Per-username bucket semantics: only ACTUAL conflicts (409s) consume the
    # bucket. An attacker spraying malformed probes at a name they do not own
    # must not be able to 429 the legitimate first registrant of that name.
    settings.trust_proxy_headers = True  # isolate the per-username bucket from the per-IP one
    settings.auth_rate_limit = 3
    for i in range(8):
        probe = await client.post("/api/auth/register", json={
            "username": "wanted-name",
            "salt": "!!!not-b64!!!",
            "verifier": base64.b64encode(b"v" * 32).decode(),
        }, headers={"X-Forwarded-For": f"10.7.{i}.1"})
        assert probe.status_code == 422  # rejected, and never counted

    emu = ClientEmulator("wanted-name", "legit-password")
    legit = await client.post("/api/auth/register", json={
        "username": emu.username,
        "salt": emu.salt_b64,
        "verifier": emu.auth_key_b64,
    }, headers={"X-Forwarded-For": "10.7.99.1"})
    assert legit.status_code == 201


async def test_processing_sessions_rate_limited(client, settings):
    settings.auth_rate_limit = 100  # keep auth flowing
    emu = ClientEmulator("proc", "p")
    await emu.register(client)
    # The processing-sessions bucket is separate (default 10/min).
    statuses = []
    for _ in range(12):
        response = await client.post(
            "/api/processing/sessions",
            headers=emu.headers,
            json={"data_key": base64.b64encode(emu.data_key).decode()},
        )
        statuses.append(response.status_code)
    assert statuses[0] == 201
    assert statuses[-1] == 429
