"""Fixed-window rate limiting on auth and processing endpoints."""

from __future__ import annotations

import base64

from httpx import ASGITransport, AsyncClient

from tests.helpers import ClientEmulator


async def test_login_rate_limited(client, settings):
    settings.auth_rate_limit = 3
    emu = ClientEmulator("flood", "p")
    await emu.register(client)  # register bucket is separate

    statuses = []
    for _ in range(5):
        response = await client.post(
            "/api/auth/login",
            json={
                "username": "flood",
                "verifier": emu.auth_key_b64,
            },
        )
        statuses.append(response.status_code)

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]
    limited = await client.post(
        "/api/auth/login",
        json={
            "username": "flood",
            "verifier": emu.auth_key_b64,
        },
    )
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers


async def test_register_rate_limited(client, settings):
    settings.auth_rate_limit = 10
    statuses = []
    for i in range(12):
        response = await client.post(
            "/api/auth/register",
            json={
                "username": f"user-{i}",
                "salt": base64.b64encode(b"0" * 16).decode(),
                "verifier": base64.b64encode(b"1" * 32).decode(),
            },
        )
        statuses.append(response.status_code)
    assert 429 in statuses
    assert statuses[-1] == 429


async def test_register_probes_do_not_lock_out_a_legitimate_registrant(app, settings):
    # Per-username bucket semantics: only ACTUAL conflicts (409s) consume the
    # bucket. A per-source request limit still deliberately counts malformed
    # requests, so model the real threat here: an attacker rotates sources
    # while probing a name they do not own.  Those probes must not spend the
    # prospective user's NAME bucket and deny their first registration.
    settings.auth_rate_limit = 3
    for i in range(8):
        transport = ASGITransport(app=app, client=(f"198.51.100.{i + 1}", 4444))
        async with AsyncClient(transport=transport, base_url="http://testserver") as attacker:
            probe = await attacker.post(
                "/api/auth/register",
                json={
                    "username": "wanted-name",
                    "salt": "!!!not-b64!!!",
                    "verifier": base64.b64encode(b"v" * 32).decode(),
                },
            )
        assert probe.status_code == 422  # rejected, and never name-counted

    emu = ClientEmulator("wanted-name", "legit-password")
    transport = ASGITransport(app=app, client=("198.51.100.200", 4444))
    async with AsyncClient(transport=transport, base_url="http://testserver") as legitimate:
        legit = await legitimate.post(
            "/api/auth/register",
            json={
                "username": emu.username,
                "salt": emu.salt_b64,
                "verifier": emu.auth_key_b64,
            },
        )
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
