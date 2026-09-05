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
