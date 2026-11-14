"""Unknown accounts pay the same scrypt input work shape as known accounts."""

from __future__ import annotations

import base64

import pytest

from app.api import auth
from app.security import envelope
from tests.helpers import ClientEmulator


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@pytest.mark.parametrize("mode", ["login", "recover"])
async def test_unknown_account_uses_same_scrypt_work_shape_as_known_account(
    client, monkeypatch, mode
):
    patient = ClientEmulator("decoy-work-patient", "test-password")
    await patient.register(client)
    if mode == "recover":
        setup = await client.put(
            "/api/account/recovery",
            headers=patient.headers,
            json={
                "password_verifier": patient.auth_key_b64,
                "verifier": b64(b"r" * 32),
                "wrapped_key": b64(b"w" * envelope.WRAPPED_DATA_KEY_BYTES),
                "scheme": "v2",
            },
        )
        assert setup.status_code == 204, setup.text

    original = auth.hash_verifier_off_loop
    calls = []

    async def record_shape(key, salt, limiter=None, n=None):
        calls.append((len(key), len(salt), n))
        return await original(key, salt, limiter=limiter, n=n)

    monkeypatch.setattr(auth, "hash_verifier_off_loop", record_shape)
    path = "/api/auth/login" if mode == "login" else "/api/auth/recover"
    payload = {"verifier": b64(b"x" * 32)}
    if mode == "recover":
        payload["scheme"] = "v2"

    for username in (patient.username, "decoy-work-unknown"):
        previous = len(calls)
        response = await client.post(path, json={**payload, "username": username})
        assert response.status_code == 401, response.text
        assert response.json() == {"detail": "invalid credentials", "code": "invalid_credentials"}
        assert len(calls) == previous + 1

    assert calls[0] == calls[1]
    assert calls[0][0:2] == (32, 16)
