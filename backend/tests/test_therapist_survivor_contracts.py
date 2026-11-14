"""Public opaque-envelope registration boundaries."""

from __future__ import annotations

import base64

import pytest

from app.security import crypto, sharing
from tests.helpers import TherapistEmulator


@pytest.mark.parametrize("envelope_bytes,outside_bytes", [(28, 27), (768, 769)])
async def test_registration_enforces_authenticated_envelope_bounds(
    client, envelope_bytes, outside_bytes
):
    therapist = TherapistEmulator(f"envelope-{envelope_bytes}", "test-password")
    # Registration checks the opaque wire envelope; its decrypted private-key
    # contents remain the client's responsibility. The wire format permits
    # 28 bytes (12-byte nonce plus 16-byte tag) through 768 decoded bytes,
    # whose base64 representation reaches the public 1024-character cap.
    envelope = crypto.encrypt(
        therapist.wrap_kek,
        b"x" * (envelope_bytes - 28),
        crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, therapist.username),
    )
    assert len(envelope) == envelope_bytes
    outside = (
        envelope[:-1]
        if outside_bytes < 28
        else crypto.encrypt(
            therapist.wrap_kek,
            b"x" * (outside_bytes - 28),
            crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, therapist.username),
        )
    )
    payload = {
        "username": therapist.username,
        "salt": therapist.salt_b64,
        "verifier": therapist.auth_key_b64,
        "age_attestation": "minimum_age_confirmed_v1",
        "display_name": therapist.display_name,
        "wrap_pub_key": therapist.wrap_pub_key,
        "wrap_key_blob": base64.b64encode(outside).decode("ascii"),
    }
    refused = await client.post("/api/therapist/register", json=payload)
    assert refused.status_code == 422, refused.text
    assert refused.json()["code"] == "validation_error"

    payload["wrap_key_blob"] = base64.b64encode(envelope).decode("ascii")
    accepted = await client.post("/api/therapist/register", json=payload)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["role"] == "therapist"
    assert accepted.json()["user_id"]
    assert accepted.json()["token"]
