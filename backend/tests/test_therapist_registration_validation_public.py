"""The therapist registration API explains malformed cryptographic inputs."""

from __future__ import annotations

import base64

import pytest

from tests.helpers import TherapistEmulator


@pytest.mark.parametrize(
    ("field", "invalid_bytes", "detail"),
    [
        ("salt", b"s" * 15, "salt must be exactly 16 bytes"),
        ("verifier", b"v" * 31, "verifier must be 32 bytes"),
        ("wrap_key_blob", b"x" * 27, "wrap_key_blob must be 28-1024 bytes"),
    ],
)
async def test_therapist_registration_reports_invalid_crypto_field(
    client, field, invalid_bytes, detail
):
    therapist = TherapistEmulator("registration-error-detail", "test-password")
    payload = {
        "username": therapist.username,
        "salt": therapist.salt_b64,
        "verifier": therapist.auth_key_b64,
        "age_attestation": "minimum_age_confirmed_v1",
        "display_name": therapist.display_name,
        "wrap_pub_key": therapist.wrap_pub_key,
        "wrap_key_blob": therapist.wrap_key_blob_b64(),
    }
    payload[field] = base64.b64encode(invalid_bytes).decode("ascii")

    response = await client.post("/api/therapist/register", json=payload)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": detail, "code": "validation_error"}
