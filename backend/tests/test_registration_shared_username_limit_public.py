"""Patient and clinician registration share one conflict budget per username."""

from __future__ import annotations

import pytest

from tests.helpers import ClientEmulator, TherapistEmulator


@pytest.mark.parametrize("first_role", ["patient", "clinician"])
async def test_registration_conflict_budget_is_shared_between_roles(client, settings, first_role):
    username = "shared-registration-name"
    patient = ClientEmulator(username, "test-password")
    await patient.register(client)
    clinician = TherapistEmulator(username, "test-password")
    settings.auth_rate_limit = 2

    patient_body = {
        "username": username,
        "salt": patient.salt_b64,
        "verifier": patient.auth_key_b64,
        "age_attestation": "minimum_age_confirmed_v1",
    }
    clinician_body = {
        "username": username,
        "salt": clinician.salt_b64,
        "verifier": clinician.auth_key_b64,
        "age_attestation": "minimum_age_confirmed_v1",
        "display_name": clinician.display_name,
        "wrap_pub_key": clinician.wrap_pub_key,
        "wrap_key_blob": clinician.wrap_key_blob_b64(),
    }
    attempts = {
        "patient": ("/api/auth/register", patient_body),
        "clinician": ("/api/therapist/register", clinician_body),
    }
    other_role = "clinician" if first_role == "patient" else "patient"
    for role in (first_role, other_role):
        path, body = attempts[role]
        response = await client.post(path, json=body)
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "conflict"

    # Both route-level client budgets still admit this request. It must be
    # refused because the combined per-name conflict budget is exhausted.
    blocked = await client.post("/api/therapist/register", json=clinician_body)
    assert blocked.status_code == 429, blocked.text
    assert blocked.json()["code"] == "rate_limited"
