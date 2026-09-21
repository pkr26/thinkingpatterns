"""Regression tests for the 2026-09-21 audit Phase 2, therapist lifecycle
(C-2 / F-4): credential rotation opened to therapist tokens, plus the
verifier-gated wrap-key rotation route with patient re-wrap via the
EXISTING consent rewrap endpoint (no re-pairing).
"""

from __future__ import annotations

from sqlalchemy import select

from app.models import AccessLog, Consent
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> str:
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return granted["body"]["id"]


# --- credential rotation is open to therapists (audit C-2) --------------------------


async def test_therapist_rotates_password_credential(client):
    old = TherapistEmulator("ther-rot", "original-deep-password")
    await old.register(client)
    successor = TherapistEmulator("ther-rot", "brand-new-password")
    response = await client.put(
        "/api/account/credential",
        headers=old.headers,
        json={
            "verifier": old.auth_key_b64,
            "new_salt": successor.salt_b64,
            "new_verifier": successor.auth_key_b64,
        },
    )
    assert response.status_code == 204, response.text
    # The epoch bump retires every bearer issued under the old credential.
    stale = await client.get("/api/therapist/me", headers=old.headers)
    assert stale.status_code == 401
    # The new password is the login credential now.
    await successor.login(client)


async def test_therapist_credential_rotation_rejects_wrong_verifier(client):
    emu = TherapistEmulator("ther-rot-bad", "original-deep-password")
    await emu.register(client)
    impostor = TherapistEmulator("ther-rot-bad", "wrong-password")
    response = await client.put(
        "/api/account/credential",
        headers=emu.headers,
        json={
            "verifier": impostor.auth_key_b64,
            "new_salt": impostor.salt_b64,
            "new_verifier": impostor.auth_key_b64,
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "verification_failed"
    # Nothing changed: the original credential still logs in.
    await emu.login(client)


# --- wrap-key rotation (audit C-2) ---------------------------------------------------


async def test_wrap_key_rotation_and_patient_rewrap_without_repairing(client, app):
    therapist = TherapistEmulator("ther-wrap", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("ther-wrap-pat", "deep-password")
    await patient.register(client)
    consent_id = await _grant(client, patient, therapist)
    assert therapist.user_id

    # A genuinely fresh keypair: same username (the blob's AAD binds it),
    # new P-256 material, blob wrapped under the CURRENT password KEK.
    successor = TherapistEmulator("ther-wrap", "deep-password")
    rotation = await client.put(
        "/api/therapist/wrap-key",
        headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
        json={
            "wrap_pub_key": successor.wrap_pub_key,
            "wrap_key_blob": successor.wrap_key_blob_b64(),
        },
    )
    assert rotation.status_code == 204, rotation.text

    # /me serves the new material — the portal's unlock path uses it next.
    me = await client.get("/api/therapist/me", headers=therapist.headers)
    assert me.json()["wrap_pub_key"] == successor.wrap_pub_key

    # The patient sees the NEW public half on their grant list and re-wraps
    # through the EXISTING endpoint — no pairing round-trip.
    consents = await client.get("/api/consents", headers=patient.headers)
    assert consents.status_code == 200
    out = consents.json()[0]
    assert out["id"] == consent_id
    assert out["status"] == "active"
    assert out["therapist_wrap_pub_key"] == successor.wrap_pub_key
    wrap = patient_wrap_for(patient, successor.wrap_pub_key, therapist.user_id)
    rewrapped = await client.put(
        f"/api/consents/{consent_id}/rewrap",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json=wrap,
    )
    assert rewrapped.status_code == 200, rewrapped.text

    # The stored grant now wraps to the new public half, and the SUCCESSOR's
    # private key (the post-rotation material) unwraps the patient's data key.
    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Consent).where(Consent.id == consent_id)
                )
            )
            .scalars()
            .one()
        )
        assert row.ephemeral_pub == wrap["ephemeral_pub"]
        audit_seen = (
            await session.execute(
                select(AccessLog).where(
                    AccessLog.actor_id == therapist.user_id,
                    AccessLog.action == "wrap_key_rotate",
                )
            )
        )
        assert audit_seen.scalars().first() is not None, "rotation must be audit-logged"
    # The successor emulator carries the SAME account identity (the
    # unwrap's AAD binds therapist_id) with the NEW key material.
    successor.user_id = therapist.user_id
    data_key = successor.unwrap_patient_data_key(
        patient, wrap["ephemeral_pub"], wrap["wrapped_key"]
    )
    assert data_key == patient.data_key

async def test_wrap_key_rotation_requires_the_current_verifier(client):
    emu = TherapistEmulator("ther-wrap-g", "deep-password")
    await emu.register(client)
    successor = TherapistEmulator("ther-wrap-g", "deep-password")
    body = {
        "wrap_pub_key": successor.wrap_pub_key,
        "wrap_key_blob": successor.wrap_key_blob_b64(),
    }
    missing = await client.put("/api/therapist/wrap-key", headers=emu.headers, json=body)
    assert missing.status_code == 422
    assert missing.json()["code"] == "validation_error"
    impostor = TherapistEmulator("ther-wrap-g", "wrong-password")
    wrong = await client.put(
        "/api/therapist/wrap-key",
        headers={**emu.headers, "X-Account-Verifier": impostor.auth_key_b64},
        json=body,
    )
    assert wrong.status_code == 403
    assert wrong.json()["code"] == "verification_failed"
    # A stolen bearer alone changed nothing.
    me = await client.get("/api/therapist/me", headers=emu.headers)
    assert me.json()["wrap_pub_key"] == emu.wrap_pub_key


async def test_wrap_key_rotation_rejects_patient_tokens_and_bad_keys(client):
    patient = ClientEmulator("ther-wrap-p", "deep-password")
    await patient.register(client)
    material = TherapistEmulator("any", "deep-password")
    forbidden = await client.put(
        "/api/therapist/wrap-key",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={
            "wrap_pub_key": material.wrap_pub_key,
            "wrap_key_blob": material.wrap_key_blob_b64(),
        },
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["code"] == "forbidden"

    therapist = TherapistEmulator("ther-wrap-bad", "deep-password")
    await therapist.register(client)
    invalid = await client.put(
        "/api/therapist/wrap-key",
        headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
        json={
            "wrap_pub_key": "not-a-spki-key",
            "wrap_key_blob": material.wrap_key_blob_b64(),
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["code"] == "validation_error"
