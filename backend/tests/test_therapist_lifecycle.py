"""Regression tests for the 2026-09-21 audit Phase 2, therapist lifecycle
(C-2 / F-4): credential rotation opened to therapist tokens, plus the
verifier-gated wrap-key rotation route with patient re-wrap via the
EXISTING consent rewrap endpoint (no re-pairing).
"""

from __future__ import annotations

import base64
import os
import uuid

from sqlalchemy import select

from app.models import AccessLog, Consent
from app.security import crypto, sharing as sharing_crypto
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
        "/api/therapist/password",
        headers=old.headers,
        json={
            "verifier": old.auth_key_b64,
            "new_salt": successor.salt_b64,
            "new_verifier": successor.auth_key_b64,
            "operation_id": str(uuid.uuid4()),
            "expected_custody_version": 0,
            "custody_version": 1,
            "notes_keyring_blob": base64.b64encode(os.urandom(60)).decode(),
            "wrap_pub_key": old.wrap_pub_key,
            "wrap_key_blob": base64.b64encode(
                crypto.encrypt(
                    successor.wrap_kek,
                    old._pkcs8(),
                    crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, old.username),
                )
            ).decode(),
        },
    )
    assert response.status_code == 204, response.text
    # The epoch bump retires every bearer issued under the old credential.
    stale = await client.get("/api/therapist/me", headers=old.headers)
    assert stale.status_code == 401
    # The new password is the login credential now; password rotation
    # deliberately preserves the enrolled second factor and recovery codes.
    successor.totp_secret = old.totp_secret
    successor.totp_backup_codes = old.totp_backup_codes
    await successor.login(client)


async def test_therapist_credential_rotation_rejects_wrong_verifier(client):
    emu = TherapistEmulator("ther-rot-bad", "original-deep-password")
    await emu.register(client)
    impostor = TherapistEmulator("ther-rot-bad", "wrong-password")
    response = await client.put(
        "/api/therapist/password",
        headers=emu.headers,
        json={
            "verifier": impostor.auth_key_b64,
            "new_salt": impostor.salt_b64,
            "new_verifier": impostor.auth_key_b64,
            "operation_id": str(uuid.uuid4()),
            "expected_custody_version": 0,
            "custody_version": 1,
            "notes_keyring_blob": base64.b64encode(os.urandom(60)).decode(),
            "wrap_pub_key": emu.wrap_pub_key,
            "wrap_key_blob": impostor.wrap_key_blob_b64(),
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "verification_failed"
    # Nothing changed: the original credential still logs in.
    await emu.login(client)


# --- wrap-key rotation (audit C-2) ---------------------------------------------------


async def test_wrap_key_rotation_revokes_old_grants_then_patient_repairs(client, app):
    therapist = TherapistEmulator("ther-wrap", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("ther-wrap-pat", "deep-password")
    await patient.register(client)
    consent_id = await _grant(client, patient, therapist)
    assert therapist.user_id

    # A genuinely fresh keypair: same username (the blob's AAD binds it),
    # new P-256 material, blob wrapped under the CURRENT password KEK.
    successor = TherapistEmulator("ther-wrap", "deep-password")
    custody = await client.put(
        "/api/therapist/custody",
        headers=therapist.headers,
        json={
            "verifier": therapist.auth_key_b64,
            "operation_id": str(uuid.uuid4()),
            "expected_custody_version": 0,
            "custody_version": 1,
            "notes_keyring_blob": base64.b64encode(os.urandom(60)).decode(),
        },
    )
    assert custody.status_code == 204, custody.text
    rotation = await client.put(
        "/api/therapist/wrap-key",
        headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
        json={
            "wrap_pub_key": successor.wrap_pub_key,
            "wrap_key_blob": successor.wrap_key_blob_b64(),
            "expected_custody_version": 1,
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
    assert out["status"] == "revoked"
    assert out["therapist_wrap_pub_key"] == successor.wrap_pub_key
    wrap = patient_wrap_for(patient, successor.wrap_pub_key, therapist.user_id)
    # Replacing a compromised identity retires every old grant. A new
    # explicit pairing consent is required, and preserves the pair's row ID.
    from app.api.consents import SHARING_DISCLOSURE_VERSION

    code = await therapist.create_pairing_code(client)
    rewrapped = await client.post(
        "/api/consents",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"code": code, **wrap, "disclosure": SHARING_DISCLOSURE_VERSION},
    )
    assert rewrapped.status_code == 201, rewrapped.text
    assert rewrapped.json()["id"] == consent_id

    # The stored grant now wraps to the new public half, and the SUCCESSOR's
    # private key (the post-rotation material) unwraps the patient's data key.
    async with app.state.sessionmaker() as session:
        row = (
            (await session.execute(select(Consent).where(Consent.id == consent_id))).scalars().one()
        )
        assert row.ephemeral_pub == wrap["ephemeral_pub"]
        audit_seen = await session.execute(
            select(AccessLog).where(
                AccessLog.actor_id == therapist.user_id,
                AccessLog.action == "wrap_key_rotate",
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
