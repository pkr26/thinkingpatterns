"""Native signed-purpose refusal and opaque custody ciphertext boundary."""

import base64
import uuid

from app.security import crypto, sharing, tokens
from tests.helpers import TherapistEmulator


def _transaction(current, replacement, wrap):
    return {
        "verifier": current.auth_key_b64,
        "new_salt": replacement.salt_b64,
        "new_verifier": replacement.auth_key_b64,
        "operation_id": str(uuid.uuid4()),
        "expected_custody_version": 0,
        "custody_version": 1,
        "notes_keyring_blob": base64.b64encode(
            crypto.encrypt(replacement.wrap_kek, b"{}", b"native boundary test")
        ).decode(),
        "wrap_pub_key": current.wrap_pub_key,
        "wrap_key_blob": base64.b64encode(wrap).decode(),
    }


async def test_signed_known_wrong_purpose_is_refused_before_native_custody_change(client, app):
    current = TherapistEmulator("custody-purpose-native", "a long native password")
    await current.register(client)
    settings = app.state.settings
    payload = tokens.verify_token(current.token, settings.auth_token_secret)
    # The token module explicitly documents detecting mis-issued purposes.
    # Native issuer/verifier admit this known-purpose signed token. Its
    # patient-purpose/therapist-row mismatch has no current API issuer claim.
    wrong = tokens.issue_token(
        current.user_id,
        settings.auth_token_secret,
        settings.token_ttl_seconds,
        epoch=payload["ep"],
        purpose=tokens.PURPOSE_PATIENT,
        ksv=settings.auth_secret_version,
    )
    wrap = crypto.encrypt(
        current.wrap_kek,
        current._pkcs8(),
        crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, current.username),
    )
    response = await client.put(
        "/api/therapist/password",
        headers={"Authorization": "Bearer " + wrong},
        json=_transaction(current, current, wrap),
    )
    assert response.status_code == 401, response.text
    assert response.json()["code"] == "unauthorized"
    assert response.json()["detail"] == "invalid token"


async def test_native_aes_at_http_schema_cap_completes_credential_change_and_login(client):
    current = TherapistEmulator("custody-native-blobcap", "a long native password")
    await current.register(client)
    replacement = TherapistEmulator(current.username, "a new long native password")
    # Public HTTP input is capped at1024 BASE64 characters, hence at768
    # decoded bytes. It is opaque native AES data, not a shippedPKCS8 blob.
    wrap = crypto.encrypt(
        replacement.wrap_kek,
        b"x" * 740,
        crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, current.username),
    )
    assert len(wrap) == 768
    assert len(base64.b64encode(wrap)) == 1024
    response = await client.put(
        "/api/therapist/password",
        headers=current.headers,
        json=_transaction(current, replacement, wrap),
    )
    assert response.status_code == 204, response.text
    assert (await client.get("/api/therapist/me", headers=current.headers)).status_code == 401
    login = await client.post(
        "/api/auth/login",
        json={
            "username": current.username,
            "verifier": replacement.auth_key_b64,
            "totp_code": current.totp_backup_codes.pop(0),
        },
    )
    assert login.status_code == 200, login.text
    me = await client.get(
        "/api/therapist/me",
        headers={
            "Authorization": "Bearer " + login.json()["token"],
        },
    )
    assert me.status_code == 200, me.text
    assert me.json()["wrap_key_blob"] == base64.b64encode(wrap).decode()
