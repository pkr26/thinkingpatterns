"""Native opaque custody HTTP bounds and signed64 snapshot refusal."""

import base64
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from app.models import User
from app.security import crypto
from tests.helpers import TherapistEmulator


def opaque_keyring(therapist, size):
    blob = crypto.encrypt(
        therapist.wrap_kek,
        b"x" * (size - 28),
        crypto.build_aad("portal-notes-keyring", therapist.user_id, "v1"),
    )
    assert len(blob) == size
    return base64.b64encode(blob).decode("ascii")


def custody_request(therapist, blob, *, expected=0, following=1):
    return {
        "verifier": therapist.auth_key_b64,
        "operation_id": str(uuid.uuid4()),
        "expected_custody_version": expected,
        "custody_version": following,
        "notes_keyring_blob": blob,
    }


@pytest.mark.parametrize("case", ["minimum", "maximum", "malformed"])
@pytest.mark.asyncio
async def test_native_custody_http_accepts_actual_cipher_bounds_and_refuses_malformed_base64(
    client, case
):
    therapist = TherapistEmulator("native-custody-bounds", "native-custody-password")
    await therapist.register(client)
    # This is the actual opaque HTTP byte contract, not a claim about
    # portal plaintext semantics. Native AES produces28/65536byte envelopes.
    blob = opaque_keyring(therapist, 65536 if case == "maximum" else 28)
    if case == "malformed":
        blob = "!!!!" + blob
    response = await client.put(
        "/api/therapist/custody",
        headers=therapist.headers,
        json=custody_request(therapist, blob),
    )
    if case == "malformed":
        assert response.status_code == 422, response.text
        assert response.json()["code"] == "validation_error"
    else:
        assert response.status_code == 204, response.text
        current = await client.get("/api/therapist/me", headers=therapist.headers)
        assert current.status_code == 200, current.text
        assert current.json()["custody_version"] == 1
        assert current.json()["notes_keyring_blob"] == blob


@pytest.mark.asyncio
async def test_native_custody_http_refuses_a_skipped_version_with_its_public_error(client):
    therapist = TherapistEmulator("native-custody-version", "native-custody-password")
    await therapist.register(client)
    response = await client.put(
        "/api/therapist/custody",
        headers=therapist.headers,
        json=custody_request(therapist, opaque_keyring(therapist, 28), following=2),
    )
    assert response.status_code == 422, response.text
    assert response.json()["code"] == "validation_error"
    assert response.json()["detail"] == "custody version must advance by one"


@pytest.mark.asyncio
async def test_native_custody_snapshot_accepts_last_signed64_revision_then_refuses_overflow(app):
    assert app.state.settings.database_url == "sqlite+aiosqlite://"
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        therapist = TherapistEmulator("native-custody-revision", "native-custody-password")
        await therapist.register(client)
        maximum = 2**63 - 1
        # A native signed64 value inside this newly registered fixture's
        # own SQLite row. No quota reduction or substituted Session/provider.
        async with app.state.sessionmaker() as session:
            result = await session.execute(
                update(User).where(User.id == therapist.user_id).values(notes_revision=maximum - 1)
            )
            assert result.rowcount == 1
            await session.commit()
        installed = opaque_keyring(therapist, 28)
        first = await client.put(
            "/api/therapist/custody",
            headers=therapist.headers,
            json=custody_request(therapist, installed),
        )
        assert first.status_code == 204, first.text
        current = await client.get("/api/therapist/me", headers=therapist.headers)
        assert current.status_code == 200, current.text
        assert current.json()["custody_version"] == 1
        assert current.json()["notes_keyring_blob"] == installed
        second = await client.put(
            "/api/therapist/custody",
            headers=therapist.headers,
            json=custody_request(therapist, opaque_keyring(therapist, 32), expected=1, following=2),
        )
        assert second.status_code == 503, second.text
        assert second.json()["code"] == "service_unavailable"
        unchanged = await client.get("/api/therapist/me", headers=therapist.headers)
        assert unchanged.status_code == 200, unchanged.text
        assert unchanged.json()["custody_version"] == 1
        assert unchanged.json()["notes_keyring_blob"] == installed
