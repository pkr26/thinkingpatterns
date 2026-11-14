"""Native opaque note HTTP decoding and the unchanged full chart byte budget."""

import base64
import uuid
from datetime import datetime, timezone

import pytest

from app.models import Consent, TherapistNote, TherapistNoteRevision
from app.schemas import NoteCreateRequest
from app.security import crypto, sharing
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for


async def _native_pair(app, client):
    assert app.state.settings.database_url == "sqlite+aiosqlite://"
    patient = ClientEmulator("native-note-patient", "native-note-patient-password")
    therapist = TherapistEmulator("native-note-therapist", "native-note-therapist-password")
    await patient.register(client)
    await therapist.register(client)
    wrapped = patient_wrap_for(patient, therapist.wrap_pub_key, therapist.user_id)
    now = datetime.now(timezone.utc)
    # This fresh fixture explicitly admits one persisted retired relationship
    # with native P-256/AES wrapping. Notes are documented to outlive revocation.
    # No claim is made about a historical producer; no consent API is invoked.
    async with app.state.sessionmaker() as session:
        session.add(
            Consent(
                id=uuid.uuid4().hex,
                user_id=patient.user_id,
                therapist_id=therapist.user_id,
                status="revoked",
                disclosure="v3",
                ephemeral_pub=wrapped["ephemeral_pub"],
                wrapped_key=base64.b64decode(wrapped["wrapped_key"], validate=True),
                granted_at=now,
                revoked_at=now,
            )
        )
        await session.commit()
    return patient, therapist


def _blob(therapist, patient, client_note_id, size):
    return crypto.encrypt(
        therapist.notes_key,
        b"x" * (size - 28),
        crypto.build_aad(
            sharing.NOTE_CONTEXT,
            therapist.user_id,
            patient.user_id,
            client_note_id,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["minimum", "malformed", "undersized"])
async def test_native_note_http_accepts_cipher_floor_and_refuses_invalid_wire(app, client, case):
    patient, therapist = await _native_pair(app, client)
    note_id = "native-note-" + case
    native = _blob(therapist, patient, note_id, 28)
    if case == "undersized":
        native = native[:-1]
    encoded = base64.b64encode(native).decode("ascii")
    if case == "malformed":
        encoded = "!!!!" + encoded
    response = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": note_id, "blob": encoded},
    )
    if case == "minimum":
        assert response.status_code == 201, response.text
        assert response.json()["blob"] == encoded
        assert response.json()["client_note_id"] == note_id
    else:
        assert response.status_code == 422, response.text
        assert response.json()["code"] == "validation_error"
        assert response.json()["detail"] == (
            "blob must be base64" if case == "malformed" else "blob must be at least 28 bytes"
        )


@pytest.mark.asyncio
async def test_native_note_http_retry_at_full_actual_chart_byte_budget(app, client):
    patient, therapist = await _native_pair(app, client)
    unit = 1024 * 1024
    now = datetime.now(timezone.utc)
    notes = []
    for index in range(30):
        client_note_id = f"native-budget-{index}"
        blob = _blob(therapist, patient, client_note_id, unit)
        # Every seeded live row has the actual current public opaque-request
        # shape, a native cipher, and its own matching note AAD. This remains
        # an explicit persisted-state fixture, not a claimed write history.
        NoteCreateRequest(
            client_note_id=client_note_id,
            blob=base64.b64encode(blob).decode("ascii"),
        )
        notes.append(
            TherapistNote(
                id=uuid.uuid4().hex,
                therapist_id=therapist.user_id,
                user_id=patient.user_id,
                client_note_id=client_note_id,
                blob=blob,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
    async with app.state.sessionmaker() as session:
        session.add_all(notes)
        await session.flush()
        session.add_all(
            [
                TherapistNoteRevision(
                    note_id=notes[0].id,
                    therapist_id=therapist.user_id,
                    blob=_blob(therapist, patient, notes[0].client_note_id, unit),
                    created_at=now,
                )
                for _ in range(2)
            ]
        )
        await session.commit()
    path = f"/api/therapist/patients/{patient.user_id}/notes"
    original = base64.b64encode(notes[0].blob).decode("ascii")
    retry = await client.post(
        path,
        headers=therapist.headers,
        json={"client_note_id": notes[0].client_note_id, "blob": original},
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["blob"] == original
    extra_id = "native-budget-overflow"
    extra = base64.b64encode(_blob(therapist, patient, extra_id, 28)).decode("ascii")
    refused = await client.post(
        path,
        headers=therapist.headers,
        json={"client_note_id": extra_id, "blob": extra},
    )
    assert refused.status_code == 413, refused.text
    assert refused.json()["code"] == "blob_quota_exceeded"
    assert refused.json()["detail"] == "note storage quota reached (total size)"
