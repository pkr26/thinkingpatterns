"""Regression tests for Phase 3 (2026-09-21): the note edit history.

Every CHANGING note update preserves the superseded blob as an immutable
revision; the endpoint serves them newest-first, ownership-scoped, and
the portal decrypts them with the live note's AAD (client_note_id is
stable across revisions).
"""

from __future__ import annotations

import base64
import json

from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator

TODAY_TEXT = "session note v1"
REVISED_TEXT = "session note v2, corrected date"


async def _shared_note(client) -> tuple[TherapistEmulator, ClientEmulator, dict]:
    therapist = TherapistEmulator("notehist-th", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("notehist-p", "deep-password")
    await patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "nh-1",
            "blob": therapist.encrypt_note(patient, "nh-1", TODAY_TEXT),
        },
    )
    assert created.status_code == 201, created.text
    return therapist, patient, created.json()


async def test_update_preserves_the_superseded_text(client):
    therapist, patient, note = await _shared_note(client)
    updated = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "nh-1", REVISED_TEXT)},
    )
    assert updated.status_code == 200, updated.text

    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert revisions.status_code == 200, revisions.text
    rows = revisions.json()
    assert len(rows) == 1
    # The revision decrypts with the SAME AAD to the ORIGINAL text.
    aad = crypto.build_aad("note", therapist.user_id or "", patient.user_id or "", "nh-1")
    plain = crypto.decrypt(
        therapist.notes_key, base64.b64decode(rows[0]["blob"]), aad
    )
    assert json.loads(plain.decode("utf-8"))["text"] == TODAY_TEXT
    # The live note carries the new text.
    notes = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
    )
    live = base64.b64decode(notes.json()[0]["blob"])
    assert json.loads(crypto.decrypt(therapist.notes_key, live, aad).decode())["text"] == REVISED_TEXT


async def test_no_change_no_revision(client):
    therapist, patient, note = await _shared_note(client)
    # Byte-identical blob (fresh GCM nonces make same-text re-encryption
    # differ bytewise — the server's change test is byte-level, as it
    # must be: it cannot read the plaintext).
    same = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": note["blob"]},
    )
    assert same.status_code == 200
    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert revisions.json() == []


async def test_idempotent_retry_with_new_text_preserves_the_superseded_text(client):
    # Independent audit V-4 (2026-09-21): the POST retry branch used to
    # rewrite the blob in place — a retried create carrying different
    # content silently replaced history. A CHANGING retry must preserve
    # the superseded blob as a revision, exactly like PATCH.
    therapist, patient, note = await _shared_note(client)
    retried = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "nh-1",
            "blob": therapist.encrypt_note(patient, "nh-1", REVISED_TEXT),
        },
    )
    assert retried.status_code == 201, retried.text
    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert revisions.status_code == 200, revisions.text
    rows = revisions.json()
    assert len(rows) == 1
    aad = crypto.build_aad("note", therapist.user_id or "", patient.user_id or "", "nh-1")
    plain = crypto.decrypt(
        therapist.notes_key, base64.b64decode(rows[0]["blob"]), aad
    )
    assert json.loads(plain.decode("utf-8"))["text"] == TODAY_TEXT
    notes = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
    )
    live = base64.b64decode(notes.json()[0]["blob"])
    assert json.loads(crypto.decrypt(therapist.notes_key, live, aad).decode())["text"] == REVISED_TEXT
    # A byte-identical retry (the genuine offline-queue replay) still
    # writes NO revision.
    replay = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "nh-1",
            "blob": retried.json()["blob"],
        },
    )
    assert replay.status_code == 201
    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert len(revisions.json()) == 1


async def test_revisions_are_ownership_scoped(client):
    therapist, _, note = await _shared_note(client)
    stranger = TherapistEmulator("notehist-other", "deep-password")
    await stranger.register(client)
    denied = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=stranger.headers
    )
    assert denied.status_code == 404


async def test_deleting_a_note_cascades_its_revisions(client, app):
    from sqlalchemy import select

    from app.models import TherapistNoteRevision

    therapist, patient, note = await _shared_note(client)
    updated = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "nh-1", REVISED_TEXT)},
    )
    assert updated.status_code == 200
    deleted = await client.delete(f"/api/therapist/notes/{note['id']}", headers=therapist.headers)
    assert deleted.status_code == 204
    async with app.state.sessionmaker() as session:
        remaining = (
            await session.execute(select(TherapistNoteRevision.id))
        ).scalars().all()
    assert remaining == []
