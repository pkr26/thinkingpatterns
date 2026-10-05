"""Behavioral history ownership, ordering and request-boundary controls."""

from __future__ import annotations

import base64

from app.models import TherapistNoteRevision
from tests.helpers import TherapistEmulator
from tests.test_note_history import REVISED_TEXT, TODAY_TEXT, _shared_note


async def _edit(client, therapist, patient, note, text, version):
    response = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "nh-1", text), "base_version": version},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _texts(response, therapist, patient):
    assert response.status_code == 200, response.text
    return [therapist.decrypt_note(patient, "nh-1", row["blob"])["text"] for row in response.json()]


async def test_foreign_revision_metadata_cannot_disrupt_owned_history(client, app):
    therapist, patient, note = await _shared_note(client)
    await _edit(client, therapist, patient, note, REVISED_TEXT, 1)
    path = f"/api/therapist/notes/{note['id']}/revisions"
    before = await client.get(path, headers=therapist.headers)
    assert _texts(before, therapist, patient) == [TODAY_TEXT]

    stranger = TherapistEmulator("history-foreign-metadata", "synthetic-history-passphrase")
    await stranger.register(client)
    foreign = stranger.encrypt_note(patient, "foreign-note", "foreign private revision")
    # The database's independent FKs permit inconsistent imported/corrupted
    # metadata. This is not an authorized API write or a demonstrated leak:
    # the final blob query also scopes ownership. The metadata query should
    # exclude this row so legitimate owned history remains available.
    async with app.state.sessionmaker() as session:
        session.add(
            TherapistNoteRevision(
                note_id=note["id"], therapist_id=stranger.user_id, blob=base64.b64decode(foreign)
            )
        )
        await session.commit()
    denied = await client.get(path, headers=stranger.headers)
    assert denied.status_code == 404
    after = await client.get(path, headers=therapist.headers)
    assert _texts(after, therapist, patient) == [TODAY_TEXT]
    assert all(row["blob"] != foreign for row in after.json())


async def test_note_history_orders_real_superseded_versions_newest_first_across_pages(client):
    therapist, patient, note = await _shared_note(client)
    for version, text in enumerate(("second revision", "third revision", "current revision"), 1):
        await _edit(client, therapist, patient, note, text, version)
    path = f"/api/therapist/notes/{note['id']}/revisions"
    first = await client.get(path, headers=therapist.headers, params={"limit": 2})
    assert _texts(first, therapist, patient) == ["third revision", "second revision"]
    assert first.headers["X-Next-Offset"] == "2"
    last = await client.get(path, headers=therapist.headers, params={"limit": 2, "offset": 2})
    assert _texts(last, therapist, patient) == [TODAY_TEXT]
    assert "X-Next-Offset" not in last.headers
    assert len({row["id"] for row in first.json() + last.json()}) == 3


async def test_note_history_accepts_limit_200_and_rejects_201_without_serving_ciphertext(client):
    therapist, patient, note = await _shared_note(client)
    await _edit(client, therapist, patient, note, REVISED_TEXT, 1)
    path = f"/api/therapist/notes/{note['id']}/revisions"
    accepted = await client.get(path, headers=therapist.headers, params={"limit": 200})
    assert _texts(accepted, therapist, patient) == [TODAY_TEXT]
    assert "X-Next-Offset" not in accepted.headers
    # This is the public request-validation bound, separate from the lower
    # per-note stored-revision retention cap. No oversized history is seeded.
    for invalid in (0, 201):
        refused = await client.get(path, headers=therapist.headers, params={"limit": invalid})
        assert refused.status_code == 422, refused.text
        assert refused.json()["code"] == "validation_error"
        assert "blob" not in refused.text
