"""Therapist note batch rekey (2026-10-01 deep audit C3).

The portal's notes used to seal under the password-derived key, so a
password change permanently orphaned every note and revision. The v2
scheme seals under a password-INDEPENDENT identity key; this endpoint
performs the one-time migration of legacy blobs. Server contract under
test: verifier gate, per-therapist ownership, same-length swap invariant,
version fence (a concurrent edit refuses the rekey), no revision creation
/ version advance / notes-revision bump, and revision-row swapping.
"""

from __future__ import annotations

import base64
import os

import pytest

from tests.helpers import ClientEmulator, TherapistEmulator


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.fixture
def therapist() -> TherapistEmulator:
    return TherapistEmulator("note-rekey-th", "correct horse battery staple")


async def _paired(client, th: TherapistEmulator, name: str) -> ClientEmulator:
    patient = ClientEmulator(name, "correct horse battery staple")
    await patient.register(client)
    code = await th.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return patient


async def _create_note(client, emu: TherapistEmulator, patient_user_id: str, blob: bytes) -> dict:
    response = await client.post(
        f"/api/therapist/patients/{patient_user_id}/notes",
        headers=emu.headers,
        json={"client_note_id": f"cn-{os.urandom(4).hex()}", "blob": b64(blob)},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
class TestNoteRekey:
    async def test_rekey_requires_the_verifier(self, client, therapist):
        await therapist.register(client)
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers=therapist.headers,
            json={"items": [{"note_id": "x" * 32, "blob": b64(b"x" * 60), "base_version": 1}]},
        )
        assert response.status_code == 403, response.text

    async def test_rekey_swaps_blob_without_touching_history(
        self, client, therapist, monkeypatch
    ):
        await therapist.register(client)
        patient = await _paired(client, therapist, "note-rekey-pat")
        note = await _create_note(client, therapist, patient.user_id, os.urandom(60))

        # Bump the notes revision BEFORE, to prove the rekey does not move it.
        list_before = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
        )
        rev_before = list_before.headers.get("X-Notes-Revision")

        same_length_blob = os.urandom(len(base64.b64decode(note["blob"])))
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
            json={
                "items": [
                    {
                        "note_id": note["id"],
                        "blob": b64(same_length_blob),
                        "base_version": note["version"],
                        "revision_blobs": [],
                    }
                ]
            },
        )
        assert response.status_code == 204, response.text

        after = (
            await client.get(
                f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
            )
        ).json()
        stored = next(row for row in after if row["id"] == note["id"])
        assert base64.b64decode(stored["blob"]) == same_length_blob
        # NOT an edit: the version is unchanged and no revision appeared.
        assert stored["version"] == note["version"]
        revs = await client.get(
            f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
        )
        assert revs.status_code == 200
        assert revs.json() == []
        list_after = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
        )
        assert list_after.headers.get("X-Notes-Revision") == rev_before

    async def test_rekey_refuses_a_length_change(self, client, therapist):
        await therapist.register(client)
        patient = await _paired(client, therapist, "note-rekey-pat")
        note = await _create_note(client, therapist, patient.user_id, os.urandom(60))
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
            json={
                "items": [
                    {
                        "note_id": note["id"],
                        "blob": b64(b"y" * 61),  # different length: not a rekey
                        "base_version": note["version"],
                    }
                ]
            },
        )
        assert response.status_code == 422, response.text

    async def test_rekey_refuses_a_stale_base_version(self, client, therapist):
        await therapist.register(client)
        patient = await _paired(client, therapist, "note-rekey-pat")
        note = await _create_note(client, therapist, patient.user_id, os.urandom(60))
        blob = base64.b64decode(note["blob"])
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
            json={
                "items": [
                    {
                        "note_id": note["id"],
                        "blob": b64(os.urandom(len(blob))),
                        "base_version": note["version"] + 5,
                    }
                ]
            },
        )
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "version_conflict"

    async def test_rekey_swaps_revision_rows(self, client, therapist):
        await therapist.register(client)
        patient = await _paired(client, therapist, "note-rekey-pat")
        note = await _create_note(client, therapist, patient.user_id, os.urandom(60))
        # One edit creates exactly one revision (of the ORIGINAL blob).
        original = base64.b64decode(note["blob"])
        await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=therapist.headers,
            json={"blob": b64(os.urandom(60)), "base_version": note["version"]},
        )
        revs = (
            await client.get(
                f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
            )
        ).json()
        assert len(revs) == 1
        assert len(base64.b64decode(revs[0]["blob"])) == len(original)

        resealed_note = os.urandom(len(base64.b64decode(
            (await client.get(
                f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
            )).json()[0]["blob"]
        )))
        resealed_rev = os.urandom(len(original))
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
            json={
                "items": [
                    {
                        "note_id": note["id"],
                        "blob": b64(resealed_note),
                        "base_version": note["version"] + 1,
                        "revision_blobs": [
                            {"revision_id": revs[0]["id"], "blob": b64(resealed_rev)}
                        ],
                    }
                ]
            },
        )
        assert response.status_code == 204, response.text
        revs_after = (
            await client.get(
                f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
            )
        ).json()
        assert base64.b64decode(revs_after[0]["blob"]) == resealed_rev

    async def test_rekey_cannot_touch_another_therapists_note(self, client, therapist):
        await therapist.register(client)
        other = TherapistEmulator("note-rekey-other", "correct horse battery staple")
        await other.register(client)
        patient = await _paired(client, therapist, "note-rekey-pat")
        note = await _create_note(client, therapist, patient.user_id, os.urandom(60))
        blob = base64.b64decode(note["blob"])
        response = await client.put(
            "/api/therapist/notes/rekey",
            headers={**other.headers, "X-Account-Verifier": other.auth_key_b64},
            json={
                "items": [
                    {
                        "note_id": note["id"],
                        "blob": b64(os.urandom(len(blob))),
                        "base_version": note["version"],
                    }
                ]
            },
        )
        assert response.status_code == 404, response.text
