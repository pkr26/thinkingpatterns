"""Regression coverage for opt-in collection snapshot pagination.

Offset pagination remains compatible for legacy callers, but a modern caller
can pin a page sequence to the revision returned with its first page.  These
tests exercise that contract through the real HTTP routes rather than
inspecting ORM state, including every mutation type that must advance a
marker.
"""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from app.api.entries import MAX_COLLECTION_REVISION
from app.deps import ApiError
from app.models import User
from tests.helpers import ClientEmulator, TherapistEmulator


TODAY = date.today()


async def _shared_pair(client, suffix: str) -> tuple[ClientEmulator, TherapistEmulator]:
    patient = ClientEmulator(f"revision-patient-{suffix}", "pw")
    therapist = TherapistEmulator(f"revision-therapist-{suffix}", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    assert lookup["status"] == 200
    grant = await patient.grant_consent(
        client,
        code,
        lookup["body"]["wrap_pub_key"],
        lookup["body"]["therapist_id"],
    )
    assert grant["status"] == 201, grant
    return patient, therapist


def _assert_stale(response, header_name: str, expected_current: str) -> None:
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "collection_changed"
    assert body["detail"].endswith("changed while paging; retry the request")
    assert response.headers[header_name] == expected_current


async def test_entries_snapshot_revision_is_strict_and_tracks_real_mutations(client):
    emu = ClientEmulator("revision-owner", "pw")
    await emu.register(client)

    # Legacy and empty/final calls continue to work; every successful page
    # carries a snapshot marker even when no continuation exists.
    empty = await client.get("/api/entries", headers=emu.headers)
    assert empty.status_code == 200
    assert empty.json() == []
    assert empty.headers["X-Entries-Revision"] == "0"
    assert "X-Next-Offset" not in empty.headers
    for invalid in ("01", "+1", str(MAX_COLLECTION_REVISION + 1)):
        rejected = await client.get(
            "/api/entries", headers=emu.headers, params={"expected_revision": invalid}
        )
        assert rejected.status_code == 422
        assert rejected.json()["code"] == "validation_error"

    for entry_id in ("revision-entry-1", "revision-entry-2"):
        await emu.create_entry(client, entry_id, TODAY, client_entry_id=entry_id)
    first = await client.get("/api/entries", headers=emu.headers, params={"limit": 1})
    assert first.status_code == 200
    assert first.headers["X-Entries-Revision"] == "2"
    assert first.headers["X-Next-Offset"] == "1"

    # A create, changed replacement, and successful delete each invalidate a
    # continuation.  The error includes the newer marker for an immediate
    # fresh traversal rather than a generic conflict retry loop.
    await emu.create_entry(client, "third", TODAY, client_entry_id="revision-entry-3")
    stale_after_create = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 1, "offset": 1, "expected_revision": "2"},
    )
    _assert_stale(stale_after_create, "X-Entries-Revision", "3")

    page_at_three = await client.get("/api/entries", headers=emu.headers, params={"limit": 1})
    replacement = await client.put(
        "/api/entries/revision-entry-1",
        headers=emu.headers,
        json={
            "blob": emu.encrypt_entry("rewritten", TODAY, "revision-entry-1"),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert replacement.status_code == 200, replacement.text
    stale_after_replace = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={
            "limit": 1,
            "offset": 1,
            "expected_revision": page_at_three.headers["X-Entries-Revision"],
        },
    )
    _assert_stale(stale_after_replace, "X-Entries-Revision", "4")

    # A byte-identical retry is not a collection mutation and therefore does
    # not make the current snapshot stale.
    unchanged = await client.put(
        "/api/entries/revision-entry-1",
        headers=emu.headers,
        json={
            "blob": replacement.json()["blob"],
            "entry_date": replacement.json()["entry_date"],
        },
    )
    assert unchanged.status_code == 200
    still_current = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 1, "expected_revision": "4"},
    )
    assert still_current.status_code == 200
    assert still_current.headers["X-Entries-Revision"] == "4"

    page_at_four = await client.get("/api/entries", headers=emu.headers, params={"limit": 1})
    removed = await client.delete("/api/entries/revision-entry-2", headers=emu.headers)
    assert removed.status_code == 204
    stale_after_delete = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={
            "limit": 1,
            "offset": 1,
            "expected_revision": page_at_four.headers["X-Entries-Revision"],
        },
    )
    _assert_stale(stale_after_delete, "X-Entries-Revision", "5")

    final = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 1, "offset": 1, "expected_revision": "5"},
    )
    assert final.status_code == 200
    assert len(final.json()) == 1
    assert final.headers["X-Entries-Revision"] == "5"
    assert "X-Next-Offset" not in final.headers


async def test_therapist_entry_snapshot_matches_patient_revision_and_rejects_stale_page(client):
    patient, therapist = await _shared_pair(client, "entries")
    for entry_id in ("shared-revision-1", "shared-revision-2"):
        await patient.create_entry(client, entry_id, TODAY, client_entry_id=entry_id)

    path = f"/api/therapist/patients/{patient.user_id}/entries"
    first = await client.get(path, headers=therapist.headers, params={"limit": 1})
    assert first.status_code == 200
    assert first.headers["X-Entries-Revision"] == "2"
    assert first.headers["X-Next-Offset"] == "1"

    await patient.create_entry(client, "third shared", TODAY, client_entry_id="shared-revision-3")
    stale = await client.get(
        path,
        headers=therapist.headers,
        params={"limit": 1, "offset": 1, "expected_revision": "2"},
    )
    _assert_stale(stale, "X-Entries-Revision", "3")

    # Legacy portal requests remain successful; the additive header is safe
    # to ignore, while an opted-in terminal page retains its marker.
    legacy = await client.get(path, headers=therapist.headers)
    assert legacy.status_code == 200
    assert legacy.headers["X-Entries-Revision"] == "3"
    final = await client.get(
        path,
        headers=therapist.headers,
        params={"limit": 1, "offset": 2, "expected_revision": "3"},
    )
    assert final.status_code == 200
    assert len(final.json()) == 1
    assert final.headers["X-Entries-Revision"] == "3"
    assert "X-Next-Offset" not in final.headers


async def test_notes_snapshot_revision_tracks_create_update_delete_and_noop_retry(client):
    patient, therapist = await _shared_pair(client, "notes")
    notes_path = f"/api/therapist/patients/{patient.user_id}/notes"

    empty = await client.get(notes_path, headers=therapist.headers)
    assert empty.status_code == 200
    assert empty.json() == []
    assert empty.headers["X-Notes-Revision"] == "0"

    created = {}
    for note_id in ("revision-note-1", "revision-note-2"):
        response = await client.post(
            notes_path,
            headers=therapist.headers,
            json={
                "client_note_id": note_id,
                "blob": therapist.encrypt_note(patient, note_id, f"initial {note_id}"),
            },
        )
        assert response.status_code == 201, response.text
        created[note_id] = response.json()

    first = await client.get(notes_path, headers=therapist.headers, params={"limit": 1})
    assert first.status_code == 200
    assert first.headers["X-Notes-Revision"] == "2"
    assert first.headers["X-Next-Offset"] == "1"

    added = await client.post(
        notes_path,
        headers=therapist.headers,
        json={
            "client_note_id": "revision-note-3",
            "blob": therapist.encrypt_note(patient, "revision-note-3", "new note"),
        },
    )
    assert added.status_code == 201
    stale_after_create = await client.get(
        notes_path,
        headers=therapist.headers,
        params={"limit": 1, "offset": 1, "expected_revision": "2"},
    )
    _assert_stale(stale_after_create, "X-Notes-Revision", "3")

    page_at_three = await client.get(notes_path, headers=therapist.headers, params={"limit": 1})
    updated = await client.patch(
        f"/api/therapist/notes/{created['revision-note-1']['id']}",
        headers=therapist.headers,
        json={
            "blob": therapist.encrypt_note(patient, "revision-note-1", "updated note"),
        },
    )
    assert updated.status_code == 200, updated.text
    stale_after_update = await client.get(
        notes_path,
        headers=therapist.headers,
        params={
            "limit": 1,
            "offset": 1,
            "expected_revision": page_at_three.headers["X-Notes-Revision"],
        },
    )
    _assert_stale(stale_after_update, "X-Notes-Revision", "4")

    # PATCH with the stored ciphertext is a retry, not a collection mutation.
    unchanged = await client.patch(
        f"/api/therapist/notes/{created['revision-note-1']['id']}",
        headers=therapist.headers,
        json={"blob": updated.json()["blob"]},
    )
    assert unchanged.status_code == 200
    # POST retries are also idempotent when every persisted note field is
    # already equal; they must not advance the therapist-global marker.
    retried_create = await client.post(
        notes_path,
        headers=therapist.headers,
        json={
            "client_note_id": "revision-note-1",
            "blob": updated.json()["blob"],
        },
    )
    assert retried_create.status_code == 201
    still_current = await client.get(
        notes_path,
        headers=therapist.headers,
        params={"limit": 1, "expected_revision": "4"},
    )
    assert still_current.status_code == 200
    assert still_current.headers["X-Notes-Revision"] == "4"

    page_at_four = await client.get(notes_path, headers=therapist.headers, params={"limit": 1})
    removed = await client.delete(
        f"/api/therapist/notes/{created['revision-note-2']['id']}", headers=therapist.headers
    )
    assert removed.status_code == 204
    stale_after_delete = await client.get(
        notes_path,
        headers=therapist.headers,
        params={
            "limit": 1,
            "offset": 1,
            "expected_revision": page_at_four.headers["X-Notes-Revision"],
        },
    )
    _assert_stale(stale_after_delete, "X-Notes-Revision", "5")

    final = await client.get(
        notes_path,
        headers=therapist.headers,
        params={"limit": 1, "offset": 1, "expected_revision": "5"},
    )
    assert final.status_code == 200
    assert len(final.json()) == 1
    assert final.headers["X-Notes-Revision"] == "5"
    assert "X-Next-Offset" not in final.headers


async def test_revision_helpers_fail_closed_when_an_owner_is_missing_or_at_limit():
    """Never permit a write/page without a trustworthy collection marker."""
    from app.api import entries as entries_api
    from app.api import therapist as therapist_api

    class MissingOwnerSession:
        async def scalar(self, statement):
            return None

    owner = User(
        id="revision-helper-owner",
        username="revision-helper-owner",
        salt="s",
        verifier=b"v",
        scrypt_salt=b"k",
    )
    with pytest.raises(ApiError) as entries_missing:
        await entries_api.current_entries_revision(MissingOwnerSession(), owner.id)
    assert entries_missing.value.status_code == 409
    assert entries_missing.value.code == "collection_changed"

    with pytest.raises(ApiError) as notes_missing:
        await therapist_api._current_notes_revision(MissingOwnerSession(), owner.id)
    assert notes_missing.value.status_code == 409
    assert notes_missing.value.code == "collection_changed"

    class UnadvanceableSession:
        async def execute(self, statement):
            return SimpleNamespace(rowcount=0)

    with pytest.raises(ApiError) as entries_limit:
        await entries_api._increment_entries_revision(UnadvanceableSession(), owner)
    assert entries_limit.value.status_code == 503
    assert entries_limit.value.headers == {"Retry-After": "1"}

    with pytest.raises(ApiError) as notes_limit:
        await therapist_api._increment_notes_revision(UnadvanceableSession(), owner)
    assert notes_limit.value.status_code == 503
    assert notes_limit.value.headers == {"Retry-After": "1"}


async def test_snapshot_pages_fail_closed_if_marker_moves_during_assembly(client, monkeypatch):
    """A post-selection marker check catches a bypassed second worker."""
    from app.api import entries as entries_api
    from app.api import therapist as therapist_api

    owner = ClientEmulator("revision-moving-owner", "pw")
    await owner.register(client)

    async def owner_revisions(session, user_id):
        return next(owner_revision_values)

    owner_revision_values = iter((0, 1))
    monkeypatch.setattr(entries_api, "current_entries_revision", owner_revisions)
    owner_page = await client.get("/api/entries", headers=owner.headers)
    _assert_stale(owner_page, "X-Entries-Revision", "1")

    patient, therapist = await _shared_pair(client, "moving")

    async def therapist_entry_revisions(session, user_id):
        return next(therapist_entry_revision_values)

    therapist_entry_revision_values = iter((0, 1))
    monkeypatch.setattr(therapist_api, "current_entries_revision", therapist_entry_revisions)
    entry_page = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries", headers=therapist.headers
    )
    _assert_stale(entry_page, "X-Entries-Revision", "1")

    async def therapist_note_revisions(session, therapist_id):
        return next(therapist_note_revision_values)

    therapist_note_revision_values = iter((0, 1))
    monkeypatch.setattr(therapist_api, "_current_notes_revision", therapist_note_revisions)
    note_page = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
    )
    _assert_stale(note_page, "X-Notes-Revision", "1")
