"""Voice attachment API (P2): storage, quota, expiry, IDOR, therapist gate.

VOICE_PLAN.md gates for this phase:
  * one opaque attachment per entry, upsert-replace semantics
  * 30-day retention: lazy expiry on fetch + the sweep function
  * per-user byte quota over LIVE (unexpired) attachments
  * owner-only fetch/delete (flat 404 for anyone else)
  * therapist fetch needs an ACTIVE consent WITH share_voice, and every
    served fetch writes an audit row
  * entry deletion cascades to the recording (object first, then row)
  * listings carry non-secret audio metadata only

The suite runs against the LocalAudioStore (the dev default): a real
filesystem store, so object lifecycles are asserted on actual files.
"""

from __future__ import annotations

import base64

import pytest
from datetime import date, timedelta

from sqlalchemy import select, update

from app.models import AccessLog, AudioAttachment, Consent, Entry, User, utcnow
from app.services.audio_store import LocalAudioStore, sweep_expired_audio
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for

TODAY = date.today()


@pytest.fixture(autouse=True)
def _scratch_audio_store(settings, tmp_path):
    """Per-test object store: the dev default (./data/audio) is a SHARED
    directory that would leak objects between tests — every test in this
    module gets its own scratch dir instead."""
    settings.audio_local_dir = str(tmp_path / "audio")


async def _voice_ready(client, settings, name="vuser") -> ClientEmulator:
    """Registered + voice-consented patient with the feature on."""
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    emu = ClientEmulator(name, "correct horse battery staple")
    await emu.register(client)
    response = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 200, response.text
    return emu


DEFAULT_AUDIO = b"RIFF-audio-blob" + b"0" * 48  # comfortably past MIN_BLOB_SIZE


def _attachment_body(entry_id: str, audio: bytes = DEFAULT_AUDIO, duration: int = 60):
    return {
        "client_entry_id": entry_id,
        "blob": base64.b64encode(audio).decode("ascii"),
        "mime": "audio/webm",
        "duration_seconds": duration,
    }


async def _make_entry(client, emu, entry_id="e-audio-1") -> str:
    await emu.create_entry(client, "a voice journal day", TODAY, client_entry_id=entry_id)
    return entry_id


def _store(app) -> LocalAudioStore:
    from app.services.audio_store import get_audio_store

    store = get_audio_store(app.state.settings)
    assert isinstance(store, LocalAudioStore)
    return store


async def _stored_objects(app) -> set:
    return {p.name for p in _store(app).root.rglob("*.enc")}


# --- upload & fetch --------------------------------------------------------------


async def test_upload_requires_consent_and_entry(client, settings):
    emu = ClientEmulator("noconsent2", "correct horse battery staple")
    await emu.register(client)
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    no_entry = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body("never-created"),
    )
    assert no_entry.status_code == 403
    assert no_entry.json()["code"] == "voice_consent_required"

    emu2 = await _voice_ready(client, settings, "noentry")
    unknown = await client.post(
        "/api/v1/audio/attachments",
        headers=emu2.headers,
        json=_attachment_body("never-created"),
    )
    assert unknown.status_code == 404
    assert unknown.json()["code"] == "unknown_entry"


async def test_upload_fetch_roundtrip_and_expiry_metadata(client, app, settings):
    emu = await _voice_ready(client, settings, "roundtrip2")
    entry_id = await _make_entry(client, emu, "e-rt")

    created = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body(entry_id, audio=b"RIFF-opus-take-one" + b"1" * 32),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["size_bytes"] == len(b"RIFF-opus-take-one" + b"1" * 32)
    # 30-day retention is the contract the disclosure copy states.
    assert body["expires_at"] > (utcnow() + timedelta(days=29)).isoformat()

    fetched = await client.get(
        f"/api/v1/audio/attachments/{body['attachment_id']}", headers=emu.headers
    )
    assert fetched.status_code == 200
    assert base64.b64decode(fetched.json()["blob"]) == b"RIFF-opus-take-one" + b"1" * 32
    assert fetched.json()["client_entry_id"] == entry_id
    # Exactly one object exists in the store.
    assert len(await _stored_objects(app)) == 1

    # The patient's entries page carries non-secret audio metadata.
    listing = await client.get("/api/entries", headers=emu.headers)
    assert listing.status_code == 200
    mine = [e for e in listing.json() if e["client_entry_id"] == entry_id]
    assert mine and mine[0]["audio"]["attachment_id"] == body["attachment_id"]
    assert "blob" not in mine[0]["audio"]


async def test_upload_replaces_previous_object(client, app, settings):
    emu = await _voice_ready(client, settings, "replace")
    entry_id = await _make_entry(client, emu, "e-replace")

    first = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body(entry_id, audio=b"take-one" + b"a" * 40),
        )
    ).json()
    second = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body(entry_id, audio=b"take-two-longer" + b"b" * 40),
        )
    ).json()
    # Same row (one attachment per entry), new object, old one gone.
    assert second["attachment_id"] == first["attachment_id"]
    objects = await _stored_objects(app)
    assert len(objects) == 1
    fetched = await client.get(
        f"/api/v1/audio/attachments/{first['attachment_id']}", headers=emu.headers
    )
    assert base64.b64decode(fetched.json()["blob"]) == b"take-two-longer" + b"b" * 40

    rows = await _run(app, select(AudioAttachment).where(AudioAttachment.user_id == emu.user_id))
    assert len(rows) == 1


async def _run(app, query):
    async with app.state.sessionmaker() as session:
        return list((await session.execute(query)).scalars().all())


async def test_quota_bounds_live_attachments(client, settings):
    settings.audio_max_user_bytes = 1024 * 20  # tiny on purpose
    emu = await _voice_ready(client, settings, "quota")
    e1 = await _make_entry(client, emu, "e-q1")
    await emu.create_entry(client, "second day", TODAY, client_entry_id="e-q2")
    ok = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body(e1, audio=b"x" * 8192),
    )
    assert ok.status_code == 201
    full = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body("e-q2", audio=b"y" * 16384),
    )
    assert full.status_code == 413
    assert full.json()["code"] == "audio_quota_exceeded"
    # Replacing the SAME entry's attachment adjusts, not double-counts.
    replace = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body(e1, audio=b"z" * 16384),
    )
    assert replace.status_code == 201


async def test_lazy_expiry_answers_410_and_cleans_up(client, app, settings):
    emu = await _voice_ready(client, settings, "expired")
    entry_id = await _make_entry(client, emu, "e-exp")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body(entry_id),
        )
    ).json()

    # Age the row past its window directly (the sweeper's clock, sped up).
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(AudioAttachment)
            .where(AudioAttachment.id == created["attachment_id"])
            .values(expires_at=utcnow() - timedelta(days=1))
        )
        await session.commit()

    gone = await client.get(
        f"/api/v1/audio/attachments/{created['attachment_id']}", headers=emu.headers
    )
    assert gone.status_code == 410
    assert gone.json()["code"] == "audio_expired"
    # Row AND object are gone; the entry metadata no longer advertises audio.
    assert await _run(app, select(AudioAttachment)) == []
    assert await _stored_objects(app) == set()
    listing = await client.get("/api/entries", headers=emu.headers)
    mine = [e for e in listing.json() if e["client_entry_id"] == entry_id]
    assert mine[0]["audio"] is None


async def test_sweep_function_deletes_expired_batch(client, app, settings):
    emu = await _voice_ready(client, settings, "sweeper")
    await _make_entry(client, emu, "e-sweep")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body("e-sweep"),
        )
    ).json()
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(AudioAttachment)
            .where(AudioAttachment.id == created["attachment_id"])
            .values(expires_at=utcnow() - timedelta(days=2))
        )
        await session.commit()

        store = _store(app)
        swept = await sweep_expired_audio(session, store)
        assert swept == 1
        remaining = await sweep_expired_audio(session, store)
        assert remaining == 0
    assert await _run(app, select(AudioAttachment)) == []
    assert await _stored_objects(app) == set()


async def test_idor_on_fetch_and_delete(client, settings):
    emu = await _voice_ready(client, settings, "owner")
    entry_id = await _make_entry(client, emu, "e-idor")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body(entry_id),
        )
    ).json()

    stranger = ClientEmulator("stranger", "correct horse battery staple")
    await stranger.register(client)
    for method in ("get", "delete"):
        response = await getattr(client, method)(
            f"/api/v1/audio/attachments/{created['attachment_id']}",
            headers=stranger.headers,
        )
        assert response.status_code == 404  # flat: no existence oracle
    # Owner can still fetch.
    ok = await client.get(
        f"/api/v1/audio/attachments/{created['attachment_id']}", headers=emu.headers
    )
    assert ok.status_code == 200


async def test_patient_delete_recording_keeps_entry(client, app, settings):
    emu = await _voice_ready(client, settings, "delaudio")
    entry_id = await _make_entry(client, emu, "e-del")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json=_attachment_body(entry_id),
        )
    ).json()

    deleted = await client.delete(
        f"/api/v1/audio/attachments/{created['attachment_id']}", headers=emu.headers
    )
    assert deleted.status_code == 204
    assert await _run(app, select(AudioAttachment)) == []
    assert await _stored_objects(app) == set()
    # The entry itself survived.
    entry = await client.get(f"/api/entries/{entry_id}", headers=emu.headers)
    assert entry.status_code == 200


async def test_entry_deletion_cascades_to_recording(client, app, settings):
    emu = await _voice_ready(client, settings, "delentry")
    entry_id = await _make_entry(client, emu, "e-cascade")
    response = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body(entry_id),
    )
    assert response.status_code == 201
    assert await _stored_objects(app)

    response = await client.delete(f"/api/entries/{entry_id}", headers=emu.headers)
    assert response.status_code == 204
    assert await _run(app, select(AudioAttachment)) == []
    assert await _stored_objects(app) == set()
    # the entry cascade prunes the account's now-empty directory too
    assert not (_store(app).root / "audio" / emu.user_id).exists()


async def test_local_store_prunes_empty_user_dirs(tmp_path):
    """Store-level pin of the directory prune (2026-09-29 E2E finding):
    deleting an object removes the account's directory once it is empty —
    an erasure must not leave the erased account's id as a directory name —
    while a directory that still holds an object, or another account's
    directory, is untouched."""
    store = LocalAudioStore(str(tmp_path / "store"))
    await store.put("audio/u1/aaa.enc", b"a" * 40)
    await store.put("audio/u1/bbb.enc", b"b" * 40)
    await store.put("audio/u2/ccc.enc", b"c" * 40)
    u1, u2 = store.root / "audio" / "u1", store.root / "audio" / "u2"

    await store.delete("audio/u1/aaa.enc")
    assert u1.is_dir() and (u1 / "bbb.enc").exists()  # one object left

    await store.delete("audio/u1/bbb.enc")
    assert not u1.exists()  # last object: pruned
    assert u2.is_dir() and (u2 / "ccc.enc").exists()  # others untouched

    await store.delete("audio/u1/bbb.enc")  # idempotent re-delete
    assert not u1.exists()


async def test_storage_unconfigured_is_503(client, settings):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    settings.audio_local_dir = ""
    settings.environment = "production-like-nope"  # kills the dev local fallback
    settings.audio_bucket = ""
    emu = ClientEmulator("nostore", "correct horse battery staple")
    await emu.register(client)
    await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    response = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json=_attachment_body("whatever"),
    )
    assert response.status_code == 503
    assert response.json()["code"] == "audio_storage_unconfigured"


# --- therapist gate ----------------------------------------------------------------


async def _patient_with_therapist(client, settings, name="shared"):
    """Patient + therapist pair with an ACTIVE consent; returns
    (patient, therapist, consent_id)."""
    patient = await _voice_ready(client, settings, name)
    therapist = TherapistEmulator(f"dr{name}", "correct horse battery staple")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    grant = await patient.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    assert grant["status"] == 201, grant["body"]
    return patient, therapist, grant["body"]["id"]


async def test_therapist_audio_requires_share_voice_flag(client, app, settings):
    patient, therapist, consent_id = await _patient_with_therapist(client, settings, "sh1")
    entry_id = await _make_entry(client, patient, "e-t1")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=patient.headers,
            json=_attachment_body(entry_id),
        )
    ).json()

    # Default-off: active consent, text entries readable, voice NOT.
    denied = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{created['attachment_id']}",
        headers=therapist.headers,
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "consent_voice_share_required"
    # No audio_access audit row was written for the refusal.
    actions = [
        row.action
        for row in await _run(app, select(AccessLog).where(AccessLog.user_id == patient.user_id))
    ]
    assert "audio_access" not in actions

    # Patient flips the grant (verifier re-auth required).
    missing_verifier = await client.put(
        f"/api/consents/{consent_id}/share-voice", headers=patient.headers, json={"enabled": True}
    )
    assert missing_verifier.status_code == 403
    assert missing_verifier.json()["code"] == "step_up_required"
    enabled = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["share_voice"] is True

    served = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{created['attachment_id']}",
        headers=therapist.headers,
    )
    assert served.status_code == 200, served.text
    assert base64.b64decode(served.json()["blob"]) == DEFAULT_AUDIO
    # Exactly one audio_access audit row, from the therapist.
    audio_rows = await _run(
        app,
        select(AccessLog).where(
            AccessLog.user_id == patient.user_id, AccessLog.action == "audio_access"
        ),
    )
    assert len(audio_rows) == 1
    assert audio_rows[0].actor_id == therapist.user_id

    # Turning the grant back off re-closes the door.
    disabled = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    reclosed = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{created['attachment_id']}",
        headers=therapist.headers,
    )
    assert reclosed.status_code == 403


async def test_therapist_cannot_read_other_patients_audio(client, settings):
    patient, therapist, _ = await _patient_with_therapist(client, settings, "sh2")
    other = await _voice_ready(client, settings, "othervictim")
    other_entry = await _make_entry(client, other, "e-other")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=other.headers,
            json=_attachment_body(other_entry),
        )
    ).json()
    response = await client.get(
        f"/api/therapist/patients/{other.user_id}/audio/{created['attachment_id']}",
        headers=therapist.headers,
    )
    # No consent with 'other' at all: the patient wall answers first.
    assert response.status_code == 404


async def test_share_voice_on_revoked_consent_is_409(client, settings):
    patient, therapist, consent_id = await _patient_with_therapist(client, settings, "sh3")
    revoked = await patient.revoke_consent(client, consent_id)
    assert revoked == 204
    response = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert response.status_code == 409


async def test_therapist_expired_audio_is_410_and_unaudited(client, app, settings):
    patient, therapist, consent_id = await _patient_with_therapist(client, settings, "sh4")
    entry_id = await _make_entry(client, patient, "e-t4")
    created = (
        await client.post(
            "/api/v1/audio/attachments",
            headers=patient.headers,
            json=_attachment_body(entry_id),
        )
    ).json()
    await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(AudioAttachment)
            .where(AudioAttachment.id == created["attachment_id"])
            .values(expires_at=utcnow() - timedelta(days=1))
        )
        await session.commit()

    gone = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{created['attachment_id']}",
        headers=therapist.headers,
    )
    assert gone.status_code == 410
    audio_rows = await _run(
        app,
        select(AccessLog).where(
            AccessLog.user_id == patient.user_id, AccessLog.action == "audio_access"
        ),
    )
    assert audio_rows == []  # nothing was served


async def test_consent_listing_carries_share_voice(client, settings):
    patient, _, consent_id = await _patient_with_therapist(client, settings, "sh5")
    before = await client.get("/api/consents", headers=patient.headers)
    assert before.json()[0]["share_voice"] is False
    await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    after = await client.get("/api/consents", headers=patient.headers)
    assert after.json()[0]["share_voice"] is True
