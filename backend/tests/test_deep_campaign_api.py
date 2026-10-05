"""Independent committed-state and semantic-input oracles for API campaigns."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import Response
from sqlalchemy import func, select

from app.api import _audit, _custody, _paging, account, audio, insights
from app.deps import ApiError
from app.models import (
    AccessLog,
    AuditSweepCursor,
    Consent,
    ConsentEvent,
    Insight,
    Measure,
    RekeyJournal,
    TherapistNoteRevision,
    User,
)
from app.schemas import RekeyRequest
from tests.helpers import ClientEmulator, TherapistEmulator


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def test_ciphertext_page_preserves_every_continuation():
    requested = [("one", 4), ("two", 5), ("three", 4)]
    first = _paging.select_byte_page(
        requested, more_after_request=False, page_bytes=9, hard_budget=20, collection="entry"
    )
    assert first.selected == requested[:2] and first.has_more
    second = _paging.select_byte_page(
        requested[2:], more_after_request=False, page_bytes=9, hard_budget=20, collection="entry"
    )
    assert second.selected == requested[2:] and not second.has_more
    response = Response()
    _paging.emit_page_headers(
        response,
        revision=7,
        header_name="X-Entries-Revision",
        has_more=True,
        rows_returned=2,
        offset=11,
    )
    assert response.headers["X-Next-Offset"] == "13"
    assert response.headers["X-Entries-Revision"] == "7"


def test_legacy_and_first_oversize_pages_fail_loudly():
    for page_bytes in (None, 3):
        with pytest.raises(ApiError) as failure:
            _paging.select_byte_page(
                [("one", 5)],
                more_after_request=False,
                page_bytes=page_bytes,
                hard_budget=4,
                collection="entry",
            )
        assert (failure.value.status_code, failure.value.code) == (413, "payload_too_large")


def test_metadata_fetch_drift_cannot_be_reported_as_complete_history():
    with pytest.raises(ApiError) as missing:
        _paging.verify_fetched_page(
            ["one", "two"],
            [SimpleNamespace(id="one", blob=b"a")],
            byte_limit=10,
            collection="entries",
            header_name="X-Entries-Revision",
            revision=8,
        )
    assert (missing.value.status_code, missing.value.code) == (409, "collection_changed")
    with pytest.raises(ApiError):
        _paging.verify_fetched_page(
            ["one"],
            [SimpleNamespace(id="one", blob=b"oversized")],
            byte_limit=3,
            collection="entries",
            header_name="X-Entries-Revision",
            revision=8,
        )


async def test_measure_correction_is_owner_scoped_and_recovers_count(client, app):
    patients = [
        ClientEmulator("deep-measure-a", "password"),
        ClientEmulator("deep-measure-b", "password"),
    ]
    for patient in patients:
        await patient.register(client)
        response = await client.post(
            "/api/measures",
            headers=patient.headers,
            json={
                "client_measure_id": "same-id",
                "blob": _b64(os.urandom(40)),
                "measure_date": date.today().isoformat(),
            },
        )
        assert response.status_code == 201, response.text
    first = patients[0]
    response = await client.delete(
        "/api/measures/same-id", headers={**first.headers, "X-Account-Verifier": first.auth_key_b64}
    )
    assert response.status_code == 200, response.text
    async with app.state.sessionmaker() as session:
        assert list((await session.scalars(select(Measure.user_id))).all()) == [patients[1].user_id]
        counters = {
            patient.user_id: (await session.get(User, patient.user_id)).measure_count
            for patient in patients
        }
        assert counters == {patients[0].user_id: 0, patients[1].user_id: 1}


def test_provider_choice_is_not_current_authorization(settings):
    user = SimpleNamespace(
        llm_consent=True,
        llm_consent_at=datetime.now(timezone.utc),
        llm_consent_disclosure="obsolete",
        llm_consent_policy="obsolete",
        voice_consent=True,
        voice_consent_at=datetime.now(timezone.utc),
        voice_consent_disclosure="obsolete",
        voice_consent_policy="obsolete",
    )
    llm, voice = (
        account._consent_response(user, settings),
        account._voice_consent_response(user, settings),
    )
    assert llm.enabled and voice.enabled
    assert not llm.active_for_current_policy and not voice.active_for_current_policy


@pytest.mark.parametrize("kind", ["voice", "llm"])
async def test_provider_withdrawal_clears_live_grant_and_preserves_decision_evidence(
    client, app, settings, kind
):
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "key"
    settings.llm_url = "https://llm.example.com/v1"
    settings.llm_api_key = "key"
    patient = ClientEmulator(f"deep-provider-withdrawal-{kind}", "password")
    await patient.register(client)
    endpoint = f"/api/account/{kind}-consent"
    grant = await client.put(
        endpoint,
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert grant.status_code == 200, grant.text
    policy = grant.json()[f"{kind}_consent_policy"]
    disclosure = grant.json()[f"{kind}_consent_disclosure"]
    assert policy and disclosure and grant.json()["active_for_current_policy"]
    withdrawal = await client.put(
        endpoint,
        headers=patient.headers,
        json={"enabled": False, "verifier": patient.auth_key_b64},
    )
    assert withdrawal.status_code == 200, withdrawal.text
    assert withdrawal.json()[f"{kind}_consent_policy"] is None
    assert withdrawal.json()[f"{kind}_consent_disclosure"] is None
    assert withdrawal.json()[f"{kind}_consent_at"] is None
    assert not withdrawal.json()["enabled"]
    async with app.state.sessionmaker() as session:
        user = await session.get(User, patient.user_id)
        assert (
            getattr(user, f"{kind}_consent"),
            getattr(user, f"{kind}_consent_at"),
            getattr(user, f"{kind}_consent_disclosure"),
            getattr(user, f"{kind}_consent_policy"),
        ) == (False, None, None, None)
        events = (
            await session.scalars(
                select(ConsentEvent)
                .where(ConsentEvent.user_id == patient.user_id, ConsentEvent.kind == kind)
                .order_by(ConsentEvent.occurred_at, ConsentEvent.id)
            )
        ).all()
        assert [event.action for event in events] == ["granted", "withdrawn"]
        assert [(event.policy, event.disclosure) for event in events] == [
            (policy, disclosure),
            (policy, disclosure),
        ]


async def test_export_retains_all_snapshot_chunks_when_byte_pages_are_short(
    client, app, monkeypatch
):
    patient = ClientEmulator("deep-export-chunks", "password")
    await patient.register(client)
    base = datetime.now(timezone.utc) - timedelta(days=1)
    expected = [f"deep-kind-{index}" for index in range(5)]
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Insight(
                    user_id=patient.user_id,
                    kind=kind,
                    for_date=None,
                    blob=bytes([index]) * 40,
                    created_at=base + timedelta(microseconds=index),
                )
                for index, kind in enumerate(expected)
            ]
        )
        await session.commit()
    monkeypatch.setattr(account, "EXPORT_METADATA_PAGE_SIZE", 2)
    monkeypatch.setattr(account, "EXPORT_PAGE_BLOB_BYTES", 50)
    response = await client.get("/api/account/export", headers=patient.headers)
    assert response.status_code == 200, response.text
    rows = response.json()["insights"]
    assert [row["kind"] for row in rows] == expected
    assert [base64.b64decode(row["blob"]) for row in rows] == [
        bytes([index]) * 40 for index in range(5)
    ]


async def test_completed_export_releases_capacity_for_next_download(client, app):
    import anyio

    patient = ClientEmulator("deep-export-capacity", "password")
    await patient.register(client)
    app.state.export_limiter = anyio.CapacityLimiter(1)
    for _ in range(2):
        response = await client.get("/api/account/export", headers=patient.headers)
        assert response.status_code == 200, response.text
        assert response.json()["user_id"] == patient.user_id
        assert app.state.export_limiter.borrowed_tokens == 0


async def test_v2_export_remains_decryptable_with_only_password_after_account_erasure(
    client, monkeypatch
):
    from app.security import crypto, envelope, kdf
    from tests.helpers import EnvelopeClientEmulator

    password = "export must retain the only random-key locker"
    patient = EnvelopeClientEmulator("deep-v2-offline-export", password)
    patient.kdf_params = kdf.validate_kdf_params(patient.kdf_params)

    # Unlike the fast generic emulator, this fixture uses the advertised
    # production KDF cost, so the exported parameters alone recover the KEK.
    def real_kek(secret, salt):
        return envelope.envelope_kek(
            kdf.derive_master_key(secret, salt, patient.kdf_params["iterations"]), salt
        )

    patient.master_key = kdf.derive_master_key(password, patient.salt)
    patient.auth_key = kdf.derive_auth_key(patient.master_key)
    monkeypatch.setattr(patient, "kek_for", real_kek)
    await patient.register(client)
    await patient.create_entry(
        client,
        "portable synthetic ciphertext remains useful after deletion",
        date.today(),
        "portable-v2-entry",
        content_version=1,
    )
    exported = await client.get("/api/account/export", headers=patient.headers)
    assert exported.status_code == 200, exported.text
    bundle = exported.json()
    assert bundle["key_scheme"] == "v2"
    assert bundle["wrapped_data_key"] is not None
    erased = await client.delete(
        "/api/account", headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64}
    )
    assert erased.status_code == 204, erased.text
    parameters = kdf.validate_kdf_params(bundle["kdf_params"])
    salt = base64.b64decode(bundle["salt"])
    master = kdf.derive_master_key(password, salt, parameters["iterations"])
    recovered_key = envelope.unwrap_data_key(
        base64.b64decode(bundle["wrapped_data_key"]),
        kek=envelope.envelope_kek(master, salt),
        username=bundle["username"],
        kdf_params=parameters,
    )
    entry = bundle["entries"][0]
    plain = json.loads(
        crypto.decrypt(
            recovered_key,
            base64.b64decode(entry["blob"]),
            crypto.entry_aad_v2(
                bundle["user_id"], entry["client_entry_id"], entry["content_version"]
            ),
        )
    )
    assert plain["text"] == "portable synthetic ciphertext remains useful after deletion"


async def test_recording_identity_stays_bound_to_patient_in_shared_reads_and_deletes(
    client, app, settings, tmp_path
):
    from tests.test_audio_attachments import (
        DEFAULT_AUDIO,
        _attachment_body,
        _make_entry,
        _voice_ready,
    )

    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "deep-audio-visible")
    owner = await _voice_ready(client, settings, "deep-audio-owner")
    clinician = TherapistEmulator("deep-audio-clinician", "password")
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    grant = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
    assert grant["status"] == 201, grant
    enabled = await client.put(
        f"/api/consents/{grant['body']['id']}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    entry_id = await _make_entry(client, owner, "deep-owned-recording")
    upload = await client.post(
        "/api/v1/audio/attachments",
        headers=owner.headers,
        json=_attachment_body(entry_id),
    )
    assert upload.status_code == 201, upload.text
    attachment_id = upload.json()["attachment_id"]
    denied = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{attachment_id}",
        headers=clinician.headers,
    )
    assert denied.status_code == 404, denied.text
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(func.count(AccessLog.id)).where(
                    AccessLog.actor_id == clinician.user_id, AccessLog.action == "audio_access"
                )
            )
        ) == 0
    deleted = await client.delete(
        f"/api/v1/audio/attachments/{attachment_id}", headers=patient.headers
    )
    assert deleted.status_code == 404, deleted.text
    preserved = await client.get(
        f"/api/v1/audio/attachments/{attachment_id}", headers=owner.headers
    )
    assert preserved.status_code == 200, preserved.text
    assert base64.b64decode(preserved.json()["blob"]) == DEFAULT_AUDIO


async def test_baseline_hides_stored_pattern_ciphertext_from_patient_and_clinician(client, app):
    patient = ClientEmulator("deep-baseline-patient", "password")
    clinician = TherapistEmulator("deep-baseline-clinician", "password")
    await patient.register(client)
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    grant = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
    assert grant["status"] == 201, grant
    residual_blob = b"prior insight phase ciphertext" * 2
    async with app.state.sessionmaker() as session:
        session.add(
            Insight(
                user_id=patient.user_id,
                kind="patterns",
                for_date=None,
                blob=residual_blob,
                state_seq=8,
            )
        )
        await session.commit()
    endpoints = [
        ("/api/insights", patient.headers),
        (f"/api/therapist/patients/{patient.user_id}/insights", clinician.headers),
    ]
    for endpoint, headers in endpoints:
        response = await client.get(endpoint, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["phase"] == "baseline"
        assert response.json()["blob"] is None
        assert response.json()["state_seq"] == 8


async def test_active_pairing_wrap_refresh_requires_a_new_voice_choice(client, app, settings):
    settings.audio_enabled = True
    patient = ClientEmulator("deep-active-refresh-patient", "password")
    clinician = TherapistEmulator("deep-active-refresh-clinician", "password")
    await patient.register(client)
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    first = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
    assert first["status"] == 201, first
    consent_id = first["body"]["id"]
    enabled = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    new_code = await clinician.create_pairing_code(client)
    refreshed = await patient.grant_consent(
        client, new_code, clinician.wrap_pub_key, clinician.user_id
    )
    assert refreshed["status"] == 201, refreshed
    assert refreshed["body"]["id"] == consent_id
    assert refreshed["body"]["share_voice"] is False
    async with app.state.sessionmaker() as session:
        row = await session.get(Consent, consent_id)
        assert row.status == "active" and row.share_voice is False
        choices = (
            await session.scalars(
                select(ConsentEvent)
                .where(
                    ConsentEvent.consent_id == consent_id,
                    ConsentEvent.kind == "sharing",
                    ConsentEvent.action == "granted",
                )
                .order_by(ConsentEvent.occurred_at, ConsentEvent.id)
            )
        ).all()
        assert [choice.share_voice for choice in choices] == [False, False]


async def test_equal_ciphertext_duplicate_note_cannot_resolve_to_another_chart(client):
    clinician = TherapistEmulator("deep-note-collision-clinician", "password")
    patients = [
        ClientEmulator("deep-note-collision-first", "password"),
        ClientEmulator("deep-note-collision-second", "password"),
    ]
    await clinician.register(client)
    for patient in patients:
        await patient.register(client)
        code = await clinician.create_pairing_code(client)
        grant = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
        assert grant["status"] == 201, grant
    body = {
        "client_note_id": "same-client-note-id",
        "blob": clinician.encrypt_note(patients[0], "same-client-note-id", "first private chart"),
    }
    first = await client.post(
        f"/api/therapist/patients/{patients[0].user_id}/notes", headers=clinician.headers, json=body
    )
    assert first.status_code == 201, first.text
    other_chart = await client.post(
        f"/api/therapist/patients/{patients[1].user_id}/notes", headers=clinician.headers, json=body
    )
    assert other_chart.status_code == 409, other_chart.text
    assert other_chart.json()["code"] == "conflict"
    original = await client.get(
        f"/api/therapist/patients/{patients[0].user_id}/notes", headers=clinician.headers
    )
    second = await client.get(
        f"/api/therapist/patients/{patients[1].user_id}/notes", headers=clinician.headers
    )
    assert [row["id"] for row in original.json()] == [first.json()["id"]]
    assert second.status_code == 200 and second.json() == []


@pytest.mark.parametrize("current,expected,target,status", [(1, 1, 3, 422), (2, 1, 2, 409)])
def test_custody_successor_and_compare_exchange(current, expected, target, status):
    with pytest.raises(ApiError) as failure:
        _custody._check_version(
            SimpleNamespace(custody_version=current),
            SimpleNamespace(expected_custody_version=expected, custody_version=target),
        )
    assert failure.value.status_code == status


async def _install_custody(client, therapist):
    response = await client.put(
        "/api/therapist/custody",
        headers=therapist.headers,
        json={
            "verifier": therapist.auth_key_b64,
            "operation_id": str(uuid.uuid4()),
            "expected_custody_version": 0,
            "custody_version": 1,
            "notes_keyring_blob": _b64(os.urandom(60)),
        },
    )
    assert response.status_code == 204, response.text


async def test_sharing_identity_change_retires_all_grant_material(client, app):
    patient = ClientEmulator("deep-identity-patient", "password")
    clinician, replacement = (
        TherapistEmulator("deep-identity-clinician", "password"),
        TherapistEmulator("deep-replacement", "password"),
    )
    await patient.register(client)
    await clinician.register(client)
    await _install_custody(client, clinician)
    code = await clinician.create_pairing_code(client)
    granted = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
    assert granted["status"] == 201, granted
    consent_id = granted["body"]["id"]
    async with app.state.sessionmaker() as session:
        consent = await session.get(Consent, consent_id)
        (
            consent.share_voice,
            consent.summary_blob,
            consent.summary_eph_pub,
            consent.summary_updated_at,
        ) = True, b"prior summary ciphertext", "prior ephemeral", datetime.now(timezone.utc)
        await session.commit()
    response = await client.put(
        "/api/therapist/wrap-key",
        headers={**clinician.headers, "X-Account-Verifier": clinician.auth_key_b64},
        json={
            "wrap_pub_key": replacement.wrap_pub_key,
            "wrap_key_blob": _b64(os.urandom(60)),
            "expected_custody_version": 1,
        },
    )
    assert response.status_code == 204, response.text
    async with app.state.sessionmaker() as session:
        consent = await session.get(Consent, consent_id)
        assert consent.status == "revoked" and not consent.share_voice
        assert (
            consent.wrapped_key,
            consent.ephemeral_pub,
            consent.summary_blob,
            consent.summary_eph_pub,
            consent.summary_updated_at,
        ) == (None,) * 5
    refused = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries", headers=clinician.headers
    )
    assert refused.status_code == 404


async def test_identity_rotation_requires_installed_current_custody(client):
    clinician = TherapistEmulator("deep-custody-before-identity", "password")
    await clinician.register(client)
    headers = {**clinician.headers, "X-Account-Verifier": clinician.auth_key_b64}
    body = {
        "wrap_pub_key": clinician.wrap_pub_key,
        "wrap_key_blob": _b64(os.urandom(60)),
        "expected_custody_version": 0,
    }
    refused = await client.put("/api/therapist/wrap-key", headers=headers, json=body)
    assert refused.status_code == 409, refused.text
    await _install_custody(client, clinician)
    stale = await client.put("/api/therapist/wrap-key", headers=headers, json=body)
    assert stale.status_code == 409, stale.text


def test_transcription_decode_enforces_decoded_provider_budget():
    with pytest.raises(ApiError) as failure:
        audio._decode_audio(_b64(b"four"), SimpleNamespace(audio_max_body_bytes=3))
    assert (failure.value.status_code, failure.value.code) == (413, "audio_too_large")


def _payload(**changes):
    return bytearray(
        json.dumps({"text": "the original words", "created_at": "2026-01-02", **changes}).encode()
    )


def test_analysis_uses_server_calendar_and_correct_voice_channel():
    parsed = insights._parse_entries(
        [_payload(transcript_lang="fr", english_text="English translation")], [date(2026, 1, 3)]
    )
    assert parsed[0].entry_date == date(2026, 1, 3) and parsed[0].text == "English translation"
    native = insights._parse_entries(
        [_payload(transcript_lang="es", english_text="English translation")], [date(2026, 1, 2)]
    )
    assert native[0].text == "the original words"


@pytest.mark.parametrize(
    "payload",
    [
        {"created_at": "2026-02-02"},
        {"sleep": 0},
        {"sleep": 6},
        {"sentiment": True},
        {"sentiment": float("nan")},
        {"energy": float("inf")},
    ],
)
def test_analysis_rejects_semantically_invalid_authenticated_payload(payload):
    with pytest.raises(ValueError):
        insights._parse_entries([_payload(**payload)], [date(2026, 1, 2)])


def test_feedback_truth_is_a_boolean_choice():
    with pytest.raises(ApiError) as failure:
        insights._parse_feedback(
            json.dumps({"feedback": [{"pid": "temporal:work", "resonated": 1}]}).encode()
        )
    assert failure.value.code == "entry_payload_malformed"


@pytest.mark.parametrize("field", ["muted", "unmuted"])
@pytest.mark.parametrize("value", [None, "temporal:work", {"pid": "temporal:work"}, 1, False])
def test_feedback_does_not_silently_drop_supplied_wrong_shape(field, value):
    raw = json.dumps({"feedback": [], field: value}).encode()
    with pytest.raises(ApiError) as failure:
        insights._parse_feedback(raw)
    assert (failure.value.status_code, failure.value.code) == (400, "entry_payload_malformed")


async def test_local_scope_claim_never_supplies_real_activity(client):
    patient = ClientEmulator("deep-local-claimed-scope", "password")
    await patient.register(client)
    declared = [(date.today() - timedelta(days=i)).isoformat() for i in range(35)]
    body = {
        "base_state_seq": 0,
        "state_blob": _b64(os.urandom(40)),
        "patterns_blob": _b64(os.urandom(40)),
        "analysis_dates": declared,
    }
    response = await client.post(
        "/api/insights/local-recompute", headers=patient.headers, json=body
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert (
        result["phase"],
        result["active_days"],
        result["patterns_stored"],
        result["state_seq"],
    ) == ("baseline", 0, 0, 1)
    malformed = await client.post(
        "/api/insights/local-recompute",
        headers=patient.headers,
        json={**body, "base_state_seq": 1, "analysis_dates": ["2026-02-30"]},
    )
    assert malformed.status_code == 422, malformed.text


async def test_resume_journal_binds_operation_even_for_same_payload_and_keys(client, app, settings):
    patient = ClientEmulator("deep-rekey-operation", "password")
    await patient.register(client)
    old, new = bytearray(b"a" * 32), bytearray(b"b" * 32)
    body = RekeyRequest(
        operation_id=str(uuid.uuid4()), new_salt=_b64(b"s" * 16), new_verifier=_b64(b"v" * 32)
    )
    async with app.state.sessionmaker() as session:
        session.add(
            RekeyJournal(
                user_id=patient.user_id,
                stage="entries",
                operation_id=str(uuid.uuid4()),
                request_digest="identical-digest",
                old_key_fingerprint=hashlib.sha256(old).hexdigest(),
                new_key_fingerprint=hashlib.sha256(new).hexdigest(),
            )
        )
        await session.commit()
        with pytest.raises(ApiError) as failure:
            await insights._load_or_create_rekey_journal(
                session,
                patient.user_id,
                body=body,
                digest="identical-digest",
                old_key=old,
                new_key=new,
                settings=settings,
            )
        assert failure.value.code == "rekey_operation_conflict"


def test_audit_seals_bind_actor_role_and_chain_position():
    instant = datetime(2026, 1, 2, tzinfo=timezone.utc)
    one = _audit.compute_entry_hash(
        None, "actor", "owner", "read", instant, actor_role="therapist", record_version=2
    )
    changed = _audit.compute_entry_hash(
        None, "actor", "owner", "read", instant, actor_role="patient", record_version=2
    )
    assert one != changed
    key = b"k" * 32
    expected = hmac.new(key, f"owner:4:{one}".encode(), hashlib.sha256).hexdigest()
    assert _audit.compute_entry_mac(key, "owner", 4, one) == expected
    assert _audit.compute_entry_mac(key, "owner", 5, one) != expected


def test_journal_compaction_preserves_old_final_owner_evidence(tmp_path):
    owner, path = "a" * 32, tmp_path / "audit.log"
    path.write_text(f"{owner} 1 {'b' * 64} {'c' * 64} 2020-01-01T00:00:00+00:00\n")
    assert _audit.compact_audit_journal(str(path), "2026-01-01T00:00:00+00:00") == (1, 0)
    assert owner in path.read_text()


def test_signed_checkpoint_binds_position_and_resets_unsealed_history():
    keys = {1: b"k" * 32}
    cursor = AuditSweepCursor(
        id=1,
        last_user_id="owner-z",
        verification_owner_id="owner-z",
        verification_snapshot_head_seq=5,
        verification_snapshot_head_hash="a" * 64,
        verification_next_seq=3,
        verification_previous_hash="b" * 64,
        verification_rows_checked=2,
    )
    _audit.seal_verification_checkpoint(cursor, keys, 1)
    cursor.verification_next_seq = 4
    with pytest.raises(ApiError):
        _audit.authenticate_verification_checkpoint(cursor, keys, 1)
    unsealed = AuditSweepCursor(id=1, last_user_id="owner-z", verification_next_seq=1000)
    _audit.authenticate_verification_checkpoint(unsealed, keys, 1)
    assert unsealed.last_user_id is None and unsealed.verification_next_seq is None


async def test_retention_refuses_to_destroy_a_tampered_prefix(client, app, settings):
    patient = ClientEmulator("deep-tampered-retention", "password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(AccessLog).where(AccessLog.user_id == patient.user_id))
        row.actor_role = "forged-actor"
        await session.commit()
        with pytest.raises(ApiError) as failure:
            await _audit.prune_access_logs(
                session,
                cutoff=datetime.now(timezone.utc) + timedelta(days=1),
                mac_keys=settings.audit_mac_keyring,
                current_mac_key_version=settings.audit_mac_key_version,
            )
        assert failure.value.code == "audit_integrity_error"
        await session.rollback()
        assert (
            await session.scalar(
                select(func.count(AccessLog.id)).where(AccessLog.user_id == patient.user_id)
            )
            == 1
        )


async def _shared_revision_note(client, suffix):
    patient = ClientEmulator("deep-history-patient-" + suffix, "password")
    clinician = TherapistEmulator("deep-history-clinician-" + suffix, "password")
    await patient.register(client)
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    grant = await patient.grant_consent(client, code, clinician.wrap_pub_key, clinician.user_id)
    assert grant["status"] == 201
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=clinician.headers,
        json={
            "client_note_id": "history-note",
            "blob": clinician.encrypt_note(patient, "history-note", "first version"),
        },
    )
    assert created.status_code == 201, created.text
    note = created.json()
    for base, text in ((1, "second version"), (2, "third version")):
        edited = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=clinician.headers,
            json={
                "base_version": base,
                "blob": clinician.encrypt_note(patient, "history-note", text),
            },
        )
        assert edited.status_code == 200, edited.text
    return patient, clinician, note


async def test_note_history_continuation_refuses_a_changed_snapshot(client):
    patient, clinician, note = await _shared_revision_note(client, "snapshot")
    url = f"/api/therapist/notes/{note['id']}/revisions"
    first = await client.get(url, headers=clinician.headers, params={"limit": 1})
    assert first.status_code == 200, first.text
    assert (
        clinician.decrypt_note(patient, "history-note", first.json()[0]["blob"])["text"]
        == "second version"
    )
    marker = first.headers.get("X-Notes-Revision")
    assert marker is not None, "historical note pages must identify their snapshot"
    edited = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=clinician.headers,
        json={
            "base_version": 3,
            "blob": clinician.encrypt_note(patient, "history-note", "fourth version"),
        },
    )
    assert edited.status_code == 200, edited.text
    stale = await client.get(
        url,
        headers=clinician.headers,
        params={"limit": 1, "offset": 1, "expected_revision": marker},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "collection_changed", stale.text


async def test_stale_clinical_patch_preserves_current_note_and_history(client):
    patient, clinician, note = await _shared_revision_note(client, "stale-edit")
    notes_url = f"/api/therapist/patients/{patient.user_id}/notes"
    history_url = f"/api/therapist/notes/{note['id']}/revisions"
    before, history = (
        await client.get(notes_url, headers=clinician.headers),
        await client.get(history_url, headers=clinician.headers),
    )
    current = before.json()[0]
    rejected = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=clinician.headers,
        json={
            "base_version": current["version"] - 1,
            "blob": clinician.encrypt_note(patient, "history-note", "stale competing text"),
        },
    )
    assert rejected.status_code == 409 and rejected.json()["code"] == "version_conflict", (
        rejected.text
    )
    after = await client.get(notes_url, headers=clinician.headers)
    history_after = await client.get(history_url, headers=clinician.headers)
    assert after.json() == before.json()
    assert history_after.json() == history.json()
    assert after.headers["X-Notes-Revision"] == before.headers["X-Notes-Revision"]


async def test_note_reseal_requires_the_complete_current_revision_set(client):
    patient, clinician, note = await _shared_revision_note(client, "complete-reseal")
    notes_url = f"/api/therapist/patients/{patient.user_id}/notes"
    history_url = f"/api/therapist/notes/{note['id']}/revisions"
    before = await client.get(notes_url, headers=clinician.headers)
    original_history = await client.get(history_url, headers=clinician.headers)
    current = before.json()[0]
    revisions = original_history.json()
    assert len(revisions) == 2
    replacements = [
        {
            "revision_id": revision["id"],
            "blob": _b64(os.urandom(len(base64.b64decode(revision["blob"])))),
        }
        for revision in revisions
    ]
    item = {
        "note_id": note["id"],
        "base_version": current["version"],
        "blob": _b64(os.urandom(len(base64.b64decode(current["blob"])))),
        "revision_blobs": replacements[:1],
    }
    headers = {**clinician.headers, "X-Account-Verifier": clinician.auth_key_b64}
    rejected = await client.put(
        "/api/therapist/notes/rekey", headers=headers, json={"items": [item]}
    )
    assert rejected.status_code == 409 and rejected.json()["code"] == "version_conflict", (
        rejected.text
    )
    unchanged = await client.get(notes_url, headers=clinician.headers)
    unchanged_history = await client.get(history_url, headers=clinician.headers)
    assert unchanged.json() == before.json()
    assert unchanged_history.json() == original_history.json()
    assert unchanged.headers["X-Notes-Revision"] == before.headers["X-Notes-Revision"]
    item["revision_blobs"] = replacements
    complete = await client.put(
        "/api/therapist/notes/rekey", headers=headers, json={"items": [item]}
    )
    assert complete.status_code == 204, complete.text
    after = await client.get(notes_url, headers=clinician.headers)
    history_after = await client.get(history_url, headers=clinician.headers)
    assert after.json()[0]["blob"] == item["blob"]
    assert after.json()[0]["version"] == current["version"] + 1
    assert int(after.headers["X-Notes-Revision"]) == int(before.headers["X-Notes-Revision"]) + 1
    assert {row["id"]: row["blob"] for row in history_after.json()} == {
        replacement["revision_id"]: replacement["blob"] for replacement in replacements
    }


async def test_note_history_response_linearizes_before_custody_change(client, monkeypatch):
    import asyncio

    from app.api import therapist as therapist_api

    _patient, clinician, note = await _shared_revision_note(client, "fence")
    fetched, release, custody_authorized = asyncio.Event(), asyncio.Event(), asyncio.Event()
    original_audit, original_fresh = therapist_api._audit, _custody._fresh

    async def hold_history_response(session, actor, owner_id, action):
        await original_audit(session, actor, owner_id, action)
        if action == "read_note_revisions":
            await session.commit()
            fetched.set()
            await release.wait()

    async def record_custody_authorization(*args):
        result = await original_fresh(*args)
        custody_authorized.set()
        return result

    monkeypatch.setattr(therapist_api, "_audit", hold_history_response)
    monkeypatch.setattr(_custody, "_fresh", record_custody_authorization)
    history_task = asyncio.create_task(
        client.get(f"/api/therapist/notes/{note['id']}/revisions", headers=clinician.headers)
    )
    await asyncio.wait_for(fetched.wait(), timeout=5)
    custody_task = asyncio.create_task(
        client.put(
            "/api/therapist/custody",
            headers=clinician.headers,
            json={
                "verifier": clinician.auth_key_b64,
                "operation_id": str(uuid.uuid4()),
                "expected_custody_version": 0,
                "custody_version": 1,
                "notes_keyring_blob": _b64(os.urandom(60)),
            },
        )
    )
    try:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(custody_authorized.wait(), timeout=0.05)
    finally:
        release.set()
        history, custody = await asyncio.gather(history_task, custody_task)
    assert history.status_code == 200 and custody.status_code == 204


@pytest.mark.parametrize("fault", ["size", "snapshot"])
async def test_note_history_fetched_access_remains_audited_after_consistency_refusal(
    client, app, settings, tmp_path, monkeypatch, fault
):
    from pathlib import Path

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import AsyncSession

    settings.audit_journal_path = str(tmp_path / "private-history-audit.jsonl")
    patient, clinician, note = await _shared_revision_note(client, f"durable-{fault}")
    original_execute, original_commit = AsyncSession.execute, AsyncSession.commit
    history_session = None
    injected = False

    async def drift_fetched_revision(session, statement, *args, **kwargs):
        nonlocal history_session
        result = await original_execute(session, statement, *args, **kwargs)
        if any(
            column.get("expr") is TherapistNoteRevision
            for column in getattr(statement, "column_descriptions", [])
        ):
            rows = result.scalars().all()
            history_session = session
            assert rows, "fault injection must follow a real private revision fetch"
            if fault == "size":
                rows[0].blob = b"changed opaque history" * 50
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
        return result

    async def change_snapshot_after_fetch_commit(session):
        nonlocal injected
        await original_commit(session)
        if session is history_session and fault == "snapshot" and not injected:
            injected = True
            async with app.state.sessionmaker() as concurrent:
                await concurrent.execute(
                    update(User)
                    .where(User.id == clinician.user_id)
                    .values(notes_revision=User.notes_revision + 1)
                )
                await concurrent.commit()

    monkeypatch.setattr(AsyncSession, "execute", drift_fetched_revision)
    monkeypatch.setattr(AsyncSession, "commit", change_snapshot_after_fetch_commit)
    refused = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions",
        headers=clinician.headers,
        params={"limit": 1, "page_bytes": 256},
    )
    assert refused.status_code == 409 and refused.json()["code"] == "collection_changed", (
        refused.text
    )
    async with app.state.sessionmaker() as session:
        rows = (
            await session.scalars(
                select(AccessLog).where(
                    AccessLog.actor_id == clinician.user_id,
                    AccessLog.user_id == patient.user_id,
                    AccessLog.action == "read_note_revisions",
                )
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].entry_hash in Path(settings.audit_journal_path).read_text()


async def test_note_history_response_linearizes_before_patient_deletion(client, monkeypatch):
    import asyncio

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.services import account_deletion

    patient, clinician, note = await _shared_revision_note(client, "patient-fence")
    fetched, release, deletion_entered, deletion_authorized = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    original_execute, original_stage = AsyncSession.execute, account_deletion.stage_account_deletion
    original_proof = account._require_step_up_or_verifier

    async def pause_after_private_fetch(session, statement, *args, **kwargs):
        result = await original_execute(session, statement, *args, **kwargs)
        if any(
            column.get("expr") is TherapistNoteRevision
            for column in getattr(statement, "column_descriptions", [])
        ):
            rows = result.scalars().all()
            assert rows
            await session.commit()
            fetched.set()
            await release.wait()
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
        return result

    def record_deletion(session, user):
        deletion_entered.set()
        return original_stage(session, user)

    async def record_deletion_proof(*args, **kwargs):
        result = await original_proof(*args, **kwargs)
        if kwargs.get("action") == "account_delete":
            deletion_authorized.set()
        return result

    monkeypatch.setattr(AsyncSession, "execute", pause_after_private_fetch)
    monkeypatch.setattr(account_deletion, "stage_account_deletion", record_deletion)
    monkeypatch.setattr(account, "_require_step_up_or_verifier", record_deletion_proof)
    path = f"/api/therapist/notes/{note['id']}/revisions"
    history_task = asyncio.create_task(client.get(path, headers=clinician.headers))
    await asyncio.wait_for(fetched.wait(), timeout=5)
    deletion_task = asyncio.create_task(
        client.delete(
            "/api/account",
            headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        )
    )
    try:
        await asyncio.wait_for(deletion_authorized.wait(), timeout=5)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(deletion_entered.wait(), timeout=0.05)
    finally:
        release.set()
        history, deletion = await asyncio.gather(history_task, deletion_task)
    assert history.status_code == 200 and deletion.status_code == 204
    after = await client.get(path, headers=clinician.headers)
    assert after.status_code == 404


async def test_revocation_preserves_clinician_owned_note_history(client):
    patient, clinician, note = await _shared_revision_note(client, "private-continuity")
    consent = (await patient.list_consents(client))[0]
    assert await patient.revoke_consent(client, consent["id"]) == 204
    response = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=clinician.headers
    )
    assert response.status_code == 200, response.text
    assert [
        clinician.decrypt_note(patient, "history-note", row["blob"])["text"]
        for row in response.json()
    ] == ["second version", "first version"]
