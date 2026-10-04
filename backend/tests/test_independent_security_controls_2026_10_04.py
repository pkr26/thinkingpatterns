"""Focused pins for the 2026-10-04 independent security remediation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import time
from dataclasses import replace
from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, event, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models import (
    AccountDeletionTombstone,
    AccessLog,
    AuditChainState,
    AudioDeletion,
    AudioInventoryCursor,
    Insight,
    KIND_QUESTION,
    PairingCode,
    RekeyJournal,
    TokenRevocation,
    User,
    utcnow,
)
from app.security import step_up, tokens, totp
from app.security.deletion_tombstone import compute_deletion_tombstone_mac
from app.services.audio_store import (
    AudioStoreError,
    get_audio_store_cached,
    new_storage_key,
    reconcile_audio_inventory,
    storage_locator,
)
from tests.helpers import ClientEmulator, TherapistEmulator


async def test_deleted_subject_signal_is_authenticated_and_multi_device_safe(client, app, settings):
    patient = ClientEmulator("deleted-auth-signal", "correct horse battery staple")
    await patient.register(client)
    primary_token = patient.token
    assert primary_token is not None

    async def login_token() -> str:
        response = await client.post(
            "/api/auth/login",
            json={"username": patient.username, "verifier": patient.auth_key_b64},
        )
        assert response.status_code == 200, response.text
        return response.json()["token"]

    second_token = await login_token()
    revoked_token = await login_token()
    logged_out = await client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {revoked_token}"},
    )
    assert logged_out.status_code == 204

    deleted = await client.request(
        "DELETE",
        "/api/account",
        headers={"Authorization": f"Bearer {primary_token}"},
        json={"verifier": patient.auth_key_b64},
    )
    assert deleted.status_code == 204, deleted.text

    for bearer in (primary_token, second_token):
        response = await client.get("/api/entries", headers={"Authorization": f"Bearer {bearer}"})
        assert response.status_code == 410
        assert response.json() == {
            "detail": "account no longer exists",
            "code": "account_deleted",
        }

    # Revocation remains authoritative even though the subject was deleted.
    revoked = await client.get("/api/entries", headers={"Authorization": f"Bearer {revoked_token}"})
    assert revoked.status_code == 401
    assert revoked.json()["code"] == "unauthorized"

    # A validly signed token for an unknown uid is not evidence of deletion.
    unknown = tokens.issue_token(
        "f" * 32,
        settings.auth_token_secret,
        settings.token_ttl_seconds,
        epoch=1,
        purpose=tokens.PURPOSE_PATIENT,
        ksv=settings.auth_secret_version,
    )
    assert (
        await client.get("/api/entries", headers={"Authorization": f"Bearer {unknown}"})
    ).status_code == 401

    wrong_epoch = tokens.issue_token(
        patient.user_id,
        settings.auth_token_secret,
        settings.token_ttl_seconds,
        epoch=2,
        purpose=tokens.PURPOSE_PATIENT,
        ksv=settings.auth_secret_version,
    )
    wrong_purpose = tokens.issue_token(
        patient.user_id,
        settings.auth_token_secret,
        settings.token_ttl_seconds,
        epoch=1,
        purpose=tokens.PURPOSE_THERAPIST,
        ksv=settings.auth_secret_version,
    )
    expired = tokens.issue_token(
        patient.user_id,
        settings.auth_token_secret,
        1,
        now=time.time() - 10,
        epoch=1,
        purpose=tokens.PURPOSE_PATIENT,
        ksv=settings.auth_secret_version,
    )
    for bearer in (wrong_epoch, wrong_purpose, expired):
        response = await client.get("/api/entries", headers={"Authorization": f"Bearer {bearer}"})
        assert response.status_code == 401
        assert response.json()["code"] == "unauthorized"

    # Integrity failure is fail-closed: never promote a corrupt row to 410.
    async with app.state.sessionmaker() as session:
        tombstone = await session.get(AccountDeletionTombstone, patient.user_id)
        assert tombstone is not None
        tombstone.record_mac = "0" * 64
        await session.commit()
    corrupt = await client.get("/api/entries", headers={"Authorization": f"Bearer {primary_token}"})
    assert corrupt.status_code == 401


async def test_deletion_tombstone_survives_restart_and_expires_at_boundary(settings, tmp_path):
    from app.main import create_app

    db_path = tmp_path / "deleted-subject.sqlite3"
    durable_settings = replace(
        settings,
        database_url=f"sqlite+aiosqlite:///{db_path}",
    )
    patient = ClientEmulator("deleted-after-restart", "correct horse battery staple")
    first = create_app(durable_settings)
    async with first.router.lifespan_context(first):
        async with AsyncClient(
            transport=ASGITransport(app=first), base_url="http://testserver"
        ) as first_client:
            await patient.register(first_client)
            bearer = patient.token
            assert bearer is not None
            assert await patient.delete_account(first_client) == 204

    restarted = create_app(durable_settings)
    async with restarted.router.lifespan_context(restarted):
        async with AsyncClient(
            transport=ASGITransport(app=restarted), base_url="http://testserver"
        ) as restarted_client:
            after_restart = await restarted_client.get(
                "/api/entries", headers={"Authorization": f"Bearer {bearer}"}
            )
            assert after_restart.status_code == 410

            async with restarted.state.sessionmaker() as session:
                tombstone = await session.get(AccountDeletionTombstone, patient.user_id)
                assert tombstone is not None
                tombstone.expires_at = utcnow()
                tombstone.record_mac = compute_deletion_tombstone_mac(
                    durable_settings.auth_token_secret, tombstone
                )
                await session.commit()

            at_boundary = await restarted_client.get(
                "/api/entries", headers={"Authorization": f"Bearer {bearer}"}
            )
            assert at_boundary.status_code == 401


async def _issue_step_up(client, patient: ClientEmulator, action: str) -> dict:
    response = await client.post(
        "/api/account/step-up",
        headers=patient.headers,
        json={"verifier": patient.auth_key_b64, "action": action},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def test_step_up_is_action_bound_one_use_expiring_and_capacity_safe(
    client, app, settings, monkeypatch
):
    settings.llm_url = "https://llm.example.invalid/v1"
    patient = ClientEmulator("step-up-contract", "correct horse battery staple")
    await patient.register(client)

    issued = await _issue_step_up(client, patient, "llm_consent")
    assert issued["action"] == "llm_consent"
    assert issued["expires_in"] == step_up.STEP_UP_TTL_SECONDS
    enabled = await client.put(
        "/api/account/llm-consent",
        headers={**patient.headers, "X-Step-Up-Proof": issued["proof"]},
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text

    replay = await client.put(
        "/api/account/llm-consent",
        headers={**patient.headers, "X-Step-Up-Proof": issued["proof"]},
        json={"enabled": False},
    )
    assert replay.status_code == 403
    assert replay.json()["code"] == "step_up_invalid"

    wrong_action = await _issue_step_up(client, patient, "voice_consent")
    rejected = await client.put(
        "/api/account/llm-consent",
        headers={**patient.headers, "X-Step-Up-Proof": wrong_action["proof"]},
        json={"enabled": False},
    )
    assert rejected.status_code == 403
    assert rejected.json()["code"] == "step_up_invalid"

    expired = await _issue_step_up(client, patient, "llm_consent")
    digest = app.state.step_up_store._digest(expired["proof"])  # noqa: SLF001
    record = app.state.step_up_store._proofs[digest]  # noqa: SLF001
    app.state.step_up_store._proofs[digest] = replace(record, expires_at=0)  # noqa: SLF001
    expired_response = await client.put(
        "/api/account/llm-consent",
        headers={**patient.headers, "X-Step-Up-Proof": expired["proof"]},
        json={"enabled": False},
    )
    assert expired_response.status_code == 403
    assert expired_response.json()["code"] == "step_up_invalid"

    async def exhausted(**_kwargs):
        raise RuntimeError("capacity")

    monkeypatch.setattr(app.state.step_up_store, "issue", exhausted)
    unavailable = await client.post(
        "/api/account/step-up",
        headers=patient.headers,
        json={"verifier": patient.auth_key_b64, "action": "account_delete"},
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "service_unavailable"
    assert unavailable.headers["Retry-After"] == "1"


async def test_step_up_can_delete_during_interrupted_rekey(client, app):
    patient = ClientEmulator("step-up-rekey-delete", "correct horse battery staple")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        session.add(RekeyJournal(user_id=patient.user_id, stage="entries"))
        await session.commit()

    issued = await _issue_step_up(client, patient, "account_delete")
    deleted = await client.request(
        "DELETE",
        "/api/account",
        headers={**patient.headers, "X-Step-Up-Proof": issued["proof"]},
    )
    assert deleted.status_code == 204, deleted.text
    async with app.state.sessionmaker() as session:
        assert await session.get(User, patient.user_id) is None
        assert (
            await session.scalar(
                select(RekeyJournal.id).where(RekeyJournal.user_id == patient.user_id)
            )
            is None
        )


async def test_therapist_must_enroll_mfa_before_patient_surfaces_and_backup_recovers(
    client,
):
    therapist = TherapistEmulator(
        "mfa-required-therapist",
        "correct horse battery staple",
        auto_enroll_mfa=False,
    )
    registered = await therapist.register(client)
    assert registered["mfa_enrollment_required"] is True
    assert (await client.get("/api/therapist/me", headers=therapist.headers)).status_code == 200

    blocked = await client.post("/api/therapist/pairing-codes", headers=therapist.headers)
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "mfa_enrollment_required"

    setup = await client.post(
        "/api/account/totp/setup",
        headers=therapist.headers,
        json={"verifier": therapist.auth_key_b64},
    )
    assert setup.status_code == 200, setup.text
    secret = base64.b32decode(setup.json()["secret_base32"])
    code = totp._code_for_counter(secret, int(time.time() // totp.STEP_SECONDS))
    enabled = await client.post(
        "/api/account/totp/enable",
        headers=therapist.headers,
        json={"verifier": therapist.auth_key_b64, "code": code},
    )
    assert enabled.status_code == 200, enabled.text
    backup = enabled.json()["backup_codes"][0]
    assert (
        await client.post("/api/therapist/pairing-codes", headers=therapist.headers)
    ).status_code == 201

    first_factor_only = await client.post(
        "/api/auth/login",
        json={"username": therapist.username, "verifier": therapist.auth_key_b64},
    )
    assert first_factor_only.status_code == 401
    assert first_factor_only.json()["code"] == "totp_required"
    recovered = await client.post(
        "/api/auth/login",
        json={
            "username": therapist.username,
            "verifier": therapist.auth_key_b64,
            "totp_code": backup,
        },
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["mfa_enrollment_required"] is False


async def test_age_attestation_is_required_persisted_and_postgres_width_is_sufficient(client, app):
    patient = ClientEmulator("age-attestation", "correct horse battery staple")
    body = {
        "username": patient.username,
        "salt": patient.salt_b64,
        "verifier": patient.auth_key_b64,
    }
    missing = await client.post("/api/auth/register", json=body)
    assert missing.status_code == 422
    assert missing.json()["code"] == "validation_error"

    await patient.register(client)
    async with app.state.sessionmaker() as session:
        user = await session.get(User, patient.user_id)
        assert user is not None
        assert user.age_attestation_version == "minimum_age_confirmed_v1"
        assert user.age_attested_at is not None

    column = User.__table__.c.age_attestation_version
    assert column.type.length == 32
    assert len("minimum_age_confirmed_v1") <= column.type.length
    ddl = str(CreateTable(User.__table__).compile(dialect=postgresql.dialect()))
    assert "age_attestation_version VARCHAR(32)" in ddl


async def test_export_v3_covers_consent_sharing_access_and_age_records(client, settings):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.invalid/v1"
    settings.stt_api_key = "test-key"
    patient = ClientEmulator("export-v3-subject", "correct horse battery staple")
    await patient.register(client)
    voice = await client.put(
        "/api/account/voice-consent",
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert voice.status_code == 200, voice.text

    therapist = TherapistEmulator("export-v3-therapist", "correct horse battery staple")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    granted = await patient.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    assert granted["status"] == 201, granted["body"]
    consent_id = granted["body"]["id"]
    voice_share = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert voice_share.status_code == 200, voice_share.text

    response = await client.get("/api/account/export", headers=patient.headers)
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["version"] == 3
    assert bundle["age_attestation_version"] == "minimum_age_confirmed_v1"
    assert bundle["age_attested_at"] is not None
    assert bundle["voice_consent"] is True
    assert bundle["voice_consent_at"] is not None
    assert bundle["voice_consent_disclosure"] is not None
    assert bundle["voice_consent_policy"] is not None

    share = next(item for item in bundle["shares"] if item["id"] == consent_id)
    assert share["therapist_id"] == therapist.user_id
    assert share["scope"] == "full"
    assert share["disclosure"] == "v3"
    assert share["share_voice"] is True

    events = {(item["kind"], item["action"]) for item in bundle["consent_events"]}
    assert ("voice", "granted") in events
    assert ("sharing", "granted") in events
    assert ("sharing_voice", "granted") in events
    actions = {item["action"] for item in bundle["access_log"]}
    assert {"voice_consent_on", "grant", "share_voice_on"} <= actions


async def test_consent_history_pages_are_revision_fenced_and_single_write(client, app):
    from app.models import Consent, ConsentEvent

    patient = ClientEmulator("paged-consents", "correct horse battery staple")
    await patient.register(client)
    consent_ids: list[str] = []
    therapists: list[TherapistEmulator] = []
    for index in range(3):
        therapist = TherapistEmulator(
            f"paged-consent-therapist-{index}", "correct horse battery staple"
        )
        await therapist.register(client)
        code = await therapist.create_pairing_code(client)
        granted = await patient.grant_consent(
            client, code, therapist.wrap_pub_key, therapist.user_id
        )
        assert granted["status"] == 201, granted["body"]
        consent_ids.append(granted["body"]["id"])
        therapists.append(therapist)

    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(func.count(Consent.id)).where(Consent.user_id == patient.user_id)
            )
        ) == 3
        assert (
            await session.scalar(
                select(func.count(ConsentEvent.id)).where(
                    ConsentEvent.user_id == patient.user_id,
                    ConsentEvent.kind == "sharing",
                    ConsentEvent.action == "granted",
                )
            )
        ) == 3
        assert (
            await session.scalar(
                select(func.count(AccessLog.id)).where(
                    AccessLog.user_id == patient.user_id,
                    AccessLog.action == "grant",
                )
            )
        ) == 3

    first = await client.get(
        "/api/consents", headers=patient.headers, params={"limit": 2, "offset": 0}
    )
    assert first.status_code == 200, first.text
    assert len(first.json()) == 2
    assert first.headers["X-Next-Offset"] == "2"
    revision = first.headers["X-Consents-Revision"]
    second = await client.get(
        "/api/consents",
        headers=patient.headers,
        params={"limit": 2, "offset": 2, "expected_revision": revision},
    )
    assert second.status_code == 200, second.text
    assert len(second.json()) == 1
    assert "X-Next-Offset" not in second.headers

    revoked = await client.delete(
        f"/api/consents/{consent_ids[0]}",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert revoked.status_code == 204, revoked.text
    # A repeated withdrawal is a true no-op: no duplicate evidence/audit or
    # revision advance.
    async with app.state.sessionmaker() as session:
        after_first_revoke = await session.get(User, patient.user_id)
        assert after_first_revoke is not None
        revision_after_revoke = after_first_revoke.consents_revision
        events_after_revoke = int(
            await session.scalar(
                select(func.count(ConsentEvent.id)).where(ConsentEvent.user_id == patient.user_id)
            )
            or 0
        )
    repeated = await client.delete(
        f"/api/consents/{consent_ids[0]}",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert repeated.status_code == 204
    async with app.state.sessionmaker() as session:
        after_repeat = await session.get(User, patient.user_id)
        assert after_repeat is not None
        assert after_repeat.consents_revision == revision_after_revoke
        assert (
            await session.scalar(
                select(func.count(ConsentEvent.id)).where(ConsentEvent.user_id == patient.user_id)
            )
        ) == events_after_revoke

    stale = await client.get(
        "/api/consents",
        headers=patient.headers,
        params={"limit": 2, "offset": 2, "expected_revision": revision},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "collection_changed"


async def test_provider_consent_noops_do_not_emit_events_audits_or_revisions(
    client, app, settings, monkeypatch
):
    from app.api import _sharing_state
    from app.models import ConsentEvent

    settings.llm_url = "https://llm.example.invalid/v1"
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.invalid/v1"
    settings.stt_api_key = "test-key"
    monkeypatch.setattr(_sharing_state, "CONSENT_EVENT_PERMISSION_CEILING", 2)
    monkeypatch.setattr(_sharing_state, "MAX_CONSENT_EVENTS_PER_PATIENT", 4)
    patient = ClientEmulator("bounded-provider-events", "correct horse battery staple")
    await patient.register(client)

    async def counts() -> tuple[int, int]:
        async with app.state.sessionmaker() as session:
            events = int(
                await session.scalar(
                    select(func.count(ConsentEvent.id)).where(
                        ConsentEvent.user_id == patient.user_id
                    )
                )
                or 0
            )
            audits = int(
                await session.scalar(
                    select(func.count(AccessLog.id)).where(
                        AccessLog.user_id == patient.user_id,
                        AccessLog.action.in_(("llm_consent_on", "llm_consent_off")),
                    )
                )
                or 0
            )
            return events, audits

    enabled = await client.put(
        "/api/account/llm-consent",
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert enabled.status_code == 200
    assert await counts() == (1, 1)
    same_enabled = await client.put(
        "/api/account/llm-consent",
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert same_enabled.status_code == 200
    assert await counts() == (1, 1)

    disabled = await client.put(
        "/api/account/llm-consent",
        headers=patient.headers,
        json={"enabled": False, "verifier": patient.auth_key_b64},
    )
    assert disabled.status_code == 200
    assert await counts() == (2, 2)
    same_disabled = await client.put(
        "/api/account/llm-consent",
        headers=patient.headers,
        json={"enabled": False, "verifier": patient.auth_key_b64},
    )
    assert same_disabled.status_code == 200
    assert await counts() == (2, 2)

    capped = await client.put(
        "/api/account/llm-consent",
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert capped.status_code == 413
    assert capped.json()["code"] == "payload_too_large"
    assert await counts() == (2, 2)
    state = await client.get("/api/account/llm-consent", headers=patient.headers)
    assert state.status_code == 200
    assert state.json()["enabled"] is False

    voice_patient = ClientEmulator("bounded-voice-events", "correct horse battery staple")
    await voice_patient.register(client)
    voice_enabled = await client.put(
        "/api/account/voice-consent",
        headers=voice_patient.headers,
        json={"enabled": True, "verifier": voice_patient.auth_key_b64},
    )
    assert voice_enabled.status_code == 200
    voice_same = await client.put(
        "/api/account/voice-consent",
        headers=voice_patient.headers,
        json={"enabled": True, "verifier": voice_patient.auth_key_b64},
    )
    assert voice_same.status_code == 200
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(func.count(ConsentEvent.id)).where(
                    ConsentEvent.user_id == voice_patient.user_id
                )
            )
        ) == 1
        assert (
            await session.scalar(
                select(func.count(AccessLog.id)).where(
                    AccessLog.user_id == voice_patient.user_id,
                    AccessLog.action == "voice_consent_on",
                )
            )
        ) == 1


async def test_therapist_patient_history_pages_have_strict_cardinality(client):
    therapist = TherapistEmulator("paged-patient-therapist", "correct horse battery staple")
    await therapist.register(client)
    patients: list[ClientEmulator] = []
    consents: list[str] = []
    for index in range(3):
        patient = ClientEmulator(f"paged-patient-{index}", "correct horse battery staple")
        await patient.register(client)
        code = await therapist.create_pairing_code(client)
        granted = await patient.grant_consent(
            client, code, therapist.wrap_pub_key, therapist.user_id
        )
        assert granted["status"] == 201, granted["body"]
        patients.append(patient)
        consents.append(granted["body"]["id"])

    first = await client.get(
        "/api/therapist/patients",
        headers=therapist.headers,
        params={"limit": 2, "offset": 0},
    )
    assert first.status_code == 200, first.text
    assert len(first.json()) == 2
    assert first.headers["X-Next-Offset"] == str(len(first.json()))
    revision = first.headers["X-Patients-Revision"]
    second = await client.get(
        "/api/therapist/patients",
        headers=therapist.headers,
        params={"limit": 2, "offset": 2, "expected_revision": revision},
    )
    assert second.status_code == 200, second.text
    assert len(second.json()) == 1
    assert "X-Next-Offset" not in second.headers

    revoked = await client.delete(
        f"/api/consents/{consents[0]}",
        headers={
            **patients[0].headers,
            "X-Account-Verifier": patients[0].auth_key_b64,
        },
    )
    assert revoked.status_code == 204
    stale = await client.get(
        "/api/therapist/patients",
        headers=therapist.headers,
        params={"limit": 2, "offset": 2, "expected_revision": revision},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "collection_changed"


async def test_export_audit_pages_are_linear_and_never_repeat_full_aggregates(client, app):
    from app.api.account import EXPORT_METADATA_PAGE_SIZE
    from tests.test_independent_audit_2026_09_27 import _seed_chain

    patient = ClientEmulator("linear-audit-export", "correct horse battery staple")
    await patient.register(client)
    await _seed_chain(
        app.state.sessionmaker,
        patient.user_id,
        bytes.fromhex(app.state.settings.audit_mac_secret_hex),
        n=405,
    )
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        normalized = " ".join(statement.lower().split())
        if " from access_log " in f" {normalized} ":
            statements.append(normalized)

    event.listen(app.state.engine.sync_engine, "before_cursor_execute", capture)
    try:
        response = await client.get("/api/account/export", headers=patient.headers)
    finally:
        event.remove(app.state.engine.sync_engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    # Registration creates the authenticated genesis record; the synthetic
    # 405-row trail follows it.
    assert len(response.json()["access_log"]) == 406
    assert not [statement for statement in statements if "count(" in statement]
    # One indexed first-sequence read plus exactly one keyset query per page.
    expected_pages = (405 + EXPORT_METADATA_PAGE_SIZE - 1) // EXPORT_METADATA_PAGE_SIZE
    assert len(statements) == 1 + expected_pages, statements


async def test_export_audit_stream_fails_closed_if_unemitted_prefix_is_pruned(app, monkeypatch):
    from starlette.requests import Request

    from app.api import account as account_api
    from app.api._audit import compute_chain_state_mac
    from app.deps import ApiError
    from tests.test_independent_audit_2026_09_27 import _seed_chain

    monkeypatch.setattr(account_api, "EXPORT_METADATA_PAGE_SIZE", 2)
    patient = ClientEmulator("audit-export-prune", "correct horse battery staple")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as local_client:
        await patient.register(local_client)
    mac_key = bytes.fromhex(app.state.settings.audit_mac_secret_hex)
    await _seed_chain(app.state.sessionmaker, patient.user_id, mac_key, n=5)

    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/api/account/export",
            "headers": [],
        }
    )
    async with app.state.sessionmaker() as endpoint_session:
        user = await endpoint_session.get(User, patient.user_id)
        assert user is not None
        response = await account_api.export_account(request, user, endpoint_session)
    iterator = response.body_iterator
    in_access_log = False
    emitted = 0
    while emitted < 2:
        chunk = await anext(iterator)
        if chunk == '],"access_log":[':
            in_access_log = True
            continue
        if in_access_log and isinstance(chunk, str) and '"chain_seq"' in chunk:
            emitted += 1

    async with app.state.sessionmaker() as prune_session:
        fourth = await prune_session.scalar(
            select(AccessLog).where(
                AccessLog.user_id == patient.user_id,
                AccessLog.chain_seq == 4,
            )
        )
        state = await prune_session.get(AuditChainState, patient.user_id)
        assert fourth is not None and state is not None
        await prune_session.execute(
            delete(AccessLog).where(
                AccessLog.user_id == patient.user_id,
                AccessLog.chain_seq <= 3,
            )
        )
        state.first_retained_seq = fourth.chain_seq
        state.first_retained_hash = fourth.entry_hash
        state.state_mac = compute_chain_state_mac(mac_key, state)
        await prune_session.commit()

    with pytest.raises(ApiError) as raised:
        while True:
            await anext(iterator)
    assert raised.value.status_code == 409
    assert raised.value.code == "collection_changed"


async def test_daily_sweep_prunes_questions_for_dormant_accounts_and_counts_them(client, app):
    from app import main as main_module
    from app.api.insights import QUESTION_RETENTION_DAYS

    patient = ClientEmulator("dormant-question-retention", "correct horse battery staple")
    await patient.register(client)
    today = utcnow().date()
    old = Insight(
        user_id=patient.user_id,
        kind=KIND_QUESTION,
        for_date=today - timedelta(days=QUESTION_RETENTION_DAYS + 1),
        blob=b"old-question",
    )
    boundary = Insight(
        user_id=patient.user_id,
        kind=KIND_QUESTION,
        for_date=today - timedelta(days=QUESTION_RETENTION_DAYS),
        blob=b"boundary-question",
    )
    async with app.state.sessionmaker() as session:
        session.add_all([old, boundary])
        await session.commit()
        old_id, boundary_id = old.id, boundary.id

    await main_module._prune_access_log_once(app)
    async with app.state.sessionmaker() as session:
        assert await session.get(Insight, old_id) is None
        assert await session.get(Insight, boundary_id) is not None
    metrics = app.state.metrics.render(keystore_sessions=0)
    assert "mindpattern_question_insights_pruned_total 1" in metrics
    assert "mindpattern_question_retention_backlog 0" in metrics


async def test_question_retention_batches_large_backlog_and_eventually_clears(
    client, app, monkeypatch
):
    from app import main as main_module
    from app.api.insights import QUESTION_RETENTION_DAYS

    monkeypatch.setattr(main_module, "QUESTION_RETENTION_BATCH", 2)
    patient = ClientEmulator("question-batch-retention", "correct horse battery staple")
    await patient.register(client)
    today = utcnow().date()
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Insight(
                    user_id=patient.user_id,
                    kind=KIND_QUESTION,
                    for_date=today - timedelta(days=QUESTION_RETENTION_DAYS + 1 + index),
                    blob=f"old-question-{index}".encode(),
                )
                for index in range(5)
            ]
        )
        await session.commit()

    assert await main_module._prune_expired_questions_once(app) is True
    assert app.state.question_retention_backlog is True
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(func.count(Insight.id)).where(
                    Insight.user_id == patient.user_id,
                    Insight.kind == KIND_QUESTION,
                )
            )
        ) == 3

    assert await main_module._prune_expired_questions_once(app) is True
    assert await main_module._prune_expired_questions_once(app) is False
    assert app.state.question_retention_backlog is False
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(func.count(Insight.id)).where(
                    Insight.user_id == patient.user_id,
                    Insight.kind == KIND_QUESTION,
                )
            )
        ) == 0
    metrics = app.state.metrics.render(keystore_sessions=0)
    assert "mindpattern_question_insights_pruned_total 5" in metrics
    assert "mindpattern_question_retention_backlog 0" in metrics


async def test_question_retention_backlog_uses_prompt_catchup_interval(app, monkeypatch):
    from app import main as main_module

    sleeps: list[int] = []

    async def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise asyncio.CancelledError

    async def clear_backlog(_app) -> bool:
        _app.state.question_retention_backlog = False
        return False

    app.state.question_retention_backlog = True
    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main_module, "_prune_expired_questions_once", clear_backlog)
    with pytest.raises(asyncio.CancelledError):
        await main_module._access_log_retention_sweep(app)
    assert sleeps == [
        main_module.QUESTION_RETENTION_CATCHUP_SECONDS,
        main_module.ACCESS_LOG_SWEEP_INTERVAL_SECONDS,
    ]


async def test_auxiliary_retention_is_bounded_and_eventually_drains(
    client, app, settings, monkeypatch
):
    from app import main as main_module

    monkeypatch.setattr(main_module, "AUXILIARY_RETENTION_BATCH", 2)
    therapist = TherapistEmulator("bounded-maintenance", "correct horse battery staple")
    await therapist.register(client)
    now = utcnow()
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                PairingCode(
                    therapist_id=therapist.user_id,
                    code_hash=f"expired-code-{index}",
                    expires_at=now - timedelta(days=10, seconds=index),
                )
                for index in range(5)
            ]
            + [
                TokenRevocation(
                    jti=f"{index:032x}",
                    expires_at=now - timedelta(seconds=index + 1),
                )
                for index in range(5)
            ]
            + [
                RekeyJournal(
                    user_id=f"{10_000 + index:032x}",
                    stage="entries",
                    updated_at=now - timedelta(days=index + 1),
                )
                for index in range(5)
            ]
            + [
                AccountDeletionTombstone(
                    user_id=f"{20_000 + index:032x}",
                    role="user",
                    token_epoch=1,
                    auth_secret_version=settings.auth_secret_version,
                    deleted_at=now - timedelta(days=40),
                    expires_at=now - timedelta(seconds=index + 1),
                    record_version=1,
                    record_mac="0" * 64,
                )
                for index in range(5)
            ]
        )
        await session.commit()

    backlogs: list[bool] = []
    for _ in range(3):
        async with app.state.sessionmaker() as session:
            progress = await main_module._prune_auxiliary_retention_once(app, session, now=now)
            await session.commit()
        app.state.metrics.observe_auxiliary_retention(progress)
        backlogs.append(any(item[0] for item in progress.values()))
    assert backlogs == [True, True, False]

    async with app.state.sessionmaker() as session:
        assert await session.scalar(select(func.count(PairingCode.id))) == 0
        assert await session.scalar(select(func.count(TokenRevocation.jti))) == 0
        assert await session.scalar(select(func.count(RekeyJournal.id))) == 0
        assert await session.scalar(select(func.count(AccountDeletionTombstone.user_id))) == 0
    rendered = app.state.metrics.render(0)
    for name in ("pairing", "revocations", "rekeys", "deletions"):
        assert f'mindpattern_auxiliary_retention_backlog{{class="{name}"}} 0' in rendered
        assert f'mindpattern_auxiliary_retention_deleted_total{{class="{name}"}} 5' in rendered


async def test_pairing_request_does_not_run_global_expiry_cleanup(client, app):
    therapist = TherapistEmulator("no-request-cleanup", "correct horse battery staple")
    await therapist.register(client)
    expired = PairingCode(
        therapist_id=therapist.user_id,
        code_hash="expired-request-path-sentinel",
        expires_at=utcnow() - timedelta(days=30),
    )
    async with app.state.sessionmaker() as session:
        session.add(expired)
        await session.commit()
        expired_id = expired.id
    assert (
        await client.post("/api/therapist/pairing-codes", headers=therapist.headers)
    ).status_code == 201
    async with app.state.sessionmaker() as session:
        assert await session.get(PairingCode, expired_id) is not None


def test_metrics_render_is_one_unique_sample_per_line_with_all_maintenance_series():
    from app.metrics import MetricsRegistry

    registry = MetricsRegistry()
    registry.observe_request(200)
    registry.observe_request(503)
    registry.observe_audit_progress(
        prune_backlog=True,
        verification_backlog=True,
        rows_pruned=3,
        owners_verified=2,
        prune_pending_rows_probe=101,
        prune_oldest_overdue_seconds=3600.5,
        verification_pending_owners_probe=7,
        verification_cycle_age_seconds=42.25,
    )
    registry.observe_auxiliary_retention(
        {name: (True, 12.5, 1) for name in ("deletions", "pairing", "revocations", "rekeys")}
    )
    registry.observe_retention(question_insights=2, question_backlog=True)
    registry.observe_audio_retention(
        backlog=4,
        oldest_age_seconds=10,
        reconciled=1,
        inventory_scanned=5,
        inventory_backlog=True,
        inventory_cycle_completed=True,
    )
    rendered = registry.render(keystore_sessions=2)
    sample_pattern = re.compile(
        r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{[^}]*\})? "
        r"(?P<value>(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)|NaN|[-+]?Inf)$"
    )
    samples: set[tuple[str, str]] = set()
    for line in rendered.splitlines():
        if not line or line.startswith("#"):
            continue
        match = sample_pattern.fullmatch(line)
        assert match is not None, line
        identity = (match.group("name"), match.group("labels") or "")
        assert identity not in samples, f"duplicate Prometheus sample: {identity}"
        samples.add(identity)
    names = {name for name, _labels in samples}
    assert {
        "mindpattern_requests_total",
        "mindpattern_audit_prune_backlog",
        "mindpattern_audit_verification_backlog",
        "mindpattern_audit_prune_pending_rows_probe",
        "mindpattern_audit_prune_oldest_overdue_seconds",
        "mindpattern_audit_verification_pending_owners_probe",
        "mindpattern_audit_verification_cycle_age_seconds",
        "mindpattern_auxiliary_retention_backlog",
        "mindpattern_question_retention_backlog",
        "mindpattern_audio_inventory_backlog",
        "mindpattern_audio_inventory_cycles_total",
    } <= names
    assert "mindpattern_audit_prune_pending_rows_probe 101" in rendered
    assert "mindpattern_audit_prune_oldest_overdue_seconds 3600.500" in rendered
    assert "mindpattern_audit_verification_pending_owners_probe 7" in rendered
    assert "mindpattern_audit_verification_cycle_age_seconds 42.250" in rendered


async def test_audit_maintenance_retry_recovers_promptly_after_startup_failure(app, monkeypatch):
    from app import main as main_module

    sleeps: list[float] = []
    attempts = 0

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise asyncio.CancelledError

    async def fail_then_recover(_app) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient")
        _app.state.audit_maintenance_retry_needed = False
        _app.state.audit_maintenance_retry_delay_seconds = (
            main_module.AUDIT_MAINTENANCE_CATCHUP_SECONDS
        )
        return False

    app.state.audit_maintenance_retry_needed = True
    app.state.audit_maintenance_retry_delay_seconds = 1
    monkeypatch.setattr(main_module.random, "random", lambda: 0.5)
    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main_module, "_prune_access_log_once", fail_then_recover)
    with pytest.raises(asyncio.CancelledError):
        await main_module._access_log_retention_sweep(app)
    assert attempts == 2
    assert sleeps == [1, 2, main_module.ACCESS_LOG_SWEEP_INTERVAL_SECONDS]


async def test_audit_maintenance_persistent_failure_uses_capped_backoff(app, monkeypatch):
    from app import main as main_module

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 5:
            raise asyncio.CancelledError

    async def always_fail(_app) -> bool:
        raise RuntimeError("persistent")

    app.state.audit_maintenance_retry_needed = True
    app.state.audit_maintenance_retry_delay_seconds = 1
    monkeypatch.setattr(main_module, "AUDIT_MAINTENANCE_RETRY_MAX_SECONDS", 4)
    monkeypatch.setattr(main_module.random, "random", lambda: 0.5)
    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main_module, "_prune_access_log_once", always_fail)
    with pytest.raises(asyncio.CancelledError):
        await main_module._access_log_retention_sweep(app)
    assert sleeps == [1, 2, 4, 4, 4]


async def test_registration_genesis_avoids_journal_scan_and_missing_state_never_resets(
    client, app, monkeypatch, tmp_path
):
    from app.api import _audit as audit_module
    from app.deps import ApiError

    # The former path scanned the whole journal synchronously on a first
    # append. A large file plus a tripwire proves registration does no such
    # read; its explicit genesis record is the authorization.
    journal = tmp_path / "large-audit.journal"
    journal.write_text("ignored historical line\n" * 10_000)
    scans = 0

    def forbidden_scan(*_args, **_kwargs):
        nonlocal scans
        scans += 1
        raise AssertionError("interactive append scanned the global journal")

    monkeypatch.setattr(audit_module, "journal_owner_status", forbidden_scan)
    patient = ClientEmulator("explicit-audit-genesis", "correct horse battery staple")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        genesis = list(
            (
                await session.scalars(
                    select(AccessLog)
                    .where(AccessLog.user_id == patient.user_id)
                    .order_by(AccessLog.chain_seq)
                )
            ).all()
        )
        assert [(row.chain_seq, row.action) for row in genesis] == [(1, "account_created")]
        state = await session.get(AuditChainState, patient.user_id)
        assert state is not None and state.state_mac is not None
        await session.execute(delete(AccessLog).where(AccessLog.user_id == patient.user_id))
        await session.execute(
            delete(AuditChainState).where(AuditChainState.user_id == patient.user_id)
        )
        await session.commit()

    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as excinfo:
            await audit_module.append_access_log(
                session,
                actor_id=patient.user_id,
                actor_role="patient",
                user_id=patient.user_id,
                action="must_not_reset",
            )
        assert excinfo.value.code == "audit_integrity_error"
        assert (
            await session.scalar(
                select(func.count(AccessLog.id)).where(AccessLog.user_id == patient.user_id)
            )
            == 0
        )
    assert scans == 0


async def test_audio_ceiling_force_retries_old_tombstone_in_local_inventory(
    app, settings, tmp_path
):
    settings.audio_local_dir = str(tmp_path / "audio")
    settings.audio_retention_days = 30
    settings.audio_lifecycle_ceiling_days = 31
    store = get_audio_store_cached(settings)
    assert store is not None
    key = new_storage_key("a" * 32)
    await store.put(key, b"opaque-client-ciphertext")
    async with app.state.sessionmaker() as session:
        row = AudioDeletion(
            backend=store.backend,
            storage_key=key,
            storage_locator=storage_locator(store),
            # The ordinary retry path is still leased far into the future;
            # reconciliation must independently enforce the ceiling.
            not_before=utcnow() + timedelta(days=10),
            created_at=utcnow() - timedelta(days=32),
            attempts=9,
        )
        session.add(row)
        await session.commit()
        tombstone_id = row.id
        assert await reconcile_audio_inventory(session, store, settings) == 1
        assert await session.get(AudioDeletion, tombstone_id) is None
    try:
        await store.get(key)
    except AudioStoreError:
        pass
    else:  # pragma: no cover - explicit assertion message is clearer
        raise AssertionError("lifecycle reconciliation left the object behind")


async def test_audio_inventory_reconciliation_is_bounded_and_fair_across_pages(
    app, settings, tmp_path, monkeypatch
):
    from app.services import audio_store as audio_store_module

    monkeypatch.setattr(audio_store_module, "INVENTORY_BATCH", 2)
    settings.audio_local_dir = str(tmp_path / "paged-audio")
    settings.audio_lifecycle_ceiling_days = 31
    store = get_audio_store_cached(settings)
    assert store is not None
    keys = [new_storage_key(f"{index:032x}") for index in range(5)]
    old_epoch = (utcnow() - timedelta(days=40)).timestamp()
    for key in keys:
        await store.put(key, b"opaque-client-ciphertext")
        os.utime(store._path(key), (old_epoch, old_epoch))  # noqa: SLF001

    async with app.state.sessionmaker() as session:
        assert await reconcile_audio_inventory(session, store, settings) == 2
        cursor = await session.get(
            AudioInventoryCursor,
            hashlib.sha256(f"{store.backend}\0{storage_locator(store) or ''}".encode()).hexdigest(),
        )
        assert cursor is not None and cursor.after_key is not None
        assert await reconcile_audio_inventory(session, store, settings) == 2
        assert await reconcile_audio_inventory(session, store, settings) == 1
        await session.refresh(cursor)
        assert cursor.after_key is None

    for key in keys:
        with pytest.raises(AudioStoreError):
            await store.get(key)


async def test_audio_reconciliation_warning_never_logs_storage_key(app, settings, caplog):
    sensitive_key = "audio/deleted-user-id/private-object.enc"

    class FailingStore:
        backend = "local"

        async def inventory_page(self, *, after_key, limit):
            assert after_key is None
            assert limit > 0
            return [(sensitive_key, utcnow() - timedelta(days=40))], None

        async def delete(self, key):
            assert key == sensitive_key
            raise AudioStoreError("provider delete failed")

    settings.audio_lifecycle_ceiling_days = 31
    caplog.set_level("WARNING", logger="mindpattern.audio_store")
    async with app.state.sessionmaker() as session:
        assert await reconcile_audio_inventory(session, FailingStore(), settings) == 0

    rendered = "\n".join(record.getMessage() for record in caplog.records)
    assert "deferred 1 object(s)" in rendered
    assert sensitive_key not in rendered
    assert "deleted-user-id" not in rendered


async def test_audio_provider_put_get_delete_failures_log_only_fixed_categories(
    client, app, settings, monkeypatch, caplog
):
    from app.api import audio as audio_module
    from app.services import audio_store as audio_store_module

    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.invalid/v1"
    settings.stt_api_key = "configured"
    patient = ClientEmulator("privacy-safe-audio-errors", "correct horse battery staple")
    await patient.register(client)
    consent = await client.put(
        "/api/account/voice-consent",
        headers=patient.headers,
        json={"enabled": True, "verifier": patient.auth_key_b64},
    )
    assert consent.status_code == 200, consent.text
    await patient.create_entry(
        client,
        "opaque",
        utcnow().date(),
        client_entry_id="privacy-audio-entry",
    )
    sensitive = f"provider-secret owner={patient.user_id} object=private.enc"

    class FailingProvider:
        async def transcribe(self, _audio, _mime):
            raise RuntimeError(sensitive)

    monkeypatch.setattr(audio_module.stt, "get_stt", lambda _settings: FailingProvider())
    caplog.set_level(logging.WARNING)
    provider = await client.post(
        "/api/v1/audio/transcriptions",
        headers=patient.headers,
        json={
            "audio_b64": base64.b64encode(b"RIFF-private-audio").decode(),
            "mime": "audio/webm",
            "duration_seconds": 1,
        },
    )
    assert provider.status_code == 502

    class SwitchingStore:
        backend = "test"

        def __init__(self):
            self.mode = "put"
            self.objects: dict[str, bytes] = {}

        async def put(self, key, blob):
            if self.mode == "put":
                raise AudioStoreError(f"{sensitive} key={key}")
            self.objects[key] = blob

        async def get(self, key, *, max_bytes=None):
            if self.mode == "get":
                raise AudioStoreError(f"{sensitive} key={key}")
            return self.objects[key]

        async def delete(self, key):
            if self.mode == "delete":
                raise AudioStoreError(f"{sensitive} key={key}")
            self.objects.pop(key, None)

    store = SwitchingStore()
    monkeypatch.setattr(audio_module, "get_audio_store_cached", lambda _settings: store)
    monkeypatch.setattr(audio_store_module, "get_audio_store_cached", lambda _settings: store)
    attachment_body = {
        "client_entry_id": "privacy-audio-entry",
        "blob": base64.b64encode(b"opaque-client-ciphertext" * 2).decode(),
        "mime": "audio/webm",
        "duration_seconds": 1,
    }
    put_failure = await client.post(
        "/api/v1/audio/attachments", headers=patient.headers, json=attachment_body
    )
    assert put_failure.status_code == 502

    store.mode = "ok"
    created = await client.post(
        "/api/v1/audio/attachments", headers=patient.headers, json=attachment_body
    )
    assert created.status_code == 201, created.text
    attachment_id = created.json()["attachment_id"]

    store.mode = "get"
    get_failure = await client.get(
        f"/api/v1/audio/attachments/{attachment_id}", headers=patient.headers
    )
    assert get_failure.status_code == 502

    store.mode = "delete"
    deleted = await client.delete(
        f"/api/v1/audio/attachments/{attachment_id}", headers=patient.headers
    )
    assert deleted.status_code == 204

    messages = [record.getMessage() for record in caplog.records]
    assert "stt upstream failed" in messages
    assert "audio object put failed" in messages
    assert "audio object get failed" in messages
    assert "audio deletion deferred after object-store failure" in messages
    assert sensitive not in "\n".join(messages)
    assert patient.user_id not in "\n".join(messages)
    assert all(record.exc_info is None for record in caplog.records)


async def test_outer_audio_sweep_drops_chained_provider_exception_text(app, monkeypatch, caplog):
    from app import main as main_module
    from app.services import audio_store as audio_store_module

    sensitive = "bucket/private-user/object.enc"
    sleeps = 0

    async def fake_sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise asyncio.CancelledError

    async def fail_sweep(*_args, **_kwargs):
        try:
            raise RuntimeError(sensitive)
        except RuntimeError as exc:
            raise AudioStoreError("object-store delete failed") from exc

    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(audio_store_module, "get_audio_store_cached", lambda _settings: object())
    monkeypatch.setattr(audio_store_module, "sweep_expired_audio", fail_sweep)
    caplog.set_level(logging.WARNING, logger="mindpattern")
    with pytest.raises(asyncio.CancelledError):
        await main_module._audio_retention_sweep(app)
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "audio retention sweep deferred after storage failure" in messages
    assert sensitive not in messages
    assert all(record.exc_info is None for record in caplog.records)


async def test_s3_provider_failures_are_normalized_to_fixed_allowlisted_messages():
    from app.services.audio_store import S3AudioStore

    sensitive = "sdk account=private-user bucket=secret-bucket object=private.enc"

    class Provider:
        def put_object(self, **_kwargs):
            raise RuntimeError(sensitive)

        def get_object(self, **_kwargs):
            raise RuntimeError(sensitive)

        def delete_object(self, **_kwargs):
            raise RuntimeError(sensitive)

        def list_objects_v2(self, **_kwargs):
            raise RuntimeError(sensitive)

    store = S3AudioStore("secret-bucket")
    store._client = Provider()  # noqa: SLF001 - injected provider boundary
    operations = (
        (lambda: store.put("audio/private/object.enc", b"opaque"), "object-store put failed"),
        (lambda: store.get("audio/private/object.enc"), "object-store get failed"),
        (lambda: store.delete("audio/private/object.enc"), "object-store delete failed"),
        (
            lambda: store.inventory_page(after_key=None, limit=1),
            "object-store inventory failed",
        ),
    )
    for operation, expected in operations:
        with pytest.raises(AudioStoreError) as excinfo:
            await operation()
        assert str(excinfo.value) == expected
        assert sensitive not in str(excinfo.value)
