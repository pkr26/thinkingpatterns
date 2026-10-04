"""Behavioral regressions for lifecycle/custody/portability remediation."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import auth
from app.api._audit import verify_access_log_chain
from app.cache import TokenRevocationStore
from app.middleware import HardeningMiddleware
from app.models import (
    AccessLog,
    AudioAttachment,
    AudioDeletion,
    Consent,
    TokenRevocation,
    User,
    RekeyJournal,
    Entry,
    Measure,
    Insight,
    utcnow,
)
from app.security import crypto
from app.services import audio_store, statsig, stt
from tests.helpers import ClientEmulator, EnvelopeClientEmulator, TherapistEmulator
from tests.test_audio_attachments import _attachment_body, _make_entry, _voice_ready
from tests.test_recovery_envelope import _setup_kit, recovery_verifier


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


async def test_clinician_password_is_one_atomic_custody_transaction(client, app):
    therapist = TherapistEmulator("custody-th", "old password")
    await therapist.register(client)
    old_headers = dict(therapist.headers)
    installed = b64(os.urandom(60))
    install = dict(
        verifier=therapist.auth_key_b64,
        operation_id=str(uuid.uuid4()),
        expected_custody_version=0,
        custody_version=1,
        notes_keyring_blob=installed,
    )
    assert (
        await client.put("/api/therapist/custody", headers=old_headers, json=install)
    ).status_code == 204
    assert (
        await client.put("/api/therapist/custody", headers=old_headers, json=install)
    ).status_code == 204
    replacement = ClientEmulator(therapist.username, "new password")
    keyring = b64(os.urandom(90))
    private_wrap = b64(os.urandom(80))
    transaction = dict(
        verifier=therapist.auth_key_b64,
        operation_id=str(uuid.uuid4()),
        expected_custody_version=1,
        custody_version=2,
        notes_keyring_blob=keyring,
        new_salt=replacement.salt_b64,
        new_verifier=replacement.auth_key_b64,
        wrap_pub_key=therapist.wrap_pub_key,
        wrap_key_blob=private_wrap,
    )
    changed = await client.put("/api/therapist/password", headers=old_headers, json=transaction)
    assert changed.status_code == 204, changed.text
    # Lost response: the exact preceding-epoch request succeeds as a no-op.
    assert (
        await client.put("/api/therapist/password", headers=old_headers, json=transaction)
    ).status_code == 204
    assert (
        await client.put(
            "/api/therapist/password",
            headers=old_headers,
            json={**transaction, "notes_keyring_blob": installed},
        )
    ).status_code == 409
    assert (await client.get("/api/therapist/me", headers=old_headers)).status_code == 401
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": therapist.username, "verifier": therapist.auth_key_b64},
        )
    ).status_code == 401
    login = await client.post(
        "/api/auth/login",
        json={
            "username": therapist.username,
            "verifier": replacement.auth_key_b64,
            "totp_code": therapist.totp_backup_codes.pop(0),
        },
    )
    assert login.status_code == 200, login.text
    me = (
        await client.get(
            "/api/therapist/me", headers={"Authorization": "Bearer " + login.json()["token"]}
        )
    ).json()
    assert (
        me["notes_keyring_blob"],
        me["wrap_key_blob"],
        me["wrap_pub_key"],
        me["custody_version"],
    ) == (keyring, private_wrap, therapist.wrap_pub_key, 2)
    async with app.state.sessionmaker() as session:
        user = await session.get(User, therapist.user_id)
        user.token_epoch += 1
        await session.commit()
    assert (
        await client.put("/api/therapist/password", headers=old_headers, json=transaction)
    ).status_code == 401


async def test_clinician_custody_cas_and_public_identity_replacement_fail_closed(client):
    therapist = TherapistEmulator("custody-cas", "old password")
    await therapist.register(client)
    body = dict(
        verifier=therapist.auth_key_b64,
        operation_id=str(uuid.uuid4()),
        expected_custody_version=0,
        custody_version=1,
        notes_keyring_blob=b64(os.urandom(60)),
    )
    assert (
        await client.put(
            "/api/therapist/custody",
            headers=therapist.headers,
            json={**body, "verifier": b64(os.urandom(32))},
        )
    ).status_code == 403
    assert (
        await client.put("/api/therapist/custody", headers=therapist.headers, json=body)
    ).status_code == 204
    assert (
        await client.put(
            "/api/therapist/custody",
            headers=therapist.headers,
            json={**body, "operation_id": str(uuid.uuid4())},
        )
    ).status_code == 409
    other = TherapistEmulator("other-identity", "password")
    replacement = ClientEmulator(therapist.username, "new password")
    password = dict(
        **body,
        new_salt=replacement.salt_b64,
        new_verifier=replacement.auth_key_b64,
        wrap_pub_key=other.wrap_pub_key,
        wrap_key_blob=b64(os.urandom(60)),
    )
    password.update(operation_id=str(uuid.uuid4()), expected_custody_version=1, custody_version=2)
    assert (
        await client.put("/api/therapist/password", headers=therapist.headers, json=password)
    ).status_code == 422
    assert (await client.get("/api/therapist/me", headers=therapist.headers)).json()[
        "custody_version"
    ] == 1


async def test_recovery_enrollment_revoked_during_hash_cannot_issue_token(client, app, monkeypatch):
    patient = ClientEmulator("recovery-race", "password")
    await patient.register(client)
    proof = os.urandom(32)
    await _setup_kit(client, patient, proof)
    proof_verifier = recovery_verifier(proof)
    original = auth.hash_verifier_off_loop

    async def race(value, salt, **kwargs):
        result = await original(value, salt, **kwargs)
        if value == proof_verifier:
            async with app.state.sessionmaker() as session:
                await session.execute(
                    update(User)
                    .where(User.id == patient.user_id)
                    .values(
                        recovery_salt=None,
                        recovery_verifier=None,
                        recovery_wrapped_data_key=None,
                        token_epoch=User.token_epoch + 1,
                    )
                )
                await session.commit()
        return result

    monkeypatch.setattr(auth, "hash_verifier_off_loop", race)
    response = await client.post(
        "/api/auth/recover",
        json={
            "username": patient.username,
            "verifier": b64(proof_verifier),
            "scheme": "v2",
        },
    )
    assert response.status_code == 401, response.text
    async with app.state.sessionmaker() as session:
        user = await session.get(User, patient.user_id)
        assert user.token_epoch == 2
        assert user.recovery_verifier is None


async def test_audio_failed_account_erasure_keeps_durable_retry_after_user_is_gone(
    client, app, settings, tmp_path, monkeypatch
):
    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "outbox-erasure")
    entry = await _make_entry(client, patient)
    uploaded = await client.post(
        "/api/audio/attachments", headers=patient.headers, json=_attachment_body(entry)
    )
    assert uploaded.status_code == 201
    original = audio_store.LocalAudioStore.delete

    async def outage(self, key):
        raise audio_store.AudioStoreError("synthetic outage")

    monkeypatch.setattr(audio_store.LocalAudioStore, "delete", outage)
    assert (
        await client.delete(
            "/api/account", headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64}
        )
    ).status_code == 204
    async with app.state.sessionmaker() as session:
        assert await session.get(User, patient.user_id) is None
        tombstones = list((await session.scalars(select(AudioDeletion))).all())
        assert len(tombstones) == 1
        assert tombstones[0].storage_locator is not None
        tombstones[0].not_before = utcnow()
        await session.commit()
        monkeypatch.setattr(audio_store.LocalAudioStore, "delete", original)
        assert await audio_store.drain_audio_deletions(session, settings) == 1
    assert not list((tmp_path / "audio").rglob("*.enc"))


async def test_audio_replacement_commit_failure_preserves_original_and_cleanup_lease(
    client, app, settings, tmp_path, monkeypatch
):
    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "audio-rollback")
    entry = await _make_entry(client, patient)
    first_blob = b"A" * 60
    uploaded = await client.post(
        "/api/audio/attachments", headers=patient.headers, json=_attachment_body(entry, first_blob)
    )
    attachment = uploaded.json()["attachment_id"]
    async with app.state.sessionmaker() as session:
        original_storage_key = (await session.get(AudioAttachment, attachment)).storage_key
    original = AsyncSession.commit
    injected = False

    async def commit(session):
        nonlocal injected
        if not injected and any(
            isinstance(row, AudioAttachment) and row.storage_key != original_storage_key
            for row in session.identity_map.values()
        ):
            injected = True
            raise RuntimeError("synthetic metadata commit failure")
        await original(session)

    monkeypatch.setattr(AsyncSession, "commit", commit)
    assert (
        await client.post(
            "/api/audio/attachments",
            headers=patient.headers,
            json=_attachment_body(entry, b"B" * 60),
        )
    ).status_code == 500
    monkeypatch.setattr(AsyncSession, "commit", original)
    fetched = await client.get("/api/audio/attachments/" + attachment, headers=patient.headers)
    assert base64.b64decode(fetched.json()["blob"]) == first_blob
    async with app.state.sessionmaker() as session:
        tombstones = list((await session.scalars(select(AudioDeletion))).all())
        assert len(tombstones) == 1
        tombstones[0].not_before = utcnow()
        await session.commit()
        await audio_store.drain_audio_deletions(session, settings)
    assert len(list((tmp_path / "audio").rglob("*.enc"))) == 1


async def test_expired_audio_replacement_does_not_subtract_excluded_bytes(
    client, app, settings, tmp_path
):
    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "expired-quota")
    for entry in ("expired", "live"):
        await _make_entry(client, patient, entry)
        assert (
            await client.post(
                "/api/audio/attachments",
                headers=patient.headers,
                json=_attachment_body(entry, b"x" * 60),
            )
        ).status_code == 201
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(AudioAttachment)
            .where(AudioAttachment.client_entry_id == "expired")
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
        await session.commit()
    settings.audio_max_user_bytes = 100
    result = await client.post(
        "/api/audio/attachments",
        headers=patient.headers,
        json=_attachment_body("expired", b"y" * 50),
    )
    assert result.status_code == 413
    assert result.json()["code"] == "audio_quota_exceeded"


async def test_export_has_one_audio_key_and_complete_v2_aad_metadata(client, settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "strict-export")
    entry = await _make_entry(client, patient)
    assert (
        await client.post(
            "/api/audio/attachments", headers=patient.headers, json=_attachment_body(entry)
        )
    ).status_code == 201
    response = await client.get("/api/account/export", headers=patient.headers)
    assert response.status_code == 200

    def unique(pairs):
        keys = [key for key, _value in pairs]
        assert len(keys) == len(set(keys))
        return dict(pairs)

    bundle = json.loads(response.text, object_pairs_hook=unique)
    assert bundle["version"] == 3 and bundle["username"] == patient.username
    assert bundle["audio"][0]["content_version"] == 1
    assert bundle["audio"][0]["created_at"]
    assert base64.b64decode(bundle["audio"][0]["blob"])


async def test_v1_rekey_includes_audio_and_invalidates_obsolete_recovery(
    client, app, settings, tmp_path
):
    settings.audio_local_dir = str(tmp_path / "audio")
    patient = await _voice_ready(client, settings, "audio-rekey")
    entry = await _make_entry(client, patient)
    recorded = b"real plaintext recording"
    original_blob = crypto.encrypt(
        patient.data_key, recorded, crypto.build_aad("audio", patient.user_id, entry, "1")
    )
    upload = await client.post(
        "/api/audio/attachments",
        headers=patient.headers,
        json=_attachment_body(entry, original_blob),
    )
    await _setup_kit(client, patient, os.urandom(32))
    new_key = os.urandom(32)
    old_session = await patient.open_processing_session(client)
    new_session = await patient.open_processing_session_for(client, new_key)
    response = await client.post(
        "/api/processing/rekey",
        headers={
            **patient.headers,
            "X-Account-Verifier": patient.auth_key_b64,
            "X-Processing-Token": old_session,
            "X-New-Processing-Token": new_session,
        },
        json=patient.rekey_payload(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["audio"] == 1 and response.json()["recovery_invalidated"] is True
    await patient.login(client)
    fetched = await client.get(
        "/api/audio/attachments/" + upload.json()["attachment_id"], headers=patient.headers
    )
    blob = base64.b64decode(fetched.json()["blob"])
    assert (
        crypto.decrypt(new_key, blob, crypto.build_aad("audio", patient.user_id, entry, "1"))
        == recorded
    )
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(
            patient.data_key, blob, crypto.build_aad("audio", patient.user_id, entry, "1")
        )
    assert (await client.get("/api/account/recovery", headers=patient.headers)).json()[
        "enabled"
    ] is False


async def test_failed_revocation_hydration_uses_durable_fallback(app):
    jti = "a" * 32
    async with app.state.sessionmaker() as session:
        session.add(TokenRevocation(jti=jti, expires_at=utcnow() + timedelta(hours=1)))
        await session.commit()
        unhydrated = TokenRevocationStore()
        assert await unhydrated.is_revoked_checked(session, jti)
        assert not await unhydrated.is_revoked_checked(session, "b" * 32)


async def test_stripping_a_current_audit_mac_does_not_become_legacy(client, app):
    patient = ClientEmulator("audit-strip", "password")
    await patient.register(client)
    await _setup_kit(client, patient, os.urandom(32))
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(AccessLog).where(AccessLog.user_id == patient.user_id))
        assert row.entry_mac is not None
        row.entry_mac = None
        await session.commit()
        result = await verify_access_log_chain(
            session, patient.user_id, mac_key=bytes.fromhex(app.state.settings.audit_mac_secret_hex)
        )
        assert result.ok is False
        assert "missing entry_mac" in result.reason


async def test_atomic_v1_rotation_response_loss_and_old_writer_fence(client, app):
    old = ClientEmulator("atomic-v1", "old password")
    await old.register(client)
    await old.create_entry(client, "record survives", utcnow().date(), "atomic-entry")
    new = ClientEmulator(old.username, "new password")
    new.user_id = old.user_id
    original_headers = dict(old.headers)
    old_token = await old.open_processing_session(client)
    new_token = await old.open_processing_session_for(client, new.data_key)
    headers = {
        **original_headers,
        "X-Account-Verifier": old.auth_key_b64,
        "X-Processing-Token": old_token,
        "X-New-Processing-Token": new_token,
    }
    body = {
        "operation_id": str(uuid.uuid4()),
        "new_salt": new.salt_b64,
        "new_verifier": new.auth_key_b64,
    }
    from app.api.insights import _entry_locks

    # Park rotation behind the entry lock AFTER it takes the lifecycle fence.
    async with _entry_locks.hold("entries:" + old.user_id):
        rotating = asyncio.create_task(
            client.post("/api/processing/rekey", headers=headers, json=body)
        )
        for _ in range(200):
            if _entry_locks._locks["entries:" + old.user_id].refs >= 2:
                break
            await asyncio.sleep(0.01)
        assert _entry_locks._locks["entries:" + old.user_id].refs >= 2
        queued_write = asyncio.create_task(
            client.post(
                "/api/entries",
                headers=original_headers,
                json={
                    "client_entry_id": "stale-writer",
                    "entry_date": utcnow().date().isoformat(),
                    "blob": old.encrypt_entry(
                        "old key late write", utcnow().date(), "stale-writer"
                    ),
                },
            )
        )
        await asyncio.sleep(0.02)
        assert not rotating.done() and not queued_write.done()
    response = await rotating
    assert response.status_code == 200, response.text
    assert response.json()["credential_rotated"] is True
    assert response.json()["operation_id"] == body["operation_id"]
    assert (await queued_write).status_code == 401
    assert (await client.get("/api/entries", headers=original_headers)).status_code == 401
    # Processing tokens have been consumed/purged. Exact response-loss retry
    # succeeds with the preceding signed epoch without touching any blob.
    repeated = await client.post("/api/processing/rekey", headers=headers, json=body)
    assert repeated.status_code == 200 and repeated.json() == response.json()
    changed = await client.post(
        "/api/processing/rekey", headers=headers, json={**body, "new_salt": b64(os.urandom(16))}
    )
    assert changed.status_code == 409
    assert (
        await client.post(
            "/api/processing/rekey",
            headers=headers,
            json={**body, "operation_id": str(uuid.uuid4())},
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/auth/login", json={"username": old.username, "verifier": old.auth_key_b64}
        )
    ).status_code == 401
    await new.login(client)
    row = await new.get_entry(client, "atomic-entry")
    assert (
        new.decrypt_entry(row["blob"], "atomic-entry", row["content_version"])["text"]
        == "record survives"
    )
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(select(RekeyJournal.id).where(RekeyJournal.user_id == new.user_id))
            is None
        )
        assert (
            await session.scalar(
                select(Entry.id).where(
                    Entry.user_id == new.user_id, Entry.client_entry_id == "stale-writer"
                )
            )
            is None
        )


async def test_legacy_partial_rekey_preflight_refuses_third_generation_without_writes(client, app):
    patient = ClientEmulator("legacy-generations", "password")
    await patient.register(client)
    await patient.create_entry(client, "first untouched", utcnow().date(), "first")
    old_key, new_key, third_key = patient.data_key, os.urandom(32), os.urandom(32)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        original = bytes(row.blob)
        session.add(
            Measure(
                user_id=patient.user_id,
                client_measure_id="third",
                measure_date=utcnow().date(),
                blob=crypto.encrypt(
                    third_key, b'{"v":1}', crypto.build_aad("measure", patient.user_id, "third")
                ),
            )
        )
        session.add(RekeyJournal(user_id=patient.user_id, stage="measures"))
        await session.commit()
    old_token = await patient.open_processing_session_for(client, old_key)
    new_token = await patient.open_processing_session_for(client, new_key)
    headers = {
        **patient.headers,
        "X-Account-Verifier": patient.auth_key_b64,
        "X-Processing-Token": old_token,
        "X-New-Processing-Token": new_token,
    }
    response = await client.post(
        "/api/processing/rekey", headers=headers, json=patient.rekey_payload()
    )
    assert response.status_code == 400 and response.json()["code"] == "rekey_key_mismatch"
    async with app.state.sessionmaker() as session:
        assert (
            bytes(
                (await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))).blob
            )
            == original
        )
        assert (
            await session.scalar(
                select(RekeyJournal).where(RekeyJournal.user_id == patient.user_id)
            )
        ).operation_id is None
    assert (
        await client.post(
            "/api/entries",
            headers=patient.headers,
            json={
                "client_entry_id": "blocked",
                "entry_date": utcnow().date().isoformat(),
                "blob": patient.encrypt_entry("blocked", utcnow().date(), "blocked"),
            },
        )
    ).status_code == 409


async def test_measure_only_envelope_upgrade_requires_real_data_key(client):
    patient = ClientEmulator("measure-only-proof", "password")
    await patient.register(client)
    blob = crypto.encrypt(
        patient.data_key, b'{"v":1}', crypto.build_aad("measure", patient.user_id, "only")
    )
    assert (
        await client.post(
            "/api/measures",
            headers=patient.headers,
            json={
                "client_measure_id": "only",
                "measure_date": utcnow().date().isoformat(),
                "blob": b64(blob),
            },
        )
    ).status_code == 201
    wrong = await patient.open_processing_session_for(client, os.urandom(32))
    response = await client.post(
        "/api/account/key-envelope/upgrade",
        headers={
            **patient.headers,
            "X-Processing-Token": wrong,
            "X-Account-Verifier": patient.auth_key_b64,
        },
        json={"wrapped_data_key": b64(os.urandom(60))},
    )
    assert response.status_code == 403 and response.json()["code"] == "envelope_key_mismatch"


async def test_legacy_audit_sealing_requires_exact_attestation_and_refuses_bad_existing_mac(
    client, app, settings
):
    from scripts.seal_legacy_audit import snapshot_rows, verify_attestation
    import hashlib

    patient = ClientEmulator("seal-review", "password")
    await patient.register(client)
    await _setup_kit(client, patient, os.urandom(32))
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(AccessLog).where(AccessLog.user_id == patient.user_id))
        selected_row_id = row.id
        row.entry_mac = None
        await session.commit()
        snapshot, rows = await snapshot_rows(session, settings)
        digest = hashlib.sha256(snapshot).hexdigest()
        with pytest.raises(ValueError):
            verify_attestation(
                snapshot,
                "0" * 64,
                "operator independently reconciled trusted backup evidence for every legacy row",
            )
        with pytest.raises(ValueError):
            verify_attestation(snapshot, digest, "trust it")
        verify_attestation(
            snapshot,
            digest,
            "operator independently reconciled trusted backup evidence for every legacy row",
        )
        selected_snapshot_row = next(item for item in rows if item.id == selected_row_id)
        assert selected_snapshot_row.entry_mac is None  # snapshot never silently seals
        row.entry_mac = "0" * 64
        await session.commit()
        with pytest.raises(ValueError, match="existing MAC"):
            await snapshot_rows(session, settings)


async def test_offline_audit_cli_snapshot_refuses_changed_evidence_then_seals_exact_review(
    tmp_path,
):
    import hashlib
    from pathlib import Path
    import sys
    from app.api._audit import compute_entry_hash
    from app.db import build_engine, build_sessionmaker, init_models

    url = "sqlite+aiosqlite:///" + str(tmp_path / "review_test.sqlite")
    engine = build_engine(url)
    await init_models(engine)
    owner, actor, row_id = "1" * 32, "2" * 32, "3" * 32
    at = utcnow()
    initial_hash = compute_entry_hash(None, actor, owner, "read_entries", at)
    async with build_sessionmaker(engine)() as session:
        session.add(
            AccessLog(
                id=row_id,
                actor_id=actor,
                actor_role="therapist",
                user_id=owner,
                action="read_entries",
                at=at,
                chain_seq=1,
                prev_hash=None,
                entry_hash=initial_hash,
                entry_mac=None,
                record_version=1,
            )
        )
        await session.commit()
    script = Path(__file__).resolve().parents[1] / "scripts" / "seal_legacy_audit.py"
    env = {
        **os.environ,
        "MINDPATTERN_ENV": "development",
        "MINDPATTERN_DB_URL": url,
        "MINDPATTERN_TOKEN_SECRET": "synthetic-offline-audit-cli-only",
        "MINDPATTERN_AUDIT_MAC_SECRET": "a5" * 32,
        "MINDPATTERN_AUDIT_JOURNAL": "",
    }

    async def command(*args):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(script),
            *args,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        return process.returncode, stdout.decode(), stderr.decode()

    snapshot, attestation, receipt = (
        tmp_path / name for name in ("review.json", "attestation.txt", "receipt.json")
    )
    status, stdout, stderr = await command("snapshot", "--output", str(snapshot))
    assert status == 0, stderr
    digest = stdout.strip()
    assert digest == hashlib.sha256(snapshot.read_bytes()).hexdigest()
    assert snapshot.stat().st_mode & 0o777 == 0o600
    attestation.write_text(
        "Synthetic test operator reconciled this exact snapshot with independently preserved test evidence."
    )
    args = (
        "seal",
        "--snapshot",
        str(snapshot),
        "--sha256",
        digest,
        "--attestation",
        str(attestation),
        "--receipt",
        str(receipt),
        "--maintenance-confirmed",
    )
    # A changed, internally consistent chain still differs from reviewed
    # evidence. The tool must refuse it before writing any seal or receipt.
    async with build_sessionmaker(engine)() as session:
        row = await session.get(AccessLog, row_id)
        row.action = "read_measures"
        row.entry_hash = compute_entry_hash(None, actor, owner, row.action, at)
        await session.commit()
    status, _, stderr = await command(*args)
    assert status == 1 and "changed after review" in stderr
    assert not receipt.exists()
    async with build_sessionmaker(engine)() as session:
        row = await session.get(AccessLog, row_id)
        assert row.entry_mac is None
        row.action, row.entry_hash = "read_entries", initial_hash
        await session.commit()
    status, stdout, stderr = await command(*args)
    assert status == 0 and "sealed 1 reviewed legacy rows" in stdout, stderr
    assert receipt.stat().st_mode & 0o777 == 0o600
    assert json.loads(receipt.read_text())["reviewed_sha256"] == digest
    async with build_sessionmaker(engine)() as session:
        verified = await verify_access_log_chain(session, owner, mac_key=bytes.fromhex("a5" * 32))
        assert verified.ok and verified.rows_checked == 1 and verified.legacy_rows == 0
    await engine.dispose()


async def test_live_journal_day_progress_survives_entry_write_replace_and_delete(client):
    patient = ClientEmulator("live-progress", "password")
    await patient.register(client)
    await patient.backdate_account(client, 20)
    today = utcnow().date()
    for index in range(1, 11):
        await patient.create_entry(
            client, "past day", today - timedelta(days=index), f"past-{index}"
        )
    before = (await client.get("/api/insights", headers=patient.headers)).json()
    assert before["active_days"] == 10 and before["blob"] is None
    await patient.create_entry(client, "today", today, "today")
    saved = (await client.get("/api/insights", headers=patient.headers)).json()
    assert saved["active_days"] == 11 and saved["days_remaining"] == 19
    await patient.replace_entry(client, "today", "edited today", today)
    assert (await client.get("/api/insights", headers=patient.headers)).json()["active_days"] == 11
    assert (await client.delete("/api/entries/today", headers=patient.headers)).status_code == 204
    assert (await client.get("/api/insights", headers=patient.headers)).json()["active_days"] == 10


async def test_installed_note_custody_rejects_legacy_and_stale_writers(client):
    patient = ClientEmulator("custody-patient", "patient password")
    await patient.register(client)
    therapist = TherapistEmulator("custody-writer", "therapist password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    grant = await patient.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    assert grant["status"] == 201
    body = {
        "verifier": therapist.auth_key_b64,
        "operation_id": str(uuid.uuid4()),
        "expected_custody_version": 0,
        "custody_version": 1,
        "notes_keyring_blob": b64(os.urandom(60)),
    }
    assert (
        await client.put("/api/therapist/custody", headers=therapist.headers, json=body)
    ).status_code == 204
    url = "/api/therapist/patients/" + patient.user_id + "/notes"
    note = {"client_note_id": "new-note", "blob": b64(os.urandom(60))}
    legacy = await client.post(url, headers=therapist.headers, json=note)
    assert legacy.status_code == 409 and legacy.json()["code"] == "upgrade_required"
    stale = await client.post(url, headers=therapist.headers, json={**note, "custody_version": 0})
    assert stale.status_code == 409 and stale.json()["code"] == "version_conflict"
    current = await client.post(url, headers=therapist.headers, json={**note, "custody_version": 1})
    assert current.status_code == 201, current.text
    note_url = "/api/therapist/notes/" + current.json()["id"]
    edit = {"blob": b64(os.urandom(60)), "base_version": current.json()["version"]}
    assert (await client.patch(note_url, headers=therapist.headers, json=edit)).status_code == 409
    assert (
        await client.patch(note_url, headers=therapist.headers, json={**edit, "custody_version": 1})
    ).status_code == 200


async def test_real_postgresql_guard_connection_loss_fails_readiness_and_purges_keys(client, app):
    if app.state.engine.dialect.name != "postgresql":
        pytest.skip("requires the isolated PostgreSQL integration database")
    from app.main import _guard_is_healthy

    guard = app.state.guard_connection
    pid = (await guard.exec_driver_sql("SELECT pg_backend_pid()")).scalar()
    await guard.commit()
    token = app.state.key_store.create(os.urandom(32), 300, owner="synthetic-guard-loss")
    async with app.state.engine.begin() as connection:
        assert (
            await connection.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
        ).scalar() is True
    assert await _guard_is_healthy(app) is False
    from app.security.enclave import KeyNotFound

    with pytest.raises(KeyNotFound):
        app.state.key_store.pop(token, owner="synthetic-guard-loss")
    assert (await client.get("/readyz")).status_code == 503
    assert (await client.get("/healthz")).status_code == 200
    assert (await client.post("/api/auth/salt", json={"username": "synthetic"})).status_code == 503


async def test_atomic_v2_corpus_envelope_and_active_grant_commit_together(client, app):
    old = EnvelopeClientEmulator("atomic-v2", "old password")
    await old.register(client)
    await old.create_entry(client, "v2 record survives", utcnow().date(), "v2-entry")
    therapist = TherapistEmulator("atomic-v2-clinician", "therapist password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    grant = await old.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    consent_id = grant["body"]["id"]
    new = EnvelopeClientEmulator(old.username, "new password")
    new.user_id = old.user_id
    from app.security import sharing

    ephemeral, wrapped = sharing.wrap_data_key(
        new.data_key, therapist.wrap_pub_key, old.user_id, therapist.user_id
    )
    body = {
        "operation_id": str(uuid.uuid4()),
        "new_salt": new.salt_b64,
        "new_verifier": new.auth_key_b64,
        "new_wrapped_data_key": new.wrap_for(new.password, new.salt),
        "new_kdf_params": new.kdf_params,
        "consent_wraps": [
            {
                "consent_id": consent_id,
                "therapist_wrap_pub_key": therapist.wrap_pub_key,
                "ephemeral_pub": ephemeral,
                "wrapped_key": wrapped,
            }
        ],
    }
    old_token = await old.open_processing_session(client)
    new_token = await old.open_processing_session_for(client, new.data_key)
    headers = {
        **old.headers,
        "X-Account-Verifier": old.auth_key_b64,
        "X-Processing-Token": old_token,
        "X-New-Processing-Token": new_token,
    }
    omitted = await client.post(
        "/api/processing/rekey", headers=headers, json={**body, "consent_wraps": []}
    )
    assert omitted.status_code == 409
    # Preflight refusal consumes the tokens; corpus and credentials stayed old.
    assert (await old.get_entry(client, "v2-entry"))["blob"]
    headers["X-Processing-Token"] = await old.open_processing_session(client)
    headers["X-New-Processing-Token"] = await old.open_processing_session_for(client, new.data_key)
    result = await client.post("/api/processing/rekey", headers=headers, json=body)
    assert result.status_code == 200, result.text
    assert result.json()["consents_rewrapped"] == 1
    await new.unlock(client)
    entry = await new.get_entry(client, "v2-entry")
    assert (
        new.decrypt_entry(entry["blob"], "v2-entry", entry["content_version"])["text"]
        == "v2 record survives"
    )
    roster = (await client.get("/api/therapist/patients", headers=therapist.headers)).json()
    assert (
        therapist.unwrap_patient_data_key(new, roster[0]["ephemeral_pub"], roster[0]["wrapped_key"])
        == new.data_key
    )
    again = await client.post("/api/processing/rekey", headers=headers, json=body)
    assert again.status_code == 200 and again.json() == result.json()


async def test_exact_interrupted_rotation_survives_deleted_therapist_without_restoring_grant(
    client, app, monkeypatch
):
    from app.api import insights
    from app.security import sharing

    old = ClientEmulator("deleted-grant-resume", "old password")
    await old.register(client)
    await old.create_entry(client, "interrupted entry", utcnow().date(), "resume-entry")
    therapist = TherapistEmulator("deleted-resume-clinician", "therapist password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    grant = await old.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    consent_id = grant["body"]["id"]
    new = ClientEmulator(old.username, "new password")
    new.user_id = old.user_id
    ephemeral, wrapped = sharing.wrap_data_key(
        new.data_key, therapist.wrap_pub_key, old.user_id, therapist.user_id
    )
    body = {
        "operation_id": str(uuid.uuid4()),
        "new_salt": new.salt_b64,
        "new_verifier": new.auth_key_b64,
        "consent_wraps": [
            {
                "consent_id": consent_id,
                "therapist_wrap_pub_key": therapist.wrap_pub_key,
                "ephemeral_pub": ephemeral,
                "wrapped_key": wrapped,
            }
        ],
    }
    aad = crypto.build_aad("measure", old.user_id, "resume-measure")
    async with app.state.sessionmaker() as session:
        session.add(
            Measure(
                user_id=old.user_id,
                client_measure_id="resume-measure",
                measure_date=utcnow().date(),
                blob=crypto.encrypt(old.data_key, b'{"score":3}', aad),
            )
        )
        await session.commit()
    original_worker = insights._rekey_blob_batch

    def interrupt(*args, **kwargs):
        raise RuntimeError("synthetic interruption after committed entry batch")

    monkeypatch.setattr(insights, "_rekey_blob_batch", interrupt)
    headers = {
        **old.headers,
        "X-Account-Verifier": old.auth_key_b64,
        "X-Processing-Token": await old.open_processing_session(client),
        "X-New-Processing-Token": await old.open_processing_session_for(client, new.data_key),
    }
    failed = await client.post("/api/processing/rekey", headers=headers, json=body)
    assert failed.status_code == 500
    async with app.state.sessionmaker() as session:
        journal = await session.scalar(
            select(RekeyJournal).where(RekeyJournal.user_id == old.user_id)
        )
        assert journal.operation_id == body["operation_id"] and journal.entries_done == 1
        entry = await session.scalar(select(Entry).where(Entry.user_id == old.user_id))
        assert (
            new.decrypt_entry(b64(entry.blob), entry.client_entry_id, entry.content_version)["text"]
            == "interrupted entry"
        )
        assert (
            crypto.decrypt(
                old.data_key,
                (await session.scalar(select(Measure).where(Measure.user_id == old.user_id))).blob,
                aad,
            )
            == b'{"score":3}'
        )
    # Different sharing identities are fenced while the saved atomic body
    # targets this key. Same-key repair preserves the target and note custody.
    custody = {
        "verifier": therapist.auth_key_b64,
        "operation_id": str(uuid.uuid4()),
        "expected_custody_version": 0,
        "custody_version": 1,
        "notes_keyring_blob": b64(os.urandom(60)),
    }
    assert (
        await client.put("/api/therapist/custody", headers=therapist.headers, json=custody)
    ).status_code == 204
    replacement = TherapistEmulator("replacement-resume-identity", "password")
    wrap_body = {
        "wrap_pub_key": replacement.wrap_pub_key,
        "wrap_key_blob": b64(os.urandom(60)),
        "expected_custody_version": 1,
    }
    wrap_headers = {**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64}
    blocked = await client.put("/api/therapist/wrap-key", headers=wrap_headers, json=wrap_body)
    assert blocked.status_code == 409 and blocked.json()["code"] == "rekey_in_progress"
    assert (
        await client.put(
            "/api/therapist/wrap-key",
            headers=wrap_headers,
            json={**wrap_body, "wrap_pub_key": therapist.wrap_pub_key},
        )
    ).status_code == 204
    me = (await client.get("/api/therapist/me", headers=therapist.headers)).json()
    assert me["notes_keyring_blob"] == custody["notes_keyring_blob"] and me["custody_version"] == 1
    assert (await client.delete("/api/therapist/account", headers=wrap_headers)).status_code == 204
    async with app.state.sessionmaker() as session:
        assert await session.get(Consent, consent_id) is None
    monkeypatch.setattr(insights, "_rekey_blob_batch", original_worker)
    headers["X-Processing-Token"] = await old.open_processing_session(client)
    headers["X-New-Processing-Token"] = await old.open_processing_session_for(client, new.data_key)
    completed = await client.post("/api/processing/rekey", headers=headers, json=body)
    assert completed.status_code == 200, completed.text
    assert completed.json()["consents_rewrapped"] == 0
    assert (
        await client.post("/api/processing/rekey", headers=headers, json=body)
    ).json() == completed.json()
    await new.login(client)
    entry = await new.get_entry(client, "resume-entry")
    assert (
        new.decrypt_entry(entry["blob"], "resume-entry", entry["content_version"])["text"]
        == "interrupted entry"
    )
    async with app.state.sessionmaker() as session:
        assert (
            crypto.decrypt(
                new.data_key,
                (await session.scalar(select(Measure).where(Measure.user_id == old.user_id))).blob,
                aad,
            )
            == b'{"score":3}'
        )
        assert await session.get(Consent, consent_id) is None
        assert (
            await session.scalar(select(RekeyJournal.id).where(RekeyJournal.user_id == old.user_id))
            is None
        )


async def test_body_admission_refuses_without_reading_and_releases_cancelled_slot():
    entered, finish = asyncio.Event(), asyncio.Event()

    async def application(scope, receive, send):
        entered.set()
        await finish.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = HardeningMiddleware(application, max_body_bytes=1024, body_buffer_concurrency=1)
    scope = {
        "type": "http",
        "path": "/x",
        "method": "POST",
        "headers": [],
        "client": ("127.0.0.1", 1234),
    }

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def discard(message):
        pass

    first = asyncio.create_task(middleware(dict(scope), receive, discard))
    await entered.wait()
    reads = 0
    messages = []

    async def forbidden_receive():
        nonlocal reads
        reads += 1
        return await receive()

    async def capture(message):
        messages.append(message)

    await middleware(dict(scope), forbidden_receive, capture)
    assert reads == 0 and messages[0]["status"] == 503
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert middleware._body_admitted == 0
    finish.set()
    await middleware(dict(scope), receive, discard)


async def test_guard_loss_closes_readiness_and_api_admission(app, client):
    app.state.guard_healthy = False
    assert (await client.get("/readyz")).status_code == 503
    assert (await client.get("/api/meta")).status_code == 503
    assert (await client.get("/healthz")).status_code == 200


@pytest.mark.parametrize("left,right", [([], [1.0, 2.0, 3.0]), ([1.0, 2.0, 3.0], [])])
def test_empty_mood_group_never_divides_by_zero(left, right):
    assert statsig.cohens_d(left, right, variance_floor=0.1) == 0


async def test_partial_translation_is_never_published(settings, monkeypatch):
    from app.services.llm import LLMAnalyzer

    settings.llm_url = "https://translation.example.invalid"
    monkeypatch.setattr(
        LLMAnalyzer,
        "_post",
        lambda self, body: {
            "choices": [
                {"finish_reason": "length", "message": {"content": "A partial translation"}}
            ]
        },
    )
    assert await stt.translate_to_english(settings, "un texto", "es") is None
