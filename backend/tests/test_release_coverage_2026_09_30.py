"""Release-gate coverage extensions (2026-09-30): the recovery + audio
paths the 2.1.0 verify job's 97% floor needs — error branches, the
insight-fallback possession probe, and the audio store's failure maps."""

from __future__ import annotations

import base64
import os
from datetime import date

import pytest

from tests.helpers import ClientEmulator, EnvelopeClientEmulator
from tests.test_recovery_envelope import recovery_body, recovery_verifier
from tests.test_voice_remediation_2026_09_29 import _voice_ready

TODAY = date.today()


@pytest.fixture(autouse=True)
def _scratch_audio_store(settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "audio")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.asyncio
class TestRecoveryErrorBranches:
    async def test_setup_422_shapes(self, client):
        emu = ClientEmulator("recov-422", "correct horse battery staple")
        await emu.register(client)
        # Non-base64 verifier.
        r = await client.put(
            "/api/account/recovery",
            headers=emu.headers,
            json={
                "password_verifier": emu.auth_key_b64,
                "verifier": "!!not b64!!",
                "wrapped_key": b64(os.urandom(60)),
            },
        )
        assert r.status_code == 422, r.text
        # Wrong recovery-key length (31 bytes).
        r2 = await client.put(
            "/api/account/recovery",
            headers=emu.headers,
            json={
                "password_verifier": emu.auth_key_b64,
                "verifier": b64(os.urandom(31)),
                "wrapped_key": b64(os.urandom(60)),
            },
        )
        assert r2.status_code == 422
        # Wrong sealed-blob length.
        r3 = await client.put(
            "/api/account/recovery",
            headers=emu.headers,
            json={
                "password_verifier": emu.auth_key_b64,
                "verifier": b64(os.urandom(32)),
                "wrapped_key": b64(os.urandom(59)),
            },
        )
        assert r3.status_code == 422

    async def test_disable_requires_the_verifier_header(self, client):
        emu = ClientEmulator("recov-del", "correct horse battery staple")
        await emu.register(client)
        r = await client.delete("/api/account/recovery", headers=emu.headers)
        assert r.status_code == 422, r.text
        assert r.json()["code"] == "validation_error"

    async def test_reset_without_a_kit_is_a_409(self, client):
        emu = EnvelopeClientEmulator("recov-nokit-reset", "correct horse battery staple")
        await emu.register(client)
        r = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={
                "proof": b64(os.urandom(32)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(60)),
            },
        )
        assert r.status_code == 409, r.text
        assert r.json()["code"] == "recovery_not_configured"

    async def test_reset_422_shapes(self, client):
        emu = EnvelopeClientEmulator("recov-reset-422", "correct horse battery staple")
        await emu.register(client)
        # Bad base64 body.
        r = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={"proof": "!!", "new_salt": "!!", "new_verifier": "!!", "wrapped_data_key": "!!"},
        )
        assert r.status_code == 422
        # Wrong proof length.
        r2 = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={
                "proof": b64(os.urandom(31)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(60)),
            },
        )
        assert r2.status_code == 422
        # Wrong salt length.
        r3 = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={
                "proof": b64(os.urandom(32)),
                "new_salt": b64(os.urandom(15)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(60)),
            },
        )
        assert r3.status_code == 422
        # Wrong verifier length.
        r4 = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={
                "proof": b64(os.urandom(32)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": b64(os.urandom(31)),
                "wrapped_data_key": b64(os.urandom(60)),
            },
        )
        assert r4.status_code == 422
        # Wrong wrapped length.
        r5 = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,
            json={
                "proof": b64(os.urandom(32)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(59)),
            },
        )
        assert r5.status_code == 422

    async def test_reset_possession_probe_falls_back_to_insights(self, client, app):
        """An account with INSIGHT rows but no entries proves possession via
        the insight AAD path (the probe's second arm)."""
        recovery_key = os.urandom(32)
        emu = EnvelopeClientEmulator("recov-insight-probe", "correct horse battery staple")
        await emu.register(client)
        from app.models import Insight as InsightRow
        from app.security import crypto as server_crypto

        # Seal a small ciphertext under the account's data key with the
        # insights AAD so the possession probe AUTHENTICATES it.
        aad = server_crypto.build_aad("insights", emu.user_id, "patterns")
        sealed = server_crypto.encrypt(emu.data_key, b"patterns-blob", aad)
        async with app.state.sessionmaker() as session:
            session.add(
                InsightRow(
                    user_id=emu.user_id,
                    kind="patterns",
                    for_date=None,
                    blob=bytes(sealed),
                )
            )
            await session.commit()

        body = recovery_body(recovery_key)
        body["password_verifier"] = emu.auth_key_b64
        setup = await client.put("/api/account/recovery", headers=emu.headers, json=body)
        assert setup.status_code == 204, setup.text

        recovered = await client.post(
            "/api/auth/recover",
            json={
                "username": "recov-insight-probe",
                "verifier": b64(recovery_verifier(recovery_key)),
                "scheme": "v2",
            },
        )
        assert recovered.status_code == 200, recovered.text
        # The epoch bump killed the emulator's bearer: re-login FIRST, then
        # open the processing session with the live token.
        await emu.login(client)
        headers = {
            "Authorization": f"Bearer {recovered.json()['token']}",
            "X-Processing-Token": await emu.open_processing_session_for(client, emu.data_key),
        }
        emu.password = "another new passphrase"
        new_wrap = emu.wrap_for(emu.password, os.urandom(16))
        r = await client.put(
            "/api/account/recovery/password",
            headers=headers,
            json={
                "proof": b64(recovery_verifier(recovery_key)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": new_wrap,
            },
        )
        assert r.status_code == 204, r.text


@pytest.mark.asyncio
class TestAudioErrorBranches:
    async def test_transcribe_without_engine_is_503(self, client, settings):
        emu = await _voice_ready(client, settings, "audio-503")
        settings.stt_url = ""  # unconfigured AFTER the helper set it
        r = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json={
                "audio_b64": b64(b"x" * 64),
                "mime": "audio/webm",
                "duration_seconds": 10,
            },
        )
        assert r.status_code == 503, r.text
        assert r.json()["code"] == "stt_unconfigured"

    async def test_transcribe_validation_branches(self, client, settings):
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        emu = await _voice_ready(client, settings, "audio-422")
        # Bad mime.
        r = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json={"audio_b64": b64(b"x" * 64), "mime": "audio/flac", "duration_seconds": 10},
        )
        assert r.status_code == 422
        # Duration over the cap.
        r2 = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json={
                "audio_b64": b64(b"x" * 64),
                "mime": "audio/webm",
                "duration_seconds": 10_000_000,
            },
        )
        assert r2.status_code == 422
        # Empty audio.
        r3 = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json={"audio_b64": b64(b""), "mime": "audio/webm", "duration_seconds": 10},
        )
        assert r3.status_code == 422

    async def test_attachment_crud_misses(self, client, settings):
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        emu = await _voice_ready(client, settings, "audio-misses")
        # Unknown attachment fetch/delete → 404.
        r = await client.get("/api/v1/audio/attachments/missing-id", headers=emu.headers)
        assert r.status_code == 404, r.text
        r2 = await client.delete("/api/v1/audio/attachments/missing-id", headers=emu.headers)
        assert r2.status_code == 404

    async def test_attachment_store_failure_maps_to_502(self, client, settings, monkeypatch):
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        emu = await _voice_ready(client, settings, "audio-put-fail")
        await emu.create_entry(client, "voice day", TODAY, client_entry_id="e-putfail")

        from app.services import audio_store as store_module

        async def failing_put(self, key, blob):
            raise store_module.AudioStoreError("boom")

        monkeypatch.setattr(store_module.LocalAudioStore, "put", failing_put)
        r = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "e-putfail",
                "blob": b64(b"RIFF-fake" * 8),
                "mime": "audio/webm",
                "duration_seconds": 10,
            },
        )
        assert r.status_code == 502, r.text

    async def test_attachment_get_store_failure_maps_to_502(self, client, settings, monkeypatch):
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        emu = await _voice_ready(client, settings, "audio-get-fail")
        await emu.create_entry(client, "voice day two", TODAY, client_entry_id="e-getfail")
        created = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "e-getfail",
                "blob": b64(b"RIFF-fake" * 8),
                "mime": "audio/webm",
                "duration_seconds": 10,
            },
        )
        assert created.status_code in (200, 201), created.text
        from app.services import audio_store as store_module

        original_get = store_module.LocalAudioStore.get

        async def failing_get(self, key, *, max_bytes=None):
            raise store_module.AudioStoreError("boom")

        monkeypatch.setattr(store_module.LocalAudioStore, "get", failing_get)
        att_id = created.json()["attachment_id"]
        r = await client.get(f"/api/v1/audio/attachments/{att_id}", headers=emu.headers)
        assert r.status_code == 502, r.text

        async def failing_delete(self, key):
            raise store_module.AudioStoreError("boom")

        monkeypatch.setattr(store_module.LocalAudioStore, "get", original_get)
        monkeypatch.setattr(store_module.LocalAudioStore, "delete", failing_delete)
        r2 = await client.delete(f"/api/v1/audio/attachments/{att_id}", headers=emu.headers)
        assert r2.status_code == 204, r2.text
        # Object deletion failed, but the committed durable outbox retains it.
        from sqlalchemy import select

        from app.models import AudioDeletion

        async with client._transport.app.state.sessionmaker() as session:
            assert await session.scalar(select(AudioDeletion.id)) is not None
