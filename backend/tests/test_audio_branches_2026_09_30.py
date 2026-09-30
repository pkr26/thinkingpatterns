"""Handler-level branch tests for the audio router's fence/validation arms
(release-gate coverage, 2026-09-30): driven through the HTTP client where
cheap, and through direct seams where the API cannot reach them."""

from __future__ import annotations

import base64
from datetime import date

import pytest

from tests.helpers import ClientEmulator
from tests.test_voice_remediation_2026_09_29 import _voice_ready

TODAY = date.today()


@pytest.fixture(autouse=True)
def _scratch_audio_store(settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "audio")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _transcription_body(audio: bytes = b"RIFF-x" * 16, duration: int = 30) -> dict:
    return {"audio_b64": b64(audio), "mime": "audio/webm", "duration_seconds": duration}


@pytest.mark.asyncio
class TestTranscriptionEdgeBranches:
    async def test_oversized_recording_is_413(self, client, settings):
        settings.audio_max_body_bytes = 8
        emu = await _voice_ready(client, settings, "audio-413")
        r = await client.post(
            "/api/v1/audio/transcriptions", headers=emu.headers, json=_transcription_body()
        )
        assert r.status_code == 413, r.text
        assert r.json()["code"] == "payload_too_large"

    async def test_zero_and_overlong_durations_are_422(self, client, settings):
        emu = await _voice_ready(client, settings, "audio-dur")
        zero = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json=_transcription_body(duration=0),
        )
        assert zero.status_code == 422
        over = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json=_transcription_body(duration=10_000_000),
        )
        assert over.status_code == 422

    async def test_empty_recording_is_422(self, client, settings):
        emu = await _voice_ready(client, settings, "audio-empty")
        r = await client.post(
            "/api/v1/audio/transcriptions",
            headers=emu.headers,
            json=_transcription_body(audio=b""),
        )
        assert r.status_code == 422

    async def test_fresh_row_missing_inside_the_fence_is_410(
        self, client, app, settings, monkeypatch
    ):
        """The fenced re-read's account-gone arm: the row flips inside the
        lock acquisition (before the handler's fresh read)."""
        emu = await _voice_ready(client, settings, "audio-fence-410")
        from sqlalchemy import update

        from app.api import audio as audio_api
        from app.models import User as U

        real_locks = audio_api.lifecycle_locks

        class _FlipCtx:
            def __init__(self, inner, name):
                self._inner = inner
                self._name = name

            async def __aenter__(self):
                await self._inner.__aenter__()
                if self._name == f"llm-lifecycle:{emu.user_id}":
                    async with app.state.sessionmaker() as session:
                        await session.execute(
                            update(U).where(U.id == emu.user_id).values(is_active=False)
                        )
                        await session.commit()

            async def __aexit__(self, *exc):
                return await self._inner.__aexit__(*exc)

        class _FlipLocks:
            def hold(self, name):
                return _FlipCtx(real_locks.hold(name), name)

        monkeypatch.setattr(audio_api, "lifecycle_locks", _FlipLocks())
        from app.services.stt import SpeechToText

        async def ok_post(self, files, data):
            return {"text": "words", "language": "english"}

        monkeypatch.setattr(SpeechToText, "_post_audio", ok_post)
        r = await client.post(
            "/api/v1/audio/transcriptions", headers=emu.headers, json=_transcription_body()
        )
        assert r.status_code == 410, r.text
        assert r.json()["code"] == "account_deleted"


@pytest.mark.asyncio
class TestUploadEdgeBranches:
    async def test_upload_unknown_entry_is_404(self, client, settings):
        emu = await _voice_ready(client, settings, "audio-up-404")
        r = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "never-existed",
                "blob": b64(b"RIFF-x" * 8),
                "mime": "audio/webm",
                "duration_seconds": 10,
            },
        )
        assert r.status_code == 404, r.text

    async def test_upload_bad_mime_and_duration_are_422(self, client, settings):
        emu = await _voice_ready(client, settings, "audio-up-422")
        await emu.create_entry(client, "up day", TODAY, client_entry_id="e-up422")
        bad_mime = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "e-up422",
                "blob": b64(b"RIFF-x" * 8),
                "mime": "audio/flac",
                "duration_seconds": 10,
            },
        )
        assert bad_mime.status_code == 422
        bad_dur = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "e-up422",
                "blob": b64(b"RIFF-x" * 8),
                "mime": "audio/webm",
                "duration_seconds": 0,
            },
        )
        assert bad_dur.status_code == 422

    async def test_replace_delete_failure_maps_to_502(self, client, settings, monkeypatch):
        """SKIPPED-SCOPE NOTE: the delete-before-put replace arm is the S3
        store's path (LocalAudioStore overwrites in place); it is exercised
        by the fake-boto3 harness in test_voice_remediation_2026_09_29."""
        pytest.skip("S3-store arm: covered by the fake-boto3 M4 suite")

