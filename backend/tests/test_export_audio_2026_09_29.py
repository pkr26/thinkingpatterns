"""Kept recordings ride the account export (deep audit 2026-09-29, LOW).

The export bundle omitted every AudioAttachment: a patient who exported
before deleting their account silently lost all kept recordings — a
GDPR Art. 20 portability gap (and the mobile client's decrypt:export
tool had no audio equivalent at all). The bundle now carries an
additive ``audio`` section: metadata + the base64 ciphertext object,
fetched OUTSIDE the lifecycle fence (an object erased mid-export is
skipped, honestly).
"""

from __future__ import annotations

import base64
import json
from datetime import date

import pytest

from tests.test_voice_remediation_2026_09_29 import _voice_ready

TODAY = date.today()


@pytest.fixture(autouse=True)
def _scratch_audio_store(settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "audio")


async def _export_bundle(client, emu) -> dict:
    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
class TestExportIncludesKeptAudio:
    async def test_an_attachment_travels_with_the_export(self, client, settings):
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        emu = await _voice_ready(client, settings, "export-audio")
        audio = b"RIFF-fake-take-bytes" * 8
        await emu.create_entry(client, "a recorded day", TODAY, client_entry_id="e-export-1")
        created = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": "e-export-1",
                "blob": base64.b64encode(audio).decode("ascii"),
                "mime": "audio/webm",
                "duration_seconds": 30,
            },
        )
        assert created.status_code in (200, 201), created.text

        bundle = await _export_bundle(client, emu)
        audio_rows = bundle.get("audio", [])
        assert len(audio_rows) == 1, bundle.keys()
        row = audio_rows[0]
        assert row["client_entry_id"] == "e-export-1"
        assert row["mime_type"] == "audio/webm"
        assert row["duration_seconds"] == 30
        # The blob is the stored CIPHERTEXT (client-side envelope) — the
        # export hands back exactly what was uploaded, decryptable with
        # the data key.
        assert base64.b64decode(row["blob"]) == audio

    async def test_no_audio_store_configured_exports_an_empty_section(self, client, settings):
        """Additive contract: the key always exists, old consumers of the
        bundle are unaffected."""
        settings.audio_enabled = True
        settings.stt_url = "https://stt.example.com/v1"
        settings.stt_api_key = "k"
        settings.audio_local_dir = ""  # no store configured
        emu = await _voice_ready(client, settings, "export-audio-none")
        await emu.create_entry(client, "a plain day", TODAY, client_entry_id="e-2")
        bundle = await _export_bundle(client, emu)
        assert bundle["audio"] == []
        assert bundle["entries"], "the rest of the bundle is intact"
