"""Voice dispatch inside the lifecycle fence (deep audit 2026-09-29, MEDIUM).

The transcription and translation routes used to read voice/LLM consent
ONCE at entry and then run up to ~120s of third-party round trips with no
``llm-lifecycle`` lock — so a consent withdrawal or account erasure that
had already RETURNED could still race a dispatch of the patient's audio
(or transcript) to the provider. The recompute path and the deletion path
both take the same named lock, which is exactly the linearizability the
deletion docstring promises ("no queued or in-flight recompute may newly
send this account's plaintext off-server").

These tests pin the fence: the lock is HELD across the provider round
trips, so withdrawal (same lock) linearizes before or after the dispatch,
never during it.
"""

from __future__ import annotations

import asyncio
import base64

import pytest

from app.locks import lifecycle_locks
from app.services import stt as stt_service
from app.services.stt import SpeechToText
from tests.helpers import ClientEmulator
from tests.test_voice_remediation_2026_09_29 import _grant_llm_consent, _voice_ready


def _transcription_body() -> dict:
    return {
        "audio_b64": base64.b64encode(b"RIFF-fake-webm-bytes" * 64).decode("ascii"),
        "mime": "audio/webm",
        "duration_seconds": 60,
    }


def _locked_out_flag(user_id: str) -> bool:
    """Deterministic held-check (2026-09-30: the 0.2s wait_for probe was
    timing-flaky on loaded CI runners). The registry's refcount for the
    key is > 0 exactly while a caller holds or is acquiring the guard —
    the same invariant the registry's own eviction relies on."""
    registry = getattr(lifecycle_locks, "_locks", None)
    assert registry is not None, "lifecycle lock registry not introspectable"
    entry = registry.get(f"llm-lifecycle:{user_id}")
    return entry is not None and entry.refs > 0


@pytest.mark.asyncio
class TestTranscriptionDispatchIsFenced:
    async def test_stt_round_trip_holds_the_lifecycle_lock(self, client, settings, monkeypatch):
        emu = await _voice_ready(client, settings, "fence-stt")
        assert emu.user_id

        observed: dict[str, bool] = {}

        async def fake_post_audio(self, files, data):
            observed["locked_during_stt"] = _locked_out_flag(emu.user_id)
            return {"text": "Texto privado del diario.", "language": "spanish"}

        async def fake_translate(s_settings, text, source_lang):
            observed["locked_during_translate"] = _locked_out_flag(emu.user_id)
            return "Private journal text."

        monkeypatch.setattr(SpeechToText, "_post_audio", fake_post_audio)
        monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)

        response = await client.post(
            "/api/v1/audio/transcriptions", headers=emu.headers, json=_transcription_body()
        )
        assert response.status_code == 200, response.text
        # The lock was held across BOTH third-party round trips: a consent
        # withdrawal (same named lock) can no longer commit between the
        # consent check and the dispatch.
        assert observed.get("locked_during_stt") is True
        assert observed.get("locked_during_translate") is True
        # And the response still carries the transcript: the fence is
        # transparent on the success path.
        assert response.json()["original_text"] == "Texto privado del diario."

    async def test_translation_route_holds_the_lifecycle_lock(self, client, settings, monkeypatch):
        settings.audio_enabled = True
        settings.llm_url = "https://llm.example.com/v1"
        settings.llm_api_key = "k"
        emu = await _voice_ready(client, settings, "fence-xlate")
        await _grant_llm_consent(client, emu)

        observed: dict[str, bool] = {}

        async def fake_translate(s_settings, text, source_lang):
            observed["locked"] = _locked_out_flag(emu.user_id)
            return "Private journal text."

        monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)

        response = await client.post(
            "/api/v1/audio/translations",
            headers=emu.headers,
            json={"text": "Texto editado", "source_lang": "es"},
        )
        assert response.status_code == 200, response.text
        assert observed.get("locked") is True
        assert response.json()["english_text"] == "Private journal text."


@pytest.mark.asyncio
class TestFenceReReadsFreshUser:
    async def test_translation_after_deactivation_returns_410(
        self, client, app, settings, monkeypatch
    ):
        """The fenced fresh re-read: an account deactivated AFTER the
        dependency loaded the row (but before the fence's read) is
        caught — the old code dispatched on the stale object. The
        dependency re-reads per request, so the only way to land in the
        race window is between the dependency load and the handler's
        fence: the row flips sequentially inside the lock acquisition
        wrapper (no concurrency — the flip commits before the handler's
        fenced session.get runs)."""
        settings.audio_enabled = True
        settings.llm_url = "https://llm.example.com/v1"
        settings.llm_api_key = "k"
        emu = await _voice_ready(client, settings, "fence-gone")
        await _grant_llm_consent(client, emu)

        dispatched = []
        monkeypatch.setattr(
            stt_service,
            "translate_to_english",
            lambda s, t, lang: dispatched.append(t),
        )

        from sqlalchemy import update

        from app.api import audio as audio_api
        from app.models import User

        real_locks = audio_api.lifecycle_locks

        class _FlipCtx:
            """Real lock, plus a sequential row flip on entry for the one
            named lock — simulating a deletion that committed inside the
            dependency→fence race window."""

            def __init__(self, inner, name: str):
                self._inner = inner
                self._name = name

            async def __aenter__(self):
                await self._inner.__aenter__()
                if self._name == f"llm-lifecycle:{emu.user_id}":
                    async with app.state.sessionmaker() as session:
                        await session.execute(
                            update(User).where(User.id == emu.user_id).values(is_active=False)
                        )
                        await session.commit()

            async def __aexit__(self, *exc):
                return await self._inner.__aexit__(*exc)

        class _FlipLocks:
            def hold(self, name: str):
                return _FlipCtx(real_locks.hold(name), name)

        monkeypatch.setattr(audio_api, "lifecycle_locks", _FlipLocks())

        response = await client.post(
            "/api/v1/audio/translations",
            headers=emu.headers,
            json={"text": "Texto editado", "source_lang": "es"},
        )
        assert response.status_code == 410, response.text
        assert response.json()["code"] == "account_deleted"
        assert dispatched == []
