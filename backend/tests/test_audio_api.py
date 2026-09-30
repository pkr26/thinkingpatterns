"""Voice journaling API (P1): flag, consent gate, transcription, translation.

VOICE_PLAN.md gates for this phase:
  * fail-closed flag (flat 404, no code advertising)
  * Art. 7 consent flow (verifier re-auth, fingerprint currency)
  * audio bytes never persisted anywhere (there is no storage path in P1 —
    the route is stateless by construction; P2's attachment tests pin the
    storage boundary explicitly)
  * route-scoped body cap vs the global cap
  * provider output normalization (language map pinned to
    shared/audio_vectors.json)
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from app.config import Settings
from app.services import stt as stt_service
from app.services.stt import (
    SpeechToText,
    normalize_language,
    normalize_mime,
)
from tests.helpers import ClientEmulator, TherapistEmulator

SHARED_VECTORS = pathlib.Path(__file__).resolve().parents[2] / "shared" / "audio_vectors.json"

FAKE_AUDIO = b"RIFF-fake-webm-bytes" * 64


def audio_body(audio: bytes = FAKE_AUDIO, mime: str = "audio/webm", duration: int = 60) -> dict:
    return {
        "audio_b64": base64.b64encode(audio).decode("ascii"),
        "mime": mime,
        "duration_seconds": duration,
    }


@pytest.fixture
def voice_settings(settings):
    """Audio on + a configured STT endpoint (translation LLM left OFF —
    the degraded-mode path is part of the contract)."""
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "test-stt-key"
    return settings


async def _register_and_consent(client, emu) -> ClientEmulator:
    await emu.register(client)
    response = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 200, response.text
    assert response.json()["active_for_current_policy"] is True
    return emu


# --- flag & configuration ------------------------------------------------------


async def test_audio_routes_are_404_when_flag_off(client, settings):
    # Development defaults the flag ON (the sharing convention); production
    # posture is what this pins: an explicit opt-out hides the router.
    settings.audio_enabled = False
    emu = ClientEmulator("flagoff", "correct horse battery staple")
    await emu.register(client)
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    # Flat 404 — the deployment must not advertise the disabled feature.
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    legacy = await client.post("/api/audio/transcriptions", headers=emu.headers, json=audio_body())
    assert legacy.status_code == 404


async def test_transcription_503_when_stt_unconfigured(client, settings):
    settings.audio_enabled = True  # flag on, but no MINDPATTERN_STT_URL
    emu = ClientEmulator("nostt", "correct horse battery staple")
    await emu.register(client)
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    assert response.status_code == 503
    assert response.json()["code"] == "stt_unconfigured"


async def test_meta_reports_audio_availability(client, voice_settings):
    response = await client.get("/api/meta")
    assert response.status_code == 200
    body = response.json()
    assert body["audio_available"] is True
    assert body["stt_policy_fingerprint"]
    # L-31 discipline: with the flag off, every stt_* field is falsy.
    voice_settings.audio_enabled = False
    response = await client.get("/api/meta")
    body = response.json()
    assert body["audio_available"] is False
    assert body["stt_provider_name"] is None
    assert body["stt_data_retention"] is None
    assert body["stt_policy_fingerprint"] is None


# --- consent flow --------------------------------------------------------------


async def test_transcription_requires_consent(client, voice_settings, monkeypatch):
    emu = ClientEmulator("noconsent", "correct horse battery staple")
    await emu.register(client)
    monkeypatch.setattr(
        SpeechToText,
        "_post_audio",
        lambda self, files, data: _json({"text": "hi", "language": "english"}),
    )
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    assert response.status_code == 403
    assert response.json()["code"] == "voice_consent_required"


async def test_consent_requires_stt_configured(client, settings):
    settings.audio_enabled = True  # but stt_url empty -> policy None
    emu = ClientEmulator("nopolicy", "correct horse battery staple")
    await emu.register(client)
    response = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "stt_unavailable"


async def test_consent_requires_correct_verifier(client, voice_settings):
    emu = ClientEmulator("badverifier", "correct horse battery staple")
    await emu.register(client)
    response = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": base64.b64encode(b"x" * 32).decode()},
    )
    # 403, not 401: the bearer authenticated; the re-auth failed.
    assert response.status_code == 403


async def test_consent_state_roundtrip_and_withdraw(client, voice_settings):
    emu = ClientEmulator("roundtrip", "correct horse battery staple")
    await emu.register(client)
    enabled = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert enabled.status_code == 200
    body = enabled.json()
    assert body["enabled"] is True
    assert body["active_for_current_policy"] is True
    assert body["voice_consent_at"] is not None
    assert body["voice_consent_policy"] == stt_service.processing_policy_fingerprint(voice_settings)
    state = await client.get("/api/account/voice-consent", headers=emu.headers)
    assert state.json()["enabled"] is True

    withdrawn = await client.put(
        "/api/account/voice-consent",
        headers=emu.headers,
        json={"enabled": False, "verifier": emu.auth_key_b64},
    )
    assert withdrawn.status_code == 200
    cleared = withdrawn.json()
    assert cleared["enabled"] is False
    assert cleared["active_for_current_policy"] is False
    assert cleared["voice_consent_at"] is None


async def test_policy_change_makes_consent_inert(client, voice_settings):
    emu = ClientEmulator("stalepolicy", "correct horse battery staple")
    await _register_and_consent(client, emu)
    # Operator rotates the model: the recorded yes no longer matches.
    voice_settings.stt_model = "gpt-4o-mini-transcribe"
    response = await client.get("/api/account/voice-consent", headers=emu.headers)
    assert response.json()["active_for_current_policy"] is False
    transcription = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    assert transcription.status_code == 403
    assert transcription.json()["code"] == "voice_consent_required"


# --- transcription happy path & validation -------------------------------------


def _json(value: dict):
    """A ready-to-await fake response (plain def: awaiting the returned
    coroutine must yield the dict itself, not another coroutine)."""

    async def _coro():
        return value

    return _coro()


async def test_transcription_happy_path(client, voice_settings, monkeypatch):
    emu = await _register_and_consent(
        client, ClientEmulator("happy", "correct horse battery staple")
    )
    captured: dict = {}

    async def fake_post_audio(self, files, data):
        captured["files"] = files
        captured["data"] = data
        return {"text": "Hola mundo, hoy fue un buen di\x00a.", "language": "spanish"}

    monkeypatch.setattr(SpeechToText, "_post_audio", fake_post_audio)

    async def fake_translate(settings, text, source_lang):
        captured["translate_input"] = (text, source_lang)
        return "Hello world, today was a good day."

    monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)

    response = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json=audio_body(mime="audio/webm;codecs=opus"),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # The NUL control character is space-replaced (the llm.py sanitizer rule).
    assert body["original_text"] == "Hola mundo, hoy fue un buen di a."
    assert body["language"] == "es"
    assert body["language_raw"] == "spanish"
    assert body["english_text"] == "Hello world, today was a good day."
    # The multipart carries the validated mime + derived extension, and the
    # whisper-1 verbose_json shape was requested.
    assert captured["files"]["file"][1] == FAKE_AUDIO
    assert captured["files"]["file"][2] == "audio/webm"
    assert captured["files"]["file"][0] == "recording.webm"
    assert captured["data"]["response_format"] == "verbose_json"
    assert captured["translate_input"][1] == "es"


async def test_transcription_degrades_without_translation_llm(client, voice_settings, monkeypatch):
    emu = await _register_and_consent(
        client, ClientEmulator("notranslate", "correct horse battery staple")
    )
    monkeypatch.setattr(
        SpeechToText,
        "_post_audio",
        lambda self, files, data: _json({"text": "Bonjour", "language": "french"}),
    )
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    assert response.status_code == 200
    body = response.json()
    assert body["language"] == "fr"
    # No LLM configured (voice_settings leaves llm_url empty): translation
    # is a null extra, not an error — the transcript stands alone.
    assert body["english_text"] is None


async def test_transcription_input_validation(client, voice_settings):
    emu = await _register_and_consent(
        client, ClientEmulator("validate", "correct horse battery staple")
    )
    bad_mime = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json=audio_body(mime="audio/flac"),
    )
    assert bad_mime.status_code == 422
    too_long = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json=audio_body(duration=3601),
    )
    assert too_long.status_code == 422
    bad_b64 = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json={**audio_body(), "audio_b64": "!!!not-base64!!!"},
    )
    assert bad_b64.status_code == 422
    empty_audio = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json=audio_body(audio=b""),
    )
    assert empty_audio.status_code == 422


async def test_transcription_upstream_failure_is_502(client, voice_settings, monkeypatch):
    emu = await _register_and_consent(
        client, ClientEmulator("upstreamfail", "correct horse battery staple")
    )

    async def boom(self, files, data):
        raise RuntimeError("provider down")

    monkeypatch.setattr(SpeechToText, "_post_audio", boom)
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=audio_body()
    )
    assert response.status_code == 502
    assert response.json()["code"] == "stt_upstream"


async def test_therapist_token_cannot_transcribe(client, voice_settings):
    # Development default: sharing on, no enrollment secret required, so a
    # therapist account can register and prove the ROLE gate (403, the
    # require_regular_user convention — a valid session with the wrong role).
    therapist = TherapistEmulator("drvoice", "correct horse battery staple")
    await therapist.register(client)
    response = await client.post(
        "/api/v1/audio/transcriptions", headers=therapist.headers, json=audio_body()
    )
    assert response.status_code == 403


# --- re-translation endpoint ----------------------------------------------------


async def test_translation_endpoint(client, voice_settings, monkeypatch):
    emu = await _register_and_consent(
        client, ClientEmulator("retranslate", "correct horse battery staple")
    )

    async def fake_translate(settings, text, source_lang):
        return "Today was a hard day at work."

    monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)
    response = await client.post(
        "/api/v1/audio/translations",
        headers=emu.headers,
        json={"text": "Hoy fue un día difícil en el trabajo.", "source_lang": "es"},
    )
    assert response.status_code == 200
    assert response.json()["english_text"] == "Today was a hard day at work."

    unconsented = ClientEmulator("unconsented", "correct horse battery staple")
    await unconsented.register(client)
    denied = await client.post(
        "/api/v1/audio/translations",
        headers=unconsented.headers,
        json={"text": "Hola", "source_lang": "es"},
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "voice_consent_required"


# --- route-scoped body cap -------------------------------------------------------


async def test_audio_routes_get_their_own_body_cap(client, settings):
    # Tiny global cap, roomier audio cap: a body the ordinary edge would
    # refuse must pass THROUGH the edge on the audio route and reach the
    # route's own logic (the consent verdict here — proving no 413), while
    # the same body on a non-audio route stays a 413.
    settings.max_body_bytes = 2048
    settings.audio_max_body_bytes = 65_536
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"

    emu = ClientEmulator("bodycap", "correct horse battery staple")
    await emu.register(client)

    big = audio_body(audio=b"x" * 10_000)  # ~13.3 KB of base64 JSON
    audio_response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=big
    )
    assert audio_response.status_code == 403  # past the edge, stopped at consent
    assert audio_response.json()["code"] == "voice_consent_required"

    entries_response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "big-entry",
            "blob": base64.b64encode(b"y" * 10_000).decode("ascii"),
            "entry_date": "2026-09-29",
        },
    )
    assert entries_response.status_code == 413  # the ordinary edge cap held


async def test_audio_body_over_route_cap_is_413_at_the_edge(client, settings):
    settings.audio_enabled = True
    settings.audio_max_body_bytes = 2048  # tiny on purpose
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    emu = ClientEmulator("edgecap", "correct horse battery staple")
    await emu.register(client)
    response = await client.post(
        "/api/v1/audio/transcriptions",
        headers=emu.headers,
        json=audio_body(audio=b"z" * 10_000),
    )
    assert response.status_code == 413


# --- settings boot gates ----------------------------------------------------------


def test_production_stt_url_must_be_https():
    with pytest.raises(RuntimeError, match="https"):
        Settings(
            environment="production",
            token_secret="x" * 40,
            database_url="postgresql+asyncpg://u:p@h/db",
            stt_url="http://stt.example.com/v1",
            stt_api_key="k",
        )


def test_production_stt_requires_policy_terms():
    with pytest.raises(RuntimeError, match="MINDPATTERN_STT_PROVIDER_NAME"):
        Settings(
            environment="production",
            token_secret="x" * 40,
            database_url="postgresql+asyncpg://u:p@h/db",
            stt_url="https://stt.example.com/v1",
            stt_api_key="k",
        )
    ok = Settings(
        environment="production",
        token_secret="x" * 40,
        database_url="postgresql+asyncpg://u:p@h/db",
        stt_url="https://stt.example.com/v1",
        stt_api_key="k",
        stt_provider_name="ExampleSTT",
        stt_data_retention="zero-retention",
        stt_policy_version="v1",
    )
    assert ok.stt_model == "whisper-1"


def test_buffer_budget_accounts_for_audio_cap():
    # The worst-case edge buffer is judged on the LARGER cap: raising the
    # audio cap past the budget must refuse to boot even with the ordinary
    # cap unchanged.
    with pytest.raises(RuntimeError, match="body-buffer memory budget"):
        Settings(
            environment="development",
            audio_max_body_bytes=64 * 1024 * 1024,
            body_buffer_concurrency=100,
        )


# --- shared contract pins ----------------------------------------------------------


def test_shared_audio_vectors_pin_the_server_contract():
    vectors = json.loads(SHARED_VECTORS.read_text(encoding="utf-8"))
    assert vectors["mime_types"] and "notes" in vectors["mime_types"]
    pinned_mimes = {k: v for k, v in vectors["mime_types"].items() if k != "notes"}
    assert pinned_mimes == dict(stt_service.MIME_TO_EXTENSION)
    assert vectors["language_normalization"]["map"] == stt_service.LANGUAGE_NAME_TO_ISO
    assert vectors["audio_aad"]["tuple"][:1] == ["audio"]
    assert vectors["audio_aad"]["audio_version"] == 1
    assert vectors["retention"]["attachment_expiry_days"] == 30
    assert vectors["recording_limits"]["max_duration_seconds_server"] == 310


def test_language_and_mime_normalization():
    assert normalize_language("spanish") == "es"
    assert normalize_language("Spanish ") == "es"
    assert normalize_language("es") == "es"
    assert normalize_language("EN") == "en"
    assert normalize_language("klingon") is None
    assert normalize_language("") is None
    assert normalize_mime("audio/webm;codecs=opus") == "audio/webm"
    assert normalize_mime("AUDIO/MP4") == "audio/mp4"


def test_fingerprint_excludes_key_and_tracks_policy_terms(voice_settings):
    first = stt_service.processing_policy_fingerprint(voice_settings)
    assert first is not None and len(first) == 64
    voice_settings.stt_api_key = "different-key"
    assert stt_service.processing_policy_fingerprint(voice_settings) == first
    voice_settings.stt_provider_name = "OtherProvider"
    assert stt_service.processing_policy_fingerprint(voice_settings) != first
    voice_settings.stt_url = ""
    assert stt_service.processing_policy_fingerprint(voice_settings) is None


# --- payload v3 analysis-text routing (P5) --------------------------------------


async def test_recompute_corpus_routes_voice_languages():
    """en/es analyze their native text; every other detected language
    analyzes the English translation; a missing translation falls back to
    the original; malformed voice channels 400 like every other channel."""
    from datetime import date as date_type

    from app.api.insights import _parse_entries

    def plain(payload: dict) -> bytearray:
        import json as _json

        return bytearray(_json.dumps(payload).encode("utf-8"))

    day = date_type(2026, 9, 29)
    entries = _parse_entries(
        [
            plain(
                {
                    "v": 3,
                    "text": "Jour difficile",
                    "sentiment": None,
                    "created_at": "2026-09-29",
                    "input_mode": "voice",
                    "transcript_lang": "fr",
                    "english_text": "Hard day",
                }
            ),
            plain(
                {
                    "v": 3,
                    "text": "Día difícil",
                    "sentiment": None,
                    "created_at": "2026-09-29",
                    "input_mode": "voice",
                    "transcript_lang": "es",
                    "english_text": "Hard day",
                }
            ),
            plain(
                {
                    "v": 3,
                    "text": "Jour sans traduction",
                    "sentiment": None,
                    "created_at": "2026-09-29",
                    "input_mode": "voice",
                    "transcript_lang": "fr",
                    "english_text": None,
                }
            ),
        ],
        [day, day, day],
    )
    assert [e.text for e in entries] == [
        "Hard day",  # fr → English translation (D-7)
        "Día difícil",  # es → native text, the ES lexicon path
        "Jour sans traduction",  # degraded: no translation → original
    ]
    with pytest.raises(ValueError, match="input_mode"):
        _parse_entries(
            [
                plain(
                    {
                        "v": 3,
                        "text": "x",
                        "sentiment": None,
                        "created_at": "2026-09-29",
                        "input_mode": "shout",
                    }
                )
            ],
            [day],
        )
    with pytest.raises(ValueError, match="transcript_lang"):
        _parse_entries(
            [
                plain(
                    {
                        "v": 3,
                        "text": "x",
                        "sentiment": None,
                        "created_at": "2026-09-29",
                        "transcript_lang": "français",
                    }
                )
            ],
            [day],
        )
