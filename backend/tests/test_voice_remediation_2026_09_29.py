"""Voice-audit remediation tests (AUDIT_VOICE_SESSION_2026-09-29).

Covers the fixes landed the same day:

  H4  translation dispatch requires the CURRENT LLM consent when an LLM
      endpoint is configured (voice consent alone must not send journal
      text to a second provider).
  M1  the dark-launch flag covers the THERAPIST audio route and the
      share-voice toggle (flat 404 while the feature is off).
  M2  account erasure removes kept-recording OBJECTS, not just rows.
  M4  S3AudioStore: endpoint/path-style wiring, SSE header, error
      mapping, capped reads — against an injected fake boto3 client.
  M9  the cached store getter reuses one instance per configuration.
  M8  the STT client retries exactly once on a transient 429/5xx.
"""

from __future__ import annotations

import base64
import sys
import types
from datetime import date

import httpx
import pytest
from sqlalchemy import select

from app.models import AudioAttachment, User
from app.services import stt as stt_service
from app.services.audio_store import (
    AudioStoreError,
    S3AudioStore,
    get_audio_store,
    get_audio_store_cached,
)
from app.services.stt import SpeechToText
from tests.helpers import ClientEmulator, TherapistEmulator

TODAY = date.today()


@pytest.fixture(autouse=True)
def _scratch_audio_store(settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "audio")


async def _voice_ready(client, settings, name="vuser") -> ClientEmulator:
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


async def _grant_llm_consent(client, emu) -> None:
    response = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 200, response.text
    assert response.json()["active_for_current_policy"] is True


def _transcription_body() -> dict:
    return {
        "audio_b64": base64.b64encode(b"RIFF-fake-webm-bytes" * 64).decode("ascii"),
        "mime": "audio/webm",
        "duration_seconds": 60,
    }


# --- H4: translation rides the LLM consent surface ------------------------------


async def test_translation_suppressed_without_llm_consent(client, settings, monkeypatch):
    """Voice consent alone must NOT dispatch the transcript to a
    CONFIGURED LLM endpoint (audit H4): english_text degrades to null."""
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    settings.llm_url = "https://llm.example.com/v1"
    settings.llm_api_key = "k"
    emu = await _voice_ready(client, settings, "nollmconsent")

    dispatched = []

    async def fake_translate(s_settings, text, source_lang):
        dispatched.append(text)
        return "must never be returned"

    monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)

    async def fake_post_audio(self, files, data):
        return {"text": "Texto privado del diario.", "language": "spanish"}

    monkeypatch.setattr(SpeechToText, "_post_audio", fake_post_audio)

    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=_transcription_body()
    )
    assert response.status_code == 200, response.text
    # Degraded mode, never a dispatch: the seam was never called.
    assert response.json()["english_text"] is None
    assert dispatched == []


async def test_translation_flows_with_llm_consent(client, settings, monkeypatch):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    settings.llm_url = "https://llm.example.com/v1"
    settings.llm_api_key = "k"
    emu = await _voice_ready(client, settings, "llmok")
    await _grant_llm_consent(client, emu)

    async def fake_translate(s_settings, text, source_lang):
        return "Private journal text."

    monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)
    monkeypatch.setattr(
        SpeechToText,
        "_post_audio",
        lambda self, files, data: _coro({"text": "Texto privado.", "language": "spanish"}),
    )

    response = await client.post(
        "/api/v1/audio/transcriptions", headers=emu.headers, json=_transcription_body()
    )
    assert response.status_code == 200, response.text
    assert response.json()["english_text"] == "Private journal text."


async def test_retranslation_route_suppressed_without_llm_consent(
    client, settings, monkeypatch
):
    """The edited-transcript re-translation route has the same gate."""
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    settings.llm_url = "https://llm.example.com/v1"
    settings.llm_api_key = "k"
    emu = await _voice_ready(client, settings, "renoconsent")

    dispatched = []

    async def fake_translate(s_settings, text, source_lang):
        dispatched.append(text)
        return "never"

    monkeypatch.setattr(stt_service, "translate_to_english", fake_translate)

    response = await client.post(
        "/api/v1/audio/translations",
        headers=emu.headers,
        json={"text": "Texto editado.", "source_lang": "es"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["english_text"] is None
    assert dispatched == []

    # With consent granted the same call dispatches.
    await _grant_llm_consent(client, emu)
    response = await client.post(
        "/api/v1/audio/translations",
        headers=emu.headers,
        json={"text": "Texto editado.", "source_lang": "es"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["english_text"] == "never"


def _coro(value):
    import asyncio

    async def _inner():
        return value

    return _inner()


async def _instant_sleep(_seconds: float) -> None:
    """Async no-op standing in for the retry backoff in tests."""


def _patch_sleep(monkeypatch):
    monkeypatch.setattr(stt_service.asyncio, "sleep", _instant_sleep)


# --- M1: flag covers the therapist route and the share-voice toggle ------------


async def test_therapist_audio_route_is_404_when_flag_off(client, settings):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    patient = ClientEmulator("flagther", "correct horse battery staple")
    await patient.register(client)
    therapist = TherapistEmulator("drflag", "correct horse battery staple")
    await therapist.register(client)
    # Any authenticated therapist probe answers the flat 404 — flag-off
    # must not advertise the route, exactly like the patient router.
    settings.audio_enabled = False
    response = await client.get(
        f"/api/therapist/patients/{patient.user_id}/audio/{'f' * 32}",
        headers=therapist.headers,
    )
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


async def test_share_voice_toggle_is_404_when_flag_off(client, settings):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    patient = ClientEmulator("flagshare", "correct horse battery staple")
    await patient.register(client)
    settings.audio_enabled = False
    response = await client.put(
        "/api/consents/ffffffffffffffffffffffffffffffff/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


# --- M2: erasure removes objects too --------------------------------------------


async def test_account_erasure_removes_audio_objects(client, app, settings):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    emu = await _voice_ready(client, settings, "erasure")
    entry_id = "e-erasure"
    await emu.create_entry(client, "final entry", TODAY, client_entry_id=entry_id)
    upload = await client.post(
        "/api/v1/audio/attachments",
        headers=emu.headers,
        json={
            "client_entry_id": entry_id,
            "blob": base64.b64encode(b"RIFF-erasure-take" + b"0" * 40).decode("ascii"),
            "mime": "audio/webm",
            "duration_seconds": 42,
        },
    )
    assert upload.status_code == 201, upload.text
    store = get_audio_store(app.state.settings)
    objects = {p.name for p in store.root.rglob("*.enc")}
    assert len(objects) == 1
    user_dir = store.root / "audio" / emu.user_id
    assert user_dir.is_dir()

    response = await client.request(
        "DELETE", "/api/account", headers=emu.headers, json={"verifier": emu.auth_key_b64}
    )
    assert response.status_code == 204, response.text
    # Rows gone (cascade) AND the stored object gone (the M2 fix) — and
    # the account's directory too: the key layout embeds the user id, so
    # an empty audio/<erased-id>/ leftover would keep the erased identity
    # on disk as a directory name (2026-09-29 E2E campaign finding).
    async with app.state.sessionmaker() as session:
        remaining = (await session.execute(select(AudioAttachment))).scalars().all()
        assert remaining == []
    assert {p.name for p in store.root.rglob("*.enc")} == set()
    assert not user_dir.exists()


# --- M4/M9: S3 store mechanics against an injected fake boto3 -------------------


class _FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, limit=-1):
        return self._data if limit < 0 else self._data[:limit]


class _FakeS3Client:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[dict] = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        self.objects[kwargs["Key"]] = kwargs["Body"]

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        if key not in self.objects:
            raise KeyError(key)
        return {"Body": _FakeBody(self.objects[key])}

    def delete_object(self, **kwargs):
        self.objects.pop(kwargs["Key"], None)


@pytest.fixture
def fake_boto3(monkeypatch):
    module = types.ModuleType("boto3")
    config_module = types.ModuleType("botocore.config")

    class _Config:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    config_module.Config = _Config
    created: dict[str, _FakeS3Client] = {}

    def client(**kwargs):
        fake = _FakeS3Client()
        fake.client_kwargs = kwargs
        created["client"] = fake
        return fake

    module.client = client
    monkeypatch.setitem(sys.modules, "boto3", module)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)
    return created


async def test_s3_store_endpoint_and_sse_wiring(fake_boto3):
    store = S3AudioStore(
        "bucket", "us-east-1", "key", "secret", endpoint="http://minio:9000"
    )
    await store.put("audio/u/abc.enc", b"bytes")
    kwargs = fake_boto3["client"].client_kwargs
    assert kwargs["endpoint_url"] == "http://minio:9000"
    assert kwargs["config"].kwargs["s3"]["addressing_style"] == "path"
    put = fake_boto3["client"].put_calls[0]
    assert put["ServerSideEncryption"] == "AES256"
    assert put["Bucket"] == "bucket"
    assert put["Body"] == b"bytes"


async def test_s3_store_roundtrip_and_error_mapping(fake_boto3):
    store = S3AudioStore("bucket")
    await store.put("k", b"payload")
    assert await store.get("k") == b"payload"
    with pytest.raises(AudioStoreError):
        await store.get("missing")
    await store.delete("k")
    with pytest.raises(AudioStoreError):
        await store.get("k")


async def test_s3_store_capped_read(fake_boto3):
    store = S3AudioStore("bucket")
    await store.put("k", b"x" * 100)
    assert await store.get("k", max_bytes=100) == b"x" * 100
    # One byte over the cap refuses instead of buffering the object.
    with pytest.raises(AudioStoreError):
        await store.get("k", max_bytes=99)


def test_cached_store_reuses_instance_per_configuration(settings, tmp_path):
    settings.audio_local_dir = str(tmp_path / "a")
    first = get_audio_store_cached(settings)
    assert get_audio_store_cached(settings) is first
    # A different configuration builds a fresh instance.
    settings.audio_local_dir = str(tmp_path / "b")
    second = get_audio_store_cached(settings)
    assert second is not first
    assert get_audio_store_cached(settings) is second


# --- M8: one bounded retry on transient upstream refusals -----------------------


class _CountingPost:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = 0

    async def __call__(self, files, data):
        self.calls += 1
        status = self.statuses.pop(0) if self.statuses else 200
        if status != 200:
            request = httpx.Request("POST", "https://stt.example.com/v1/audio/transcriptions")
            response = httpx.Response(status, request=request, headers={"retry-after": "0"})
            raise httpx.HTTPStatusError("boom", request=request, response=response)
        return {"text": "retried ok", "language": "english"}


async def test_stt_retries_once_on_429(monkeypatch):
    engine = SpeechToText("https://stt.example.com/v1", "k")
    counting = _CountingPost([429, 200])
    monkeypatch.setattr(engine, "_post_audio", counting)
    _patch_sleep(monkeypatch)
    result = await engine.transcribe(b"audio", "audio/webm")
    assert result.text == "retried ok"
    assert counting.calls == 2


async def test_stt_does_not_retry_client_errors(monkeypatch):
    engine = SpeechToText("https://stt.example.com/v1", "k")
    counting = _CountingPost([400])
    monkeypatch.setattr(engine, "_post_audio", counting)
    _patch_sleep(monkeypatch)
    with pytest.raises(httpx.HTTPStatusError):
        await engine.transcribe(b"audio", "audio/webm")
    assert counting.calls == 1


async def test_stt_gives_up_after_one_retry(monkeypatch):
    engine = SpeechToText("https://stt.example.com/v1", "k")
    counting = _CountingPost([503, 503])
    monkeypatch.setattr(engine, "_post_audio", counting)
    _patch_sleep(monkeypatch)
    with pytest.raises(httpx.HTTPStatusError):
        await engine.transcribe(b"audio", "audio/webm")
    assert counting.calls == 2


# --- P5 completion: roster share-voice indicator field --------------------------


async def test_patient_list_carries_share_voice_grant_state(client, settings):
    """The therapist roster serves the live share_voice grant (VOICE_PLAN
    P5): False on a fresh active consent, True after the patient widens
    it, None after revocation (nothing left to share)."""
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    patient = await _voice_ready(client, settings, "roster")
    therapist = TherapistEmulator("drroster", "correct horse battery staple")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    grant = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id
    )
    assert grant["status"] == 201, grant["body"]
    consent_id = grant["body"]["id"]

    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200, listed.text
    row = next(r for r in listed.json() if r["user_id"] == patient.user_id)
    assert row["status"] == "active"
    assert row["share_voice"] is False

    widened = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"enabled": True},
    )
    assert widened.status_code == 200, widened.text
    relisted = await client.get("/api/therapist/patients", headers=therapist.headers)
    row = next(r for r in relisted.json() if r["user_id"] == patient.user_id)
    assert row["share_voice"] is True

    revoked = await patient.revoke_consent(client, consent_id)
    assert revoked == 204
    final = await client.get("/api/therapist/patients", headers=therapist.headers)
    row = next(r for r in final.json() if r["user_id"] == patient.user_id)
    assert row["status"] != "active"
    assert row["share_voice"] is None
