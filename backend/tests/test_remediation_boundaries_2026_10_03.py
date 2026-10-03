"""Real transport and ownership boundaries for the remediated protocols."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.models import User
from app.security.enclave import KeyNotFound
from app.services import stt
from app.services.llm import LLMAnalyzer
from tests.helpers import TherapistEmulator


async def test_guard_lost_ownership_cancels_work_and_never_silently_reacquires(app, monkeypatch):
    from app import main

    class Connection:
        owned = True
        probes = 0
        commits = 0

        async def exec_driver_sql(self, statement):
            assert (
                "pg_locks" in statement
                and "pg_backend_pid()" in statement
                and "granted" in statement
            )
            self.probes += 1
            return type("Result", (), {"scalar": lambda _self: self.owned})()

        async def commit(self):
            self.commits += 1

    connection = Connection()
    app.state.guard_connection = connection
    token = app.state.key_store.create(os.urandom(32), 300, owner="guard-boundary")
    assert await main._guard_is_healthy(app) is True
    assert connection.probes == connection.commits == 1
    entered = asyncio.Event()

    async def pending_work():
        entered.set()
        await asyncio.Event().wait()

    pending = asyncio.create_task(pending_work())
    await entered.wait()
    app.state.request_tasks.update({pending, asyncio.current_task()})
    connection.owned = False  # connection responds normally but owns no lock
    original_sleep = asyncio.sleep

    async def immediate_poll(_delay):
        await original_sleep(0)

    monkeypatch.setattr(main.asyncio, "sleep", immediate_poll)
    await main._guard_monitor(app)
    with pytest.raises(asyncio.CancelledError):
        await pending
    with pytest.raises(KeyNotFound):
        app.state.key_store.pop(token, owner="guard-boundary")
    assert app.state.guard_healthy is False and connection.probes == 2
    connection.owned = True
    assert await main._guard_is_healthy(app) is False
    assert connection.probes == 2  # restart is required, no automatic re-acquire


@pytest.mark.parametrize(
    "headers,chunks,expected",
    [
        ({"content-length": "invalid"}, [b"{}"], "invalid Content-Length"),
        ({"content-length": "-1"}, [b"{}"], "exceeds size limit"),
        ({"content-length": "65"}, [b"{}"], "exceeds size limit"),
        ({"content-length": "1"}, [b"x" * 40, b"y" * 40], "exceeds size limit"),
        ({}, [b"{malformed"], "Expecting property name"),
    ],
)
async def test_stt_actual_http_stream_refuses_bad_length_and_decoded_overflow(
    monkeypatch, headers, chunks, expected
):
    monkeypatch.setattr(stt, "STT_MAX_RESPONSE_BYTES", 64)
    closed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks:
                yield chunk

        async def aclose(self):
            closed.append(True)

    def provider(request):
        assert request.url.path == "/v1/audio/transcriptions"
        assert request.headers["authorization"] == "Bearer synthetic-key"
        return httpx.Response(200, headers=headers, stream=Stream())

    original_client = httpx.AsyncClient

    def bounded_client(**options):
        assert options["follow_redirects"] is False and options["trust_env"] is False
        return original_client(transport=httpx.MockTransport(provider), **options)

    monkeypatch.setattr(httpx, "AsyncClient", bounded_client)
    speech = stt.SpeechToText("https://synthetic-provider.invalid/v1", "synthetic-key")
    with pytest.raises(ValueError, match=expected):
        await speech.transcribe(b"original recording", "audio/webm")
    assert closed == [True]  # refusal still releases the provider stream


async def test_stt_actual_http_roundtrip_preserves_language_and_clean_text(monkeypatch):
    seen = []
    original_client = httpx.AsyncClient

    def provider(request):
        seen.append(request.content)
        return httpx.Response(200, json={"text": "hola\x00 mundo", "language": "Spanish"})

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(provider), **kwargs),
    )
    speech = stt.SpeechToText(
        "https://synthetic-provider.invalid/v1", "synthetic-key", model="gpt-4o-transcribe"
    )
    result = await speech.transcribe(b"original recording", "audio/webm;codecs=opus")
    assert (result.text, result.language_iso, result.language_raw) == (
        "hola  mundo",
        "es",
        "spanish",
    )
    assert len(seen) == 1 and b"original recording" in seen[0] and b"recording.webm" in seen[0]


async def test_translation_exact_output_limit_or_refusal_never_publishes_a_slice(
    settings, monkeypatch
):
    settings.llm_url = "https://synthetic-translation.invalid/v1"
    length = stt.MAX_TRANSLATION_OUTPUT_CHARS
    supplied = {"text": "x" * length}
    calls = []

    def provider(self, body):
        calls.append(json.loads(body["messages"][1]["content"])["text"])
        return {"choices": [{"finish_reason": "stop", "message": {"content": supplied["text"]}}]}

    monkeypatch.setattr(LLMAnalyzer, "_post", provider)
    assert await stt.translate_to_english(settings, "texto completo", "es") == "x" * length
    supplied["text"] += "y"
    assert await stt.translate_to_english(settings, "texto completo", "es") is None
    overlong_input = "z" * (stt.MAX_TRANSLATION_INPUT_CHARS + 1)
    assert await stt.translate_to_english(settings, overlong_input, "es") is None
    assert calls == ["texto completo", "texto completo"]


@pytest.mark.parametrize(
    "response",
    [{"choices": []}, {"choices": [{"finish_reason": "stop", "message": {"content": None}}]}],
)
async def test_translation_malformed_response_keeps_original_and_emits_no_text(
    settings, monkeypatch, response
):
    settings.llm_url = "https://synthetic-translation.invalid/v1"
    monkeypatch.setattr(LLMAnalyzer, "_post", lambda self, body: response)
    assert await stt.translate_to_english(settings, "original spoken text", "es") is None


@pytest.mark.parametrize(
    "change",
    [
        {"notes_keyring_blob": "!"},
        {"notes_keyring_blob": base64.b64encode(b"x" * 27).decode()},
        {"custody_version": 2},
    ],
)
async def test_custody_invalid_material_or_version_never_mutates_account(client, app, change):
    therapist = TherapistEmulator("custody-boundary", "therapist password")
    await therapist.register(client)
    body = {
        "verifier": therapist.auth_key_b64,
        "operation_id": str(uuid.uuid4()),
        "expected_custody_version": 0,
        "custody_version": 1,
        "notes_keyring_blob": base64.b64encode(os.urandom(60)).decode(),
    }
    refused = await client.put(
        "/api/therapist/custody", headers=therapist.headers, json={**body, **change}
    )
    assert refused.status_code == 422 and refused.json()["code"] == "validation_error"
    async with app.state.sessionmaker() as session:
        user = await session.scalar(select(User).where(User.id == therapist.user_id))
        assert (
            user.notes_keyring_blob is None
            and user.custody_version == 0
            and user.notes_revision == 0
        )
