"""Actual bounded speech/translation transport and disclosed payload behavior."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import importlib
import json
import logging
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _stt(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.services.stt")


def _settings(**overrides):
    return SimpleNamespace(
        stt_url="https://speech.invalid/v1/",
        stt_api_key="speech-key",
        stt_model="whisper-1",
        stt_timeout_seconds=60.5,
        llm_url="https://translation.invalid/v1/",
        llm_api_key="translation-key",
        llm_model="translation-model",
        **overrides,
    )


@pytest.mark.parametrize(
    "mode",
    [
        "accepted",
        "invalid-header",
        "negative-header",
        "large-header",
        "headerless-large",
        "lying-header-large",
        "empty",
    ],
)
def test_speech_transport_native_response_cap_and_both_context_closures(
    monkeypatch, mode
):
    stt = _stt(monkeypatch)
    import httpx

    cap = 1_048_576
    data = b'{"text":"private transcript"}'
    padded = data + b" " * (cap - len(data))
    headers = {"content-length": str(cap)}
    if mode == "invalid-header":
        headers = {"content-length": "invalid"}
    if mode == "negative-header":
        headers = {"content-length": "-1"}
    if mode == "large-header":
        headers = {"content-length": str(cap + 1)}
    if mode == "headerless-large":
        headers = {}
    if mode == "lying-header-large":
        headers = {"content-length": "1"}
    if mode == "empty":
        headers = {"content-length": "0"}
    events = []
    read = []

    class Response:
        def __init__(self):
            self.headers = headers

        async def __aenter__(self):
            events.append("response-enter")
            return self

        async def __aexit__(self, *_):
            events.append("response-exit")

        def raise_for_status(self):
            events.append("status-checked")

        async def aiter_bytes(self, *, chunk_size):
            assert chunk_size == 65_536
            read.append(True)
            if mode == "empty":
                return
            yield padded[:600_000]
            yield padded[600_000:]
            if mode in ("headerless-large", "lying-header-large"):
                yield b" "

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
            timeout = kwargs["timeout"]
            assert (
                timeout.connect == 5
                and timeout.read == timeout.write == timeout.pool == 60.5
            )

        async def __aenter__(self):
            events.append("client-enter")
            return self

        async def __aexit__(self, *_):
            events.append("client-exit")

        def stream(self, method, url, **kwargs):
            assert (
                method == "POST"
                and url == "https://speech.invalid/v1/audio/transcriptions"
            )
            assert kwargs == {
                "files": {"file": "private-audio"},
                "data": {"model": "whisper-1"},
                "headers": {"Authorization": "Bearer speech-key"},
            }
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    speech = stt.SpeechToText(
        "https://speech.invalid/v1/", "speech-key", total_timeout_seconds=60.5
    )
    request = speech._post_audio({"file": "private-audio"}, {"model": "whisper-1"})
    if mode in ("accepted", "empty"):
        assert asyncio.run(request) == (
            {} if mode == "empty" else {"text": "private transcript"}
        )
    else:
        diagnostic = (
            "STT response has invalid Content-Length"
            if mode == "invalid-header"
            else "STT response exceeds size limit"
        )
        with pytest.raises(ValueError, match=f"^{diagnostic}$"):
            asyncio.run(request)
    assert events == [
        "client-enter",
        "response-enter",
        "status-checked",
        "response-exit",
        "client-exit",
    ]
    assert bool(read) is (
        mode in ("accepted", "headerless-large", "lying-header-large", "empty")
    )


def test_speech_retry_status_matrix_native_delay_bounds_and_second_failure(monkeypatch):
    stt = _stt(monkeypatch)
    import httpx

    for status in (429, 500, 502, 503, 504, 400, 401, 403, 404, 501, 505):
        for header, expected_delay in (
            (None, 1),
            ("invalid", 1),
            ("-1", 1),
            ("0", 1),
            ("1", 1),
            ("2.5", 2.5),
            ("5", 5),
            ("6", 5),
        ):
            attempts = []
            sleeps = []
            speech = stt.SpeechToText("https://speech.invalid", "secret")
            response = httpx.Response(
                status,
                headers={} if header is None else {"retry-after": header},
                request=httpx.Request("POST", "https://speech.invalid"),
            )
            error = httpx.HTTPStatusError(
                "provider refused", request=response.request, response=response
            )

            async def post(files, data, attempts=attempts, error=error):
                assert files == {"audio": "private"} and data == {"model": "speech"}
                attempts.append(True)
                raise error

            async def sleep(delay, sleeps=sleeps):
                sleeps.append(delay)

            monkeypatch.setattr(speech, "_post_audio", post)
            monkeypatch.setattr(stt.asyncio, "sleep", sleep)
            with pytest.raises(httpx.HTTPStatusError) as observed:
                asyncio.run(
                    speech._post_audio_with_retry(
                        {"audio": "private"}, {"model": "speech"}
                    )
                )
            assert observed.value is error
            retryable = status in (429, 500, 502, 503, 504)
            assert len(attempts) == (2 if retryable else 1)
            assert sleeps == ([expected_delay] if retryable else [])


def test_speech_multipart_wire_shapes_and_sanitized_result(monkeypatch):
    stt = _stt(monkeypatch)
    formats = {
        "audio/webm": ".webm",
        "audio/mp4": ".m4a",
        "audio/m4a": ".m4a",
        "audio/x-m4a": ".m4a",
        "audio/ogg": ".ogg",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
    }
    for mime, extension in formats.items():
        for model in ("whisper-1", "gpt-4o-transcribe", "gpt-4o-mini-transcribe"):
            speech = stt.SpeechToText("https://speech.invalid/", "key", model)
            dispatched = []

            async def post(files, data, dispatched=dispatched):
                dispatched.append((files, data))
                return {"text": "\x00 Hola\x01mundo\x7f \t\n", "language": " Spanish "}

            monkeypatch.setattr(speech, "_post_audio_with_retry", post)
            result = asyncio.run(
                speech.transcribe(
                    b"private audio", "  " + mime.upper() + ";codec=opus  "
                )
            )
            assert dataclasses.asdict(result) == {
                "text": "Hola mundo",
                "language_iso": "es",
                "language_raw": "spanish",
            }
            assert dispatched == [
                (
                    {"file": ("recording" + extension, b"private audio", mime)},
                    {
                        "model": model,
                        "response_format": (
                            "json" if model.startswith("gpt-4o") else "verbose_json"
                        ),
                    },
                )
            ]
    with pytest.raises(ValueError, match="^unsupported audio mime 'audio/unknown'$"):
        asyncio.run(speech.transcribe(b"private", "audio/unknown"))
    speech = stt.SpeechToText("https://speech.invalid", "key")

    async def hostile(files, data):
        return {"text": "x" * 100_001, "language": "z" * 65}

    monkeypatch.setattr(speech, "_post_audio_with_retry", hostile)
    result = asyncio.run(speech.transcribe(b"private", "audio/webm"))
    assert result.text == "x" * 100_000 and result.language_raw == "z" * 64
    assert result.language_iso is None
    for absent in (None, True, [], {}, 1):
        assert stt._clean_transcript(absent) == ""

    async def absent_language(files, data):
        return {"text": "private", "language": None}

    monkeypatch.setattr(speech, "_post_audio_with_retry", absent_language)
    result = asyncio.run(speech.transcribe(b"private", "audio/webm"))
    assert dataclasses.asdict(result) == {
        "text": "private",
        "language_iso": None,
        "language_raw": "unknown",
    }
    assert stt.normalize_language(" ZZ ") == "zz"
    assert stt.normalize_language("zzz") is None
    assert stt._clean_transcript(" \tfirst\nsecond\t ") == "first\nsecond"


@pytest.mark.parametrize(
    "length,tokens",
    [(1, 512), (512, 512), (513, 512), (1000, 756), (7680, 4096), (100_000, 4096)],
)
def test_translation_dispatched_payload_bounds_and_actual_return(
    monkeypatch, length, tokens
):
    stt = _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    captured = []

    def post(analyzer, payload):
        assert analyzer.url == "https://translation.invalid/v1"
        assert (
            analyzer.api_key == "translation-key"
            and analyzer.model == "translation-model"
        )
        captured.append(payload)
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "  translated\x00text  "},
                }
            ]
        }

    monkeypatch.setattr(llm.LLMAnalyzer, "_post", post)
    text = "x" * length
    assert (
        asyncio.run(stt.translate_to_english(_settings(), text, "es"))
        == "translated text"
    )
    assert len(captured) == 1
    payload = captured[0]
    assert payload["model"] == "translation-model" and payload["temperature"] == 0.0
    assert payload["max_tokens"] == tokens
    assert payload["messages"][0] == {
        "role": "system",
        "content": "You are a translation engine for personal journal entries. Translate "
        "the user's text into plain, natural English. Preserve the original "
        "meaning and tone; do not summarize, embellish, answer, or comment. "
        "Return ONLY the translation as plain text.",
    }
    assert payload["messages"][1]["role"] == "user"
    assert json.loads(payload["messages"][1]["content"]) == {
        "source_language": "es",
        "text": text,
    }


def test_translation_degraded_modes_and_operational_failure_logs(monkeypatch, caplog):
    stt = _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    settings = _settings()
    calls = []
    body = [
        {"choices": [{"finish_reason": "stop", "message": {"content": "y" * 100_000}}]}
    ]

    def post(analyzer, payload):
        calls.append(payload)
        return body[0]

    monkeypatch.setattr(llm.LLMAnalyzer, "_post", post)
    assert asyncio.run(stt.translate_to_english(settings, "x" * 100_001, "es")) is None
    assert asyncio.run(stt.translate_to_english(settings, " \n\t", "es")) is None
    settings.llm_url = " "
    assert asyncio.run(stt.translate_to_english(settings, "private", "es")) is None
    assert calls == []
    settings.llm_url = "https://translation.invalid/v1/"
    assert (
        asyncio.run(stt.translate_to_english(settings, "private", None))
        == "y" * 100_000
    )
    assert json.loads(calls[-1]["messages"][1]["content"])["source_language"] == "auto"
    for invalid in ("y" * 100_001, None, [], {}, "", "\x00\t"):
        body[0] = {
            "choices": [{"finish_reason": "stop", "message": {"content": invalid}}]
        }
        assert asyncio.run(stt.translate_to_english(settings, "private", "es")) is None
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        body[0] = {
            "choices": [
                {"finish_reason": "length", "message": {"content": "private output"}}
            ]
        }
        assert (
            asyncio.run(stt.translate_to_english(settings, "private input", "es"))
            is None
        )
        body[0] = {"choices": []}
        assert (
            asyncio.run(stt.translate_to_english(settings, "private input", "es"))
            is None
        )
    assert [(r.name, r.levelno, r.message) for r in caplog.records] == [
        (
            "mindpattern.stt",
            logging.WARNING,
            "transcript translation was incomplete; returning untranslated",
        ),
        (
            "mindpattern.stt",
            logging.WARNING,
            "transcript translation failed; returning untranslated",
        ),
    ]


def test_speech_factory_uses_configured_timeout_and_default_provider_contract(
    monkeypatch,
):
    stt = _stt(monkeypatch)
    speech = stt.get_stt(_settings())
    assert speech is not None and speech.name == "stt"
    assert (speech.url, speech.api_key, speech.model, speech.total_timeout_seconds) == (
        "https://speech.invalid/v1",
        "speech-key",
        "whisper-1",
        60.5,
    )
    default = stt.SpeechToText("https://speech.invalid/", "key")
    assert default.model == "whisper-1" and default.total_timeout_seconds == 120.0
    assert (
        stt.SpeechToText("https://speech.invalid/X/", "key").url
        == "https://speech.invalid/X"
    )
    settings = _settings()
    settings.stt_url = " "
    assert stt.get_stt(settings) is None


@pytest.mark.parametrize("provider", ["stt", "llm"])
def test_provider_disclosure_fingerprint_and_current_persisted_consent(
    monkeypatch, provider
):
    stt = _stt(monkeypatch)
    module = stt if provider == "stt" else importlib.import_module("app.services.llm")
    values = {
        "url": " https://provider.invalid/X/ ",
        "model": "private-model",
        "provider_name": " Released provider ",
        "data_retention": " no retention 雪 ",
        "policy_version": " current ",
    }
    settings = SimpleNamespace(
        **{provider + "_" + field: value for field, value in values.items()}
    )
    expected_policy = {
        "url": "https://provider.invalid/X",
        "model": "private-model",
        "provider": "Released provider",
        "retention": "no retention 雪",
        "version": "current",
        "disclosure": "v2",
    }
    expected = hashlib.sha256(
        json.dumps(expected_policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert module.processing_policy_fingerprint(settings) == expected
    permission = "voice_consent" if provider == "stt" else "llm_consent"
    user = SimpleNamespace(
        **{
            permission: True,
            permission + "_disclosure": "v2",
            permission + "_policy": expected,
        }
    )
    assert module.consent_is_current(user, settings) is True
    for field, replacement in (
        (permission, False),
        (permission + "_disclosure", "v1"),
        (permission + "_policy", "0" * 64),
    ):
        original = getattr(user, field)
        setattr(user, field, replacement)
        assert module.consent_is_current(user, settings) is False
        setattr(user, field, original)
    setattr(settings, provider + "_url", " ")
    assert module.processing_policy_fingerprint(settings) is None
    assert module.consent_is_current(user, settings) is False


def test_llm_stream_accepts_exact_native_declared_cap_and_empty_declared_response(
    monkeypatch,
):
    _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    import httpx

    for declared_length in ("0", "1048576", "invalid"):
        length = int(declared_length) if declared_length != "invalid" else 1
        payload = b'{"choices":[]}'
        payload += b" " * (length - len(payload)) if length else b""
        payload = payload if length else b""

        class Response:
            def __init__(self, declared_length=declared_length):
                self.headers = {"content-length": declared_length}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            def raise_for_status(self):
                return None

            async def aiter_bytes(self, *, chunk_size, payload=payload):
                assert chunk_size == 65_536
                if payload:
                    yield payload

        class Client:
            def __init__(self, **kwargs):
                assert (
                    kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
                )

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            def stream(self, *_args, **_kwargs):
                return Response()

        monkeypatch.setattr(httpx, "AsyncClient", Client)
        request = llm.LLMAnalyzer("https://provider.invalid/X/", "key")._post_async({})
        if declared_length == "invalid":
            with pytest.raises(
                ValueError, match="^LLM response has invalid Content-Length$"
            ):
                asyncio.run(request)
        elif length:
            assert asyncio.run(request) == {"choices": []}
        else:
            with pytest.raises(json.JSONDecodeError):
                asyncio.run(request)


def test_llm_label_number_runs_grounding_and_sanitized_defaults(monkeypatch):
    _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    assert llm._clean_label("x" * 80) == "x" * 80
    assert llm._clean_label("x" * 81) is None
    for label in ("one two", "work one two", "one work two"):
        assert llm._clean_label(label) == label
    for label in ("one two three", "one-two-three", "one two three four"):
        assert llm._clean_label(label) is None
    assert llm._label_grounded("cat", set()) is False
    assert llm._label_grounded("with zebra", set()) is False
    assert llm._label_grounded("at zebra", set()) is False
    assert llm._label_grounded("cat", {"cat"}) is True
    assert (
        llm.sanitize_pattern(
            {"kind": "recurring_phrase", "label": "green blue"}, ["blue green"]
        )
        is None
    )
    result = llm.sanitize_pattern(
        {
            "kind": "mood_correlation",
            "label": "work",
            "detail": {"direction": "lower", "current": 0.5},
        },
        ["work"],
    )
    assert dataclasses.asdict(result) == {
        "kind": "mood_correlation",
        "label": "work",
        "occurrences": 0,
        "confidence": 0.5,
        "detail": {"direction": "lower", "current": 0.5},
    }
    assert (
        llm._clean_narrative("Private\x00thoughts recur.") == "Private thoughts recur."
    )
    assert llm._clean_narrative("A link recurs: https://provider.invalid/path.") is None


def test_llm_recent_payload_observes_native_entry_and_character_caps(monkeypatch):
    _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    patterns = importlib.import_module("app.services.patterns")
    analyzer = llm.LLMAnalyzer("https://provider.invalid/X/", "key")
    entries = [
        patterns.JournalEntry(
            "entry-" + str(i), date(2020, 1, 1) + timedelta(days=i), sentiment=0.1
        )
        for i in range(201)
    ]
    recent = analyzer._recent_payload(entries)
    assert len(recent) == 200 and recent[0] == {
        "date": "2020-01-02",
        "sentiment": 0.1,
        "text": "entry-1",
    }
    older = patterns.JournalEntry(
        "older private entry", date(2020, 1, 1), sentiment=-0.5
    )
    newest = patterns.JournalEntry("x" * 150_000, date(2020, 1, 2), sentiment=0.5)
    assert analyzer._recent_payload([older, newest]) == [
        {"date": "2020-01-02", "sentiment": 0.5, "text": newest.text}
    ]
    newest = dataclasses.replace(newest, text="x" * 149_999)
    assert analyzer._recent_payload([older, newest]) == [
        {"date": "2020-01-01", "sentiment": -0.5, "text": "o"},
        {"date": "2020-01-02", "sentiment": 0.5, "text": newest.text},
    ]


def test_llm_narration_payload_counters_and_later_valid_findings(monkeypatch, caplog):
    _stt(monkeypatch)
    llm = importlib.import_module("app.services.llm")
    patterns = importlib.import_module("app.services.patterns")
    analyzer = llm.LLMAnalyzer("https://provider.invalid/X/", "key")
    assert (
        analyzer.model == "gpt-4o-mini" and analyzer.url == "https://provider.invalid/X"
    )
    assert analyzer.requests_made == 0 and analyzer.last_error is None
    entry = patterns.JournalEntry("work", date(2026, 1, 1), sentiment=-0.5)
    finding = patterns.Pattern(
        "mood_correlation", "work", 7, 0.8, {"direction": "lower"}
    )
    captured = []

    def post(payload):
        captured.append(payload)
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "patterns": [
                                    {"kind": "unknown", "label": "work"},
                                    {
                                        "kind": "mood_correlation",
                                        "label": "work",
                                        "narrative": "Work appears in these entries.",
                                    },
                                ]
                            }
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(analyzer, "_post", post)
    for count in (1, 2):
        result = analyzer.extract_patterns([entry], findings=[finding])
        assert analyzer.requests_made == count and analyzer.last_error is None
        assert len(result) == 1
        assert dataclasses.asdict(result[0]) == {
            "kind": "mood_correlation",
            "label": "work",
            "occurrences": 7,
            "confidence": 0.8,
            "detail": {
                "direction": "lower",
                "narrative": "Work appears in these entries.",
            },
        }
    payload = captured[0]
    assert payload["model"] == "gpt-4o-mini" and payload["max_tokens"] == 512
    assert payload["temperature"] == 0.0
    assert payload["messages"][0] == {
        "role": "system",
        "content": "You REFINE deterministic statistical findings about a journal, never "
        'discover new ones. Return strict JSON: {"patterns": [{"kind": '
        '"temporal|mood_correlation|recurring_phrase|mood_shift", "label": str (EXACTLY one of the '
        'provided findings\' labels), "narrative": str (<= 240 chars)}]}. The '
        "narrative is one calm, plain sentence reframing the finding for its "
        "author: observational, no advice, no diagnosis, no questions. "
        "Findings you cannot improve, omit.",
    }
    assert payload["messages"][1]["role"] == "user"
    assert json.loads(payload["messages"][1]["content"]) == {
        "findings": [
            {"kind": "mood_correlation", "label": "work", "direction": "lower"}
        ],
        "recent_entries": [{"date": "2026-01-01", "sentiment": -0.5, "text": "work"}],
    }

    def failed(_):
        raise OSError("provider unavailable")

    monkeypatch.setattr(analyzer, "_post", failed)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert analyzer.extract_patterns([entry], findings=[finding]) == []
    assert analyzer.last_error == "provider_failure"
    assert [(r.name, r.levelno, r.message) for r in caplog.records] == [
        (
            "mindpattern.llm",
            logging.WARNING,
            "llm enrichment failed; continuing with deterministic patterns only",
        )
    ]
    settings = _settings()
    assert llm.get_enricher(settings) is None
