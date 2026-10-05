"""Provider protocol and hostile-output boundaries exposed to callers."""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.services.llm"), importlib.import_module(
        "app.services.stt"
    )


def test_named_provider_languages_normalize_to_their_iso6391_codes(monkeypatch):
    _, stt = _modules(monkeypatch)
    pairs = [
        "afrikaans",
        "af",
        "albanian",
        "sq",
        "amharic",
        "am",
        "arabic",
        "ar",
        "armenian",
        "hy",
        "azerbaijani",
        "az",
        "basque",
        "eu",
        "belarusian",
        "be",
        "bengali",
        "bn",
        "bosnian",
        "bs",
        "bulgarian",
        "bg",
        "catalan",
        "ca",
        "chinese",
        "zh",
        "croatian",
        "hr",
        "czech",
        "cs",
        "danish",
        "da",
        "dutch",
        "nl",
        "english",
        "en",
        "estonian",
        "et",
        "finnish",
        "fi",
        "french",
        "fr",
        "galician",
        "gl",
        "german",
        "de",
        "greek",
        "el",
        "gujarati",
        "gu",
        "hebrew",
        "he",
        "hindi",
        "hi",
        "hungarian",
        "hu",
        "icelandic",
        "is",
        "indonesian",
        "id",
        "italian",
        "it",
        "japanese",
        "ja",
        "javanese",
        "jv",
        "kannada",
        "kn",
        "kazakh",
        "kk",
        "khmer",
        "km",
        "korean",
        "ko",
        "lao",
        "lo",
        "latvian",
        "lv",
        "lithuanian",
        "lt",
        "macedonian",
        "mk",
        "malay",
        "ms",
        "malayalam",
        "ml",
        "maltese",
        "mt",
        "marathi",
        "mr",
        "myanmar",
        "my",
        "nepali",
        "ne",
        "norwegian",
        "no",
        "pashto",
        "ps",
        "persian",
        "fa",
        "polish",
        "pl",
        "portuguese",
        "pt",
        "punjabi",
        "pa",
        "romanian",
        "ro",
        "russian",
        "ru",
        "serbian",
        "sr",
        "sinhala",
        "si",
        "slovak",
        "sk",
        "slovenian",
        "sl",
        "somali",
        "so",
        "spanish",
        "es",
        "swahili",
        "sw",
        "swedish",
        "sv",
        "tagalog",
        "tl",
        "tajik",
        "tg",
        "tamil",
        "ta",
        "telugu",
        "te",
        "thai",
        "th",
        "turkish",
        "tr",
        "ukrainian",
        "uk",
        "urdu",
        "ur",
        "uzbek",
        "uz",
        "vietnamese",
        "vi",
        "welsh",
        "cy",
        "yiddish",
        "yi",
        "yoruba",
        "yo",
    ]
    for name, code in zip(pairs[::2], pairs[1::2], strict=True):
        assert stt.normalize_language(name) == code
        assert stt.normalize_language(" " + name.upper() + " ") == code
        assert stt.normalize_language(code.upper()) == code


def test_hostile_labels_refuse_spelled_contact_channels_and_every_number_word(
    monkeypatch,
):
    llm, _ = _modules(monkeypatch)
    for label in (
        "dot com",
        "dot net",
        "dot org",
        "at gmail",
        "at hotmail",
        "at yahoo",
        "at outlook",
        "at icloud",
        "at proton",
        "text me at",
        "call me at",
        "phone me at",
        "dial me at",
        "ring me at",
    ):
        assert llm._clean_label(label) is None
        assert (
            llm.sanitize_pattern({"kind": "recurring_phrase", "label": label}, [label])
            is None
        )
    for word in (
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "oh",
    ):
        assert llm._clean_label(" ".join([word] * 3)) is None
        assert llm._clean_label(" ".join([word] * 2)) == " ".join([word] * 2)
        assert llm._clean_narrative(f"A pattern is {word} {word} today.") is None


def test_function_vocabulary_and_numeric_display_fields_are_preserved(monkeypatch):
    llm, _ = _modules(monkeypatch)
    words = [
        "your",
        "the",
        "a",
        "an",
        "and",
        "or",
        "for",
        "with",
        "that",
        "this",
        "you",
        "was",
        "were",
        "are",
        "is",
        "be",
        "been",
        "when",
        "what",
        "from",
        "into",
        "than",
        "more",
        "less",
        "most",
        "lately",
        "usual",
        "baseline",
        "mood",
        "day",
        "days",
        "entry",
        "entries",
        "writing",
        "read",
        "reads",
        "reading",
        "lower",
        "higher",
        "after",
        "before",
        "near",
        "appears",
        "present",
        "mostly",
        "often",
        "several",
        "times",
        "keeps",
        "returning",
        "returned",
        "shows",
        "up",
    ]
    for word in words:
        pattern = llm.sanitize_pattern({"kind": "temporal", "label": word}, [])
        assert pattern is not None and pattern.label == word
    bounds = {
        "mood_delta": (-1.0, 1.0),
        "day_fraction": (0.0, 1.0),
        "span_days": (0.0, 3650.0),
        "shift": (-1.0, 1.0),
        "baseline": (-1.0, 1.0),
        "current": (-1.0, 1.0),
    }
    for name, (lower, upper) in bounds.items():
        for raw, expected in (
            (lower - 1, lower),
            (lower, lower),
            (upper, upper),
            (upper + 1, upper),
        ):
            pattern = llm.sanitize_pattern(
                {
                    "kind": "temporal",
                    "label": "work",
                    "occurrences": 100_001,
                    "detail": {name: raw},
                },
                ["work"],
            )
            assert pattern.occurrences == 100_000
            assert pattern.detail == {name: expected}


def test_narratives_keep_native_240_character_limit_and_refuse_clinical_prose(
    monkeypatch,
):
    llm, _ = _modules(monkeypatch)
    assert llm._clean_narrative("p" * 240) == "p" * 240
    assert llm._clean_narrative("p" * 241) == "p" * 240
    for term in (
        "dose",
        "dosage",
        "medication",
        "medications",
        "meds",
        "medicine",
        "medicines",
        "pill",
        "pills",
        "prescription",
        "prescriptions",
        "prescribe",
        "prescribed",
        "diagnosis",
        "diagnose",
        "diagnosed",
    ):
        assert llm._clean_narrative(f"The window mentions {term}.") is None
    for phrase in (
        "tired of you",
        "burden",
        "better off without you",
        "nobody cares",
        "no one cares",
        "not worth it",
        "your fault",
        "the problem is you",
        "push them away",
    ):
        assert llm._clean_narrative("The finding says " + phrase + ".") is None


def test_narrative_address_advice_and_imperative_shapes_are_refused(monkeypatch):
    llm, _ = _modules(monkeypatch)
    phrases = [
        "quietplace.example.net",
        "quietplace dot online",
        "You should pause.",
        "You shouldn't pause.",
        "You must pause.",
        "You mustn't pause.",
        "You need to pause.",
        "You ought to pause.",
        "You have to pause.",
        "You would have to pause.",
        "You might want to pause.",
        "You could try pausing.",
        "You'd better pause.",
        "Why don't you pause.",
        "It would help if you pause.",
        "It might help to you pause.",
    ]
    phrases.extend(
        word + " gathering here."
        for word in [
            "Stop",
            "Start",
            "Quit",
            "Try",
            "Remember",
            "Consider",
            "Make sure",
            "Be sure",
            "Don't",
            "Do not",
            "Never",
            "Always",
            "Take",
            "Call",
            "Text",
            "Visit",
            "Reach out",
            "Hold on",
            "Let go",
            "Focus",
            "Avoid",
            "Block",
            "Delete",
        ]
    )
    for phrase in phrases:
        assert llm._clean_narrative(phrase) is None, phrase
    assert (
        llm._clean_narrative("The writing shows a quiet pause.")
        == "The writing shows a quiet pause."
    )


@pytest.mark.parametrize("mode", ["native-cap", "cap-plus-one", "headerless-plus-one"])
def test_completion_transport_enforces_native_timeout_and_actual_byte_boundaries(
    monkeypatch, mode
):
    llm, _ = _modules(monkeypatch)
    import httpx

    cap = 1_048_576
    data = b"{}" + b" " * (cap - 2)
    if mode != "native-cap":
        data += b" "
    deadlines, events = [], []
    real_timeout = asyncio.timeout

    def timeout(seconds):
        deadlines.append(seconds)
        return real_timeout(seconds)

    class Response:
        headers = (
            {} if mode == "headerless-plus-one" else {"content-length": str(len(data))}
        )

        async def __aenter__(self):
            events.append("response-enter")
            return self

        async def __aexit__(self, *_):
            events.append("response-exit")

        def raise_for_status(self):
            pass

        async def aiter_bytes(self, *, chunk_size):
            assert chunk_size == 65_536
            yield data[:600_000]
            yield data[600_000:]

    class Client:
        def __init__(self, **kwargs):
            value = kwargs["timeout"]
            assert (
                value.connect == 3.0 and value.read == value.write == value.pool == 10.0
            )
            assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False

        async def __aenter__(self):
            events.append("client-enter")
            return self

        async def __aexit__(self, *_):
            events.append("client-exit")

        def stream(self, method, url, **kwargs):
            assert (
                method == "POST" and url == "https://provider.invalid/chat/completions"
            )
            assert kwargs == {
                "json": {"prompt": "private"},
                "headers": {"Authorization": "Bearer key"},
            }
            return Response()

    monkeypatch.setattr(llm.asyncio, "timeout", timeout)
    monkeypatch.setattr(httpx, "AsyncClient", Client)
    analyzer = llm.LLMAnalyzer("https://provider.invalid/", "key")
    if mode == "native-cap":
        assert asyncio.run(analyzer._post_async({"prompt": "private"})) == {}
    else:
        with pytest.raises(
            llm.LLMResponseTooLarge, match="^LLM response exceeds size limit$"
        ):
            asyncio.run(analyzer._post_async({"prompt": "private"}))
    assert deadlines == [10.0]
    assert events == ["client-enter", "response-enter", "response-exit", "client-exit"]
