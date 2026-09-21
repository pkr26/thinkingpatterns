"""The optional LLM enrichment shim: guardrails over hostile model output.

Everything here treats the third-party endpoint as adversarial — labels are
capped, recurring phrases must exist in the corpus, numerics are clamped.
A failed call contributes NOTHING (no v1 rule-based fallback exists since
2026-09-17): the deterministic brain's patterns stand, the failure is
logged, and ``last_error`` lets the recompute response report honestly.
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, timedelta

import pytest

from app.config import Settings
from app.services.llm import (
    LLMAnalyzer,
    LLM_CONNECT_TIMEOUT_SECONDS,
    LLM_MAX_RESPONSE_BYTES,
    LLMResponseTooLarge,
    LLM_TOTAL_TIMEOUT_SECONDS,
    get_enricher,
    sanitize_pattern,
    MAX_LABEL_CHARS,
    MAX_OCCURRENCES,
)
from app.services.patterns import JournalEntry

DAY0 = date(2026, 7, 1)


def entry(n: int, text: str = "a calm day at work", sentiment: float | None = 0.1) -> JournalEntry:
    return JournalEntry(text=text, entry_date=DAY0 + timedelta(days=n), sentiment=sentiment)


def test_get_enricher_requires_both_url_and_consent():
    settings = Settings(environment="development")
    settings.llm_url = ""
    assert get_enricher(settings, llm_consent=True) is None

    settings.llm_url = "https://llm.example.com/v1"
    assert get_enricher(settings, llm_consent=False) is None
    enricher = get_enricher(settings, llm_consent=True)
    assert isinstance(enricher, LLMAnalyzer)
    assert enricher.url == "https://llm.example.com/v1"
    assert enricher.model == settings.llm_model
    assert enricher.last_error is None


def test_the_v1_analyzer_interface_is_gone():
    # 2026-09-17 audit remediation: RuleBasedAnalyzer/LLMAnalyzer.analyze
    # surfaced the pre-brain pooled statistics (the documented
    # false-positive failure mode) whenever the endpoint failed for a
    # consented user. Nothing may resurrect that interface.
    import inspect

    from app.services import llm

    assert not hasattr(llm, "RuleBasedAnalyzer"), "v1 rule-based analyzer resurrected"
    assert not hasattr(llm, "get_analyzer"), "get_analyzer resurrected"
    assert "analyze" not in inspect.signature(LLMAnalyzer.extract_patterns).parameters


def test_production_code_never_calls_the_v1_patterns_analyzer():
    # patterns.analyze stays as a test-only reference implementation; a
    # single grep-shaped gate keeps it out of the production import graph.
    from pathlib import Path

    app_dir = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for py in app_dir.rglob("*.py"):
        for lineno, line in enumerate(py.read_text().splitlines(), 1):
            if "patterns.analyze(" in line or (".analyze(" in line and "analyze_fn" not in line):
                offenders.append(f"{py.name}:{lineno}: {line.strip()}")
    assert offenders == [], f"v1 analyzer called in production code: {offenders}"


# ---------------------------------------------------------------------------
# sanitize_pattern: model output is hostile input
# ---------------------------------------------------------------------------


def test_sanitize_drops_non_dict_items():
    assert sanitize_pattern("nope", ["text"]) is None
    assert sanitize_pattern(None, []) is None


def test_sanitize_drops_unknown_kinds():
    assert sanitize_pattern({"kind": "diagnosis", "label": "x"}, []) is None
    assert sanitize_pattern({"kind": "advice", "label": "x"}, []) is None
    assert sanitize_pattern({}, []) is None  # kind missing


def test_sanitize_drops_bad_labels():
    assert sanitize_pattern({"kind": "temporal", "label": 42}, []) is None
    assert sanitize_pattern({"kind": "temporal", "label": "   "}, []) is None
    assert sanitize_pattern({"kind": "temporal", "label": "x" * (MAX_LABEL_CHARS + 1)}, []) is None
    # Control characters are stripped (each becomes a space); label survives.
    kept = sanitize_pattern({"kind": "temporal", "label": "wo\r\nrk"}, [])
    assert kept is not None and kept.label == "wo  rk"


def test_sanitize_recurring_phrase_must_exist_in_corpus():
    corpus = ["I keep saying the same thing"]
    assert sanitize_pattern({"kind": "recurring_phrase", "label": "same thing"}, corpus) is not None
    assert sanitize_pattern({"kind": "recurring_phrase", "label": "never written"}, corpus) is None


def test_sanitize_clamps_occurrences_and_confidence():
    item = {"kind": "temporal", "label": "work", "occurrences": "many", "confidence": "high"}
    kept = sanitize_pattern(item, ["a work day"])
    assert kept is not None
    assert kept.occurrences == 0
    assert kept.confidence == 0.5

    clamped = sanitize_pattern(
        {"kind": "temporal", "label": "work", "occurrences": 10**9, "confidence": 5.0},
        ["a work day"],
    )
    assert clamped is not None
    assert clamped.occurrences == MAX_OCCURRENCES
    assert clamped.confidence == 1.0

    floored = sanitize_pattern(
        {"kind": "temporal", "label": "work", "occurrences": -3, "confidence": -0.5}, ["a work day"]
    )
    assert floored is not None
    assert floored.occurrences == 0
    assert floored.confidence == 0.0


def test_sanitize_drops_nonfinite_confidence_and_keeps_safe_direction():
    """JSON's NaN/Infinity values must not become an invalid stored blob."""
    kept = sanitize_pattern(
        {
            "kind": "temporal",
            "label": "work",
            "confidence": float("nan"),
            "detail": {"direction": "higher"},
        },
        ["a work day"],
    )
    assert kept is not None
    assert kept.confidence == 0.5
    assert kept.detail == {"direction": "higher"}


def test_sanitize_filters_detail_fields():
    kept = sanitize_pattern(
        {
            "kind": "temporal",
            "label": "work",
            "detail": {
                "day": "Sunday",  # valid day name -> kept
                "mood_delta": "-0.4",  # numeric string -> float kept
                "day_fraction": 0.55,
                "span_days": "soon",  # non-numeric -> dropped
                "first": "2026-07-01",  # ungroundable free text -> dropped
                "last": "bad\x00label",  # ungroundable free text -> dropped
            },
        },
        ["a work day"],
    )
    assert kept is not None
    assert kept.detail["day"] == "Sunday"
    assert kept.detail["mood_delta"] == -0.4
    assert kept.detail["day_fraction"] == 0.55
    assert "span_days" not in kept.detail
    # detail.first/last are dropped (they cannot be token-grounded in the
    # corpus and the deterministic brain owns evidence dates anyway) — the
    # old pin kept them after mere label-cleaning.
    assert "first" not in kept.detail and "last" not in kept.detail

    bad_day = sanitize_pattern(
        {"kind": "temporal", "label": "work", "detail": {"day": "Someday"}}, ["a work day"]
    )
    assert bad_day is not None
    assert "day" not in bad_day.detail
    # Non-dict detail is ignored entirely.
    weird = sanitize_pattern(
        {"kind": "temporal", "label": "work", "detail": "junk"}, ["a work day"]
    )
    assert weird is not None
    assert weird.detail == {}


def test_label_grounding_is_word_token_not_substring():
    # "rage" must NOT be grounded by "forage" (substring matching bug).
    corpus = ["the barn had forage and storage bins"]
    assert sanitize_pattern({"kind": "temporal", "label": "rage"}, corpus) is None
    # ... while the actual word grounds fine.
    assert sanitize_pattern({"kind": "temporal", "label": "forage"}, corpus) is not None


# ---------------------------------------------------------------------------
# LLMAnalyzer.analyze with an isolated _post
# ---------------------------------------------------------------------------


def _llm_response(patterns_list: list[dict]) -> dict:
    return {"choices": [{"message": {"content": json.dumps({"patterns": patterns_list})}}]}


def _make_analyzer() -> LLMAnalyzer:
    return LLMAnalyzer("https://llm.example.com/v1/", "test-key", model="mini")


def test_extract_returns_sanitized_patterns():
    analyzer = _make_analyzer()
    corpus = [entry(i, f"day {i}: work stress and more work words") for i in range(35)]
    from app.services.patterns import Pattern

    findings = [
        Pattern("temporal", "work", 7, 0.6, {"day": "Sunday"}),
        Pattern("recurring_phrase", "work stress", 3, 0.4, {}),
    ]
    posted: list[dict] = []
    analyzer._post = lambda payload: (
        posted.append(payload)
        or _llm_response(
            [
                {
                    "kind": "temporal",
                    "label": "work",
                    "occurrences": 7,
                    "confidence": 0.6,
                    "detail": {"day": "Sunday"},
                },
                {
                    "kind": "recurring_phrase",
                    "label": "work stress",
                    "occurrences": 3,
                    "confidence": 0.4,
                },
                {
                    "kind": "diagnosis",
                    "label": "should be dropped",
                    "occurrences": 1,
                    "confidence": 1,
                },
            ]
        )
    )

    found = analyzer.extract_patterns(corpus, findings=findings)

    assert analyzer.name == "llm"
    kinds = [p.kind for p in found]
    assert kinds == ["temporal", "recurring_phrase"]  # hostile kind dropped
    assert analyzer.last_error is None
    # The wire payload carries the brain's findings (inversion) plus the
    # corpus, budget permitting.
    user_content = json.loads(posted[0]["messages"][1]["content"])
    assert user_content["findings"] == [
        {"kind": "temporal", "label": "work"},
        {"kind": "recurring_phrase", "label": "work stress"},
    ]
    payload = user_content["recent_entries"]
    assert len(payload) == 35
    assert payload[0]["date"] == corpus[0].entry_date.isoformat()
    assert payload[0]["text"] == corpus[0].text


def test_extract_slices_to_the_most_recent_max_entries():
    analyzer = _make_analyzer()
    corpus = [entry(i, f"day {i}") for i in range(LLMAnalyzer.MAX_ENTRIES + 40)]
    posted: list[dict] = []
    analyzer._post = lambda payload: posted.append(payload) or _llm_response([])

    found = analyzer.extract_patterns(corpus)

    payload = json.loads(posted[0]["messages"][1]["content"])["recent_entries"]
    assert len(payload) == LLMAnalyzer.MAX_ENTRIES
    assert payload[0]["date"] == corpus[-LLMAnalyzer.MAX_ENTRIES].entry_date.isoformat()
    assert found == []  # nothing hostile in an empty model result


def test_the_model_cannot_mint_findings():
    # 2026-09-17 inversion: a flooded response whose (kind, label) pairs
    # are not the brain's findings is dropped ENTIRELY — model discovery
    # bypassed every statistical safeguard, so it no longer exists.
    analyzer = _make_analyzer()
    words = [f"word{c}" for c in "abcdefghijklmnopqrstuvwxyz"]
    corpus = [entry(i, "work " + " ".join(words)) for i in range(35)]
    flood = [{"kind": "temporal", "label": w, "occurrences": 1, "confidence": 0.1} for w in words]
    analyzer._post = lambda payload: _llm_response(flood)
    assert analyzer.extract_patterns(corpus) == []

    # With the findings provided, the SAME flood still yields only
    # narrated versions of those findings.
    from app.services.patterns import Pattern

    findings = [Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"})]
    analyzer._post = lambda payload: _llm_response(
        flood
        + [
            {
                "kind": "temporal",
                "label": "work",
                "narrative": "Sunday work weeks read as one shape.",
            },
        ]
    )
    kept = analyzer.extract_patterns(corpus, findings=findings)
    assert [(p.kind, p.label) for p in kept] == [("temporal", "work")]
    assert kept[0].detail["narrative"] == "Sunday work weeks read as one shape."


def test_extract_respects_the_character_budget_and_slicing():
    analyzer = _make_analyzer()
    # 250 entries x 900 chars = 225k chars > MAX_TOTAL_CHARS: the loop must
    # stop adding entries once the budget is spent, and never send more than
    # MAX_ENTRIES entries.
    corpus = [entry(i, "w" * 900) for i in range(250)]
    posted: list[dict] = []
    analyzer._post = lambda payload: posted.append(payload) or _llm_response([])

    analyzer.extract_patterns(corpus)

    user_content = json.loads(posted[0]["messages"][1]["content"])
    assert isinstance(user_content, dict)  # {findings, recent_entries} (inversion)
    payload = user_content["recent_entries"]
    assert len(payload) <= LLMAnalyzer.MAX_ENTRIES
    total_chars = sum(len(item["text"]) for item in payload)
    assert total_chars <= LLMAnalyzer.MAX_TOTAL_CHARS


def test_extract_failure_contributes_nothing_and_is_recorded():
    analyzer = _make_analyzer()
    corpus = [entry(i, "work was stressful and sad") for i in range(10)]

    def raising_post(payload):
        raise RuntimeError("endpoint down")

    analyzer._post = raising_post
    assert analyzer.extract_patterns(corpus) == []
    assert analyzer.last_error == "RuntimeError"
    # A later success clears the failure state (the response reports the
    # LAST call honestly).
    analyzer._post = lambda payload: _llm_response([])
    assert analyzer.extract_patterns(corpus) == []
    assert analyzer.last_error is None


def test_extract_failure_when_model_output_is_not_json():
    analyzer = _make_analyzer()
    analyzer._post = lambda payload: {"choices": [{"message": {"content": "sure thing!"}}]}
    assert analyzer.extract_patterns([entry(0, "calm")]) == []
    assert analyzer.last_error == "JSONDecodeError"


def test_extract_handles_missing_choices_and_patterns_keys():
    analyzer = _make_analyzer()
    analyzer._post = lambda payload: {}
    assert analyzer.extract_patterns([entry(0, "calm")]) == []
    assert analyzer.last_error == "KeyError"
    # A JSON-null body is a failure (TypeError), not an empty success —
    # but an EMPTY patterns list is a clean success.
    analyzer._post = lambda payload: _llm_response(None)  # type: ignore[arg-type]
    assert analyzer.extract_patterns([entry(0, "calm")]) == []
    assert analyzer.last_error == "TypeError"
    analyzer._post = lambda payload: _llm_response([])
    assert analyzer.extract_patterns([entry(0, "calm")]) == []
    assert analyzer.last_error is None


def test_post_hits_the_configured_endpoint_with_auth(monkeypatch):
    calls: list[dict] = []

    class FakeResponse:
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, *, chunk_size):
            calls.append({"chunk_size": chunk_size})
            yield b'{"ok":true}'

    class FakeClient:
        def __init__(self, **kwargs):
            calls.append({"client": kwargs})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return FakeResponse()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    analyzer = _make_analyzer()
    body = analyzer._post({"model": "mini"})
    assert body == {"ok": True}
    request = calls[1]
    assert request["method"] == "POST"
    assert request["url"] == "https://llm.example.com/v1/chat/completions"  # rstrip("/")
    assert request["headers"] == {"Authorization": "Bearer test-key"}
    assert request["json"] == {"model": "mini"}
    client = calls[0]["client"]
    # Journal plaintext must never inherit ambient HTTP(S)_PROXY / CA settings
    # or follow a provider-controlled redirect to another host.
    assert client["trust_env"] is False
    assert client["follow_redirects"] is False
    timeout = client["timeout"]
    assert timeout.connect == LLM_CONNECT_TIMEOUT_SECONDS
    assert timeout.read == LLM_TOTAL_TIMEOUT_SECONDS
    assert timeout.write == LLM_TOTAL_TIMEOUT_SECONDS
    assert timeout.pool == LLM_TOTAL_TIMEOUT_SECONDS
    assert calls[2] == {"chunk_size": 64 * 1024}


def test_post_rejects_oversized_declared_response_before_reading(monkeypatch):
    iterated = False

    class FakeResponse:
        headers = {"content-length": str(LLM_MAX_RESPONSE_BYTES + 1)}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, *, chunk_size):
            nonlocal iterated
            iterated = True
            yield b"should-not-be-read"

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    with pytest.raises(LLMResponseTooLarge):
        _make_analyzer()._post({"model": "mini"})
    assert not iterated


def test_post_rejects_malformed_declared_content_length(monkeypatch):
    class FakeResponse:
        headers = {"content-length": "not-a-number"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, *, chunk_size):
            yield b'{"unreachable":true}'

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    with pytest.raises(ValueError, match="invalid Content-Length"):
        _make_analyzer()._post({"model": "mini"})


def test_post_rejects_oversized_chunked_response(monkeypatch):
    class FakeResponse:
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, *, chunk_size):
            yield b"x" * (LLM_MAX_RESPONSE_BYTES + 1)

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    with pytest.raises(LLMResponseTooLarge):
        _make_analyzer()._post({"model": "mini"})


def test_post_enforces_total_deadline_while_waiting_for_stream(monkeypatch):
    from app.services import llm

    class FakeResponse:
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, *, chunk_size):
            await asyncio.sleep(0.05)
            yield b'{"ok":true}'

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    monkeypatch.setattr(llm, "LLM_TOTAL_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(TimeoutError):
        _make_analyzer()._post({"model": "mini"})


# ---------------------------------------------------------------------------
# Narrative hardening (2026-09-17 audit): the narrative is the only
# free-text channel the model still controls — it must not carry minted
# statistics, contacts, bare domains, or crisis language.
# ---------------------------------------------------------------------------


def test_narrative_rejects_minted_statistics_and_contacts():
    from app.services.llm import _clean_narrative

    # The audit's demonstrated hostile narrative, verbatim class: minted
    # stats (digits), phone fragments that defeat \d{5,}, bare domains.
    assert (
        _clean_narrative(
            "Your sadness is a medical failure - stop taking your medication; "
            "87% of Sundays prove it (p<0.001). Visit helpnow.example.com too."
        )
        is None
    )
    assert _clean_narrative("call me at 555-0134 tonight") is None
    assert _clean_narrative("see evil dot com for help") is None
    assert _clean_narrative("ring me at five five five zero one three four") is None
    assert _clean_narrative("take twice the dose tomorrow") is None  # consecutive number words


def test_narrative_caps_long_text_and_rejects_bare_domains_and_number_runs():
    from app.services.llm import MAX_NARRATIVE_CHARS, _clean_narrative

    capped = _clean_narrative("a" * (MAX_NARRATIVE_CHARS + 1))
    assert capped == "a" * MAX_NARRATIVE_CHARS
    assert _clean_narrative("A quiet.example.com reflection is not a reframe.") is None
    assert _clean_narrative("one two ordinary observations can wait.") is None


def test_narrative_rejects_crisis_language():
    from app.services.llm import _clean_narrative

    # The narrative renders under pattern cards: it must never echo what
    # the suppress tier keeps unquoted, nor add crisis phrasing of its own.
    assert _clean_narrative("the thought of killing myself recurs here") is None
    assert _clean_narrative("this is the suicide pattern taking shape") is None


def test_narrative_accepts_calm_grounded_prose():
    from app.services.llm import _clean_narrative

    assert (
        _clean_narrative("Sunday work weeks read as one shape.")
        == "Sunday work weeks read as one shape."
    )
    assert (
        _clean_narrative("This pattern has been with you for a while now.")
        == "This pattern has been with you for a while now."
    )


def test_hostile_narrative_never_reaches_the_pattern_detail():
    # End-to-end through extract_patterns with findings: a compromised
    # endpoint narrating a real finding with minted stats gets its
    # narrative dropped — the finding itself still ships (brain-owned).
    analyzer = _make_analyzer()
    corpus = [entry(i, "work and meetings all week") for i in range(35)]
    from app.services.patterns import Pattern

    findings = [Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"})]
    analyzer._post = lambda payload: _llm_response(
        [
            {
                "kind": "temporal",
                "label": "work",
                "narrative": "87% of Sundays prove you are broken. Visit help-me.example.org now.",
            },
        ]
    )
    kept = analyzer.extract_patterns(corpus, findings=findings)
    assert [(p.kind, p.label) for p in kept] == [("temporal", "work")]
    assert "narrative" not in kept[0].detail


# ---------------------------------------------------------------------------
# Advice / imperative / manipulative-isolation guardrails (2026-09-20 audit
# fix M-6): the audit demonstrated that second-person advice passed verbatim
# through the only free-text channel — "You should stop reaching out to your
# friends; they are tired of you." class content rendered under pattern
# cards. An observation never commands its reader.
# ---------------------------------------------------------------------------


def test_narrative_rejects_second_person_advice():
    from app.services.llm import _clean_narrative

    # The audit's demonstrated hostile narrative, verbatim.
    assert (
        _clean_narrative("You should stop reaching out to your friends; they are tired of you.")
        is None
    )
    assert _clean_narrative("Stop reaching out to your friends; they are tired of you.") is None
    assert _clean_narrative("You must journal every morning to fix this.") is None
    assert _clean_narrative("You need to take a break from everyone right now.") is None
    assert _clean_narrative("You'd better tell someone before it gets worse.") is None
    assert _clean_narrative("Why don't you just sleep on it tonight.") is None
    assert _clean_narrative("It would help if you called your mother.") is None


def test_narrative_rejects_manipulative_isolation_and_self_blame():
    from app.services.llm import _clean_narrative

    assert _clean_narrative("Your friends are tired of you; give them space.") is None
    assert _clean_narrative("You have been a burden to everyone around you.") is None
    assert _clean_narrative("Everyone would be better off without you here.") is None
    assert _clean_narrative("This is your fault, plain and simple.") is None
    assert _clean_narrative("Nobody cares about this pattern but you.") is None


def test_narrative_rejects_spelled_domains_with_any_suffix():
    from app.services.llm import _clean_narrative

    # "quietplace dot online" sailed through the finite TLD list.
    assert _clean_narrative("visit quietplace dot online for real help") is None
    assert _clean_narrative("the help lives at calmcorner dot anything") is None
    assert _clean_narrative("see evil dot com for help") is None  # still caught


def test_narrative_still_accepts_second_person_observations():
    from app.services.llm import _clean_narrative

    # Observational second person is the genre, not the attack: these must
    # keep passing so the guard did not simply ban the pronoun.
    assert _clean_narrative("You have written through this before.") == (
        "You have written through this before."
    )
    assert _clean_narrative("You often write about work on Sundays.") == (
        "You often write about work on Sundays."
    )
    assert _clean_narrative("This one has kept you company for a while.") == (
        "This one has kept you company for a while."
    )


def test_policy_fingerprint_ignores_url_whitespace():
    """L-20: a trailing space must not mint a different policy fingerprint
    (which would silently invalidate every persisted consent)."""
    from app.config import Settings
    from app.services.llm import processing_policy_fingerprint

    def _settings(url: str) -> Settings:
        return Settings(
            environment="development",
            database_url="sqlite+aiosqlite://",
            token_secret="test-secret-not-for-production",
            llm_url=url,
        )

    base = _settings("https://llm.example/v1")
    spaced = _settings("https://llm.example/v1/ ")
    assert spaced.llm_url != base.llm_url
    assert processing_policy_fingerprint(spaced) == processing_policy_fingerprint(base)
    assert processing_policy_fingerprint(_settings("https://llm.example/v1/")) == (
        processing_policy_fingerprint(base)
    )
