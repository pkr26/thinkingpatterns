"""The optional LLM enrichment shim: guardrails over hostile model output.

Everything here treats the third-party endpoint as adversarial — labels are
capped, recurring phrases must exist in the corpus, numerics are clamped.
A failed call contributes NOTHING (no v1 rule-based fallback exists since
2026-09-17): the deterministic brain's patterns stand, the failure is
logged, and ``last_error`` lets the recompute response report honestly.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from app.config import Settings
from app.services.llm import (
    LLMAnalyzer,
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
    assert sanitize_pattern(
        {"kind": "recurring_phrase", "label": "same thing"}, corpus
    ) is not None
    assert sanitize_pattern(
        {"kind": "recurring_phrase", "label": "never written"}, corpus
    ) is None


def test_sanitize_clamps_occurrences_and_confidence():
    item = {"kind": "temporal", "label": "work", "occurrences": "many", "confidence": "high"}
    kept = sanitize_pattern(item, ["a work day"])
    assert kept is not None
    assert kept.occurrences == 0
    assert kept.confidence == 0.5

    clamped = sanitize_pattern(
        {"kind": "temporal", "label": "work", "occurrences": 10**9, "confidence": 5.0}, ["a work day"]
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


def test_sanitize_filters_detail_fields():
    kept = sanitize_pattern(
        {
            "kind": "temporal",
            "label": "work",
            "detail": {
                "day": "Sunday",          # valid day name -> kept
                "mood_delta": "-0.4",     # numeric string -> float kept
                "day_fraction": 0.55,
                "span_days": "soon",      # non-numeric -> dropped
                "first": "2026-07-01",    # ungroundable free text -> dropped
                "last": "bad\x00label",   # ungroundable free text -> dropped
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
    weird = sanitize_pattern({"kind": "temporal", "label": "work", "detail": "junk"}, ["a work day"])
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
    analyzer._post = lambda payload: posted.append(payload) or _llm_response([
        {"kind": "temporal", "label": "work", "occurrences": 7, "confidence": 0.6,
         "detail": {"day": "Sunday"}},
        {"kind": "recurring_phrase", "label": "work stress", "occurrences": 3, "confidence": 0.4},
        {"kind": "diagnosis", "label": "should be dropped", "occurrences": 1, "confidence": 1},
    ])

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
    flood = [
        {"kind": "temporal", "label": w, "occurrences": 1, "confidence": 0.1}
        for w in words
    ]
    analyzer._post = lambda payload: _llm_response(flood)
    assert analyzer.extract_patterns(corpus) == []

    # With the findings provided, the SAME flood still yields only
    # narrated versions of those findings.
    from app.services.patterns import Pattern
    findings = [Pattern("temporal", "work", 12, 0.9, {"day": "Sunday"})]
    analyzer._post = lambda payload: _llm_response(flood + [
        {"kind": "temporal", "label": "work", "narrative": "Sunday work weeks read as one shape."},
    ])
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
        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    def fake_post(url, json=None, timeout=None, headers=None):
        calls.append({"url": url, "json": json, "timeout": timeout, "headers": headers})
        return FakeResponse()

    monkeypatch.setattr("httpx.post", fake_post)
    analyzer = _make_analyzer()
    body = analyzer._post({"model": "mini"})
    assert body == {"ok": True}
    assert calls[0]["url"] == "https://llm.example.com/v1/chat/completions"  # rstrip("/")
    assert calls[0]["headers"] == {"Authorization": "Bearer test-key"}
    # 2026-09-16 remediation (D2): 10s, not 30 — the call runs inside the
    # secure processing context, so its latency IS the key/plaintext
    # exposure window.
    assert calls[0]["timeout"] == 10
    assert calls[0]["json"] == {"model": "mini"}
