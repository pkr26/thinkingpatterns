"""Wave-5 completion pins: llm.py's label/narrative sanitizer semantics —
the last 51 campaign survivors (all in this module).

The survivors were the sanitizer's internal logic: the digit-word-run
phone detector (>= 3 consecutive number-words, hyphens split), the
corpus-grounding tokenizer (punctuation stripping, the <3-char and
allowlist exemptions, word-token matching), the clinical-term gate, and
the recurring-phrase verbatim rule. All are injection defenses — the
module's own threat model treats model output as hostile.
"""

from __future__ import annotations

import pytest

from app.services import llm


def test_clean_label_rejects_digit_word_runs():
    """Three or more consecutive number-words is a spelled phone number;
    two is legitimate ('two minds' style vocabulary passes)."""
    assert llm._clean_label("call five five five zero") is None
    assert llm._clean_label("five five five start") is None  # exactly 3 in a run
    assert llm._clean_label("one two many thoughts") == "one two many thoughts"  # 2
    # hyphenated number words count as runs too ("six-seven-eight")
    assert llm._clean_label("six-seven-eight") is None


def test_label_grounded_token_rules():
    vocab = {"sleep", "pressure", "work", "forage"}
    # every content token in vocab -> grounded
    assert llm._label_grounded("sleep pressure", vocab)
    # punctuation stripped before matching
    assert llm._label_grounded("(sleep), pressure!", vocab)
    # short tokens (<3) are exempt
    assert llm._label_grounded("to sleep", vocab | {"sleep"})
    # allowlisted function words are exempt
    assert llm._label_grounded("sleep and pressure", vocab)
    # unknown content token -> NOT grounded
    assert not llm._label_grounded("sleep anxiety", vocab)
    # word tokens, never substrings: "rage" is not grounded by "forage"
    assert not llm._label_grounded("rage", vocab)


def test_clean_narrative_clinical_gate():
    """A calm reframe never contains clinical/advice vocabulary — the
    exact blocked set, word for word."""
    for term in ("dose", "dosage", "medication", "medications", "meds",
                 "medicine", "medicines", "pill", "pills", "prescription"):
        assert llm._clean_narrative(f"you mentioned your {term} routine") is None, term
    assert llm._clean_narrative(
        "Work came up more often than usual this week."
    ) == "Work came up more often than usual this week."


def test_sanitize_pattern_recurring_phrase_needs_verbatim():
    """recurring_phrase labels must exist in the corpus VERBATIM — other
    kinds need only token grounding."""
    corpus = ["i can't sleep, my mind won't stop spinning"]
    item = {"kind": "recurring_phrase", "label": "can't sleep", "occurrences": 2}
    got = llm.sanitize_pattern(item, corpus)
    assert got is not None and got.kind == "recurring_phrase"
    # grounded tokens but never written verbatim -> rejected
    fiction = {"kind": "recurring_phrase", "label": "sleep spinning", "occurrences": 2}
    assert llm.sanitize_pattern(fiction, corpus) is None


def test_sanitize_pattern_occurrences_clamped():
    """Occurrences arrive clamped to [0, MAX_OCCURRENCES]; garbage -> 0."""
    corpus = ["sleep sleep sleep"]
    item = {"kind": "temporal", "label": "sleep", "occurrences": 10**9}
    got = llm.sanitize_pattern(item, corpus)
    assert got.occurrences == llm.MAX_OCCURRENCES
    bad = {"kind": "temporal", "label": "sleep", "occurrences " + "": "x"}
    bad = {"kind": "temporal", "label": "sleep", "occurrences": "not-a-number"}
    assert llm.sanitize_pattern(bad, corpus).occurrences == 0


def test_llm_logger_name():
    """The ops/structured-logging contract (runbooks key on it)."""
    assert llm.logger.name == "mindpattern.llm"


# -- the last holdout boundaries (wave-6b) -----------------------------------


def test_fingerprint_rstrip_only_slashes():
    """Trailing X's must survive URL canonicalization — rstrip('/') never
    eats content characters."""
    from app.services.llm import processing_policy_fingerprint

    s = _llm_settings()
    s.llm_url = "https://llm.example.com/v1/XX"
    other = _llm_settings()
    other.llm_url = "https://llm.example.com/v1"
    # "/XX" is a different path, not a trailing slash: different fingerprints
    assert processing_policy_fingerprint(s) != processing_policy_fingerprint(other)


def _llm_settings():
    from app.config import Settings

    s = Settings(environment="development")
    s.llm_url = "https://llm.example.com/v1/"
    s.llm_model = "model-x"
    s.llm_provider_name = "prov"
    s.llm_data_retention = "30d"
    s.llm_policy_version = "v1"
    return s


def test_digit_run_resets_on_non_number_words():
    """A non-number word RESETS the run: 'five five start five five' is
    two short runs and passes; a never-resetting counter would see five."""
    assert llm._clean_label("five five start five five") == "five five start five five"


def test_grounding_strip_set_is_punctuation_only():
    """Leading/dangling capital X is content, not punctuation — 'Xsleep'
    is NOT the token 'sleep'."""
    assert not llm._label_grounded("Xsleep", {"sleep"})


def test_grounding_exact_short_token_threshold():
    """3-char and 4-char unknown tokens must be CHECKED (not exempt):
    only tokens shorter than 3 skate through."""
    assert not llm._label_grounded("abc zzq", set())    # 3-char checked
    assert not llm._label_grounded("abcd zzzq", set())  # 4-char checked
    assert llm._label_grounded("ab xy", {"zzz"})        # <3 exempt


def test_grounding_continues_past_exempt_tokens():
    """An exempt (short) token continues the scan; an unknown content
    token later in the label still fails grounding."""
    assert not llm._label_grounded("to anxiety", {"to"})


def test_narrative_control_char_replacement():
    """Control chars become a single space each — never marker prose."""
    assert llm._clean_narrative("work\rpressure lifted") == "work pressure lifted"


def test_narrative_single_signal_gates():
    """Each gate rejects on ITS OWN: a URL alone, a spelled contact alone,
    and a dialog-only crisis phrase alone are each enough."""
    assert llm._clean_narrative("see https://x.example now") is None
    assert llm._clean_narrative("email foo at example dot com today") is None
    from app.services import crisis

    dialog_only = next(
        p for p in crisis.DIALOG_TIER_PHRASES
        if not crisis.matches_suppress(p)
    ) if hasattr(crisis, "DIALOG_TIER_PHRASES") else "i want to hurt myself"
    assert llm._clean_narrative(f"he said {dialog_only}") is None


def test_requests_made_counts_every_request():
    """The observability counter increments by exactly one per narration
    round (the increment lives in _fetch_patterns around its one _post)."""
    analyzer = llm.LLMAnalyzer("http://x", "", "m")
    import json as _json

    content = _json.dumps({"patterns": [{"kind": "temporal", "label": "sleep",
                            "narrative": "Work came up more often this week."}]})
    analyzer._post = lambda payload: {"choices": [{"message": {"content": content}}]}
    from app.services.patterns import JournalEntry, Pattern

    finding = Pattern("temporal", "sleep", 2, 0.9, {"direction": "lower"})
    from datetime import date as _date

    corpus = [JournalEntry("sleep sleep sleep", _date(2026, 9, 1))]
    analyzer._fetch_patterns(corpus, [finding])
    analyzer._fetch_patterns(corpus, [finding])
    assert analyzer.requests_made == 2


# -- wave-7: the final thirteen ------------------------------------------------


def test_narrative_clinical_strip_is_punctuation_only():
    """The clinical-term strip set contains punctuation only — a leading X
    (or any content char) is NOT stripped, so 'Xprescription' is not the
    clinical word 'prescription' and the narrative survives."""
    got = llm._clean_narrative("your Xprescription routine")
    assert got == "your Xprescription routine"


def test_narration_payload_carries_direction():
    """The findings summary sent to the model includes each finding's
    direction when present and omits the key when not."""
    import json as _json
    from datetime import date as _date

    from app.services.patterns import JournalEntry, Pattern

    analyzer = llm.LLMAnalyzer("http://x", "", "m")
    captured = {}

    content = _json.dumps({"patterns": [
        {"kind": "temporal", "label": "sleep",
         "narrative": "Work came up more often this week."}]})

    def fake_post(payload):
        captured.update(payload)
        return {"choices": [{"message": {"content": content}}]}

    analyzer._post = fake_post
    corpus = [JournalEntry("sleep sleep sleep", _date(2026, 9, 1))]
    with_dir = Pattern("temporal", "sleep", 2, 0.9, {"direction": "lower"})
    analyzer._fetch_patterns(corpus, [with_dir])
    user = _json.loads(captured["messages"][1]["content"])
    assert user["findings"][0]["direction"] == "lower"

    captured.clear()
    no_dir = Pattern("temporal", "sleep", 2, 0.9, {})
    analyzer._fetch_patterns(corpus, [no_dir])
    user = _json.loads(captured["messages"][1]["content"])
    assert "direction" not in user["findings"][0]


def test_sanitize_pattern_copies_direction():
    """sanitize_pattern keeps the finding's direction in the refined
    detail (lower/higher only)."""
    corpus = ["sleep sleep sleep"]
    item = {"kind": "temporal", "label": "sleep",
            "detail": {"direction": "lower"}}
    got = llm.sanitize_pattern(item, corpus)
    assert got.detail["direction"] == "lower"


def test_size_guard_prose_and_streaming_cap(monkeypatch):
    """Exact refusal prose for a lying Content-Length; an exactly-max
    streamed body passes the > cap gate."""
    import httpx
    import pytest as _pytest

    from app.services.llm import LLMResponseTooLarge

    analyzer = llm.LLMAnalyzer("http://x", "", "m")
    state = {"handler": None}

    def handler(request):
        return state["handler"](request)

    real = httpx.AsyncClient

    def patched(**kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(**kw)

    monkeypatch.setattr(httpx, "AsyncClient", patched)

    state["handler"] = lambda request: httpx.Response(
        200, headers={"content-length": "abc"}, content=b"{}")
    with _pytest.raises(ValueError, match=r"^LLM response has invalid Content-Length$"):
        analyzer._post({})

    state["handler"] = lambda request: httpx.Response(
        200, headers={"content-length": str(llm.LLM_MAX_RESPONSE_BYTES + 1)},
        content=b"{}")
    with _pytest.raises(LLMResponseTooLarge, match=r"^LLM response exceeds size limit$"):
        analyzer._post({})

    # (the stream-site refusal shares the header site's exact prose; the
    # mid-stream cap is exercised by the exactly-at-cap case below — see
    # the campaign report's residual ledger for the duplicate-site note)

    state["handler"] = lambda request: httpx.Response(
        200, content=bytes([123] * llm.LLM_MAX_RESPONSE_BYTES))
    try:
        analyzer._post({})  # exactly-at-cap passes the streaming gate
    except LLMResponseTooLarge:
        raise AssertionError("exactly-at-cap body must pass the > cap gate")
    except Exception:
        pass  # the all-'{' body fails JSON parsing — the gate let it through


def test_recent_payload_budget_stops_cleanly():
    """The budget loop breaks (not continues) when the char budget is
    exhausted: no empty trailing entries ride along."""
    from datetime import date as _date

    from app.services.patterns import JournalEntry

    analyzer = llm.LLMAnalyzer("http://x", "", "m")
    big = "word " * 1000
    from datetime import timedelta as _td

    base = _date(2026, 9, 1)
    entries = [JournalEntry(big, base + _td(days=i)) for i in range(60)]
    payload = analyzer._recent_payload(entries)
    assert payload, "payload never empty when budget is positive"
    # every included entry carries non-empty content (a continue-mutant
    # appends truncated-to-empty entries after the budget dies)
    assert all(m["text"].strip() for m in payload)


def test_narration_skips_unknown_then_processes_known():
    """Model-discovered items are SKIPPED (continue), not fatal (break):
    a valid narration after an unknown one still lands."""
    import json as _json
    from datetime import date as _date

    from app.services.patterns import JournalEntry, Pattern

    analyzer = llm.LLMAnalyzer("http://x", "", "m")
    content = _json.dumps({"patterns": [
        {"kind": "temporal", "label": "never-written", "narrative": "x"},
        {"kind": "temporal", "label": "sleep",
         "narrative": "Work came up more often this week."}]})
    analyzer._post = lambda payload: {"choices": [{"message": {"content": content}}]}
    corpus = [JournalEntry("sleep sleep sleep", _date(2026, 9, 1))]
    refined = analyzer._fetch_patterns(corpus, [Pattern("temporal", "sleep", 2, 0.9, {})])
    assert refined and refined[0].detail.get("narrative") == "Work came up more often this week."
