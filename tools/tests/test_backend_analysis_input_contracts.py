"""Real decrypted entry/feedback ingestion and export byte-budget contracts."""

from __future__ import annotations

import dataclasses
import importlib
import json
import math
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DAY = date(2026, 1, 2)


def _api(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.api.insights")


def _entry(**values):
    return bytearray(
        json.dumps({"created_at": "2026-01-02", "text": "private", **values}).encode()
    )


def test_decrypted_entry_channels_keep_native_dates_and_normalized_values(monkeypatch):
    api = _api(monkeypatch)
    raw = _entry(
        created_at="2026-01-03T01:30:00+03:00",
        sentiment=-2,
        energy=2,
        sleep=5,
        tags=[" Work ", "work", " ", "x" * 25],
        tod="evening",
        input_mode="voice",
        transcript_lang="es",
        english_text="translated",
    )
    [entry] = api._parse_entries([raw], [DAY])
    assert dataclasses.asdict(entry) == {
        "text": "private",
        "entry_date": DAY,
        "sentiment": -1.0,
        "energy": 1.0,
        "sleep_quality": 5,
        "tags": ("work", "x" * 24),
        "tod": "evening",
    }
    for inner in ("2026-01-01", "2026-01-02", "2026-01-03"):
        assert (
            api._parse_entries([_entry(created_at=inner)], [DAY])[0].entry_date == DAY
        )
    for language, expected in [
        ("en", "private"),
        ("es", "private"),
        ("fr", "translated"),
        ("de", "translated"),
        (None, "private"),
    ]:
        result = api._parse_entries(
            [_entry(transcript_lang=language, english_text="translated")], [DAY]
        )
        assert result[0].text == expected
    for translation in (None, "", " \t\n"):
        assert (
            api._parse_entries(
                [_entry(transcript_lang="fr", english_text=translation)], [DAY]
            )[0].text
            == "private"
        )
    for energy in (-1, 0, 1):
        assert api._parse_entries([_entry(energy=energy)], [DAY])[0].energy == energy
    assert api._parse_entries([_entry(energy=-2)], [DAY])[0].energy == -1
    assert api._parse_entries([_entry(input_mode="typed")], [DAY])[0].text == "private"
    for sleep in (1, 5):
        assert (
            api._parse_entries([_entry(sleep=sleep)], [DAY])[0].sleep_quality == sleep
        )
    assert len(api._parse_entries([_entry(tags=list("abcdefgh"))], [DAY])[0].tags) == 8


def test_decrypted_entry_malformed_shapes_explain_the_refused_channel(monkeypatch):
    api = _api(monkeypatch)
    cases = [
        ({"text": True}, "text must be a string"),
        ({"created_at": True}, "created_at must be a string"),
        ({"created_at": "2026-01-04"}, "created_at does not match entry_date"),
        ({"created_at": "2025-12-31"}, "created_at does not match entry_date"),
        ({"tags": {}}, "tags must be a list of at most 8 strings"),
        ({"tags": list("abcdefghi")}, "tags must be a list of at most 8 strings"),
        ({"tags": [1]}, "tags must be strings"),
        ({"tod": "midnight"}, "tod must be one of: afternoon, evening, morning, night"),
        ({"tod": True}, "tod must be one of: afternoon, evening, morning, night"),
        ({"input_mode": "unsupported"}, "input_mode must be 'typed' or 'voice'"),
        ({"transcript_lang": "english"}, "transcript_lang must be an ISO 639-1 code"),
        ({"english_text": True}, "english_text must be a string or null"),
    ]
    for channel in ("sentiment", "energy"):
        cases.extend(
            ({channel: value}, channel + " must be a finite number")
            for value in (True, "1", [], math.nan, math.inf, -math.inf)
        )
    cases.extend(
        ({"sleep": value}, "sleep must be an integer 1..5")
        for value in (0, 6, True, 1.0, "1", [])
    )
    for values, diagnostic in cases:
        with pytest.raises(ValueError) as observed:
            api._parse_entries([_entry(**values)], [DAY])
        assert str(observed.value) == diagnostic


def test_analysis_native_per_entry_and_total_plaintext_bounds(monkeypatch):
    api = _api(monkeypatch)
    assert (
        api._parse_entries([_entry(text="x" * 20_000)], [DAY])[0].text == "x" * 20_000
    )
    assert (
        api._parse_entries([_entry(text="x" * 20_001)], [DAY])[0].text == "x" * 20_000
    )
    assert (
        api._parse_entries(
            [_entry(transcript_lang="fr", english_text="x" * 20_001)], [DAY]
        )[0].text
        == "x" * 20_000
    )
    # 100 native-size entries fit; one extra oldest character must be
    # removed without changing their date, order or structured channels.
    plains = [_entry(text="oldest")] + [_entry(text="x" * 20_000) for _ in range(100)]
    dates = [DAY + timedelta(days=i) for i in range(101)]
    plains = [
        bytearray(
            json.dumps(
                {"text": json.loads(raw)["text"], "created_at": day.isoformat()}
            ).encode()
        )
        for raw, day in zip(plains, dates, strict=True)
    ]
    entries = api._parse_entries(plains, dates)
    assert entries[0].text == "" and entries[0].entry_date == DAY
    assert sum(len(entry.text) for entry in entries) == 2_000_000
    assert all(entry.text == "x" * 20_000 for entry in entries[1:])
    plains[0] = _entry(text="x")
    assert api._parse_entries(plains, dates)[0].text == ""


def test_feedback_volume_bound_and_missing_lists_are_exact(monkeypatch):
    api = _api(monkeypatch)
    payload = {
        "feedback": [{"pid": "x" * 128, "resonated": False} for _ in range(100)]
        + [None],
        "muted": ["a" * 128] * 100 + [None],
        "unmuted": ["b"] * 100 + [None],
    }
    result = api._parse_feedback(json.dumps(payload).encode())
    assert result.taps == [("x" * 128, False)] * 100
    assert result.muted == ["a" * 128] * 100 and result.unmuted == ["b"] * 100
    assert api._parse_feedback(b'{"muted":["a"]}') == api.FeedbackEvents([], ["a"], [])
    assert api._parse_feedback(b'{"unmuted":["b"]}') == api.FeedbackEvents(
        [], [], ["b"]
    )
    assert api._parse_feedback(b'{"feedback":[]}') == api.FeedbackEvents([], [], [])
    assert api._parse_feedback(
        b'{"feedback":[{"pid":"a","resonated":true}]}'
    ) == api.FeedbackEvents([("a", True)], [], [])


def test_feedback_malformed_shapes_have_identical_api_error_envelopes(monkeypatch):
    api = _api(monkeypatch)
    invalid = [
        b"\xff",
        b"{",
        b"[]",
        b"null",
        b"{}",
        b'{"feedback":null}',
        b'{"feedback":{}}',
        b'{"feedback":[null]}',
        b'{"feedback":[true]}',
    ]
    for pid in ("", "x" * 129, None, 1, True, []):
        invalid.append(
            json.dumps({"feedback": [{"pid": pid, "resonated": True}]}).encode()
        )
        for field in ("muted", "unmuted"):
            invalid.append(json.dumps({"feedback": [], field: [pid]}).encode())
    for flag in (None, 1, 0, "true", []):
        invalid.append(
            json.dumps({"feedback": [{"pid": "a", "resonated": flag}]}).encode()
        )
    for field in ("muted", "unmuted"):
        for value in (None, {}, "x", True):
            invalid.append(json.dumps({"feedback": [], field: value}).encode())
    for raw in invalid:
        with pytest.raises(api.ApiError) as observed:
            api._parse_feedback(raw)
        assert (
            observed.value.status_code,
            observed.value.code,
            observed.value.detail,
        ) == (400, "entry_payload_malformed", "feedback blob is malformed")


def test_export_metadata_budget_is_inclusive_and_never_omits_first_oversized_row(
    monkeypatch,
):
    _api(monkeypatch)
    account = importlib.import_module("app.api.account")
    cap = 2_097_152
    rows = [("a", cap - 1), ("b", 1), ("c", 1)]
    assert account._take_export_metadata_page(rows) == rows[:2]
    assert account._take_export_metadata_page([("a", cap + 1), ("b", 1)]) == [
        ("a", cap + 1)
    ]
    assert account._take_export_metadata_page([("a", None), ("b", cap)]) == [
        ("a", None),
        ("b", cap),
    ]
    assert account._take_export_metadata_page([]) == []
    assert account._take_export_metadata_page(
        [("a", cap), ("oversized", 1), ("zero", 0)]
    ) == [("a", cap)]


def test_selected_question_pid_matches_actual_public_question_in_both_languages(
    monkeypatch,
):
    api = _api(monkeypatch)
    questions = importlib.import_module("app.services.questions")
    patterns = importlib.import_module("app.services.patterns")
    candidates = [
        patterns.Pattern(
            "mood_correlation",
            "work",
            5,
            0.8,
            {"direction": "lower", "pattern_pid": "work-pid"},
        ),
        patterns.Pattern(
            "recurring_phrase", "quiet space", 6, 0.9, {"pattern_pid": "quiet-pid"}
        ),
        patterns.Pattern(
            "mood_correlation",
            "work",
            5,
            0.8,
            {"direction": "lower", "pattern_pid": "duplicate-work-pid"},
        ),
        patterns.Pattern(
            "mood_correlation",
            "danger",
            2,
            0.8,
            {"muted": True, "pattern_pid": "muted-pid", "direction": "higher"},
        ),
    ]
    for language in ("en", "es"):
        owners = {}
        for pattern in candidates[:3]:
            for text in questions.render_pattern_questions(pattern, language):
                owners.setdefault(text, pattern.detail["pattern_pid"])
        for offset in range(60):
            day = DAY + timedelta(days=offset)
            question = questions.question_for_today(
                "patient", candidates, day, language=language
            )
            assert api._chosen_pattern_pid(
                day, candidates, "patient", language
            ) == owners.get(question)
