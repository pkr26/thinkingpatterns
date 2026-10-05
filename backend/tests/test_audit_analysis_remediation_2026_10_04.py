"""Independent behavioral regressions for ANL-01 and ANL-02.

These exercise the production update, not a copied language classifier.
Unsupported text is missing evidence; an explicitly neutral report is data.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

START = date(2026, 1, 1)
GERMAN = (
    "Kartoffelschalen Straßenbahnhaltestelle Weltanschauung Grundstücksgrenze "
    "Schmetterlingsflügel Eichhörnchen Weihnachtsbaum Geschwindigkeitsbegrenzung "
    "Schneeflocken Waschmaschine Fensterrahmen Zahnzwischenraum"
)
CHINESE = "今天我去了图书馆然后在公园散步晚上回家做饭听音乐和朋友聊天。"


def analyze(texts, moods=None):
    moods = moods or [None] * len(texts)
    entries = [
        JournalEntry(text, START + timedelta(days=i), sentiment=mood)
        for i, (text, mood) in enumerate(zip(texts, moods))
    ]
    return brain.update(brain.fresh_state(), entries, START + timedelta(days=len(entries)))


def test_unsupported_summary_is_unavailable_and_does_not_fabricate_neutral_mood():
    result = analyze([GERMAN + " sad"] * 35)
    assert result.stats["language"] == "other"
    assert result.stats["avg_sentiment"] is None
    assert result.stats["active_days"] == result.stats["total_entries"] == 35
    assert result.stats["mood_summary"] == {
        "observations": 0,
        "explicit_mood": 0,
        "text_estimates": 0,
        "excluded_entries": 35,
        "source": "unavailable",
    }


def test_one_explicit_rating_is_not_diluted_by_34_unsupported_entries():
    result = analyze([GERMAN] * 35, [1.0] + [None] * 34)
    assert result.stats["avg_sentiment"] == 1.0
    assert result.stats["mood_summary"] == {
        "observations": 1,
        "explicit_mood": 1,
        "text_estimates": 0,
        "excluded_entries": 34,
        "source": "explicit_mood",
    }


@pytest.mark.parametrize(
    "foreign",
    [
        CHINESE,
        "Мне сегодня тяжело и грустно.",
        "Σήμερα πήγα στη βιβλιοθήκη και μετά περπάτησα στο πάρκο.",
        "ذهبت اليوم إلى المكتبة ثم مشيت في الحديقة وعدت إلى المنزل.",
    ],
)
def test_english_quotation_in_unsupported_script_does_not_enable_text_scoring(foreign):
    result = analyze([foreign * 10 + " sad"] * 35)
    assert result.stats["language"] == "other"
    assert result.stats["avg_sentiment"] is None
    assert result.stats["mood_summary"]["text_estimates"] == 0
    assert not any(p.kind in {"mood_correlation", "mood_shift", "inertia"} for p in result.surfaced)


def test_supported_window_excludes_its_unsupported_minority_entries():
    result = analyze(["I am happy and calm today."] * 30 + [CHINESE + " sad"] * 5)
    assert result.stats["language"] == "en"
    assert result.stats["avg_sentiment"] == 1.0
    assert result.stats["mood_summary"]["observations"] == 30
    assert result.stats["mood_summary"]["excluded_entries"] == 5


def test_supported_prose_with_short_foreign_quotation_remains_eligible():
    result = analyze(["I am happy and calm today after dinner with my family. 今天"] * 35)
    assert result.stats["language"] == "en"
    assert result.stats["avg_sentiment"] == 1.0
    assert result.stats["mood_summary"]["text_estimates"] == 35


@pytest.mark.parametrize(
    "text",
    [
        "Hoy me siento feliz y tranquilo después de cenar con mi familia.",
        "Hoy me siento feliz y tranquilo despue\u0301s de cenar con mi familia.",
    ],
)
def test_spanish_diacritic_forms_remain_supported(text):
    result = analyze([text] * 35)
    assert result.stats["language"] == "es"
    assert result.stats["avg_sentiment"] > 0
    assert result.stats["mood_summary"]["observations"] == 35


def test_explicit_moods_survive_unsupported_script_and_nonfinite_ratings_do_not():
    result = analyze([CHINESE + " sad"] * 4, [2.0, 0.0, float("nan"), float("inf")])
    assert result.stats["language"] == "other"
    assert result.stats["avg_sentiment"] == 0.5
    assert result.stats["mood_summary"]["explicit_mood"] == 2
    assert result.stats["mood_summary"]["excluded_entries"] == 2


def test_budget_blanks_are_unavailable_but_explicit_zero_is_a_real_observation():
    result = analyze([""] * 5)
    assert result.stats["avg_sentiment"] is None
    rated = analyze([""] * 5, [0.0] + [None] * 4)
    assert rated.stats["avg_sentiment"] == 0.0
    assert rated.stats["mood_summary"]["source"] == "explicit_mood"
    assert rated.stats["mood_summary"]["observations"] == 1


def test_mixed_mood_sources_are_disclosed_and_cadence_keeps_excluded_days():
    result = analyze(
        ["I am happy and calm today after dinner with my family.", "", CHINESE],
        [None, -1.0, None],
    )
    assert result.stats["avg_sentiment"] == 0.0
    assert result.stats["mood_summary"] == {
        "observations": 2,
        "explicit_mood": 1,
        "text_estimates": 1,
        "excluded_entries": 1,
        "source": "mixed",
    }
    assert result.stats["active_days"] == 3
