"""Writing-window precision and language-specific scores through real consumers."""

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

SUNDAY = date(2026, 8, 2)


def _temporal_cards(buckets):
    entries = [
        JournalEntry("busy day at work again", SUNDAY + timedelta(weeks=index), tod=bucket)
        for index, bucket in enumerate(buckets)
    ]
    entries += [
        JournalEntry("quiet day, some reading", SUNDAY + timedelta(days=2 + index))
        for index in range(14)
    ]
    today = SUNDAY + timedelta(weeks=len(buckets))
    first = brain.update(brain.fresh_state(), entries, today)
    entries += [
        JournalEntry("another busy work day", today + timedelta(weeks=offset)) for offset in (1, 2)
    ]
    later = brain.update(first.new_state, entries, today + timedelta(weeks=2))
    cards = [card for card in later.surfaced if card.kind == "temporal" and card.label == "work"]
    assert cards, "A well-supported weekday claim is the positive control"
    return cards


@pytest.mark.parametrize("count", [1, 2])
def test_one_or_two_timestamps_do_not_narrow_a_supported_weekday_claim(count):
    cards = _temporal_cards(["evening"] * count + [None] * (9 - count))
    assert "time_of_day" not in cards[0].detail


def test_exact_seventy_percent_dominance_narrows_a_supported_weekday_claim():
    cards = _temporal_cards(["evening"] * 7 + ["morning"] * 3)
    assert cards[0].detail["time_of_day"] == "evening"


@pytest.mark.parametrize(
    ("word", "english", "spanish"),
    [
        ("genial", 0.45, 0.7),
        ("fatal", -0.625, -0.7),
        ("perfecto", 0.325, 0.7),
        ("tension", -0.325, -0.55),
        ("horrible", -0.775, -0.75),
    ],
)
def test_shared_words_use_the_published_language_specific_scoring(word, english, spanish):
    # Public scoring examples from the shipped EN/ES lexicons, checked via
    # actual normalization/scoping rather than inspecting the merge table.
    assert brain.sentiment_score([word], "en") == pytest.approx(english)
    assert brain.sentiment_score([word], "es") == pytest.approx(spanish)
    assert brain.sentiment_score([word]) == pytest.approx(english)


def test_one_supported_word_cannot_enable_a_dominantly_unknown_latin_window():
    foreign = (
        "Kartoffelschalen Straßenbahnhaltestelle Weltanschauung Grundstücksgrenze "
        "Schmetterlingsflügel Eichhörnchen Weihnachtsbaum Geschwindigkeitsbegrenzung "
        "Schneeflocken Waschmaschine Fensterrahmen Zahnzwischenraum "
    ) * 3 + "sad"
    entries = [JournalEntry(foreign, SUNDAY + timedelta(days=index)) for index in range(35)]
    result = brain.update(brain.fresh_state(), entries, entries[-1].entry_date)
    assert result.stats["language"] == "other"
    assert result.stats["avg_sentiment"] is None
    assert result.stats["mood_summary"]["excluded_entries"] == len(entries)
