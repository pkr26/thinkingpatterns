"""The mini-brain: deterministic pattern extraction."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import patterns
from app.services.patterns import JournalEntry, Pattern, analyze, recurring_phrases

BASE = date(2026, 7, 5)  # a Sunday


def sunday(n: int) -> date:
    return BASE + timedelta(weeks=n)


def weekday(n: int) -> date:
    return BASE + timedelta(weeks=n, days=3)  # Wednesdays


WORK_ANXIOUS = (
    "Big deadline at work on monday and the boss wants the presentation "
    "revised. I feel anxious and stressed about this project."
)
CALM_DAY = "Walked by the river, felt calm and grateful. Cooked a nice meal and slept well."


def make_sunday_work_corpus(weeks=5):
    entries = []
    for week in range(weeks):
        entries.append(JournalEntry(text=WORK_ANXIOUS, entry_date=sunday(week)))
        entries.append(JournalEntry(text=CALM_DAY, entry_date=weekday(week)))
    return entries


class TestSentiment:
    def test_positive_negative_neutral(self):
        assert patterns.sentiment_score("felt great, happy and grateful") > 0
        assert patterns.sentiment_score("anxious stressed and worried") < 0
        assert patterns.sentiment_score("the meeting is at three") == 0

    def test_empty_text(self):
        assert patterns.sentiment_score("") == 0.0

    def test_score_bounded(self):
        assert patterns.sentiment_score("good " * 100) == 1.0
        assert patterns.sentiment_score("awful terrible hate") == -1.0


class TestThemes:
    def test_theme_extraction(self):
        assert patterns.extract_themes("boss deadline meeting") == {"work"}
        assert "sleep" in patterns.extract_themes("could not sleep, exhausted")
        assert patterns.extract_themes("nothing here") == set()

    def test_punctuation_and_case_ignored(self):
        assert patterns.extract_themes("DEADLINE!!! deadline, deadline.") == {"work"}


class TestTemporalPattern:
    def test_sunday_work_anxiety_detected(self):
        analysis = analyze(make_sunday_work_corpus())
        temporal = [p for p in analysis.patterns if p.kind == "temporal" and p.label == "work"]
        assert temporal, (
            f"expected temporal work pattern, got {[p.label for p in analysis.patterns]}"
        )
        pattern = temporal[0]
        assert pattern.occurrences == 5
        assert pattern.detail["day"] == "Sunday"
        assert pattern.detail["day_fraction"] == 1.0
        assert "Sunday" in pattern.describe() and "work" in pattern.describe()

    def test_below_occurrence_floor_not_detected(self):
        entries = make_sunday_work_corpus(weeks=3)  # only 3 work mentions
        analysis = analyze(entries)
        assert not [p for p in analysis.patterns if p.kind == "temporal" and p.label == "work"]

    def test_spread_across_days_not_temporal(self):
        entries = [
            JournalEntry(text=WORK_ANXIOUS, entry_date=BASE + timedelta(days=4 * i))
            for i in range(6)
        ]
        analysis = analyze(entries)
        assert not [p for p in analysis.patterns if p.kind == "temporal"]


class TestMoodCorrelation:
    def test_work_days_drag_mood(self):
        analysis = analyze(make_sunday_work_corpus())
        mood = [p for p in analysis.patterns if p.kind == "mood_correlation" and p.label == "work"]
        assert mood
        assert mood[0].detail["mood_delta"] >= 0.3
        assert "lower" in mood[0].describe()

    def test_no_correlation_when_mood_flat(self):
        entries = [
            JournalEntry(text="meeting at work", entry_date=sunday(i), sentiment=0.0)
            for i in range(5)
        ] + [
            JournalEntry(text="walk by the river", entry_date=weekday(i), sentiment=0.0)
            for i in range(5)
        ]
        analysis = analyze(entries)
        assert not [p for p in analysis.patterns if p.kind == "mood_correlation"]

    def test_client_sentiment_override_used(self):
        entries = [
            JournalEntry(text="meeting at work", entry_date=sunday(i), sentiment=-0.8)
            for i in range(4)
        ] + [
            JournalEntry(text="walk by the river", entry_date=weekday(i), sentiment=0.8)
            for i in range(4)
        ]
        analysis = analyze(entries)
        assert [p for p in analysis.patterns if p.kind == "mood_correlation"]


class TestRecurringPhrase:
    def test_phrase_across_weeks_detected(self):
        entries = [
            JournalEntry(
                text=f"weather note {i}. i just want to disappear from all of this",
                entry_date=BASE + timedelta(weeks=i),
            )
            for i in range(4)
        ]
        found = recurring_phrases(entries)
        labels = [p.label for p in found]
        assert "i just want to disappear from all of this" in labels
        phrase = next(p for p in found if "disappear" in p.label)
        assert phrase.occurrences == 4
        assert phrase.detail["span_days"] >= 21
        assert "keeps returning" in phrase.describe()

    def test_same_week_phrase_not_flagged(self):
        entries = [
            JournalEntry(
                text="i just want to disappear from everything today",
                entry_date=BASE + timedelta(days=i),
            )
            for i in range(3)
        ]
        assert recurring_phrases(entries) == []

    def test_two_mentions_not_enough(self):
        entries = [
            JournalEntry(text="i just want to disappear from it all", entry_date=BASE),
            JournalEntry(
                text="i just want to disappear from it all", entry_date=BASE + timedelta(weeks=2)
            ),
        ]
        assert recurring_phrases(entries) == []

    def test_short_sentences_ignored(self):
        entries = [
            JournalEntry(text="fine. okay. meh.", entry_date=BASE + timedelta(weeks=i))
            for i in range(4)
        ]
        assert recurring_phrases(entries) == []

    def test_repeated_sentence_yields_single_pattern(self):
        entries = [
            JournalEntry(
                text="deadline at work monday and the boss piled on another meeting",
                entry_date=BASE + timedelta(weeks=i),
            )
            for i in range(5)
        ]
        assert len(recurring_phrases(entries)) == 1


class TestAnalysisShape:
    def test_stats(self):
        entries = make_sunday_work_corpus(weeks=5)
        analysis = analyze(entries)
        assert analysis.total_entries == 10
        assert analysis.active_days == 10  # all distinct dates
        assert -1 <= analysis.avg_sentiment <= 1
        assert analysis.avg_sentiment == pytest.approx(0.0)  # 5x(-1.0) + 5x(+1.0)
        assert analysis.first_date == sunday(0)
        assert analysis.last_date == weekday(4)

    def test_deterministic(self):
        corpus = make_sunday_work_corpus()
        assert analyze(corpus).to_dict() == analyze(corpus).to_dict()

    def test_empty_corpus(self):
        analysis = analyze([])
        assert analysis.patterns == []
        assert analysis.total_entries == 0
        assert analysis.avg_sentiment == 0.0
        assert analysis.first_date is None

    def test_pattern_cap(self):
        assert patterns.MAX_PATTERNS <= 20
        entries = [JournalEntry(text=WORK_ANXIOUS, entry_date=sunday(i)) for i in range(6)]
        assert len(analyze(entries).patterns) <= patterns.MAX_PATTERNS

    def test_to_dict_roundtrip_fields(self):
        analysis = analyze(make_sunday_work_corpus())
        payload = analysis.to_dict()
        assert payload["total_entries"] == 10
        assert all(
            set(p) == {"kind", "label", "occurrences", "confidence", "detail"}
            for p in payload["patterns"]
        )

    def test_confidence_bounded(self):
        analysis = analyze(make_sunday_work_corpus(weeks=6))
        assert all(0 <= p.confidence <= 1 for p in analysis.patterns)

    def test_describe_unknown_kind_falls_back(self):
        pattern = Pattern(kind="mystery", label="x", occurrences=2, confidence=0.1)
        assert "x" in pattern.describe()
