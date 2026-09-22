"""Regression tests for the independent audit, round 2 (2026-09-21).

Each test names its finding (F-2/F-3/F-5 from
INDEPENDENT_AUDIT_ROUND_2_2026-09-21.md) and pins the fixed behavior:

* F-2: the D-3 fabrication class survived in ``stats.avg_sentiment`` —
  blank-text untagged (budget-truncated) entries averaged in a fabricated
  neutral 0.0; explicitly tagged entries keep counting.
* F-3: truncation keeps activity tags while blanking text, so a
  blanked-but-tagged entry joined its theme's mood-correlation group
  scored 0.0. Theme membership (prevalence/cadence) stays — the tag is a
  real signal; the fabricated residual does not.
* F-5: every consumer of the graded Spanish lexicons is a PER-TOKEN
  lookup, so multi-word keys can never match; the maps must stay
  whitespace-free and the round-1 removals must stay gone.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain, patterns
from app.services.patterns import JournalEntry
from app.services.sentiment_lexicon_es import INTENSIFIERS_ES, VADER_BASE_ES

T0 = date(2026, 9, 4)
CALM = "felt calm and grateful today"
ANXIOUS_WORK = "anxious about work"


def consecutive(start: date, count: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(count)]


def _has_whitespace(key: str) -> bool:
    return any(ch.isspace() for ch in key)


# --- F-2: truncated entries out of stats.avg_sentiment --------------------------------


class TestAvgSentimentTruncation:
    def test_blank_untagged_entries_leave_avg_sentiment_unchanged(self):
        # 20 tagged days at +0.7 plus 10 blank-text untagged days (the shape
        # budget truncation produces). Pre-fix the blanks averaged in as a
        # fabricated neutral 0.0 and dragged the therapist-facing "average
        # reading" toward the middle; the engine must report exactly the
        # 20-day average.
        days = consecutive(T0 - timedelta(days=19), 20)
        tagged = [JournalEntry("ordinary day notes", d, sentiment=0.7) for d in days]
        blanks = [JournalEntry("", T0 + timedelta(days=k)) for k in range(1, 11)]
        today = T0 + timedelta(days=10)

        base = brain.update(brain.load_state(None), tagged, today)
        grown = brain.update(brain.load_state(None), tagged + blanks, today)

        assert grown.stats["avg_sentiment"] == base.stats["avg_sentiment"] == 0.7
        # The truncated days still count as entries and WRITING days.
        assert grown.stats["total_entries"] == 30
        assert grown.stats["active_days"] == 30

    def test_blank_entry_with_explicit_tag_still_counts(self):
        # A mood-tagged textless entry is the user's own report: one -0.9
        # among twenty +0.7 days must move the reported average.
        days = consecutive(T0 - timedelta(days=19), 20)
        tagged = [JournalEntry("ordinary day notes", d, sentiment=0.7) for d in days]
        result = brain.update(
            brain.load_state(None), tagged + [JournalEntry("", T0, sentiment=-0.9)], T0
        )
        assert result.stats["avg_sentiment"] == 0.624  # (20*0.7 - 0.9) / 21

    def test_all_blank_corpus_keeps_the_zero_default(self):
        # No qualifying entry remains: the historical 0.0 stands.
        blanks = [JournalEntry("", T0 + timedelta(days=k)) for k in range(5)]
        result = brain.update(brain.load_state(None), blanks, T0 + timedelta(days=4))
        assert result.stats["avg_sentiment"] == 0.0


class TestAvgSentimentTruncationLegacyAnalyzer:
    """The v1 reference analyzer carries the same defect; same rule."""

    def test_blank_untagged_entries_leave_avg_sentiment_unchanged(self):
        days = consecutive(T0 - timedelta(days=19), 20)
        tagged = [JournalEntry("ordinary day notes", d, sentiment=0.7) for d in days]
        blanks = [JournalEntry("", T0 + timedelta(days=k)) for k in range(10)]

        assert patterns.analyze(tagged + blanks).avg_sentiment == patterns.analyze(
            tagged
        ).avg_sentiment

    def test_blank_entry_with_explicit_tag_still_counts(self):
        days = consecutive(T0 - timedelta(days=19), 20)
        tagged = [JournalEntry("ordinary day notes", d, sentiment=0.7) for d in days]
        with_report = patterns.analyze(tagged + [JournalEntry("", T0, sentiment=-0.9)])
        assert with_report.avg_sentiment < patterns.analyze(tagged).avg_sentiment

    def test_all_blank_corpus_keeps_the_zero_default(self):
        blanks = [JournalEntry("", T0 + timedelta(days=k)) for k in range(5)]
        assert patterns.analyze(blanks).avg_sentiment == 0.0


# --- F-3: tagged truncated entries out of mood-correlation residuals ------------------


def _work_corpus(days: int = 70) -> list[JournalEntry]:
    """Anxious-work Sundays (10 theme-days, past TEMPORAL_MIN_N) and calm
    text otherwise — the standard mood_correlation:work shape."""
    return [
        JournalEntry(ANXIOUS_WORK if d.weekday() == 6 else CALM, d)
        for d in consecutive(T0 - timedelta(days=days - 1), days)
    ]


def _mood_stats(result) -> dict:
    record = result.new_state["patterns"]["mood_correlation:work"]
    return {k: record.detail[k] for k in ("mood_delta", "direction", "cohens_d", "p_value")}


class TestTaggedTruncationResiduals:
    def test_blank_tagged_entries_do_not_move_the_mood_correlation(self):
        # Budget truncation blanks text but keeps client tags: 10 textless
        # entries carrying only the "work" tag. Their THEME membership is
        # real (prevalence keeps counting them below), but they carry no
        # mood evidence — the mood statistics must equal the corpus with
        # those entries absent entirely, not a group padded with fabricated
        # 0.0 residuals.
        base = _work_corpus()
        truncated = [JournalEntry("", T0 + timedelta(days=k), tags=("work",)) for k in range(10)]
        today = T0 + timedelta(days=9)

        without = brain.update(brain.load_state(None), base, today)
        with_blanks = brain.update(brain.load_state(None), base + truncated, today)

        assert _mood_stats(with_blanks) == _mood_stats(without)
        # Prevalence keeps the truncated days: 10 text Sundays + 10 tagged
        # blank days = 20 theme-days against 10 without them.
        assert with_blanks.new_state["patterns"]["mood_correlation:work"].occurrences == 20
        assert without.new_state["patterns"]["mood_correlation:work"].occurrences == 10

    def test_blank_tagged_entry_with_sentiment_still_contributes(self):
        # Positive control: a blank entry carrying BOTH the activity tag and
        # an explicit mood tag is the user's own report — its residual must
        # keep moving the work group. The reports land on the SAME days as
        # the text Sundays (same-date second entries), so the work group's
        # day-means absorb the -0.9 reports directly.
        base = _work_corpus()
        sundays = [d for d in consecutive(T0 - timedelta(days=69), 70) if d.weekday() == 6]
        reported = [JournalEntry("", d, tags=("work",), sentiment=-0.9) for d in sundays]
        today = T0 + timedelta(days=9)

        without = brain.update(brain.load_state(None), base, today)
        with_reports = brain.update(brain.load_state(None), base + reported, today)

        delta_without = without.new_state["patterns"]["mood_correlation:work"].detail[
            "mood_delta"
        ]
        delta_with = with_reports.new_state["patterns"]["mood_correlation:work"].detail[
            "mood_delta"
        ]
        # Ten strongly negative reports on work-tagged days deepen the
        # with-work group's dip: the delta (without − with) grows.
        assert delta_with > delta_without


# --- F-5: dead multi-word lexicon keys -------------------------------------------------


class TestPerTokenLexiconKeys:
    """Both consumers of the graded lexicons are PER-TOKEN lookups: the
    engine folds and tokenizes first, then consults single tokens and
    their word forms (brain._word_valence, topic eligibility, the
    intensifier window). A key containing whitespace can therefore never
    match — it is dead weight that still ships to the on-device port.
    This invariant would have caught all 30 dead entries (27 graded + the
    intensifier "un poco" purged by F-5, plus the 3 removed in round 1)."""

    def test_es_source_maps_carry_no_whitespace_keys(self):
        for key in VADER_BASE_ES:
            assert not _has_whitespace(key), key
        for key in INTENSIFIERS_ES:
            assert not _has_whitespace(key), key

    def test_merged_engine_maps_carry_no_whitespace_keys(self):
        per_token_maps = {
            "SENTIMENT_LEXICON": brain.SENTIMENT_LEXICON,
            "INTENSIFIERS": brain.INTENSIFIERS,
            "IRREGULAR_FORMS": brain.IRREGULAR_FORMS,
            "EMOJI_VALENCES": brain.EMOJI_VALENCES,
        }
        per_token_sets = {
            "NEGATORS": brain.NEGATORS,
            "BUT_WORDS": brain.BUT_WORDS,
            "ABSOLUTIST_WORDS": brain.ABSOLUTIST_WORDS,
            "SENSE_WORDS": brain.SENSE_WORDS,
            "THEME_WORDS": brain.THEME_WORDS,
            "THEME_WORDS_ES": brain.THEME_WORDS_ES,
        }
        for name, mapping in per_token_maps.items():
            for key in mapping:
                assert not _has_whitespace(key), (name, key)
        for name, words in per_token_sets.items():
            for word in words:
                assert not _has_whitespace(word), (name, word)

    def test_round1_dead_entries_stay_gone(self):
        # Removed by the round-1 audit's ES-lexicon item; nothing may
        # reintroduce them.
        for dead in ("eterno es", "por eso", "darme cuenta"):
            assert dead not in VADER_BASE_ES
            assert dead not in brain.SENTIMENT_LEXICON

    def test_single_word_siblings_survived_the_purge(self):
        # The purge removed only multi-word keys: the graded single-word
        # readings next to them must all still be there.
        for kept in ("encantado", "paz", "quiero", "esperanza", "duele", "equivocado"):
            assert VADER_BASE_ES[kept] != 0.0
        assert INTENSIFIERS_ES["medio"] != 1.0
