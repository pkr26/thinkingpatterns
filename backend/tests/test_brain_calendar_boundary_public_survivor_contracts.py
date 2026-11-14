"""Native gap statistics and language-aware mood correction on real journal inputs."""

import random
from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T = date(2026, 10, 22)


def recompute(stages):
    state = brain.fresh_state()
    for entries, today in stages:
        result = brain.update(brain.load_state(brain.dump_state(state)), entries, today)
        state = result.new_state
    return result


def native_cadence():
    earlier = [T - timedelta(days=124)]
    for i in range(81):
        earlier.append(earlier[-1] + timedelta(days=4 if i == 40 else 1))
    assert earlier[-1] == T - timedelta(days=40)
    stages = []
    for offset in (-7, 0):
        end = T + timedelta(days=offset)
        days = [end - timedelta(days=22)]
        for i in range(16):
            days.append(days[-1] + timedelta(days=2 if i in (1, 3, 6, 9, 12, 15) else 1))
        assert days[-1] == end
        stages.append(([JournalEntry("I have notes", d) for d in earlier + days], end))
    return stages


def native_contaminated(seed):
    rng = random.Random(seed)
    mood = 1
    es = []
    for i in range(100):
        if rng.random() < 0.12:
            mood = -mood
        themed = rng.random() < (0.65 if mood > 0 else 0.35)
        text = (
            ("insomnia " if themed else "") + "good"
            if mood > 0
            else ("insomnia " if themed else "") + "bad"
        )
        es.append(JournalEntry("I am " + text, T - timedelta(days=99 - i)))
    final = es + [
        JournalEntry("I am insomnia " + word, T + timedelta(days=k))
        for k, word in [(1, "good"), (2, "bad")]
    ]
    return [(es, T), (final, T + timedelta(days=2))]


def test_integer_gap_calendar_replicates_at_both_inclusive_spread_bars():
    # Each collection has 82 earlier writing dates with one four-day gap,
    # and 17 recent dates with six two-day gaps. The two native current
    # journal collections are recomputed seven days apart; no estimator
    # output or private gap sequence is substituted into the engine.
    result = recompute(native_cadence())
    (card,) = [p for p in result.surfaced if p.kind == "cadence"]
    assert card.occurrences == 17
    assert card.detail["gap_spread_recent"] == 0.5
    assert card.detail["gap_spread_earlier"] == 0.333
    assert card.detail["median_gap_recent"] == 1.0


def test_theme_word_removal_retains_the_native_clean_series_dependence():
    # This bounded, deterministic input has persistent good/bad runs.
    # The theme's own scored word must not remove the correction for
    # dependence in the remaining actual text observations.
    result = recompute(native_contaminated(0))
    assert result.stats["language"] == "en"
    assert not any(p.kind == "mood_correlation" and p.label == "sleep" for p in result.surfaced)
