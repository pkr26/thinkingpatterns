"""2026-09-28 lexicon polysemy remediation — regression pins.

Found by the 1-year, 10-user simulation (reports/simulation1y): two
polysemous words mislabeled affect at the rumination gate, in opposite
directions.

  * "down" carried near-maximal negative weight (-1.3), so the
    DIRECTIONAL particle ("took it down", "wrote it down", "calmed
    down") pushed a whole mundane cluster past the -0.30 rumination
    bar on its own — two simulation personas received a "repeated
    worry" card for a recycling chore. Curated to -0.6 (VADER's own
    weight for the affective sense, x4 scale); "feeling down" stays
    mildly negative, direction no longer classifies.

  * "stop" inherited VADER's -1.2, so perseverative negation INVERTED
    it: "can't sleep, my mind won't stop" scored +0.222 (the x-0.74
    negation scalar flips a negative to a positive) and the flagship
    worry shape escaped the rumination kind entirely — the exact shape
    the negation-heavy path (non-positive + >= 2 negators) exists to
    catch. Curated to 0.0: the word's affect lives in what is stopped.

These tests pin the word weights, the sentence-level scores the gate
reads, and the end-to-end cluster classification in both directions —
plus the negative controls (a genuinely negative cluster keeps the
rumination kind; the affective "feeling down" sense survives, mildly).
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 28)

RECYCLING = "sorted the recycling and took it down"
SLEEP_WORRY = "i can't sleep, my mind won't stop"
HEAVY = "everything felt heavy again tonight"
FEELING_DOWN = "felt really down again today"

FILLER = "watered the plants and walked past the old bookshop slowly"


def _recurring_corpus(phrase: str, *, every: int = 7, days: int = 56) -> list[JournalEntry]:
    """A recurring near-duplicate phrase across separated days (the same
    shape test_crisis.py's engine interlock uses)."""
    entries: list[JournalEntry] = []
    start = T0 - timedelta(days=days - 1)
    for i in range(days):
        day = start + timedelta(days=i)
        entries.append(JournalEntry(phrase if i % every == 0 else FILLER, day))
    return entries


def _surfaced_after_recomputes(corpus: list[JournalEntry], runs: int = 3):
    """Fold the corpus through update() like the daily client does."""
    state = None
    result = None
    for k in range(runs):
        result = brain.update(state, corpus, T0 - timedelta(days=runs - 1 - k))
        state = result.new_state
    return result


class TestWordWeights:
    def test_down_is_polysemy_safe(self):
        assert brain.SENTIMENT_LEXICON["down"] == -0.6
        assert brain.SENTIMENT_LEXICON_ES["down"] == -0.6  # mirror merge inherits

    def test_stop_is_neutral(self):
        # Curated override beats VADER_BASE's -1.2 in BOTH runtime merges.
        assert brain.SENTIMENT_LEXICON["stop"] == 0.0
        assert brain.SENTIMENT_LEXICON_ES["stop"] == 0.0
        assert brain.CURATED_SENTIMENT["stop"] == 0.0


class TestSentenceScores:
    def test_directional_down_stays_above_the_rumination_bar(self):
        # The bar is RUMINATION_NEGATIVITY_MAX (-0.30); with every other
        # word neutral the phrase score is exactly weight/4.
        score = brain.sentiment_score(RECYCLING.split(), None)
        assert score == pytest.approx(-0.15)
        assert score > brain.RUMINATION_NEGATIVITY_MAX

    def test_perseverative_negation_is_non_positive(self):
        # +0.222 before the fix; 0.0 after — eligible for the
        # negation-heavy path (non-positive + >= 2 negators).
        for phrase in (SLEEP_WORRY, "can't sleep, my mind won't stop racing"):
            assert brain.sentiment_score(phrase.split(), None) <= 0.0

    def test_affective_down_survives_mildly(self):
        assert brain.sentiment_score(FEELING_DOWN.split(), None) < 0.0
        assert brain.sentiment_score("really down lately".split(), None) < 0.0


class TestClusterClassification:
    def test_mundane_chore_is_not_a_worry(self):
        result = _surfaced_after_recomputes(_recurring_corpus(RECYCLING))
        cards = [p for p in result.surfaced if RECYCLING in p.label]
        assert cards, "the repeated chore sentence must still surface (direct measurement)"
        assert all(p.kind == "recurring_phrase" for p in cards)
        assert not any(p.kind == "rumination" for p in result.surfaced)

    def test_perseverative_worry_is_rumination(self):
        result = _surfaced_after_recomputes(_recurring_corpus(SLEEP_WORRY))
        cards = [p for p in result.surfaced if "mind won't stop" in p.label]
        assert cards, "the recurring worry phrase must surface"
        assert any(p.kind == "rumination" for p in cards)

    def test_genuinely_negative_cluster_keeps_rumination(self):
        # "heavy" is curated -1.3 and untouched: a real worry phrase must
        # not lose its kind to the polysemy fix.
        result = _surfaced_after_recomputes(_recurring_corpus(HEAVY))
        cards = [p for p in result.surfaced if "heavy" in p.label]
        assert cards and any(p.kind == "rumination" for p in cards)

    def test_affective_down_cluster_is_measured_not_pathologized(self):
        # Post-fix calibration, pinned deliberately: a repeated "felt
        # really down" cluster is a recurring_phrase card (mild negative,
        # above the bar), not a rumination diagnosis from one word.
        result = _surfaced_after_recomputes(_recurring_corpus(FEELING_DOWN))
        cards = [p for p in result.surfaced if "down" in p.label]
        assert cards and all(p.kind == "recurring_phrase" for p in cards)
