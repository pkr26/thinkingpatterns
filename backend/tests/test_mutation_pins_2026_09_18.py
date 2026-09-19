"""Mutation-campaign pins (2026-09-18).

Campaign: redteam/mutation_campaign_2026-09-18/ — 36 behavioral mutants
across the statistics engine, lifecycle, crypto boundaries, clinical
guardrails, crisis handling, and the sharing clients. 31 were killed by
the existing suites; each test here kills one of the five survivors, and
its docstring names the mutant it pins. The canary tests re-run the same
input with the guard relaxed, so a corpus that silently loses
discriminating power fails loudly instead of passing vacuously.
"""

from __future__ import annotations

import random
from datetime import date, timedelta

import pytest

from app.services import brain, llm, questions
from app.services.patterns import JournalEntry, Pattern

CALM = "felt calm and grateful today"
T0 = date(2026, 9, 4)


def _trivial_effect_corpus() -> tuple[list[JournalEntry], JournalEntry]:
    """Sundays carry 'work' with a tight, low mood tag; every other day is
    calm text with a wide, noisy tag. Result (measured, deterministic seed):
    reported mood_delta ≈ 0.25 (clears MOOD_MIN_DELTA) while |d| ≈ 0.42
    (under the 0.5 floor) — a statistically detectable but practically
    trivial separation that ONLY the effect-size gate refuses."""
    rng = random.Random(5)
    days = [T0 - timedelta(days=279 - i) for i in range(280)]

    def mood(theme_day: bool) -> float:
        center, width = (-0.25, 0.12) if theme_day else (0.03, 0.65)
        return max(-1.0, min(1.0, rng.gauss(center, width)))

    entries = [
        JournalEntry(
            "anxious about work" if d.weekday() == 6 else CALM,
            d,
            sentiment=mood(d.weekday() == 6),
        )
        for d in days
    ]
    extra = JournalEntry("anxious about work", T0 + timedelta(days=1), sentiment=mood(True))
    return entries, extra


def _surface_after_two_qualification_days(
    entries: list[JournalEntry], extra: JournalEntry
) -> list[Pattern]:
    first = brain.update(brain.load_state(None), entries, T0)
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        entries + [extra],
        T0 + timedelta(days=1),
    )
    return list(second.surfaced)


class TestEffectSizeFloor:
    def test_trivial_standardized_effect_never_surfaces(self):
        """A5: MOOD_MIN_EFFECT = 0.0 survived the ENTIRE suite. The only
        prior pin (test_effect_and_significance_gates) asserts the card's
        detail against the constant itself — true for any constant. This
        corpus clears the delta gate with a |d| well under the floor and
        must earn no mood_correlation card, even after a second,
        independently-qualifying day."""
        entries, extra = _trivial_effect_corpus()
        surfaced = _surface_after_two_qualification_days(entries, extra)
        assert all(not (p.kind == "mood_correlation" and p.label == "work") for p in surfaced)

    def test_trivial_effect_corpus_canary(self):
        """Same corpus with the floor relaxed to 0.0 MUST surface the card —
        this is what proves the corpus still discriminates (and what the
        A5 mutant does to production code)."""
        entries, extra = _trivial_effect_corpus()
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(brain, "MOOD_MIN_EFFECT", 0.0)
            surfaced = _surface_after_two_qualification_days(entries, extra)
        work = [p for p in surfaced if p.kind == "mood_correlation" and p.label == "work"]
        assert work, "corpus lost its discriminating power — recalibrate it"
        assert work[0].detail["mood_delta"] >= brain.MOOD_MIN_DELTA
        assert abs(work[0].detail["cohens_d"]) < 0.5

    def test_floor_value_is_pinned(self):
        """The 0.5 Cohen's d floor is a product decision (RESEARCH.md):
        smaller effects are honest noise at journal scale. Changes must be
        deliberate, not a silent constant edit — which is exactly mutant A5."""
        assert brain.MOOD_MIN_EFFECT == 0.5


class TestNarrativeClinicalBoundary:
    def test_narrative_rejects_diagnosis_language(self):
        """D1: deleting the diagnosis words from _CLINICAL_TERMS survived —
        every existing narrative input overlapped another rule
        ('medication', domains, phones). These inputs trip ONLY the
        clinical-term check: no digits, no contacts, no crisis echo."""
        clean = llm._clean_narrative
        assert clean("a doctor would diagnose this pattern quickly") is None
        assert clean("you are clearly diagnosed with something common") is None
        assert clean("this reads like a textbook diagnosis of low mood") is None

    def test_narrative_rejects_digits_alone(self):
        """D2: the digit ban was only exercised through inputs that also
        contained phones/domains/medication wording. A bare minted statistic
        must die on the digit rule alone."""
        clean = llm._clean_narrative
        assert clean("your darker Saturdays came to 87 percent of them") is None
        assert clean("mood dipped for 14 of the last 30 days") is None


class TestQuestionInterlockLayers:
    def test_label_tripwire_fires_without_the_sensitive_flag(self):
        """E3: disabling the label tripwire of pattern_is_sensitive survived
        the full suite — the composite outcome stayed safe through the
        'sensitive' flag (brain-side) and the belt-and-braces filter on
        rendered questions. But the label tripwire is the layer that covers
        patterns arriving WITHOUT the flag (LLM extras, legacy payloads);
        it earns its own pin. Defense in depth only counts if every layer
        is individually testable."""
        unflagged = Pattern("recurring_phrase", "want to disappear", 4, 0.4, {})
        assert questions.pattern_is_sensitive(unflagged) is True

    def test_unflagged_crisis_label_never_renders_a_question(self):
        """End-to-end form of the same pin: an unflagged crisis-adjacent
        pattern must contribute no rendered question to the pool."""
        unflagged = Pattern("recurring_phrase", "want to disappear", 4, 0.4, {})
        pool = questions.build_pool([unflagged])
        assert all("disappear" not in q for q in pool)
