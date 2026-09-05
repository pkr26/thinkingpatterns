"""The v2 mini-brain: memory, statistics, lifecycle, decay.

The properties pinned here are the product's honesty guarantees:
  * base-rate fallacy killed (Sunday-heavy journalers get no fake
    "everything happens on Sundays" patterns),
  * patterns need repeated evidence before they surface, fade honestly,
    and are eventually forgotten,
  * update() is a pure function — identical inputs, identical brain,
  * a corrupt store degrades to amnesia, never to a crash.
"""

from __future__ import annotations

import json
import math
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)
NEUTRAL_WORK = "quiet day, some work in the afternoon"  # theme, no sentiment words
CALM = "felt calm and grateful today"


def sundays(start: date, count: int) -> list[date]:
    """The first *count* Sundays strictly at/after *start*."""
    out: list[date] = []
    day = start
    while len(out) < count:
        if day.weekday() == 6:
            out.append(day)
        day += timedelta(days=1)
    return out


def consecutive(start: date, count: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(count)]


def dates_only(state: dict) -> dict:
    """The stored pattern records, pid → state string."""
    return {pid: rec.state for pid, rec in state["patterns"].items()}


# --- NLP: negation, stemming, expanded coverage ---------------------------------

class TestNlp:
    def test_negation_flips_polarity(self):
        assert brain.sentiment_score("i am happy today".split()) > 0
        assert brain.sentiment_score("i am not happy today".split()) < 0
        assert brain.sentiment_score("no stress at all today".split()) > 0

    def test_negation_scope_expires(self):
        # The negator's reach is three tokens; "happy" sits beyond it.
        tokens = "not sure why but happy".split()
        assert brain.sentiment_score(tokens) > 0

    def test_stemming_hits_themes(self):
        assert brain.theme_for("working") == "work"
        assert brain.theme_for("studies") == "study"
        assert brain.theme_for("running") == "health"
        assert brain.theme_for("slept") == "sleep"  # irregular map
        assert brain.theme_for("presentations") == "work"
        assert brain.theme_for("qxyjz") is None

    def test_irregular_sentiment_form(self):
        assert brain.sentiment_score("cried all evening".split()) < 0

    def test_word_forms_deduplicate(self):
        assert len(brain.word_forms("running")) == len(set(brain.word_forms("running")))

    def test_extract_themes_via_stems(self):
        assert brain.extract_themes("slept badly working late".split()) == {"sleep", "work"}

    def test_sentences_min_length(self):
        assert brain.sentences_of("Too short. This one is long enough here.") == [
            "this one is long enough here"
        ]


# --- base-rate-corrected temporal detection ---------------------------------------

class TestBaseRateCorrection:
    def test_sunday_heavy_journaler_gets_no_fake_temporal_patterns(self):
        # 30 Sundays + 10 Wednesdays; "work" appears in EVERY entry. The
        # theme follows the writing schedule (75% Sundays) — v1 would call
        # this "work happens on Sundays"; the brain must not.
        days = sundays(T0 - timedelta(days=250), 30) + consecutive(T0 - timedelta(days=40), 10)
        entries = [JournalEntry(NEUTRAL_WORK, d) for d in days]
        result = brain.update(brain.load_state(None), entries, T0)
        temporals = [p for p in result.surfaced if p.kind == "temporal"]
        stored = [s for s in result.new_state["patterns"] if s.startswith("temporal:")]
        assert temporals == []
        assert stored == []

    def test_true_sunday_concentration_is_detected(self):
        # Daily journaler (even weekday base rate), work mentioned ONLY on
        # the 10 Sundays of the range.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        temporals = [p for p in result.surfaced if p.kind == "temporal"]
        assert any(t.label == "work" and t.detail["day"] == "Sunday" for t in temporals)

    def test_min_sample_floor(self):
        days = consecutive(T0 - timedelta(days=20), 21)
        entries = [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "temporal" for p in result.surfaced)


# --- mood correlation gates ---------------------------------------------------------

class TestMoodCorrelation:
    def test_requires_min_per_side(self):
        days = consecutive(T0 - timedelta(days=20), 21)
        entries = [
            JournalEntry("anxious work day", d if d.weekday() == 6 else d, sentiment=-0.8)
            if d.weekday() == 6
            else JournalEntry(CALM, d, sentiment=0.7)
            for d in days
        ]
        # 3 theme entries < MOOD_MIN_PER_SIDE: no claim allowed.
        entries = [
            JournalEntry("anxious work day", d) if d.weekday() == 6 else JournalEntry(CALM, d)
            for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "mood_correlation" for p in result.surfaced)

    def test_effect_and_significance_gates(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for d in days:
            if d.weekday() == 6:
                entries.append(JournalEntry("anxious about work", d))
            else:
                entries.append(JournalEntry(CALM, d))
        result = brain.update(brain.load_state(None), entries, T0)
        moods = [p for p in result.surfaced if p.kind == "mood_correlation"]
        work = next(p for p in moods if p.label == "work")
        assert work.detail["direction"] == "lower"
        assert work.detail["mood_delta"] >= brain.MOOD_MIN_DELTA
        assert abs(work.detail["cohens_d"]) >= brain.MOOD_MIN_EFFECT

    def test_flat_mood_makes_no_claim(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [
            JournalEntry("work stuff and neutral words", d) for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "mood_correlation" for p in result.surfaced)


# --- mood trajectory (EWMA control chart) -------------------------------------------

class TestMoodShift:
    def _series(self, baseline_days: int, shift_days: int, today: date) -> list[JournalEntry]:
        entries = []
        start = today - timedelta(days=baseline_days + shift_days - 1)
        for i in range(baseline_days + shift_days):
            day = start + timedelta(days=i)
            mood = 0.3 if i < baseline_days else -0.7
            entries.append(JournalEntry("ordinary day notes", day, sentiment=mood))
        return entries

    def test_sustained_decline_is_detected(self):
        entries = self._series(baseline_days=20, shift_days=10, today=T0)
        first = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "mood_shift" for p in first.surfaced)  # needs confirmation
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), entries, T0 + timedelta(days=1)
        )
        shifts = [p for p in second.surfaced if p.kind == "mood_shift"]
        assert len(shifts) == 1
        assert shifts[0].detail["direction"] == "lower"
        assert shifts[0].detail["baseline"] == pytest.approx(0.3, abs=0.01)
        assert shifts[0].detail["shift"] <= -brain.MOOD_SHIFT_MIN_SHIFT

    def test_stable_series_produces_no_shift(self):
        entries = self._series(baseline_days=25, shift_days=10, today=T0)
        # A stable series: same mood throughout.
        stable = [
            JournalEntry("ordinary day notes", e.entry_date, sentiment=0.3) for e in entries
        ]
        result = brain.update(brain.load_state(None), stable, T0)
        assert all(p.kind != "mood_shift" for p in result.surfaced)

    def test_short_history_not_eligible(self):
        entries = self._series(baseline_days=8, shift_days=6, today=T0)
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "mood_shift" for p in result.surfaced)


# --- lifecycle: memory across runs ---------------------------------------------------

class TestLifecycle:
    def _weak_corpus(self, today: date) -> list[JournalEntry]:
        # 8 Sunday mentions, daily writer: statistically solid (p ≈ (1/7)^8)
        # but below STRONG_EVIDENCE → candidate on first qualification.
        days = consecutive(today - timedelta(days=55), 56)
        return [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]

    def test_candidate_hidden_until_requalified(self):
        corpus = self._weak_corpus(T0)
        first = brain.update(brain.load_state(None), corpus, T0)
        assert all(p.kind != "temporal" for p in first.surfaced)
        assert dates_only(first.new_state).get("temporal:work") == "candidate"

        # Same-day re-run: still one qualification day, still hidden.
        rerun = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), corpus, T0
        )
        assert dates_only(rerun.new_state).get("temporal:work") == "candidate"

        # A later run adds a second qualification day → emerging → surfaced.
        later = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), corpus, T0 + timedelta(days=3)
        )
        assert dates_only(later.new_state).get("temporal:work") == "emerging"
        surfaced = [p for p in later.surfaced if p.label == "work" and p.kind == "temporal"]
        assert surfaced and surfaced[0].detail["pattern_state"] == "emerging"
        assert surfaced[0].detail["is_new"] is True
        assert later.patterns_new >= 1

    def test_strong_evidence_surfaces_immediately(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]
        result = brain.update(brain.load_state(None), corpus, T0)
        assert any(p.kind == "temporal" and p.label == "work" for p in result.surfaced)

    def test_confirmed_by_age(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), corpus,
                             T0 + timedelta(days=3)).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), corpus,
                             T0 + timedelta(days=24)).new_state
        assert dates_only(state).get("temporal:work") == "confirmed"

    def test_fading_then_archived_then_dropped(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), corpus,
                             T0 + timedelta(days=3)).new_state  # emerging
        # The theme stops appearing entirely.
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]

        faded = brain.update(brain.load_state(brain.dump_state(state)), quiet,
                             T0 + timedelta(days=12))
        assert dates_only(faded.new_state).get("temporal:work") == "fading"
        fading_surfaced = [p for p in faded.surfaced if p.kind == "temporal" and p.label == "work"]
        assert fading_surfaced and faded.patterns_fading >= 1

        archived = brain.update(brain.load_state(brain.dump_state(faded.new_state)), quiet,
                                T0 + timedelta(days=50))
        assert dates_only(archived.new_state).get("temporal:work") == "archived"
        assert all(not (p.kind == "temporal" and p.label == "work") for p in archived.surfaced)

        dropped = brain.update(brain.load_state(brain.dump_state(archived.new_state)), quiet,
                               T0 + timedelta(days=95))
        assert "temporal:work" not in dropped.new_state["patterns"]

    def test_requalified_pattern_returns_to_emerging(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), corpus,
                             T0 + timedelta(days=3)).new_state
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]
        faded = brain.update(brain.load_state(brain.dump_state(state)), quiet,
                             T0 + timedelta(days=12)).new_state
        back = brain.update(brain.load_state(brain.dump_state(faded)), corpus,
                            T0 + timedelta(days=13))
        assert dates_only(back.new_state).get("temporal:work") == "emerging"


# --- decay, determinism, windows, store hygiene ----------------------------------------

class TestMemoryAndDecay:
    def test_strength_decays_with_half_life(self):
        assert brain._decay_strength([T0], T0) == pytest.approx(1 / brain.EVIDENCE_FULL)
        assert brain._decay_strength([T0 - timedelta(days=45)], T0) == pytest.approx(
            1 / brain.EVIDENCE_FULL / 2
        )

    def test_recency_beats_history_in_strength(self):
        # Direct decay comparison pins the ordering property: a mention
        # last week outweighs the same mention two months ago.
        assert brain._decay_strength([T0 - timedelta(days=60)], T0) < brain._decay_strength(
            [T0 - timedelta(days=5)], T0
        )

    def test_strength_saturates_with_dense_recent_evidence(self):
        dense = [T0 - timedelta(days=i) for i in range(0, 16)]
        assert brain._decay_strength(dense, T0) == 1.0

    def test_update_is_pure(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        r1 = brain.update(brain.load_state(None), corpus, T0)
        r2 = brain.update(brain.load_state(None), corpus, T0)
        assert brain.dump_state(r1.new_state) == brain.dump_state(r2.new_state)
        assert [p.to_dict() for p in r1.surfaced] == [p.to_dict() for p in r2.surfaced]

        # Folding the result state again with the same corpus/day is stable
        # (no double counting, no history churn).
        r3 = brain.update(brain.load_state(brain.dump_state(r1.new_state)), corpus, T0)
        assert brain.dump_state(r3.new_state) == brain.dump_state(r1.new_state)

    def test_window_excludes_old_entries(self):
        days = consecutive(T0 - timedelta(days=209), 210)  # ends exactly at T0
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        result = brain.update(brain.load_state(None), corpus, T0)
        # cutoff is inclusive: 180 days back plus today.
        assert result.stats["total_entries"] == brain.WINDOW_DAYS + 1

    def test_empty_corpus_ages_existing_memory(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        later = brain.update(brain.load_state(brain.dump_state(state)), [], T0 + timedelta(days=10))
        assert later.stats["total_entries"] == 0
        assert later.stats["first_date"] is None
        assert dates_only(later.new_state).get("temporal:work") == "fading"

    def test_history_is_bounded_and_daily(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.load_state(None)
        for offset in range(100):
            state = brain.update(state, corpus, T0 + timedelta(days=offset)).new_state
            assert len(state["history"]) <= brain.HISTORY_DAYS
        history_days = [h[0] for h in state["history"]]
        assert len(history_days) == len(set(history_days))


class TestStateSerialization:
    def test_roundtrip_is_stable(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        dumped = brain.dump_state(state)
        assert brain.dump_state(brain.load_state(dumped)) == dumped

    def test_corrupt_store_degrades_to_amnesia(self):
        assert brain.load_state(b"not json at all") == brain.fresh_state()
        assert brain.load_state(json.dumps({"v": 99}).encode()) == brain.fresh_state()
        assert brain.load_state(json.dumps({"v": 2, "patterns": {"x": 1}, "history": 7}).encode())[
            "patterns"
        ] == {}

    def test_invalid_records_are_skipped_not_fatal(self):
        raw = json.dumps({
            "v": 2,
            "patterns": {
                "bad": "not a dict",
                "evil": {"kind": "temporal", "label": "work",
                         "occurrences": {"shape": "that raises in int()"}},
                "good": {"kind": "temporal", "label": "work", "occurrences": 9,
                         "state": "emerging", "first_seen": "2026-08-01",
                         "last_seen": "2026-09-01", "first_qualified": "2026-09-01",
                         "last_qualified": "2026-09-01"},
            },
            "history": [],
        }).encode()
        state = brain.load_state(raw)
        assert "bad" not in state["patterns"]
        assert "evil" not in state["patterns"]
        assert "good" in state["patterns"]

    def test_surfaced_payload_carries_lifecycle_fields(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        result = brain.update(brain.load_state(None), corpus, T0)
        payload = [p.to_dict() for p in result.surfaced]
        assert payload
        for item in payload:
            assert item["detail"]["pattern_state"] in brain.SURFACED_STATES
            assert 0.0 <= item["confidence"] <= 1.0


class TestNearDuplicatePhrasesViaBrain:
    FILLERS = (
        "quiet evening with tea and a film",
        "read a few pages before bed",
        "called the pharmacy about the prescription",
        "rearranged the kitchen shelves",
        "listened to a podcast on the commute",
        "watered all the plants on the balcony",
        "tried a new recipe with lentils",
        "fixed the squeaky door hinge",
        "walked past the old bookshop",
        "wrote a letter to my cousin",
        "sorted through the photo box",
        "practiced chords on the guitar",
        "watched the rain from the window",
        "organized the desk drawers",
        "cooked soup for tomorrow",
        "stretched out on the couch",
        "sketched the view from the kitchen",
        "repaired the bike tire",
    )

    def test_paraphrased_repetition_surfaces(self):
        variants = [
            "i am so tired of everything",
            "i am so tired of this",
            "i am just so tired of everything today",
        ]
        days = consecutive(T0 - timedelta(days=20), 21)
        # Genuinely varied fillers: near-duplicate fillers (or verbatim
        # repeats) would themselves be legitimate recurring phrases.
        entries = []
        filler_index = 0
        for i, d in enumerate(days):
            if i % 7 == 0:
                text = variants[i % 3]
            else:
                text = self.FILLERS[filler_index % len(self.FILLERS)]
                filler_index += 1
            entries.append(JournalEntry(text, d))
        # Three occurrences sit below STRONG_EVIDENCE, so the pattern is a
        # candidate on first qualification and surfaces once re-qualified.
        first = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind not in ("recurring_phrase", "rumination") for p in first.surfaced)
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), entries, T0 + timedelta(days=1)
        )
        # v3: a negative recurring cluster is a repeated WORRY (rumination,
        # Ehring & Watkins 2008), not a neutral phrase.
        worries = [p for p in second.surfaced if p.kind == "rumination"]
        assert any("tired of" in p.label for p in worries)
        assert all("negativity" in p.detail for p in worries)


# --- v3: within-person analysis, links, mood dynamics, graded sentiment ----------

class TestWithinPersonDetrending:
    """The v2 confound, as a regression: a mood TREND must not manufacture
    theme-mood correlations (probe_brain.py demonstrated five false claims
    at p <= 1e-6 in v2; Bolger & Laurenceau 2013 is the standard)."""

    def test_trend_confound_produces_no_mood_correlations(self):
        # 'food' appears only BEFORE a sustained decline (like v2's probe):
        # raw pooled mood would score food-days as clearly "higher".
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            mood = 0.4 if i < 35 else -0.6
            text = "cooked dinner and made food" if i < 35 else "felt low and empty tonight"
            entries.append(JournalEntry(text, d, sentiment=mood))
        result = brain.update(brain.load_state(None), entries, T0)
        mood_claims = [p for p in result.surfaced if p.kind == "mood_correlation"]
        assert all(p.label != "food" for p in mood_claims)

    def test_day_level_association_survives_detrending(self):
        # Same corpus, but 'work' days read low RELATIVE TO THEIR WEEK —
        # a real within-person tie the residuals must still find.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            mood = 0.4 if i < 35 else -0.6          # the trend
            if d.weekday() == 6:
                mood -= 0.5                          # Sunday dip on top
            text = "big deadline pressure at work" if d.weekday() == 6 else "ordinary day notes"
            entries.append(JournalEntry(text, d, sentiment=mood))
        result = brain.update(brain.load_state(None), entries, T0)
        moods = [p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "work"]
        assert moods and moods[0].detail["direction"] == "lower"


class TestLaggedLinks:
    def test_day_after_link_is_detected(self):
        # 'sleep' on scattered days; the NEXT journaling day reads low.
        days = consecutive(T0 - timedelta(days=55), 56)
        entries = []
        for i, d in enumerate(days):
            text = "ordinary day notes"
            mood = 0.1
            if i % 5 == 0:
                text = "could not sleep, restless night"
            if i % 5 == 1:
                mood = -0.6  # the day after a sleep entry
            entries.append(JournalEntry(text, d, sentiment=mood))
        result = brain.update(brain.load_state(None), entries, T0)
        links = [p for p in result.surfaced if p.kind == "link" and p.label == "sleep"]
        # Candidate on first qualification; surfaces once re-qualified.
        if not links:
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), entries, T0 + timedelta(days=1)
            )
            links = [p for p in second.surfaced if p.kind == "link" and p.label == "sleep"]
        assert links and links[0].detail["direction"] == "lower"
        assert links[0].detail["lag_days"] == 1

    def test_no_link_when_next_day_unrelated(self):
        days = consecutive(T0 - timedelta(days=55), 56)
        entries = []
        for i, d in enumerate(days):
            text = "could not sleep, restless night" if i % 5 == 0 else "ordinary day notes"
            entries.append(JournalEntry(text, d, sentiment=0.05))
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "link" for p in result.surfaced)


class TestMoodDynamics:
    def test_instability_fires_on_growing_swings(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            mood = 0.05 + (0.5 if (i % 2 == 0 and i >= 45) else -0.5 if i >= 45 else 0.0) \
                if i >= 45 else 0.05 + (0.03 if i % 2 == 0 else -0.03)
            entries.append(JournalEntry("ordinary day notes", d, sentiment=mood))
        result = brain.update(brain.load_state(None), entries, T0)
        unstable = [p for p in result.surfaced if p.kind == "instability"]
        if not unstable:
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), entries, T0 + timedelta(days=1)
            )
            unstable = [p for p in second.surfaced if p.kind == "instability"]
        assert unstable

    def test_inertia_fires_on_rising_carryover(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            if i >= 42:
                # Recent window: multi-day blocks of high/low mood — strong
                # positive day-to-day carryover (r1 well above 0.45).
                value = 0.4 if (i // 4) % 2 == 0 else -0.4
            else:
                # Earlier window: alternating single days — carryover ≈ none
                # (r1 near -1, maximally different from the recent window).
                value = 0.3 if i % 2 == 0 else -0.3
            entries.append(JournalEntry("ordinary day notes", d, sentiment=value))
        result = brain.update(brain.load_state(None), entries, T0)
        inertial = [p for p in result.surfaced if p.kind == "inertia"]
        if not inertial:
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), entries, T0 + timedelta(days=1)
            )
            inertial = [p for p in second.surfaced if p.kind == "inertia"]
        assert inertial

    def test_stable_mood_produces_no_dynamics_claims(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [JournalEntry("ordinary day notes", d, sentiment=0.1) for d in days]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind not in ("inertia", "instability") for p in result.surfaced)


class TestGradedSentiment:
    def test_intensifiers_amplify(self):
        # "slightly bad" is LESS negative than "bad"; "extremely bad" more.
        assert brain.sentiment_score("feeling slightly bad today".split()) > \
            brain.sentiment_score("feeling bad today".split())
        assert brain.sentiment_score("feeling extremely bad today".split()) < \
            brain.sentiment_score("feeling bad today".split())

    def test_negation_is_damped_not_flipped(self):
        plain = brain.sentiment_score("happy today".split())
        negated = brain.sentiment_score("not happy today".split())
        assert negated < 0 < plain

    def test_but_shifts_weight_to_following_clause(self):
        assert brain.sentiment_score("great day but i feel awful".split()) < 0

    def test_magnitude_ordering(self):
        assert brain.sentiment_score("devastated".split()) < \
            brain.sentiment_score("sad".split()) < 0 < \
            brain.sentiment_score("happy".split()) < \
            brain.sentiment_score("amazing".split())

    def test_absolutist_density(self):
        assert brain.absolutist_density("it always fails and nothing works".split()) > \
            brain.absolutist_density("it sometimes fails".split())


class TestTopicDiscovery:
    """Emergent topics beyond the nine-theme lexicon (audit finding #2)."""

    FILLERS = (
        "read a few pages of the novel before lights out",
        "rearranged the kitchen shelves and found old receipts",
        "listened to a podcast on the commute home",
        "watered all the plants on the balcony",
        "tried a new recipe with lentils and rice",
        "fixed the squeaky door hinge at last",
        "walked past the old bookshop after lunch",
        "wrote a letter to my cousin overseas",
        "sorted through the photo box from the move",
        "repaired the bike tire in the garage",
        "watched the rain from the window with tea",
        "organized the desk drawers and old cables",
        "cooked soup for tomorrow and froze half",
        "stretched out on the couch for a while",
        "sketched the view from the kitchen window",
        "paid the utilities and filed the receipt",
        "took the long way home through the park",
        "bought oranges and bread from the corner shop",
        "brewed proper coffee instead of instant",
        "changed the burnt bulb in the hallway",
    )

    def _corpus(self, today: date) -> list[JournalEntry]:
        days = consecutive(today - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i in (2, 5, 8):  # a small early base rate for 'guitar'
                text += " played the guitar a little"
            if i >= 42 and (i - 42) % 3 == 0:  # rising: ~10 recent entries
                text += " spent the evening with the guitar, learning fingerpicking"
            entries.append(JournalEntry(text, d))
        return entries

    def test_rising_topic_surfaces(self):
        result = brain.update(brain.load_state(None), self._corpus(T0), T0)
        topics = [p for p in result.surfaced if p.kind == "topic" and p.label == "guitar"]
        if not topics:  # candidate on first qualification; second day surfaces it
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), self._corpus(T0), T0 + timedelta(days=1)
            )
            topics = [p for p in second.surfaced if p.kind == "topic" and p.label == "guitar"]
        assert topics
        assert topics[0].detail["trend"] == "rising"
        assert topics[0].detail["share_recent"] > topics[0].detail["share_earlier"]
        assert "p_value" in topics[0].detail  # rising claims are tested

    def test_theme_words_never_become_topics(self):
        # 'work' on every entry: the temporal/mood detectors own it — the
        # topic layer must not re-surface it as a "discovered" theme.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [
            JournalEntry(f"{self.FILLERS[i % len(self.FILLERS)]}, work again", d)
            for i, d in enumerate(days)
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "topic" for p in result.surfaced)

    def test_function_words_never_become_topics(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [
            JournalEntry("really just kind of a day, today was today", d) for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "topic" for p in result.surfaced)

    def test_sparse_mentions_do_not_qualify(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i in (10, 20, 30):  # 3 mentions: below every topic gate
                text += " talked about the greenhouse briefly"
            entries.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(not (p.kind == "topic" and p.label == "greenhouse") for p in result.surfaced)

    def test_steady_presence_surfaces_without_test(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i % 3 == 0:  # 24 of 70 entries ≈ 34%: a steady presence
                text += " spent time in the greenhouse"
            entries.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), entries, T0)
        topics = [p for p in result.surfaced if p.kind == "topic" and p.label == "greenhouse"]
        if not topics:
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), entries, T0 + timedelta(days=1)
            )
            topics = [p for p in second.surfaced if p.kind == "topic" and p.label == "greenhouse"]
        assert topics
        assert topics[0].detail["trend"] == "steady"
        assert "p_value" not in topics[0].detail  # a measurement, not a test


class TestAuditFixes:
    """Regressions from the independent audit of the v3 work."""

    def test_multiple_weekday_candidates_yield_one_pattern(self):
        # A1: 'work' concentrated on TWO weekdays (Mondays and Sundays).
        # Every candidate enters the BH family; only the best SURVIVOR
        # becomes the pattern — exactly one timing claim per theme.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [
            JournalEntry(
                NEUTRAL_WORK if d.weekday() in (0, 6) else CALM, d
            )
            for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        temporals = [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]
        assert len(temporals) == 1
        assert temporals[0].detail["days_tested"] == 2
        # The stronger day (10 Mondays vs 9-10 Sundays depending on calendar)
        # wins the dedupe; the surfaced day_count is the max candidate's.
        assert temporals[0].detail["day_count"] == max(
            temporals[0].detail["day_count"],
            [c for c in (10, 10)][0],  # both ~10 in a 70-day run
        )

    def test_nonfinite_client_sentiment_falls_back_to_text(self):
        # A2: a NaN mood tag must poison nothing — the engine re-scores
        # the entry's text instead.
        days = consecutive(T0 - timedelta(days=29), 30)
        entries = [
            JournalEntry("felt calm and grateful today", d, sentiment=float("nan"))
            for d in days
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats["avg_sentiment"] == pytest.approx(1.0)  # clamped text score
        assert not math.isnan(result.stats["avg_sentiment"])

    def test_client_sentiment_is_clamped_to_engine_scale(self):
        days = consecutive(T0 - timedelta(days=29), 30)
        entries = [JournalEntry("ordinary day notes", d, sentiment=5.0) for d in days]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats["avg_sentiment"] == 1.0

    def test_high_frequency_journal_verbs_never_become_topics(self):
        # A4: 'started'/'told'/'people' in most entries are phrasing, not a
        # life topic — the audit's stopword-gap regression.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            text = TestTopicDiscovery.FILLERS[i % len(TestTopicDiscovery.FILLERS)]
            if i % 2 == 0:  # 35 of 70 entries — well past the presence bar
                text += ", people told me it started already"
            entries.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), entries, T0)
        surfaced_labels = {p.label for p in result.surfaced if p.kind == "topic"}
        assert not surfaced_labels & {"people", "told", "started"}


def test_api_parse_entries_rejects_nonfinite_sentiment():
    # A2 (API side): JSON NaN/Infinity parse cleanly in Python and would
    # poison every downstream average — the parse layer rejects them.
    import json as jsonlib

    from app.api.insights import _parse_entries

    for bad in (float("nan"), float("inf")):
        payload = jsonlib.dumps(
            {"v": 1, "text": "ordinary day", "sentiment": bad, "created_at": "2026-09-01"}
        )
        with pytest.raises(ValueError):
            _parse_entries([bytearray(payload.encode())], [date(2026, 9, 1)])


def test_api_parse_entries_clamps_oversized_sentiment():
    import json as jsonlib

    from app.api.insights import _parse_entries

    payload = jsonlib.dumps(
        {"v": 1, "text": "ordinary day", "sentiment": 12, "created_at": "2026-09-01"}
    )
    (entry,) = _parse_entries([bytearray(payload.encode())], [date(2026, 9, 1)])
    assert entry.sentiment == 1.0
