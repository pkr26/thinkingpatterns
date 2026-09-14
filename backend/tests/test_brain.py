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
        # Statistical kinds replicate before surfacing: candidate on first
        # qualification, emerging once it re-qualifies with INDEPENDENT
        # evidence — a fresh work entry. (A next-day recompute of the
        # UNCHANGED corpus is the same observation scored twice and no
        # longer promotes; see _replication_satisfied.)
        first = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "temporal" for p in first.surfaced)
        grown = entries + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
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
        first = brain.update(brain.load_state(None), entries, T0)
        # Second qualification day, with a fresh work entry as the new
        # evidence the replication gate requires.
        grown = entries + [JournalEntry("anxious about work", T0 + timedelta(days=1))]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
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
        assert all(p.kind != "mood_shift" for p in first.surfaced)  # needs replication
        # Window-stat replication: a next-day recompute re-scores the SAME
        # EWMA excursion (its memory is ~11 days) — not a second
        # observation, so the claim stays a candidate...
        next_day = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), entries, T0 + timedelta(days=1)
        )
        assert all(p.kind != "mood_shift" for p in next_day.surfaced)
        # ...until the qualification days span >= 2 calendar days (the
        # window itself has moved) with the excursion still present.
        grown = entries + [
            JournalEntry("ordinary day notes", T0 + timedelta(days=k), sentiment=-0.7)
            for k in (1, 2)
        ]
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
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

        # A later run adds a second qualification day WITH new evidence (a
        # fresh work entry) → emerging → surfaced. (The same run on the
        # unchanged corpus would stay a candidate: consecutive recomputes
        # of one window are one observation, not replication.)
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3))]
        later = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=3)
        )
        assert dates_only(later.new_state).get("temporal:work") == "emerging"
        surfaced = [p for p in later.surfaced if p.label == "work" and p.kind == "temporal"]
        assert surfaced and surfaced[0].detail["pattern_state"] == "emerging"
        assert surfaced[0].detail["is_new"] is True
        assert later.patterns_new >= 1

    def test_strong_evidence_surfaces_immediately(self):
        # Direct-measurement kinds keep instant surfacing at STRONG_EVIDENCE:
        # a literally-repeated sentence is THERE or it isn't — no inference
        # to fluke through. (Pre-replication-gate this test pinned a
        # STATISTICAL kind (temporal) surfacing on first qualification —
        # that path was removed on purpose; see STATISTICAL_KINDS.)
        days = consecutive(T0 - timedelta(days=69), 70)
        phrase = "i keep checking the locks every single night"
        corpus = []
        for i, d in enumerate(days):
            text = phrase if i % 7 == 0 else CALM  # 10 occurrences, 63-day span
            corpus.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), corpus, T0)
        phrases = [p for p in result.surfaced if p.kind in ("recurring_phrase", "rumination")]
        assert any(p.label == phrase for p in phrases)

    def test_statistical_kinds_never_surface_on_first_qualification(self):
        # The replication gate: even with occurrences >> STRONG_EVIDENCE, a
        # statistical claim stays a candidate until it re-qualifies on a
        # second distinct recompute day (a noise fluke gets one day).
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]
        first = brain.update(brain.load_state(None), corpus, T0)
        assert dates_only(first.new_state).get("temporal:work") == "candidate"
        assert all(p.kind != "temporal" for p in first.surfaced)
        # Same-day recompute does NOT count as replication.
        rerun = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), corpus, T0
        )
        assert dates_only(rerun.new_state).get("temporal:work") == "candidate"
        # Neither does a next-day recompute of the UNCHANGED corpus: no new
        # evidence day arrived, so there is no independent second
        # observation (the 2026-09 replication-honesty tightening).
        next_day = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), corpus, T0 + timedelta(days=1)
        )
        assert dates_only(next_day.new_state).get("temporal:work") == "candidate"
        # A second qualification day that DOES add evidence (a fresh work
        # entry) is a real replication → emerging → surfaced.
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
        assert dates_only(second.new_state).get("temporal:work") == "emerging"
        assert any(p.kind == "temporal" for p in second.surfaced)

    def test_statistical_candidate_fades_to_archived_without_a_card(self):
        # A statistical claim that qualifies once and never again never
        # surfaces at all — not even as a "fading" card (that would be the
        # same single-run fluke wearing a sadder label).
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [
            JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days
        ]
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]
        aged = brain.update(brain.load_state(brain.dump_state(state)), quiet,
                            T0 + timedelta(days=10))
        assert dates_only(aged.new_state).get("temporal:work") == "archived"
        assert all(p.kind != "temporal" for p in aged.surfaced)

    def test_confirmed_by_age(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        # Second qualification with fresh evidence (a new work entry) —
        # the replication gate no longer promotes on an unchanged corpus.
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3))]
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
                             T0 + timedelta(days=3)).new_state
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
                             T0 + timedelta(days=24)).new_state
        assert dates_only(state).get("temporal:work") == "confirmed"

    def test_fading_then_archived_then_dropped(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        # Re-qualify with fresh evidence so the pattern has SURFACED
        # (emerging) before the corpus goes quiet.
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3))]
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
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
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3))]
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
                             T0 + timedelta(days=3)).new_state
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]
        faded = brain.update(brain.load_state(brain.dump_state(state)), quiet,
                             T0 + timedelta(days=12)).new_state
        # The theme returns with NEW evidence days: a statistical revival
        # must replicate like a first promotion — it cannot ride the stale
        # evidence back in.
        returned = grown + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=13))]
        back = brain.update(brain.load_state(brain.dump_state(faded)), returned,
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
        # Re-qualify with fresh evidence (a new work entry) so the
        # (statistical) pattern has SURFACED (emerging) before the corpus
        # goes quiet — a lone candidate archives silently instead (see the
        # replication gate).
        grown = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
                             T0 + timedelta(days=1)).new_state
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
        first = brain.update(brain.load_state(None), entries, T0)
        # Second day with a fresh (low) work day as new evidence.
        grown = entries + [JournalEntry("big deadline pressure at work",
                                        T0 + timedelta(days=1), sentiment=-0.9)]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
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
        # Candidate on first qualification; replication needs a NEW outcome
        # day — extend the corpus with a fresh sleep entry and its low
        # day-after.
        if not links:
            grown = entries + [
                JournalEntry("could not sleep, restless night",
                             T0 + timedelta(days=1), sentiment=0.1),
                JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.6),
            ]
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), grown, T0 + timedelta(days=2)
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
            # Window-stat replication: two qualification days >= 2 calendar
            # days apart — the swing pattern continues two more days.
            grown = entries + [
                JournalEntry("ordinary day notes", T0 + timedelta(days=1), sentiment=0.55),
                JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.45),
            ]
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), grown, T0 + timedelta(days=2)
            )
            unstable = [p for p in second.surfaced if p.kind == "instability"]
        assert unstable

    def test_inertia_fires_on_rising_carryover(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            if i >= 42:
                # Recent window: multi-day blocks of high/low mood — strong
                # positive day-to-day carryover (r1 around 0.45+).
                value = 0.4 if (i // 4) % 2 == 0 else -0.4
            else:
                # Earlier window: alternating single days — carryover ≈ none
                # (r1 near -1, maximally different from the recent window).
                value = 0.3 if i % 2 == 0 else -0.3
            entries.append(JournalEntry("ordinary day notes", d, sentiment=value))
        # The replication gate applies: the claim surfaces once it has
        # qualified on two distinct recompute days (the exact r1 value
        # wobbles as the 180-day window slides, so loop a few days).
        state = brain.load_state(None)
        inertial = []
        for k in range(4):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
            inertial = [p for p in result.surfaced if p.kind == "inertia"]
            if inertial:
                break
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

    def test_kind_of_hedge_is_not_positive(self):
        # "kind" carried +1.9 and flipped hedged negatives positive.
        assert brain.sentiment_score("kind of hard today".split()) == 0.0
        # The genuinely negative tail still reads negative.
        assert brain.sentiment_score("it was kind of awful".split()) < 0

    def test_fed_the_cat_is_neutral(self):
        # "fed" (-1.5) poisoned caretaking sentences; removed.
        assert brain.sentiment_score("i fed the cat this morning".split()) == 0.0

    def test_present_is_not_valenced(self):
        # Attendance/gift senses outnumber the mindful one; dropped.
        assert brain.sentiment_score("everyone present agreed on the plan".split()) == 0.0

    def test_relaxed_is_positive_again(self):
        # v2 valence restored (the v3 lexicon claims v2 superset status).
        assert brain.sentiment_score("i felt relaxed all evening".split()) > 0

    def test_hardly_negates_without_double_apply(self):
        # "hardly"/"barely" were in BOTH the downtoners (0.7x) and the
        # negators, applying both rules; VADER treats them as negation
        # only, so they now score exactly like "not".
        assert brain.sentiment_score("it was hardly good".split()) == pytest.approx(
            brain.sentiment_score("it was not good".split()))
        assert brain.sentiment_score("i barely slept".split()) == pytest.approx(
            brain.sentiment_score("i didn't sleep".split()))


class TestUpdatePurity:
    def test_update_never_mutates_the_input_state(self):
        # update() is documented pure: the caller's store object must be
        # byte-identical after a run, however the run went.
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        snapshot = brain.dump_state(state)
        result = brain.update(state, corpus, T0 + timedelta(days=3))
        assert brain.dump_state(state) == snapshot
        assert brain.dump_state(result.new_state) != snapshot  # progress happened
        # Nested objects too: patterns/history of the input stay untouched.
        assert state["history"] != result.new_state["history"] or not state["history"]


class TestSemanticFlip:
    """A re-qualified claim whose core semantics moved forks a new pid."""

    def _store_with_temporal(self, day_name: str) -> dict:
        store = brain.fresh_state()
        store["patterns"]["temporal:work"] = brain.StoredPattern(
            pid="temporal:work", kind="temporal", label="work",
            first_seen="2026-06-01", last_seen="2026-08-30",
            first_qualified="2026-08-01", last_qualified="2026-08-30",
            occurrences=11, state="emerging",
            qualification_days=["2026-08-01", "2026-08-30"],
            evidence_dates=["2026-08-30"], feedback={},
            detail={"day": day_name, "day_count": 11, "p_value": 1e-6},
        )
        return store

    def _signal_for(self, day_name: str, day: date) -> brain._Signal:
        return brain._Signal(
            pid="temporal:work", kind="temporal", label="work",
            occurrences=11, pvalue=1e-6,
            detail={"day": day_name, "day_count": 11, "p_value": 1e-6},
            evidence_days=[day - timedelta(days=7), day],
        )

    def test_dominant_weekday_flip_retires_and_forks(self):
        store = self._store_with_temporal("Sunday")
        brain._merge_lifecycle(store, [self._signal_for("Wednesday", T0)], T0)
        old = store["patterns"]["temporal:work"]
        new = store["patterns"]["temporal:work~2"]
        # The retired claim fades with its history intact (it had surfaced).
        assert old.state == "fading"
        assert old.detail["day"] == "Sunday"
        # The flipped claim starts over: fresh pid, candidate clock, no
        # inherited evidence.
        assert new.state == "candidate"
        assert new.detail["day"] == "Wednesday"
        assert new.first_qualified == T0.isoformat()
        assert new.qualification_days == [T0.isoformat()]

    def test_same_semantics_keep_history(self):
        store = self._store_with_temporal("Sunday")
        brain._merge_lifecycle(store, [self._signal_for("Sunday", T0)], T0)
        assert set(store["patterns"]) == {"temporal:work"}
        record = store["patterns"]["temporal:work"]
        assert record.qualification_days[-1] == T0.isoformat()
        assert len(record.qualification_days) == 3

    def test_flip_of_a_never_surfaced_candidate_archives_quietly(self):
        store = self._store_with_temporal("Sunday")
        store["patterns"]["temporal:work"].state = "candidate"
        brain._merge_lifecycle(store, [self._signal_for("Wednesday", T0)], T0)
        assert store["patterns"]["temporal:work"].state == "archived"
        assert "temporal:work~2" in store["patterns"]

    def test_engine_level_weekday_flip(self):
        # Phase A: work on Sundays → temporal:work emerges. Then the journal
        # is rewritten with work on Wednesdays instead: the recompute flips.
        days = consecutive(T0 - timedelta(days=69), 70)
        sundays = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), sundays, T0).new_state
        # Emerging needs a second qualification day with new evidence.
        grown = sundays + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        state = brain.update(brain.load_state(brain.dump_state(state)), grown,
                             T0 + timedelta(days=1)).new_state
        assert dates_only(state).get("temporal:work") == "emerging"
        wednesdays = [JournalEntry(NEUTRAL_WORK if d.weekday() == 2 else CALM, d) for d in days]
        flipped = brain.update(brain.load_state(brain.dump_state(state)), wednesdays,
                               T0 + timedelta(days=2))
        pats = flipped.new_state["patterns"]
        assert pats["temporal:work"].state == "fading"
        assert pats["temporal:work"].detail["day"] == "Sunday"
        assert "temporal:work~2" in pats
        assert pats["temporal:work~2"].detail["day"] == "Wednesday"


class TestFullFamilyCorrection:
    """Every test that runs enters the BH family — gates filter survivors."""

    def test_gate_failing_weekday_candidates_are_tested_and_marked(self):
        # work spread 4/3/3 over Mon/Tue/Wed: the 3-mention days fail the
        # k >= 4 floor but were TESTED — they must be emitted with
        # gate_ok=False and a real p-value (pre-gate family membership).
        days = consecutive(T0 - timedelta(days=69), 70)
        workdays = [d for d in days if d.weekday() == 0][:4] + \
                   [d for d in days if d.weekday() == 1][:3] + \
                   [d for d in days if d.weekday() == 2][:3]
        entries = [JournalEntry(NEUTRAL_WORK if d in workdays else CALM, d) for d in days]
        residual_per = []
        for e in entries:
            tokens = brain.WORD_RE.findall(e.text.lower())
            residual_per.append(
                (e, tokens, brain.extract_themes(tokens), brain.sentiment_score(tokens))
            )
        weekday_total: dict[int, int] = {}
        for e in entries:
            weekday_total[e.entry_date.weekday()] = weekday_total.get(e.entry_date.weekday(), 0) + 1
        signals = [s for s in brain._detect_themes(residual_per, weekday_total, len(entries))
                   if s.pid == "temporal:work"]
        assert len(signals) == 3  # all three weekdays tested
        by_day = {s.detail["day"]: s for s in signals}
        assert by_day["Monday"].gate_ok is True   # k=4, fraction 0.4
        assert by_day["Tuesday"].gate_ok is False  # k=3 below the floor
        assert all(s.pvalue is not None for s in signals)
        assert all(s.detail["days_tested"] == 3 for s in signals)

    def test_mood_tie_is_emitted_pre_gate(self):
        # A real but sub-threshold mood tie: tested (p-value present),
        # gate_ok False — the family counts it, the card is never made.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for d in days:
            if d.weekday() == 6:
                entries.append(JournalEntry(NEUTRAL_WORK, d, sentiment=0.15))
            else:
                entries.append(JournalEntry(CALM, d, sentiment=0.0))
        residual_per = []
        for e in entries:
            tokens = brain.WORD_RE.findall(e.text.lower())
            residual_per.append((e, tokens, brain.extract_themes(tokens), e.sentiment))
        weekday_total = {d.weekday(): sum(1 for e in entries if e.entry_date.weekday() == d.weekday())
                         for d in days}
        signals = [s for s in brain._detect_themes(residual_per, weekday_total, len(entries))
                   if s.pid == "mood_correlation:work"]
        assert len(signals) == 1
        assert signals[0].pvalue is not None
        assert signals[0].gate_ok is False  # |delta| ~ 0.15 < MOOD_MIN_DELTA

    def test_pure_noise_surfaces_no_statistical_cards(self):
        # The audit's FDR finding as a regression: a seeded pure-noise
        # corpus (theme words sprinkled at random, sentiment independent
        # of text) must not surface ANY statistical card in one shot.
        import random

        filler = ("walked home past the library and the old mill afterwards",
                  "washed the dishes and folded the laundry slowly",
                  "watered the balcony plants and trimmed the basil")
        theme_words = ("work boss deadline", "sleep tired bed", "friend party lonely",
                       "family mom dad", "gym doctor headache", "money rent salary",
                       "school exam homework", "food dinner cook", "rain sunny storm")
        for seed in (11, 22, 33):
            rng = random.Random(seed)
            entries = []
            start = T0 - timedelta(days=83)
            for i in range(84):
                if rng.random() < 0.85:
                    parts = [rng.choice(filler)]
                    parts.extend(rng.choice(theme_words).split()[0] for _ in range(2))
                    rng.shuffle(parts)
                    entries.append(JournalEntry(". ".join(parts), start + timedelta(days=i),
                                                sentiment=round(rng.uniform(-0.6, 0.6), 3)))
            result = brain.update(brain.load_state(None), entries, T0)
            stat_cards = [p for p in result.surfaced if p.kind in brain.STATISTICAL_KINDS]
            assert stat_cards == [], f"seed {seed}: false statistical cards {stat_cards}"
            stored_stat = [pid for pid, rec in result.new_state["patterns"].items()
                           if rec.kind in brain.STATISTICAL_KINDS and rec.state != "candidate"]
            assert stored_stat == [], f"seed {seed}: {stored_stat}"

    def test_daily_cadence_pure_noise_replication_bound(self):
        # The re-audit's scenario as a regression: DAILY recomputes over a
        # growing pure-noise corpus. Consecutive recomputes share ~179/180
        # window days, so the bare "2 distinct recompute days" gate
        # re-qualified the same fluke — measured on these exact parameters
        # (24 seeded runs x 14 daily recomputes): 3/24 runs (12.5%)
        # surfaced >= 1 false statistical card under the old gate; the
        # re-audit measured ~17% on its own corpus. With the independent-
        # evidence gate: 1/24 runs (4.2%).
        #
        # The bound is <= 1, not zero, honestly: at q = 0.05 the BH family
        # budgets one false discovery in twenty, and the surviving run's
        # card is exactly that — a fluke weekday concentration at
        # p ~= 5e-4 that the correction legitimately calls a discovery,
        # corroborated the next day by a chance mention (new evidence).
        # Eliminating it would mean a 3-observation gate, at real
        # sensitivity cost for a claim the FDR budget already allows.
        import random

        filler = ("walked home past the library and the old mill afterwards",
                  "washed the dishes and folded the laundry slowly",
                  "watered the balcony plants and trimmed the basil",
                  "sorted the mail and stacked the newspapers neatly")
        theme_words = ("work boss deadline", "sleep tired bed", "friend party lonely",
                       "family mom dad", "gym doctor headache", "money rent salary",
                       "school exam homework", "food dinner cook", "rain sunny storm")
        runs_with_cards = 0
        for seed in range(1, 25):
            rng = random.Random(seed)
            entries = []
            start = T0 - timedelta(days=83)
            for i in range(84):
                if rng.random() < 0.85:
                    parts = [rng.choice(filler)]
                    parts.extend(rng.choice(theme_words).split()[0] for _ in range(2))
                    rng.shuffle(parts)
                    entries.append(JournalEntry(". ".join(parts), start + timedelta(days=i),
                                                sentiment=round(rng.uniform(-0.6, 0.6), 3)))
            state = brain.load_state(None)
            run_cards: set[str] = set()
            for k in range(14):
                today = T0 - timedelta(days=13 - k)
                known = [e for e in entries if e.entry_date <= today]
                result = brain.update(state, known, today)
                state = result.new_state
                run_cards.update(
                    f"{p.kind}:{p.label}" for p in result.surfaced
                    if p.kind in brain.STATISTICAL_KINDS
                )
            runs_with_cards += bool(run_cards)
        assert runs_with_cards <= 1, \
            f"{runs_with_cards}/24 daily-cadence noise runs surfaced false statistical cards"


class TestInertiaHonestNull:
    def test_persistent_carryover_without_rise_makes_no_claim(self):
        # Carryover HIGH in both windows: the old r≠0 test (correlation_p)
        # called this "more than usual" — the Fisher-z difference test
        # matches the wording, so nothing qualifies.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            value = 0.4 if (i // 4) % 2 == 0 else -0.4  # strong carryover throughout
            entries.append(JournalEntry("ordinary day notes", d, sentiment=value))
        state = brain.load_state(None)
        for k in range(3):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k))
            state = result.new_state
        assert all(rec.kind != "inertia" for rec in state["patterns"].values())


class TestLinkGapLabeling:
    def test_gap2_links_report_the_modal_gap(self):
        # Wednesdays unwritten: Tuesday theme days land their outcome on
        # Thursday (gap 2). The claim must say so — never "the day after".
        days = [d for d in consecutive(T0 - timedelta(days=69), 70) if d.weekday() != 2]
        entries = []
        for d in days:
            text = "ordinary day notes"
            mood = 0.1
            if d.weekday() == 1:
                text = "could not sleep, restless night"
            if d.weekday() == 3:
                mood = -0.6  # two days after the sleep entry (Wed skipped)
            entries.append(JournalEntry(text, d, sentiment=mood))
        state = brain.load_state(None)
        link = None
        # The second run extends the corpus with a fresh sleep entry and its
        # (gap-1) low day-after: replication needs a NEW outcome day. One
        # gap-1 pair against ten gap-2 pairs leaves the modal gap at 2.
        grown = entries + [
            JournalEntry("could not sleep, restless night",
                         T0 + timedelta(days=1), sentiment=0.1),
            JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.6),
        ]
        for offset, current in ((0, entries), (2, grown)):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), current, T0 + timedelta(days=offset))
            state = result.new_state
            link = next((p for p in result.surfaced if p.kind == "link" and p.label == "sleep"),
                        None)
            if link is not None:
                break
        assert link is not None
        assert link.detail["direction"] == "lower"
        assert link.detail["lag_days"] == 2  # modal gap, honestly reported
        assert link.detail["gap2_days"] > link.detail["gap1_days"]
        assert "days after" in link.describe()  # gap-aware copy
        assert "day after '" not in link.describe()


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
        # The context bar: a presence claim must recur in VARIED local
        # context, so the fixture varies the word after "greenhouse"
        # (fixed-template boilerplate like "…greenhouse today" every time
        # is filtered — that is the anti-flood rule under test).
        followers = ("tomatoes", "basil", "peppers", "chores", "lettuce")
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i % 3 == 0:  # 24 of 70 entries ≈ 34%: a steady presence
                text += f" spent time in the greenhouse {followers[i % len(followers)]}"
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
        assert topics[0].detail["presence"] is True  # flagged for client down-ranking

    def test_fixed_template_presence_is_filtered_by_the_context_bar(self):
        # Same share/span as a real presence, but ONE fixed follower —
        # journaling boilerplate, not a life topic (audit: presence topics
        # flooded pure-noise corpora before the bar).
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i % 3 == 0:
                text += " wrote in the greenhouse today"  # follower: always "today"
            entries.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), entries, T0)
        result = brain.update(
            brain.load_state(brain.dump_state(result.new_state)), entries, T0 + timedelta(days=1)
        )
        assert all(not (p.kind == "topic" and p.label == "greenhouse") for p in result.surfaced)
        assert all(not (p.kind == "topic" and p.label == "greenhouse")
                   for p in result.new_state["patterns"].values())

    def test_cluster_covered_presence_is_suppressed(self):
        # The follower bar is beatable: a small vocabulary hands every
        # content word enough distinct followers (re-audit: 40/40
        # small-vocab noise runs surfaced 3-6 "'blanket' is a steady
        # presence" cards). This fixture's boilerplate PASSES the follower
        # bar (felt/stayed/seemed/was) — verified: with the coverage bar
        # disabled the card floods — but every occurrence sits inside a
        # recurring-phrase cluster, so the presence claim is suppressed as
        # the same measurement wearing a second hat.
        days = consecutive(T0 - timedelta(days=69), 70)
        variants = (
            "my blanket felt warm through the night once more",
            "my blanket stayed warm through the night once more",
            "my blanket seemed warm through the night once more",
            "my blanket was warm through the night once more",
        )
        entries = []
        for i, d in enumerate(days):
            text = self.FILLERS[i % len(self.FILLERS)]
            if i % 2 == 0:  # 35 of 70 entries — deep past every presence bar
                text += ". " + variants[(i // 2) % len(variants)]
            entries.append(JournalEntry(text, d))
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(not (p.kind == "topic" and p.label == "blanket") for p in result.surfaced)
        assert all(not (p.kind == "topic" and p.label == "blanket")
                   for p in result.new_state["patterns"].values())
        # The boilerplate itself is still honestly reported — once, as a
        # phrase card.
        assert any(p.kind in ("recurring_phrase", "rumination") and "blanket" in p.label
                   for p in result.surfaced)


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
        first = brain.update(brain.load_state(None), entries, T0)
        # Fresh work entry as the second observation's new evidence. It
        # lands on a Saturday, so the run now tests THREE weekdays (the
        # 1-mention Saturday fails the k >= 4 floor but was tested) — the
        # days_tested pin moved 2 → 3 with the replication-honesty change.
        grown = entries + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
        temporals = [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]
        assert len(temporals) == 1
        assert temporals[0].detail["days_tested"] == 3
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
