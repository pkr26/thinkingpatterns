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
import random
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


def _jitter(i: int) -> float:
    """Deterministic +-0.05 wobble for test corpora (item 7: exactly
    constant groups carry no variance and now fail the Welch test
    closed — real corpora are never exactly constant)."""
    return 0.05 if i % 2 == 0 else -0.05


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
        entries = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        # Statistical kinds replicate before surfacing: candidate on first
        # qualification, emerging once the evidence accumulated since the
        # first qualification covers >= 2 NEW evidence days (item 5,
        # 2026-09-26: a single clustered mention is the same fluke shape
        # the gate exists to stop). A next-day recompute of the UNCHANGED
        # corpus is the same observation scored twice and never promotes.
        first = brain.update(brain.load_state(None), entries, T0)
        assert all(p.kind != "temporal" for p in first.surfaced)
        grown = entries + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=2)),
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
        )
        temporals = [p for p in result.surfaced if p.kind == "temporal"]
        assert any(t.label == "work" and t.detail["day"] == "Sunday" for t in temporals)

    def test_min_sample_floor(self):
        days = consecutive(T0 - timedelta(days=20), 21)
        entries = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
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
        # Work days spread across EVERY weekday (every third day): the mood
        # tie must be a same-day within-person association, not a weekly
        # cycle riding one weekday (item 1's deconfounding would absorb a
        # Sunday-only pattern — correctly).
        for i, d in enumerate(days):
            if i % 3 == 0:
                entries.append(JournalEntry("anxious about work", d))
            else:
                entries.append(JournalEntry(CALM, d))
        first = brain.update(brain.load_state(None), entries, T0)
        # Second qualification day: >= 2 fresh work-evidence days since the
        # first qualification (item 5).
        grown = entries + [
            JournalEntry("anxious about work", T0 + timedelta(days=1)),
            JournalEntry("anxious about work", T0 + timedelta(days=2)),
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
        )
        moods = [p for p in result.surfaced if p.kind == "mood_correlation"]
        work = next(p for p in moods if p.label == "work")
        assert work.detail["direction"] == "lower"
        assert work.detail["mood_delta"] >= brain.MOOD_MIN_DELTA
        assert abs(work.detail["cohens_d"]) >= brain.MOOD_MIN_EFFECT

    def test_flat_mood_makes_no_claim(self):
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [JournalEntry("work stuff and neutral words", d) for d in days]
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
        stable = [JournalEntry("ordinary day notes", e.entry_date, sentiment=0.3) for e in entries]
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
        return [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]

    def test_candidate_hidden_until_requalified(self):
        corpus = self._weak_corpus(T0)
        first = brain.update(brain.load_state(None), corpus, T0)
        assert all(p.kind != "temporal" for p in first.surfaced)
        assert dates_only(first.new_state).get("temporal:work") == "candidate"

        # Same-day re-run: still one qualification day, still hidden.
        rerun = brain.update(brain.load_state(brain.dump_state(first.new_state)), corpus, T0)
        assert dates_only(rerun.new_state).get("temporal:work") == "candidate"

        # A later run adds qualification days WITH >= 2 new evidence days
        # (fresh work entries; item 5) → emerging → surfaced. (The same run
        # on the unchanged corpus would stay a candidate: consecutive
        # recomputes of one window are one observation, not replication.)
        grown = corpus + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=4)),
        ]
        later = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=4)
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
        # statistical claim stays a candidate until it re-qualifies with
        # genuinely independent evidence (a noise fluke gets one day).
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        first = brain.update(brain.load_state(None), corpus, T0)
        assert dates_only(first.new_state).get("temporal:work") == "candidate"
        assert all(p.kind != "temporal" for p in first.surfaced)
        # Same-day recompute does NOT count as replication.
        rerun = brain.update(brain.load_state(brain.dump_state(first.new_state)), corpus, T0)
        assert dates_only(rerun.new_state).get("temporal:work") == "candidate"
        # Neither does a next-day recompute of the UNCHANGED corpus: no new
        # evidence day arrived, so there is no independent second
        # observation (the 2026-09 replication-honesty tightening).
        next_day = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), corpus, T0 + timedelta(days=1)
        )
        assert dates_only(next_day.new_state).get("temporal:work") == "candidate"
        # ONE fresh evidence day (a single additional clustered mention) is
        # STILL not enough (item 5, 2026-09-26): one new day is the same
        # fluke shape the gate exists to stop.
        grown_one = corpus + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1))]
        one_day = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown_one, T0 + timedelta(days=1)
        )
        assert dates_only(one_day.new_state).get("temporal:work") == "candidate"
        # A second qualification day that DOES bring >= 2 new evidence days
        # is a real replication → emerging → surfaced.
        grown_two = grown_one + [JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=2))]
        second = brain.update(
            brain.load_state(brain.dump_state(one_day.new_state)), grown_two, T0 + timedelta(days=2)
        )
        assert dates_only(second.new_state).get("temporal:work") == "emerging"
        assert any(p.kind == "temporal" for p in second.surfaced)

    def test_statistical_candidate_fades_to_archived_without_a_card(self):
        # A statistical claim that qualifies once and never again never
        # surfaces at all — not even as a "fading" card (that would be the
        # same single-run fluke wearing a sadder label).
        days = consecutive(T0 - timedelta(days=69), 70)
        corpus = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]
        aged = brain.update(
            brain.load_state(brain.dump_state(state)), quiet, T0 + timedelta(days=10)
        )
        assert dates_only(aged.new_state).get("temporal:work") == "archived"
        assert all(p.kind != "temporal" for p in aged.surfaced)

    def test_confirmed_by_age(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        # Second qualification with >= 2 fresh evidence days (item 5) —
        # the replication gate no longer promotes on an unchanged corpus.
        grown = corpus + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=4)),
        ]
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=4)
        ).new_state
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=25)
        ).new_state
        assert dates_only(state).get("temporal:work") == "confirmed"

    def test_fading_then_archived_then_dropped(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        # Re-qualify with >= 2 fresh evidence days so the pattern has
        # SURFACED (emerging) before the corpus goes quiet.
        grown = corpus + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=4)),
        ]
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=4)
        ).new_state  # emerging
        # The theme stops appearing entirely.
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]

        faded = brain.update(
            brain.load_state(brain.dump_state(state)), quiet, T0 + timedelta(days=12)
        )
        assert dates_only(faded.new_state).get("temporal:work") == "fading"
        fading_surfaced = [p for p in faded.surfaced if p.kind == "temporal" and p.label == "work"]
        assert fading_surfaced and faded.patterns_fading >= 1

        archived = brain.update(
            brain.load_state(brain.dump_state(faded.new_state)), quiet, T0 + timedelta(days=50)
        )
        assert dates_only(archived.new_state).get("temporal:work") == "archived"
        assert all(not (p.kind == "temporal" and p.label == "work") for p in archived.surfaced)

        dropped = brain.update(
            brain.load_state(brain.dump_state(archived.new_state)), quiet, T0 + timedelta(days=95)
        )
        assert "temporal:work" not in dropped.new_state["patterns"]

    def test_requalified_pattern_returns_to_emerging(self):
        corpus = self._weak_corpus(T0)
        state = brain.update(brain.load_state(None), corpus, T0).new_state
        grown = corpus + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=4)),
        ]
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=4)
        ).new_state
        quiet = [JournalEntry(CALM, e.entry_date) for e in corpus]
        faded = brain.update(
            brain.load_state(brain.dump_state(state)), quiet, T0 + timedelta(days=12)
        ).new_state
        # The theme returns with >= 2 NEW evidence days past the fading: a
        # statistical revival must replicate like a first promotion — it
        # cannot ride the stale evidence back in (item 5).
        returned = grown + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=13)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=14)),
        ]
        back = brain.update(
            brain.load_state(brain.dump_state(faded)), returned, T0 + timedelta(days=14)
        )
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
        # Re-qualify with >= 2 fresh evidence days so the (statistical)
        # pattern has SURFACED (emerging) before the corpus goes quiet — a
        # lone candidate archives silently instead (see the replication
        # gate).
        grown = corpus + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=2)),
        ]
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=2)
        ).new_state
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
        assert (
            brain.load_state(json.dumps({"v": 2, "patterns": {"x": 1}, "history": 7}).encode())[
                "patterns"
            ]
            == {}
        )

    def test_invalid_records_are_skipped_not_fatal(self):
        raw = json.dumps(
            {
                "v": 2,
                "patterns": {
                    "bad": "not a dict",
                    "evil": {
                        "kind": "temporal",
                        "label": "work",
                        "occurrences": {"shape": "that raises in int()"},
                    },
                    "good": {
                        "kind": "temporal",
                        "label": "work",
                        "occurrences": 9,
                        "state": "emerging",
                        "first_seen": "2026-08-01",
                        "last_seen": "2026-09-01",
                        "first_qualified": "2026-09-01",
                        "last_qualified": "2026-09-01",
                    },
                },
                "history": [],
            }
        ).encode()
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
        # Same corpus shape, but the work dip rides days spread across EVERY
        # weekday (every third day): a real within-person same-day tie the
        # de-trended AND weekday-deconfounded residuals must still find
        # (item 1: a dip confined to one weekday is a weekly cycle, not a
        # theme association — see TestWeeklyCycleDeconfounding below).
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for i, d in enumerate(days):
            mood = 0.4 if i < 35 else -0.6  # the trend
            is_work = i % 3 == 0
            if is_work:
                mood -= 0.5  # the same-day dip on top
            text = "big deadline pressure at work" if is_work else "ordinary day notes"
            entries.append(JournalEntry(text, d, sentiment=mood))
        first = brain.update(brain.load_state(None), entries, T0)
        # Two fresh (low) work days as the new evidence (item 5).
        grown = entries + [
            JournalEntry("big deadline pressure at work", T0 + timedelta(days=1), sentiment=-0.9),
            JournalEntry("big deadline pressure at work", T0 + timedelta(days=2), sentiment=-0.9),
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
        )
        moods = [p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "work"]
        assert moods and moods[0].detail["direction"] == "lower"

    def test_weekday_confounded_association_is_absorbed(self):
        """Item 1 (2026-09-26 review), regression A: a theme that appears
        ONLY on Mondays, on a globally-low Monday, must NOT surface a
        mood_correlation or link card — the per-weekday centering absorbs
        the shared rhythm. The temporal card may still fire (the theme IS
        a Monday thing); only the mood association is confounded."""
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = []
        for d in days:
            if d.weekday() == 0:  # Mondays only
                entries.append(JournalEntry("quiet morning some work", d, sentiment=-0.6))
            else:
                entries.append(JournalEntry("ordinary day notes", d, sentiment=0.3))
        state = brain.load_state(None)
        for k in range(4):  # replication room: fresh Mondays + following days
            grown = entries + [
                JournalEntry("quiet morning some work", T0 + timedelta(days=1 + j), sentiment=-0.6)
                if (T0 + timedelta(days=1 + j)).weekday() == 0
                else JournalEntry("ordinary day notes", T0 + timedelta(days=1 + j), sentiment=0.3)
                for j in range(k + 1)
            ]
            result = brain.update(
                brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=1 + k)
            )
            state = result.new_state
        assert all(
            not (p.kind == "mood_correlation" and p.label == "work") for p in result.surfaced
        )
        assert all(not (p.kind == "link" and p.label == "work") for p in result.surfaced)
        # The store itself must not even hold a qualified work mood claim.
        assert "mood_correlation:work" not in result.new_state["patterns"]

    def test_within_weekday_association_surfaces(self):
        """Item 1, regression B: 'work' on ~half the MONDAYS only, with the
        work-Mondays lower than the non-work Mondays — a genuine
        within-weekday contrast the deconfounding must PRESERVE (centering
        subtracts the Monday mean; work-Mondays sit below it, the others
        above)."""
        days = consecutive(T0 - timedelta(days=139), 140)  # 20 Mondays
        entries = []
        mondays = [d for d in days if d.weekday() == 0]
        work_mondays = set(mondays[::2])  # every other Monday
        for i, d in enumerate(days):
            # Jittered levels: a constant group carries zero actual
            # variance and the Welch test now fails CLOSED (item 7) — a
            # real corpus is never exactly constant.
            wobble = 0.08 if i % 2 == 0 else -0.08
            if d in work_mondays:
                entries.append(JournalEntry("quiet morning some work", d, sentiment=-0.7 + wobble))
            elif d.weekday() == 0:
                entries.append(JournalEntry("ordinary day notes", d, sentiment=0.2 + wobble))
            else:
                entries.append(JournalEntry("ordinary day notes", d, sentiment=0.3 + wobble))
        first = brain.update(brain.load_state(None), entries, T0)
        state = first.new_state
        result = first
        extras: list[JournalEntry] = []
        for k in range(4):  # fresh LOW WORK days accumulate (item 5: >= 2)
            extra_day = T0 + timedelta(days=1 + k)
            wobble = 0.08 if k % 2 == 0 else -0.08
            extras.append(
                JournalEntry("quiet morning some work", extra_day, sentiment=-0.7 + wobble)
            )
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries + extras, extra_day
            )
            state = result.new_state
            if any(p.kind == "mood_correlation" and p.label == "work" for p in result.surfaced):
                break
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
        # Candidate on first qualification; replication needs >= 2 NEW
        # outcome days (item 5) — extend the corpus with two fresh sleep
        # entries and their low day-afters.
        if not links:
            grown = entries + [
                JournalEntry(
                    "could not sleep, restless night", T0 + timedelta(days=1), sentiment=0.1
                ),
                JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.6),
                JournalEntry(
                    "could not sleep, restless night", T0 + timedelta(days=3), sentiment=0.1
                ),
                JournalEntry("ordinary day notes", T0 + timedelta(days=4), sentiment=-0.6),
            ]
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)), grown, T0 + timedelta(days=4)
            )
            links = [p for p in second.surfaced if p.kind == "link" and p.label == "sleep"]
        assert links and links[0].detail["direction"] == "lower"
        assert links[0].detail["lag_days"] == 1
        # Day-after phrasing (item 4): every exposure is gap-1, so the
        # strict-mode + 70% dominance gate holds.
        assert (
            links[0].detail["gap1_days"] >= brain.LINK_DAY_AFTER_SHARE * links[0].detail["n_after"]
        )

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
            mood = (
                0.05 + (0.5 if (i % 2 == 0 and i >= 45) else -0.5 if i >= 45 else 0.0)
                if i >= 45
                else 0.05 + (0.03 if i % 2 == 0 else -0.03)
            )
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
        assert brain.sentiment_score("feeling slightly bad today".split()) > brain.sentiment_score(
            "feeling bad today".split()
        )
        assert brain.sentiment_score("feeling extremely bad today".split()) < brain.sentiment_score(
            "feeling bad today".split()
        )

    def test_negation_is_damped_not_flipped(self):
        plain = brain.sentiment_score("happy today".split())
        negated = brain.sentiment_score("not happy today".split())
        assert negated < 0 < plain

    def test_but_shifts_weight_to_following_clause(self):
        assert brain.sentiment_score("great day but i feel awful".split()) < 0

    def test_magnitude_ordering(self):
        assert (
            brain.sentiment_score("devastated".split())
            < brain.sentiment_score("sad".split())
            < 0
            < brain.sentiment_score("happy".split())
            < brain.sentiment_score("amazing".split())
        )

    def test_absolutist_density(self):
        assert brain.absolutist_density(
            "it always fails and nothing works".split()
        ) > brain.absolutist_density("it sometimes fails".split())

    def test_kind_of_hedge_is_not_positive(self):
        # "kind" carried +1.9 and flipped hedged negatives positive.
        # (2026-09-17: with the VADER base merged in, "hard" now carries
        # its own mild negative valence — the pin is the INTENT: the hedge
        # stays non-positive, never flipped.)
        assert brain.sentiment_score("kind of hard today".split()) <= 0.0
        assert brain._word_valence("kind") == 0.0
        # The genuinely negative tail still reads negative.
        assert brain.sentiment_score("it was kind of awful".split()) < 0

    def test_fed_the_cat_is_neutral(self):
        # "fed" (-1.5) poisoned caretaking sentences; removed.
        assert brain.sentiment_score("i fed the cat this morning".split()) == 0.0

    def test_present_is_not_valenced(self):
        # Attendance/gift senses outnumber the mindful one; dropped. The
        # WORD itself carries no valence (2026-09-17: with VADER breadth,
        # other words in such sentences may score — the curation wins only
        # where it spoke).
        assert brain._word_valence("present") == 0.0
        assert brain.sentiment_score("present".split()) == 0.0

    def test_relaxed_is_positive_again(self):
        # v2 valence restored (the v3 lexicon claims v2 superset status).
        assert brain.sentiment_score("i felt relaxed all evening".split()) > 0

    def test_hardly_negates_without_double_apply(self):
        # "hardly"/"barely" were in BOTH the downtoners (0.7x) and the
        # negators, applying both rules; VADER treats them as negation
        # only, so they now score exactly like "not".
        assert brain.sentiment_score("it was hardly good".split()) == pytest.approx(
            brain.sentiment_score("it was not good".split())
        )
        assert brain.sentiment_score("i barely slept".split()) == pytest.approx(
            brain.sentiment_score("i didn't sleep".split())
        )


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
            pid="temporal:work",
            kind="temporal",
            label="work",
            first_seen="2026-06-01",
            last_seen="2026-08-30",
            first_qualified="2026-08-01",
            last_qualified="2026-08-30",
            occurrences=11,
            state="emerging",
            qualification_days=["2026-08-01", "2026-08-30"],
            evidence_dates=["2026-08-30"],
            feedback={},
            detail={"day": day_name, "day_count": 11, "p_value": 1e-6},
        )
        return store

    def _signal_for(self, day_name: str, day: date) -> brain._Signal:
        return brain._Signal(
            pid="temporal:work",
            kind="temporal",
            label="work",
            occurrences=11,
            pvalue=1e-6,
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

    def test_repeated_flip_reuses_the_matching_fork(self):
        # 2026-09-20 audit H-11: detectors always emit the base pid and the
        # base record's semantic detail froze at the first flip, so every
        # LATER run flipped again — minting ~3, ~4, ~11 …, each holding one
        # qualification day, never surfacing, churning the store. A fork
        # whose stored semantic detail matches the incoming signal IS the
        # claim: it must be reused, not re-forked.
        store = self._store_with_temporal("Sunday")
        brain._merge_lifecycle(store, [self._signal_for("Wednesday", T0)], T0)
        day2 = T0 + timedelta(days=1)
        brain._merge_lifecycle(store, [self._signal_for("Wednesday", day2)], day2)
        pats = store["patterns"]
        # No ~3 was minted: exactly the retired base and the one fork.
        assert set(pats) == {"temporal:work", "temporal:work~2"}
        fork = pats["temporal:work~2"]
        assert fork.detail["day"] == "Wednesday"
        assert fork.qualification_days == [T0.isoformat(), day2.isoformat()]

    def test_opposite_flip_still_mints_a_distinct_fork(self):
        # Reuse must be SEMANTIC: a flip to a third weekday is a new claim
        # and still earns its own fork.
        store = self._store_with_temporal("Sunday")
        brain._merge_lifecycle(store, [self._signal_for("Wednesday", T0)], T0)
        day2 = T0 + timedelta(days=1)
        brain._merge_lifecycle(store, [self._signal_for("Friday", day2)], day2)
        pats = store["patterns"]
        assert "temporal:work~2" in pats and "temporal:work~3" in pats
        assert pats["temporal:work~2"].detail["day"] == "Wednesday"
        assert pats["temporal:work~3"].detail["day"] == "Friday"

    def test_stale_candidate_archives_never_fades(self):
        # 2026-09-20 audit M-9: a candidate that never surfaced must not
        # become a user-visible "fading" card when it stops qualifying —
        # weak signals stay hidden and archive quietly, whatever the kind.
        store = self._store_with_temporal("Sunday")
        rec = store["patterns"]["temporal:work"]
        rec.state = "candidate"
        rec.last_qualified = (T0 - timedelta(days=30)).isoformat()
        brain._merge_lifecycle(store, [], T0)
        assert store["patterns"]["temporal:work"].state == "archived"

    def test_engine_level_weekday_flip(self):
        # Phase A: work on Sundays → temporal:work emerges. Then the journal
        # is rewritten with work on Wednesdays instead: the recompute flips.
        days = consecutive(T0 - timedelta(days=69), 70)
        sundays = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        state = brain.update(brain.load_state(None), sundays, T0).new_state
        # Emerging needs >= 2 new evidence days since the first
        # qualification (item 5).
        grown = sundays + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=2)),
        ]
        state = brain.update(
            brain.load_state(brain.dump_state(state)), grown, T0 + timedelta(days=2)
        ).new_state
        assert dates_only(state).get("temporal:work") == "emerging"
        wednesdays = [JournalEntry(NEUTRAL_WORK if d.weekday() == 2 else CALM, d) for d in days]
        flipped = brain.update(
            brain.load_state(brain.dump_state(state)), wednesdays, T0 + timedelta(days=3)
        )
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
        workdays = (
            [d for d in days if d.weekday() == 0][:4]
            + [d for d in days if d.weekday() == 1][:3]
            + [d for d in days if d.weekday() == 2][:3]
        )
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
        signals = [
            s
            for s in brain._detect_themes(residual_per, weekday_total, len(entries))
            if s.pid == "temporal:work"
        ]
        assert len(signals) == 3  # all three weekdays tested
        by_day = {s.detail["day"]: s for s in signals}
        assert by_day["Monday"].gate_ok is True  # k=4, fraction 0.4
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
        weekday_total = {
            d.weekday(): sum(1 for e in entries if e.entry_date.weekday() == d.weekday())
            for d in days
        }
        signals = [
            s
            for s in brain._detect_themes(residual_per, weekday_total, len(entries))
            if s.pid == "mood_correlation:work"
        ]
        assert len(signals) == 1
        assert signals[0].pvalue is not None
        assert signals[0].gate_ok is False  # |delta| ~ 0.15 < MOOD_MIN_DELTA

    def test_pure_noise_surfaces_no_statistical_cards(self):
        # The audit's FDR finding as a regression: a seeded pure-noise
        # corpus (theme words sprinkled at random, sentiment independent
        # of text) must not surface ANY statistical card in one shot.
        import random

        filler = (
            "walked home past the library and the old mill afterwards",
            "washed the dishes and folded the laundry slowly",
            "watered the balcony plants and trimmed the basil",
        )
        theme_words = (
            "work boss deadline",
            "sleep tired bed",
            "friend party lonely",
            "family mom dad",
            "gym doctor headache",
            "money rent salary",
            "school exam homework",
            "food dinner cook",
            "rain sunny storm",
        )
        for seed in (11, 22, 33):
            rng = random.Random(seed)
            entries = []
            start = T0 - timedelta(days=83)
            for i in range(84):
                if rng.random() < 0.85:
                    parts = [rng.choice(filler)]
                    parts.extend(rng.choice(theme_words).split()[0] for _ in range(2))
                    rng.shuffle(parts)
                    entries.append(
                        JournalEntry(
                            ". ".join(parts),
                            start + timedelta(days=i),
                            sentiment=round(rng.uniform(-0.6, 0.6), 3),
                        )
                    )
            result = brain.update(brain.load_state(None), entries, T0)
            stat_cards = [p for p in result.surfaced if p.kind in brain.STATISTICAL_KINDS]
            assert stat_cards == [], f"seed {seed}: false statistical cards {stat_cards}"
            stored_stat = [
                pid
                for pid, rec in result.new_state["patterns"].items()
                if rec.kind in brain.STATISTICAL_KINDS and rec.state != "candidate"
            ]
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

        filler = (
            "walked home past the library and the old mill afterwards",
            "washed the dishes and folded the laundry slowly",
            "watered the balcony plants and trimmed the basil",
            "sorted the mail and stacked the newspapers neatly",
        )
        theme_words = (
            "work boss deadline",
            "sleep tired bed",
            "friend party lonely",
            "family mom dad",
            "gym doctor headache",
            "money rent salary",
            "school exam homework",
            "food dinner cook",
            "rain sunny storm",
        )
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
                    entries.append(
                        JournalEntry(
                            ". ".join(parts),
                            start + timedelta(days=i),
                            sentiment=round(rng.uniform(-0.6, 0.6), 3),
                        )
                    )
            state = brain.load_state(None)
            run_cards: set[str] = set()
            for k in range(14):
                today = T0 - timedelta(days=13 - k)
                known = [e for e in entries if e.entry_date <= today]
                result = brain.update(state, known, today)
                state = result.new_state
                run_cards.update(
                    f"{p.kind}:{p.label}"
                    for p in result.surfaced
                    if p.kind in brain.STATISTICAL_KINDS
                )
            runs_with_cards += bool(run_cards)
        assert runs_with_cards <= 1, (
            f"{runs_with_cards}/24 daily-cadence noise runs surfaced false statistical cards"
        )


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
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert all(rec.kind != "inertia" for rec in state["patterns"].values())


class TestLinkGapLabeling:
    @staticmethod
    def _skip_gap_corpus(skip_mod: int, skip_residues: tuple[int, ...]) -> list[JournalEntry]:
        """A link corpus whose gap mix comes from JOURNALING SKIPS, not a
        weekday-locked schedule: 'sleep' every 5th day (crossing all
        weekdays), the outcome day reads low, and for the sleep
        occurrences whose index k = i//5 satisfies k % skip_mod in
        skip_residues the user skips the immediate next day — that
        outcome then lands gap 2. Item 1's weekday deconfounding absorbs
        a weekday-locked dip (correctly), so a gap-labeling fixture must
        vary the exposure/outcome weekdays.
        """
        days = list(consecutive(T0 - timedelta(days=69), 70))
        written: dict = {}
        for i, d in enumerate(days):
            if i % 5 == 0:
                written[d] = ("could not sleep, restless night", 0.1 + _jitter(i))
                if (i // 5) % skip_mod in skip_residues and i + 1 < len(days):
                    days[i + 1] = None
        days = [d for d in days if d is not None]
        entries = []
        for i, d in enumerate(days):
            if d in written:
                text, mood = written[d]
            else:
                text = "ordinary day notes"
                mood = 0.1 + _jitter(i)
            entries.append(JournalEntry(text, d, sentiment=mood))
        # Outcomes: the written day right after each sleep entry reads low.
        out: list[JournalEntry] = []
        for i, e in enumerate(entries):
            if e.text.startswith("could not sleep") and i + 1 < len(entries):
                nxt = entries[i + 1]
                out.append(
                    JournalEntry("ordinary day notes", nxt.entry_date, sentiment=-0.6 + _jitter(i))
                )
        by_day = {x.entry_date: x for x in out}
        return [by_day.get(e.entry_date, e) for e in entries]

    def test_gap2_links_report_the_modal_gap(self):
        # Most sleep days are followed by a skipped day, so the modal
        # exposed gap is 2. The claim must say so — never "the day after".
        # 10 of 14 sleep days are followed by a skipped day -> the modal
        # exposed gap is 2.
        entries = self._skip_gap_corpus(skip_mod=4, skip_residues=(1, 2, 3))
        state = brain.load_state(None)
        link = None
        # The second run extends the corpus with fresh sleep evidence and
        # low outcome days: replication needs >= 2 NEW outcome days
        # (item 5).
        grown = entries + [
            JournalEntry("could not sleep, restless night", T0 + timedelta(days=1), sentiment=0.1),
            JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.6),
            JournalEntry("could not sleep, restless night", T0 + timedelta(days=3), sentiment=0.1),
            JournalEntry("ordinary day notes", T0 + timedelta(days=4), sentiment=-0.6),
        ]
        for offset, current in ((0, entries), (4, grown)):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), current, T0 + timedelta(days=offset)
            )
            state = result.new_state
            link = next(
                (p for p in result.surfaced if p.kind == "link" and p.label == "sleep"), None
            )
            if link is not None:
                break
        assert link is not None
        assert link.detail["direction"] == "lower"
        assert link.detail["lag_days"] == 2  # modal gap, honestly reported
        assert link.detail["gap2_days"] > link.detail["gap1_days"]
        assert "days after" in link.describe()  # gap-aware copy
        assert "day after '" not in link.describe()

    def test_mixed_gap_majority_never_says_day_after(self):
        """Item 4 (2026-09-26 review): a gap mix where gap-1 is the mode but
        NOT a >= 70% majority must render the lag-generic copy. The old
        tie-break (gap1 >= gap2) printed 'the day after' for such a
        mixture, overstating the precision of the lag. Corpus: 5 of 14
        sleep days are followed by a skipped day (gap-2), the rest land
        gap-1 — gap-1 leads at ~64%, far short of the 70% dominance
        bar."""
        entries = self._skip_gap_corpus(skip_mod=3, skip_residues=(0,))
        state = brain.load_state(None)
        grown = entries + [
            JournalEntry("could not sleep, restless night", T0 + timedelta(days=1), sentiment=0.1),
            JournalEntry("ordinary day notes", T0 + timedelta(days=2), sentiment=-0.6),
            JournalEntry("could not sleep, restless night", T0 + timedelta(days=3), sentiment=0.1),
            JournalEntry("ordinary day notes", T0 + timedelta(days=4), sentiment=-0.6),
        ]
        link = None
        for offset, current in ((0, entries), (4, grown)):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), current, T0 + timedelta(days=offset)
            )
            state = result.new_state
            link = next(
                (p for p in result.surfaced if p.kind == "link" and p.label == "sleep"), None
            )
            if link is not None:
                break
        assert link is not None, "the mixed-gap corpus must still surface the link"
        gap1, gap2 = link.detail["gap1_days"], link.detail["gap2_days"]
        n_after = link.detail["n_after"]
        assert gap1 > gap2, "fixture check: gap-1 must (barely) lead the mix"
        assert gap1 < brain.LINK_DAY_AFTER_SHARE * n_after, "fixture check: not a 70% majority"
        assert link.detail["lag_days"] == 2  # honest lag-generic copy
        assert "days after" in link.describe()
        assert "day after '" not in link.describe()


class TestReplicationGateCoversEveryInferenceKind:
    """2026-09-20 audit H-9: the newer statistical kinds (and rising-topic
    claims) were bypassing the replication gate — they surfaced on their
    FIRST qualification, exactly the single-run-fluke surfacing the gate
    exists to stop. These pins keep every inference kind inside the gate
    (the seeded-noise suites above count them in their bounds now that
    they share STATISTICAL_KINDS)."""

    def test_every_inference_kind_is_gated(self):
        for kind in (
            "cadence",
            "avoidance",
            "energy_inertia",
            "pa_inertia",
            "na_inertia",
            "energy_mood_coupling",
            "sense_making",
            "activity_diversity",
            "temporal",
            "mood_correlation",
            "link",
            "inertia",
            "instability",
            "mood_shift",
        ):
            assert kind in brain.STATISTICAL_KINDS, kind
            assert kind in brain.EVIDENCE_DATE_KINDS | brain.WINDOW_STAT_KINDS, kind

    def test_rising_topics_are_gated_steady_ones_are_not(self):
        assert brain._is_statistical("topic", {"trend": "rising", "presence": True})
        assert not brain._is_statistical("topic", {"trend": "steady", "presence": True})
        # Direct-measurement phrase kinds keep first-qualification surfacing.
        assert not brain._is_statistical("rumination", {})
        assert not brain._is_statistical("recurring_phrase", {})


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
        if not topics:
            # Candidate on first qualification. Rising trends are
            # p-value-tested INFERENCES (audit H-9), so promotion needs
            # >= 2 genuinely NEW evidence days (item 5) — two more recent
            # guitar entries — not just a second calendar day over the
            # same corpus.
            corpus = self._corpus(T0) + [
                JournalEntry(
                    "practiced the guitar after dinner, new chord shapes",
                    T0 + timedelta(days=1),
                ),
                JournalEntry(
                    "played the guitar before breakfast, warmups",
                    T0 + timedelta(days=2),
                ),
            ]
            second = brain.update(
                brain.load_state(brain.dump_state(result.new_state)),
                corpus,
                T0 + timedelta(days=2),
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
        entries = [JournalEntry("really just kind of a day, today was today", d) for d in days]
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
                brain.load_state(brain.dump_state(result.new_state)),
                entries,
                T0 + timedelta(days=1),
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
        assert all(
            not (p.kind == "topic" and p.label == "greenhouse")
            for p in result.new_state["patterns"].values()
        )

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
        assert all(
            not (p.kind == "topic" and p.label == "blanket")
            for p in result.new_state["patterns"].values()
        )
        # The boilerplate itself is still honestly reported — once, as a
        # phrase card.
        assert any(
            p.kind in ("recurring_phrase", "rumination") and "blanket" in p.label
            for p in result.surfaced
        )


class TestAuditFixes:
    """Regressions from the independent audit of the v3 work."""

    def test_multiple_weekday_candidates_yield_one_pattern(self):
        # A1: 'work' concentrated on TWO weekdays (Mondays and Sundays).
        # Every candidate enters the BH family; only the best SURVIVOR
        # becomes the pattern — exactly one timing claim per theme.
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [JournalEntry(NEUTRAL_WORK if d.weekday() in (0, 6) else CALM, d) for d in days]
        first = brain.update(brain.load_state(None), entries, T0)
        # >= 2 fresh work entries as the replication's new evidence (item
        # 5). They land on Saturday and Monday... T0+1 is a Saturday, so
        # the run tests THREE weekdays (the 1-mention Saturday fails the
        # k >= 4 floor but was tested).
        # T0 is a Friday: T0+1 lands on a Saturday and T0+3 on a Monday,
        # so the fresh evidence neither creates a new dominant weekday nor
        # flips the stored claim's semantics.
        grown = entries + [
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=1)),
            JournalEntry(NEUTRAL_WORK, T0 + timedelta(days=3)),
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=3)
        )
        temporals = [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]
        assert len(temporals) == 1
        assert temporals[0].detail["days_tested"] >= 3
        # The concrete winner, pinned by value (2026-09-26 test-infrastructure
        # audit, item 7 — this used to read day_count == max(day_count, 10),
        # a tautology that could never fail). The calendar is FIXED: T0 is a
        # Friday, the 70-day window holds 10 Mondays/10 Sundays/10 Saturdays,
        # and the fresh evidence adds one Monday (T0+3) and one Saturday
        # (T0+1) — so the strongest candidate is Monday at 11 mentions.
        assert temporals[0].detail["day"] == "Monday"
        assert temporals[0].detail["day_count"] == 11

    def test_nonfinite_client_sentiment_falls_back_to_text(self):
        # A2: a NaN mood tag must poison nothing — the engine re-scores
        # the entry's text instead.
        days = consecutive(T0 - timedelta(days=29), 30)
        entries = [
            JournalEntry("felt calm and grateful today", d, sentiment=float("nan")) for d in days
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


# --- per-pattern mute + the energy channel (2026-09-19) ---------------------------


def _inertia_corpus(channel_values):
    """70 days whose RECENT window carries multi-day mood/energy blocks and
    whose earlier window alternates — rising carryover on whichever channel
    the values are placed on."""
    entries = []
    for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
        if i >= 42:
            value = 0.4 if (i // 4) % 2 == 0 else -0.4
        else:
            value = 0.3 if i % 2 == 0 else -0.3
        entries.append(channel_values(value, d))
    return entries


def _surface_inertia(entries, muted=None, unmuted=None, kinds=("inertia", "energy_inertia")):
    """Run update() over consecutive days until an inertia claim surfaces
    (the replication gate needs two qualification days; the window slides,
    so the recent-window correlation wobbles across the gate)."""
    state = brain.load_state(None)
    for k in range(5):
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=k),
            muted=muted,
            unmuted=unmuted,
        )
        state = result.new_state
        if any(p.kind in kinds for p in result.surfaced):
            return state, result
    raise AssertionError("inertia never surfaced")


class TestEnergyInertia:
    def test_rising_energy_carryover_surfaces_with_channel_marker(self):
        entries = _inertia_corpus(
            lambda value, d: JournalEntry("ordinary day notes", d, energy=value)
        )
        state, result = _surface_inertia(entries)
        energy_claims = [p for p in result.surfaced if p.kind == "energy_inertia"]
        assert energy_claims, "rising energy carryover must surface"
        claim = energy_claims[0]
        assert claim.detail.get("channel") == "energy"
        assert claim.detail.get("pattern_pid") == "inertia:energy"
        assert isinstance(claim.detail.get("p_value"), float)
        # The copy is the energy axis, never the mood axis.
        assert "energy" in claim.describe()

    def test_energy_claims_absent_without_energy_data(self):
        entries = _inertia_corpus(
            lambda value, d: JournalEntry("ordinary day notes", d, sentiment=value)
        )
        state, result = _surface_inertia(entries)
        assert [p for p in result.surfaced if p.kind == "energy_inertia"] == []
        assert [p for p in result.surfaced if p.kind == "inertia"], "mood inertia still fires"

    def test_energy_and_mood_surface_with_distinct_pids(self):
        # Identical values on both channels: both claims exist in the store
        # under their own pids (they may qualify on different sliding days).
        entries = _inertia_corpus(
            lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v, energy=v)
        )
        state = brain.load_state(None)
        surfaced_kinds: set[str] = set()
        for k in range(6):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
            surfaced_kinds |= {p.kind for p in result.surfaced}
        assert "inertia" in surfaced_kinds
        assert "energy_inertia" in surfaced_kinds
        assert "inertia:mood" in state["patterns"]
        assert "inertia:energy" in state["patterns"]


class TestPatternMute:
    def test_mute_flags_the_card_and_orders_it_after_live_cards(self):
        entries = _inertia_corpus(lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v))
        state, result = _surface_inertia(entries)
        pid = "inertia:mood"
        assert any(p.detail.get("pattern_pid") == pid for p in result.surfaced)

        muted_result = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=5),
            muted=[pid],
        )
        muted_cards = [p for p in muted_result.surfaced if p.detail.get("pattern_pid") == pid]
        assert muted_cards and muted_cards[0].detail.get("muted") is True
        # Muted cards surface AFTER every live card — they never displace.
        live_indexes = [i for i, p in enumerate(muted_result.surfaced) if not p.detail.get("muted")]
        for i, p in enumerate(muted_result.surfaced):
            if p.detail.get("muted"):
                assert live_indexes == [] or i > max(live_indexes)
        # A muted pattern never counts as "new".
        assert all(
            not p.detail.get("is_new") for p in muted_result.surfaced if p.detail.get("muted")
        )

    def test_unmute_restores_the_live_card(self):
        entries = _inertia_corpus(lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v))
        state, _ = _surface_inertia(entries)
        muted = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=5),
            muted=["inertia:mood"],
        )
        restored = brain.update(
            brain.load_state(brain.dump_state(muted.new_state)),
            entries,
            T0 + timedelta(days=6),
            unmuted=["inertia:mood"],
        )
        cards = [p for p in restored.surfaced if p.detail.get("pattern_pid") == "inertia:mood"]
        assert cards and "muted" not in cards[0].detail

    def test_mute_survives_the_state_roundtrip(self):
        entries = _inertia_corpus(lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v))
        state, _ = _surface_inertia(entries)
        muted = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=5),
            muted=["inertia:mood"],
        )
        # dump→load is also update()'s copy-on-entry path: a mute forgotten
        # here would vanish on the very next recompute.
        reloaded = brain.load_state(brain.dump_state(muted.new_state))
        assert reloaded["muted"] == {"inertia:mood": True}

    def test_unknown_pid_mute_is_ignored(self):
        entries = _inertia_corpus(lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v))
        state, _ = _surface_inertia(entries)
        result = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=5),
            muted=["totally:unknown"],
        )
        assert result.new_state.get("muted") in (None, {})

    def test_questions_never_quote_a_muted_pattern(self):
        from app.services import questions

        entries = _inertia_corpus(lambda v, d: JournalEntry("ordinary day notes", d, sentiment=v))
        state, _ = _surface_inertia(entries)
        muted_result = brain.update(
            brain.load_state(brain.dump_state(state)),
            entries,
            T0 + timedelta(days=5),
            muted=["inertia:mood"],
        )
        pool = questions.build_pool(muted_result.surfaced)
        assert pool, "generic questions still fill the pool"
        assert all("carrying over from day to day" not in q for q in pool), (
            "a muted pattern's templates must never become the day's question"
        )


# --- PA/NA split + energy-mood coupling (2026-09-19 wave 2) ----------------------


class TestSentimentComponents:
    def test_components_sum_by_sign_and_match_the_compound_direction(self):
        tokens = "felt happy and calm but tired".split()
        pa, na = brain.sentiment_components(tokens)
        assert pa > 0 and na > 0  # both streams present in mixed text
        compound = brain.sentiment_score(tokens)
        assert (compound > 0 and pa > na) or (compound < 0 and na > pa) or compound == 0

    def test_pure_positive_and_pure_negative(self):
        pa, na = brain.sentiment_components("wonderful great day".split())
        assert pa > 0 and na == 0
        pa, na = brain.sentiment_components("terrible awful day".split())
        assert pa == 0 and na > 0

    def test_neutral_text_has_no_components(self):
        assert brain.sentiment_components("ordinary day notes".split()) == (0.0, 0.0)

    def test_walk_refactor_left_the_compound_byte_identical(self):
        # The accumulation was extracted into _valence_walk; the compound
        # must not have moved. Spot-check shapes the old engine pinned.
        cases = [
            "i am happy today",
            "i am not happy today",
            "felt happy and calm but tired",
            "extremely bad no good very anxious",
            "quiet day, some work in the afternoon",
        ]
        for text in cases:
            tokens = text.split()
            walk = brain._valence_walk(tokens)
            expected = max(-1.0, min(1.0, sum(walk) / brain.SENTIMENT_SCALE)) if walk else 0.0
            assert brain.sentiment_score(tokens) == pytest.approx(expected)


class TestPanaInertia:
    def _pana_corpus(self, pos: str, neg: str):
        """Blocks in the recent window vs alternation earlier, expressed
        through TEXT (sentiment words) so the PA/NA split has real input."""
        entries = []
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if i >= 42:
                text = pos if (i // 4) % 2 == 0 else neg
            else:
                text = pos if i % 2 == 0 else neg
            entries.append(JournalEntry(text, d))
        return entries

    def test_rising_negative_affect_carryover_surfaces(self):
        entries = self._pana_corpus("a calm and grateful day", "an anxious tired day")
        state = brain.load_state(None)
        na_surfaced = False
        for k in range(6):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
            if any(p.kind == "na_inertia" for p in result.surfaced):
                na_surfaced = True
                break
        assert na_surfaced, "rising negative-affect carryover must surface"

    def test_pa_and_na_pids_are_distinct_from_the_compound(self):
        entries = self._pana_corpus("a calm and grateful day", "an anxious tired day")
        state = brain.load_state(None)
        for k in range(6):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert "inertia:pa" in state["patterns"] or "inertia:na" in state["patterns"]

    def test_no_sentiment_words_no_pana_claims(self):
        entries = [
            JournalEntry("ordinary day notes", d, sentiment=None)
            for d in consecutive(T0 - timedelta(days=69), 70)
        ]
        state = brain.load_state(None)
        for k in range(3):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert "inertia:pa" not in state["patterns"]
        assert "inertia:na" not in state["patterns"]

    def test_mood_tag_overrides_do_not_feed_pana(self):
        # The explicit check-in is one valence judgment; the PA/NA streams
        # stay text-only even when every entry carries an override.
        entries = [
            JournalEntry("ordinary day notes", d, sentiment=0.4 if (i // 4) % 2 == 0 else -0.4)
            for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70))
        ]
        state = brain.load_state(None)
        for k in range(3):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert "inertia:pa" not in state["patterns"]
        assert "inertia:na" not in state["patterns"]


class TestEnergyMoodCoupling:
    def _coupled_corpus(self):
        """Energy and mood residuals move together in the recent window
        (blocks) and independently earlier (mood alternates while energy
        holds steady — near-zero cross-correlation)."""
        entries = []
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if i >= 42:
                mood = 0.4 if (i // 4) % 2 == 0 else -0.4
                energy = mood  # concordant recent window
            else:
                mood = 0.3 if i % 2 == 0 else -0.3
                energy = 0.05  # steady: no cross-correlation
            entries.append(JournalEntry("ordinary day notes", d, sentiment=mood, energy=energy))
        return entries

    def test_rising_coupling_surfaces_with_cross_channel_marker(self):
        entries = self._coupled_corpus()
        state = brain.load_state(None)
        coupled = None
        for k in range(6):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
            coupled = next((p for p in result.surfaced if p.kind == "energy_mood_coupling"), None)
            if coupled:
                break
        assert coupled is not None, "rising energy-mood coupling must surface"
        assert coupled.detail.get("channel") == "energy_mood"
        assert coupled.detail.get("pattern_pid") == "coupling:energy_mood"
        assert isinstance(coupled.detail.get("p_value"), float)
        assert "energy and your mood" in coupled.describe()

    def test_uncoupled_channels_stay_quiet(self):
        # Energy blocks and mood blocks with OFFSET periods: correlation
        # near zero in BOTH windows — nothing to claim.
        entries = []
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            mood = 0.4 if (i // 4) % 2 == 0 else -0.4
            energy = 0.4 if ((i + 2) // 4) % 2 == 0 else -0.4
            entries.append(JournalEntry("ordinary day notes", d, sentiment=mood, energy=energy))
        state = brain.load_state(None)
        for k in range(4):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert "coupling:energy_mood" not in state["patterns"]

    def test_missing_energy_channel_no_coupling_claim(self):
        entries = [
            JournalEntry("ordinary day notes", d, sentiment=0.3 if i % 2 == 0 else -0.3)
            for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70))
        ]
        state = brain.load_state(None)
        for k in range(3):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
        assert "coupling:energy_mood" not in state["patterns"]


# --- sense-making + activity diversity (2026-09-19 wave 3) -----------------------


class TestSenseMaking:
    SENSEY_A = (
        "i realize the reason i felt tense was the meeting, because i "
        "understand now that the deadline caused it and i notice why"
    )
    SENSEY_B = (
        "i realize the reason i felt tense was the meeting, because i "
        "understand now that the deadline caused it and i notice why, "
        "and later the walk helped"
    )

    def _corpus(self, recent_sense: bool):
        """Dense causal/insight phrasing in the recent window (or not),
        plain narrative earlier — density measured per 100 tokens. Two
        alternating sense-heavy variants: the recent side must carry REAL
        spread (item 7, 2026-09-26: a constant group's zero actual
        variance now fails the Welch test closed instead of riding the
        measurement-noise floor)."""
        plain = "we went to the market and i saw a friend there and walked home"
        entries = []
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if recent_sense and i >= 42:
                text = self.SENSEY_A if i % 2 == 0 else self.SENSEY_B
            else:
                text = plain
            entries.append(JournalEntry(text, d))
        return entries

    def _surface(self, entries, growing_texts: list[str]):
        # The replication gate (audit H-9) applies to sense_making: the
        # evidence accumulated since the first qualification must cover
        # >= 2 new high-density days (item 5), so every iteration appends
        # one fresh same-shape entry instead of re-scoring the same corpus
        # on a later calendar day.
        state = brain.load_state(None)
        result = None
        growing: list[JournalEntry] = []
        for k in range(6):
            day = T0 + timedelta(days=k)
            growing.append(JournalEntry(growing_texts[k % len(growing_texts)], day))
            result = brain.update(
                brain.load_state(brain.dump_state(state)),
                entries + growing,
                day,
            )
            state = result.new_state
            found = next((p for p in result.surfaced if p.kind == "sense_making"), None)
            if found:
                return state, result, found
        return state, result, None

    def test_rising_sense_making_density_surfaces(self):
        state, result, found = self._surface(
            self._corpus(recent_sense=True), [self.SENSEY_A, self.SENSEY_B]
        )
        assert found is not None, "rising sense-making density must surface"
        assert found.detail.get("direction") == "higher"
        assert found.detail.get("density_recent", 0) > found.detail.get("density_earlier", 99)
        assert "sense-making words" in found.describe()

    def test_flat_density_stays_quiet(self):
        plain = "we went to the market and i saw a friend there and walked home"
        plain_b = plain + " and the sky was clear"
        state, result, found = self._surface(self._corpus(recent_sense=False), [plain, plain_b])
        assert found is None, "no change in density means no claim"

    def test_short_entries_are_not_measured(self):
        assert brain._sense_density(["tiny", "note"]) is None
        assert brain._sense_density(["because"] * 10) == 100.0


class TestActivityDiversity:
    """Item 3 (2026-09-26 review) semantics: Miller-Madow-corrected weekly
    entropy over weeks that clear the volume floor (>= 2 distinct tagged
    days AND >= 2 distinct tags); DIVERSITY_MIN_WEEKS per window side."""

    # Tags rotate through a 12-tag pool so NO single tag reaches the
    # TEMPORAL_MIN_N theme floor: every tag above that floor rides the
    # theme machinery and adds junk weekday/mood tests to the
    # Benjamini-Hochberg family — and with DIVERSITY_VARIANCE_FLOOR
    # bounding the achievable significance from below, an honest
    # diversity claim cannot top a crowded family (the correction is the
    # honest verdict; the fixture simply keeps the family clean).
    SPREAD_POOL = tuple(f"tag{i:02d}" for i in range(12))

    def _corpus(self, narrow_recent: bool):
        """Monday-aligned weeks: ~6 full-pool weeks (high entropy), then
        narrow weeks — a weekly two-tag pair at ~50/50 (narrowing but
        still measurable: a one-tag week is EXCLUDED from the sample by
        the volume floor, not scored as zero entropy). narrow_recent
        False keeps the pool rotation throughout (no claim)."""
        start = T0 - timedelta(days=67)  # a Monday
        days = [start + timedelta(days=i) for i in range((T0 - start).days + 1)]
        entries = []
        for i, d in enumerate(days):
            week = (d - timedelta(days=d.weekday())).toordinal()
            if narrow_recent and d >= date(2026, 8, 10):
                pair = self.SPREAD_POOL[2 * (week % 5) : 2 * (week % 5) + 2]
                tags = (pair[i % 2],)
            else:
                # Alternate weekly between a full 7-tag rotation and a
                # 3-tag rotation: weekly entropies genuinely vary — an
                # exactly-constant earlier side carries no variance and
                # fails Welch closed (item 7).
                if week % 2 == 0:
                    tags = (self.SPREAD_POOL[(i + 3 * (week // 7)) % len(self.SPREAD_POOL)],)
                else:
                    tags = (self.SPREAD_POOL[3 * (i % 3) + (week % 3)],)
            entries.append(JournalEntry("ordinary day notes", d, tags=tags))
        return entries

    def _pair_tags(self, day: date, k: int) -> tuple[str, ...]:
        """The narrow-phase tag schedule for extension days."""
        week = (day - timedelta(days=day.weekday())).toordinal()
        pair = self.SPREAD_POOL[2 * (week % 5) : 2 * (week % 5) + 2]
        return (pair[k % 2],)

    def test_narrowing_variety_is_detected_with_direction(self):
        """Detector level (item 3): the narrowing corpus yields a
        Miller-Madow-corrected claim with the honest direction and a
        recent/earlier entropy gap. (Surfacing additionally requires the
        claim to top the run's Benjamini-Hochberg family and replicate on
        >= 2 new qualifying WEEKS — the lifecycle bar is pinned directly
        below, and for evidence-date kinds generally by the temporal
        replication tests.)"""
        entries = self._corpus(narrow_recent=True)
        extension = [
            JournalEntry(
                "ordinary day notes",
                T0 + timedelta(days=k),
                tags=self._pair_tags(T0 + timedelta(days=k), k),
            )
            for k in range(8)
        ]
        td: dict[str, set] = {}
        for e in entries + extension:
            for t in e.tags:
                td.setdefault(t, set()).add(e.entry_date)
        sig = brain._detect_activity_diversity(td, T0 + timedelta(days=7))
        assert sig is not None, "narrowing activity variety must be measured"
        assert sig.gate_ok is True
        assert sig.detail.get("direction") == "narrowed"
        assert sig.detail.get("entropy_recent", 9) < sig.detail.get("entropy_earlier", 0)
        assert sig.pvalue is not None and sig.pvalue < 0.05

    def test_diversity_replication_needs_two_new_weeks(self):
        """Item 5 at the lifecycle seam: a diversity candidate promotes
        only when the evidence accumulated since its FIRST qualification
        covers >= 2 new qualifying weeks; one new week is the same
        single-clustered-mention shape the gate exists to stop."""
        record = brain.StoredPattern(
            pid="diversity:activity_tags",
            kind="activity_diversity",
            label="activity variety",
            first_seen="2026-08-20",
            last_seen="2026-09-08",
            first_qualified="2026-09-08",
            last_qualified="2026-09-08",
            occurrences=4,
            state="candidate",
            qualification_days=["2026-09-08", "2026-09-15"],
            evidence_dates=["2026-08-24", "2026-08-31", "2026-09-07"],
            feedback={},
            detail={},
        )
        entries = self._corpus(narrow_recent=True)
        small_extension = [
            JournalEntry(
                "ordinary day notes",
                T0 + timedelta(days=k),
                tags=self._pair_tags(T0 + timedelta(days=k), k),
            )
            for k in range(8)
        ]
        td_small: dict[str, set] = {}
        for e in entries + small_extension:
            for t in e.tags:
                td_small.setdefault(t, set()).add(e.entry_date)
        one_new = brain._detect_activity_diversity(td_small, T0 + timedelta(days=7))
        assert one_new is not None
        assert one_new.evidence_days  # fixture check: real evidence exists
        assert sum(1 for d in one_new.evidence_days if d.isoformat() > "2026-09-08") <= 1
        assert not brain._replication_satisfied(record, one_new)
        big_extension = [
            JournalEntry(
                "ordinary day notes",
                T0 + timedelta(days=k),
                tags=self._pair_tags(T0 + timedelta(days=k), k),
            )
            for k in range(19)
        ]
        td_big: dict[str, set] = {}
        for e in entries + big_extension:
            for t in e.tags:
                td_big.setdefault(t, set()).add(e.entry_date)
        two_new = brain._detect_activity_diversity(td_big, T0 + timedelta(days=18))
        assert two_new is not None
        assert sum(1 for d in two_new.evidence_days if d.isoformat() > "2026-09-08") >= 2
        assert brain._replication_satisfied(record, two_new)

    def test_steady_variety_stays_quiet(self):
        entries = self._corpus(narrow_recent=False)
        state = brain.update(brain.load_state(None), entries, T0).new_state
        for k in range(4):
            result = brain.update(
                brain.load_state(brain.dump_state(state)),
                entries + [JournalEntry("ordinary day notes", T0 + timedelta(days=k))],
                T0 + timedelta(days=k),
            )
            state = result.new_state
        assert all(p.kind != "activity_diversity" for p in result.surfaced)

    def test_single_tag_history_never_measures(self):
        entries = [
            JournalEntry("ordinary day notes", d, tags=("work",))
            for d in consecutive(T0 - timedelta(days=69), 70)
        ]
        assert (
            brain._detect_activity_diversity({"work": {e.entry_date for e in entries}}, T0) is None
        )

    def test_low_volume_weeks_are_excluded_not_zero(self):
        """The volume floor (item 3b): a week with one tagged day or one
        distinct tag is EXCLUDED from the sample entirely — its 'entropy'
        was a journaling-volume artifact, not variety."""
        d0 = T0 - timedelta(days=T0.weekday()) - timedelta(days=60)
        d0 = d0 - timedelta(days=d0.weekday())  # align to Monday
        week1 = [d0 + timedelta(days=k) for k in range(7)]
        week2 = [d0 + timedelta(days=7 + k) for k in range(7)]
        week3 = [d0 + timedelta(days=14 + k) for k in range(7)]
        tag_days = {
            # week 1: rich spread (qualifies)
            "a": set(week1),
            "b": set(week1[::2]),
            "c": set(week1[1::2]),
            # week 2: one tagged day only (excluded)
            "a2": {week2[0]},
            "b2": {week2[0]},
            # week 3: two days but ONE distinct tag (excluded)
            "solo": set(week3[:2]),
        }
        entropies = brain._weekly_tag_entropies(tag_days)
        assert [week for week, _ in entropies] == [d0]

    def test_weekly_entropy_is_miller_madow_bits(self):
        # any Monday works for a unit check of the entropy math itself
        d0 = T0 - timedelta(days=T0.weekday()) - timedelta(days=60)
        d0 = d0 - timedelta(days=d0.weekday())  # align to Monday
        days = [d0 + timedelta(days=k) for k in range(14)]
        tag_days = {
            "a": set(days[:7]),
            "b": set(days[:7]),
        }
        entropies = brain._weekly_tag_entropies(tag_days)
        # Week 1: a+b evenly split over 7 days -> MLE 1 bit, N=14, m=2 ->
        # Miller-Madow + (2-1)/(2*14*ln2) ~= 0.0514. Week 2 carries no
        # tags at all: absent, not zero.
        assert len(entropies) == 1
        expected = 1.0 + 1 / (2 * 14 * math.log(2))
        assert entropies[0][1] == pytest.approx(expected)

    def test_entropy_bias_correction_recovers_a_known_distribution(self):
        """Item 3a regression: for weeks drawn from a KNOWN 4-category
        uniform distribution, the Miller-Madow estimator's weekly average
        must sit within tolerance of the true 2 bits — the MLE plug-in
        sits systematically low, and the corrected estimator must recover
        most of the gap."""
        import random as _random

        rng = _random.Random(11)
        tags = ("work", "family", "exercise", "friends")
        mle_total = corrected_total = 0.0
        weeks = 60
        for _w in range(weeks):
            counts = {t: 0 for t in tags}
            for _day in range(12):  # a floor-passing week: 12 tagged days
                counts[rng.choice(tags)] += 1
            total = sum(counts.values())
            m = sum(1 for c in counts.values() if c > 0)
            mle = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
            corrected = mle + (m - 1) / (2 * total * math.log(2))
            mle_total += mle
            corrected_total += corrected
        mle_mean = mle_total / weeks
        corrected_mean = corrected_total / weeks
        assert corrected_mean > mle_mean  # the correction pushes UP, as designed
        assert abs(corrected_mean - 2.0) < abs(mle_mean - 2.0)  # and closer to truth
        assert corrected_mean == pytest.approx(2.0, abs=0.10)


# --- Spanish: the first supported non-English language (2026-09-19 final wave) ---


class TestSpanishEngine:
    def test_detection_separates_english_spanish_and_other(self):
        import re as _re

        def detect(text: str) -> str:
            tokens = _re.findall(r"[a-z']+", text.lower())
            scored = [t for t in tokens if len(t) >= 3]
            if len(scored) < brain.LANGUAGE_MIN_TOKENS:
                return "en"
            en = sum(1 for t in scored if t in brain._KNOWN_TOKENS) / len(scored)
            es = sum(1 for t in scored if t in brain._KNOWN_TOKENS_ES) / len(scored)
            if es >= brain.LANGUAGE_HIT_FLOOR and es > en:
                return "es"
            if en >= brain.LANGUAGE_HIT_FLOOR:
                return "en"
            return "other"

        # Each sample repeats to clear LANGUAGE_MIN_TOKENS (50 scored
        # tokens) — below it the gate honestly defaults to English.
        spanish = (
            "Hoy me siento bastante cansado porque el trabajo fue duro, "
            "pero la cena con mi familia me dejó tranquilo y agradecido. "
        ) * 4
        english = (
            "Today I feel rather tired because work was hard, but dinner "
            "with my family left me calm and grateful. "
        ) * 4
        german = (
            "Heute fühle ich mich ziemlich müde, weil die Arbeit hart "
            "war, aber das Abendessen mit meiner Familie hat mich ruhig "
            "und dankbar gemacht. "
        ) * 4
        assert detect(spanish) == "es"
        assert detect(english) == "en"
        assert detect(german) == "other"

    def test_stats_report_the_detected_language(self):
        entries = [
            JournalEntry(
                "me siento tranquilo y agradecido, un dia tranquilo con calma",
                T0 - timedelta(days=ago),
            )
            for ago in range(70, 0, -1)
        ]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats.get("language") == "es"

    def test_spanish_negation_pero_and_intensifiers(self):
        # Negation flips with damping; "pero" re-weights toward the final
        # clause; "muy" intensifies. Spot values from the graded lexicon.
        assert brain.sentiment_score("no estoy bien".split()) < 0
        assert brain.sentiment_score("estoy cansado pero feliz".split()) > 0
        plain = brain.sentiment_score("feliz hoy".split())
        boosted = brain.sentiment_score("muy feliz hoy".split())
        assert boosted > plain
        assert brain.sentiment_score("me siento triste y cansado".split()) < 0

    def test_spanish_corpus_surfaces_patterns(self):
        """Blocks vs alternation in SPANISH text — the same rising-carryover
        corpus shape that surfaces for English must surface for Spanish
        (previously the language gate suppressed everything)."""
        calma = "me siento tranquilo y agradecido, un dia con calma y paz"
        ansioso = "me siento ansioso y cansado, mucha preocupacion por todo"
        entries = []
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if i >= 42:
                text = calma if (i // 4) % 2 == 0 else ansioso
            else:
                text = calma if i % 2 == 0 else ansioso
            entries.append(JournalEntry(text, d))
        state = brain.load_state(None)
        surfaced_any = False
        for k in range(6):
            result = brain.update(
                brain.load_state(brain.dump_state(state)), entries, T0 + timedelta(days=k)
            )
            state = result.new_state
            if any(
                p.kind in ("inertia", "na_inertia", "pa_inertia", "instability")
                for p in result.surfaced
            ):
                surfaced_any = True
                break
        assert surfaced_any, "a Spanish corpus must surface dynamics claims"


# --- 2026-09-26 statistical review: item regressions -------------------------------


class TestEwmaCalibration:
    """Item 2: the run-rule alarm probability fed to BH is CALIBRATED —
    seeded Monte Carlo over the exact chart pins the per-recompute
    false-alarm rate at the constraint (<= 5% at phi = 0.5) and the
    magnitude-conditioned interpolator's shape."""

    LAMBDA = brain.MOOD_SHIFT_LAMBDA
    L = brain.MOOD_SHIFT_LIMIT

    @staticmethod
    def _chart(series: list[float], phi: float) -> bool:
        """The EXACT _detect_mood_shift rule, mirror-implemented (baseline
        quarter, AR(1)-inflated limits, last-of-5 run rule)."""
        n = len(series)
        baseline = series[: max(brain.MOOD_SHIFT_BASELINE_MIN, n // 4)]
        mu = sum(baseline) / len(baseline)
        m = mu
        var = sum((v - m) ** 2 for v in baseline) / (len(baseline) - 1)
        sigma = max(math.sqrt(var), brain.MOOD_SHIFT_SIGMA_FLOOR)
        inflation = min(max((1 + phi) / (1 - phi), 1.0), 16.0)
        se = sigma * math.sqrt(TestEwmaCalibration.LAMBDA / (2 - TestEwmaCalibration.LAMBDA))
        se *= math.sqrt(inflation)
        upper = mu + TestEwmaCalibration.L * se
        lower = mu - TestEwmaCalibration.L * se
        ewma = mu
        signs: list[int] = []
        for s in series[len(baseline) :]:
            ewma = TestEwmaCalibration.LAMBDA * s + (1 - TestEwmaCalibration.LAMBDA) * ewma
            signs.append(1 if ewma > upper else (-1 if ewma < lower else 0))
        if not signs or signs[-1] == 0:
            return False
        tail = signs[-brain.MOOD_SHIFT_TAIL :]
        return sum(1 for s in tail if s == tail[-1]) >= brain.MOOD_SHIFT_RUN

    @staticmethod
    def _ar1(rng: random.Random, phi: float, n: int) -> list[float]:
        out = [rng.gauss(0, 1)]
        innov = math.sqrt(1 - phi * phi)
        for _ in range(n - 1):
            out.append(phi * out[-1] + innov * rng.gauss(0, 1))
        return out

    def test_false_alarm_rate_at_phi_05_is_within_the_calibrated_band(self):
        # The review's constraint: the calibrated per-recompute false-alarm
        # rate is <= 5% at phi = 0.5. 600 seeded null runs; the band allows
        # the 5% line plus 3 Monte-Carlo sigmas of slack.
        rng = random.Random(20260926)
        n = 90
        alarms = sum(1 for _ in range(600) if self._chart(self._ar1(rng, 0.5, n), phi=0.5))
        band = 0.05 + 3 * math.sqrt(0.05 * 0.95 / 600)
        assert alarms / 600 <= band, f"false-alarm rate {alarms / 600:.3f} exceeds the band"

    def test_false_alarm_rate_at_phi_0_stays_small(self):
        rng = random.Random(7)
        alarms = sum(1 for _ in range(600) if self._chart(self._ar1(rng, 0.0, 90), phi=0.0))
        assert alarms / 600 <= 0.05

    def test_power_for_a_large_sustained_shift_stays_high(self):
        # A 3-sigma sustained shift over the last 10 days must still fire
        # with high probability (the reason L stopped at 3.1, not higher).
        rng = random.Random(11)
        n = 90
        hits = 0
        for _ in range(300):
            series = self._ar1(rng, 0.5, n)
            series = [v + (3.0 if i >= n - 10 else 0.0) for i, v in enumerate(series)]
            if self._chart(series, phi=0.5):
                hits += 1
        assert hits / 300 >= 0.8, f"detection power {hits / 300:.2f} too low"

    def test_alarm_probability_is_monotone_and_magnitude_aware(self):
        # Monotone in phi (more autocorrelation, higher null alarm rate)...
        base = brain._ewma_alarm_probability(0.0, 90, brain.MOOD_SHIFT_LIMIT)
        for phi in (0.2, 0.4, 0.6, 0.8):
            assert brain._ewma_alarm_probability(phi, 90, brain.MOOD_SHIFT_LIMIT) >= base
        # ...and strictly falling in the excursion magnitude (item 2's
        # detection-power requirement: an honest 9-sigma excursion must
        # report a far smaller p than a barely-clearing one).
        tiny = brain._ewma_alarm_probability(0.3, 60, brain.MOOD_SHIFT_LIMIT + 0.1)
        huge = brain._ewma_alarm_probability(0.3, 60, 9.0)
        assert 0 < huge < tiny / 1e4
        # Both stay valid p-values.
        assert 0.0 < tiny <= brain._MOOD_SHIFT_ALARM_MAX
        assert 0.0 < huge <= brain._MOOD_SHIFT_ALARM_MAX

    def test_constants_are_the_calibrated_ones(self):
        assert brain.MOOD_SHIFT_LIMIT == 3.1
        assert brain.MOOD_SHIFT_TAIL == 5 and brain.MOOD_SHIFT_RUN == 3
        # The inflation cap [1, 16] survives (item 2c).
        assert min(max((1 + 0.99) / (1 - 0.99), 1.0), 16.0) == 16.0


class TestEwmaDeployedPathCalibration:
    """Re-audit (2026-09-27), item 2: the MIRROR-implemented chart above
    validates the alarm TABLE under true phi, but the DEPLOYED detector
    estimates phi from the data (shrunk low) and now widens its limits
    with phi_eff = phi_hat + k/sqrt(n-1). The calibration condition —
    limits widened with the SAME phi the table row assumes — holds only
    on that deployed path, so the false-alarm rate must be pinned through
    the REAL _detect_mood_shift: end-to-end seeded nulls at the short
    chart lengths where the pre-fix p was anti-conservative (measured
    13.4% at phi=0.5/n=40, 28.1% at phi=0.8/n=21 before phi_eff)."""

    @staticmethod
    def _day_series(rng: random.Random, phi: float, n: int) -> list[tuple[date, float]]:
        """An AR(1) null mood series as (date, value) pairs — the shape
        _detect_mood_shift consumes."""
        start = date(2026, 1, 1)
        out = [(start, rng.gauss(0, 1))]
        innov = math.sqrt(1 - phi * phi)
        for i in range(1, n):
            out.append((start + timedelta(days=i), phi * out[-1][1] + innov * rng.gauss(0, 1)))
        return out

    @staticmethod
    def _min_p(series: list[tuple[date, float]]) -> float:
        """The smallest BH-input p the deployed detector reports for this
        series (its mood_shift signal, or 1.0 when the chart stays calm)."""
        signals = brain._detect_mood_shift(series)
        if not signals:
            return 1.0
        return min(s.pvalue for s in signals if s.pvalue is not None)

    def test_deployed_false_alarm_rate_at_short_lengths(self):
        # 400 seeded nulls per cell, driving the REAL detector (baseline
        # estimation, shrunk phi_hat, phi_eff widening, table lookup). The
        # re-audit bound: P(min-p <= 0.05) <= 6% per cell (5% line + MC
        # slack) at the exact (phi, n) corners that failed pre-fix.
        rng = random.Random(20260927)
        reps = 400
        for phi in (0.5, 0.8):
            for n in (21, 40):
                violations = sum(
                    1 for _ in range(reps) if self._min_p(self._day_series(rng, phi, n)) <= 0.05
                )
                band = 0.06 + 3 * math.sqrt(0.06 * 0.94 / reps)
                assert violations / reps <= band, (
                    f"deployed false-alarm rate at phi={phi}, n={n} is "
                    f"{violations / reps:.3f} (band {band:.3f})"
                )

    def test_deployed_phi_zero_is_untouched(self):
        # phi_eff == phi_hat == 0 keeps the iid chart bit-identical to the
        # pre-phi_eff behavior: same false-alarm ceiling, no widening.
        rng = random.Random(31)
        violations = sum(
            1 for _ in range(300) if self._min_p(self._day_series(rng, 0.0, 90)) <= 0.05
        )
        assert violations / 300 <= 0.08

    def test_power_survives_the_deployed_path(self):
        # The estimator's upper branch widens limits, costing power. The
        # K sweep (2026-09-27, seeded, in-tree constants) measured the
        # frontier: K=1.0 keeps mirror-chart power (0.84) but leaves the
        # phi=0.8 nulls at 15-23% false alarms — exactly the
        # anti-conservatism the fix exists to remove. K=2.0 (shipped) is
        # the smallest K that holds every false-alarm cell near nominal,
        # at a measured deployed power of ~0.68 for a 3-sigma sustained
        # shift (phi=0.5, n=90). The old >=0.8 contract was set against
        # the TRUE-phi mirror chart and was implicitly subsidized by the
        # invalid p-values; the honest deployed contract is >=0.65.
        # Recovering 0.8+ deployed power needs a different lever (a longer
        # chart or a length-scaled L), not a smaller K — see the constant
        # block in brain.py.
        rng = random.Random(97)
        n = 90
        hits = 0
        for _ in range(200):
            series = self._day_series(rng, 0.5, n)
            shift = 3.0
            series = [(d, v + (shift if i >= n - 10 else 0.0)) for i, (d, v) in enumerate(series)]
            if self._min_p(series) <= 0.05:
                hits += 1
        assert hits / 200 >= 0.65, f"deployed detection power {hits / 200:.2f} too low"


class TestInertiaBoundaryPairOwnership:
    """Item 8: the pair anchored ON the window boundary carries the
    boundary day's observation into BOTH windows' correlations; it is now
    dropped from the EARLIER window (the recent window keeps it), so the
    Fisher-z samples are built on disjoint observations."""

    def test_boundary_anchored_pair_is_excluded_from_earlier(self):
        today = date(2026, 9, 30)
        cutoff = today - timedelta(days=brain.INERTIA_RECENT_DAYS)
        rng = random.Random(3)
        carry = 0.0

        def block(days_: list[date]) -> list[tuple[date, float]]:
            # Strong positive day-to-day carryover inside the block.
            nonlocal carry
            out = []
            for d in days_:
                carry = 0.8 * carry + 0.2 * rng.uniform(-0.5, 0.5)
                out.append((d, carry))
            return out

        # Earlier side: EXACTLY INERTIA_MIN_PAIRS + 1 consecutive pairs
        # when the boundary-anchored pair (cutoff-1 -> cutoff) counts.
        # With that pair dropped from the earlier window (item 8), the
        # earlier side falls to INERTIA_MIN_PAIRS - ... one below? No:
        # exactly the minimum is REQUIRED; (MIN+1) - 1 = MIN keeps the
        # signal alive, so the discriminating corpus has exactly MIN
        # earlier pairs INCLUDING the boundary one: dropped -> MIN - 1
        # -> no claim; extended by one pre-boundary day -> MIN -> claim.
        earlier_days = [cutoff - timedelta(days=i) for i in range(brain.INERTIA_MIN_PAIRS, 0, -1)]
        recent_days = [cutoff + timedelta(days=i) for i in range(1, brain.INERTIA_MIN_PAIRS + 4)]
        series = block(earlier_days) + block(recent_days)
        sig_without = brain._inertia_signal(series, "inertia:mood", "inertia", "mood", today)
        assert sig_without is None, (
            "fixture check: with the boundary pair dropped the earlier "
            f"window holds only {brain.INERTIA_MIN_PAIRS - 1} pairs and no "
            "claim may exist"
        )
        # One more pre-boundary day (one more earlier pair, boundary pair
        # still dropped) revives the signal: the exclusion is exactly the
        # boundary-anchored pair, no more.
        extended = block([earlier_days[0] - timedelta(days=1)]) + series
        sig = brain._inertia_signal(extended, "inertia:mood", "inertia", "mood", today)
        assert sig is not None


class TestLanguageGatingShortAndZeroToken:
    """Item 9: zero-token corpora report 'other' when text exists; short
    windows apply the share rule instead of defaulting to English."""

    def test_zero_token_corpora_with_text_report_other(self):
        for text in ("今天心情不好，很累。", "Мне сегодня тяжело и грустно.", "😞😞😞"):
            entries = [JournalEntry(text, T0 - timedelta(days=ago)) for ago in range(70, 0, -1)]
            result = brain.update(brain.load_state(None), entries, T0)
            assert result.stats["language"] == "other", text

    def test_fully_empty_corpus_keeps_the_english_default(self):
        entries = [JournalEntry("", T0 - timedelta(days=ago)) for ago in range(70, 0, -1)]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats["language"] == "en"

    def test_short_window_with_low_english_share_steps_aside(self):
        # 20 short Latin-script non-English entries (< 50 scored tokens):
        # the length-aware tie rule defaults AWAY from English scoring.
        text = "heute fuehle ich mich ziemlich muede und traurig"
        entries = [JournalEntry(text, T0 - timedelta(days=ago)) for ago in range(20, 0, -1)]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats["language"] == "other"

    def test_short_window_with_clear_english_share_stays_english(self):
        text = "felt really tired today but the walk helped and i am grateful"
        entries = [JournalEntry(text, T0 - timedelta(days=ago)) for ago in range(20, 0, -1)]
        result = brain.update(brain.load_state(None), entries, T0)
        assert result.stats["language"] == "en"


class TestEmojiCanonicalization:
    """Item 10: emoji are counted on a VS16-canonicalized copy — a bare
    base scores exactly like its fully-qualified form, and shared-base
    keys never double-count."""

    @staticmethod
    def _tokens(text: str) -> list[str]:
        # The update() pipeline's tokenization: words + canonical emoji.
        return brain.WORD_RE.findall(
            brain._fold_sentiment_text(text.lower())
        ) + brain._emoji_tokens(text)

    def test_bare_heart_scores_like_the_vs16_form(self):
        with_vs16 = brain.sentiment_score(self._tokens("good day ❤️"))
        bare = brain.sentiment_score(self._tokens("good day ❤"))
        assert bare == pytest.approx(with_vs16)
        assert bare > brain.sentiment_score(["good", "day"])

    def test_occurrences_count_once_per_grapheme(self):
        # One bare heart and one VS16 heart: exactly two sob/heart tokens —
        # the old per-key count() could not see the bare form at all, and a
        # shared-base key pair would have counted the VS16 one twice.
        tokens = brain._emoji_tokens("love ❤ and love ❤️ and ☀️")
        assert tokens.count("❤️") == 2
        assert tokens.count("☀️") == 1

    def test_vs16_canonical_text_equality(self):
        assert brain._emoji_tokens("🌧") == brain._emoji_tokens("🌧️") == ["🌧️"]
        assert brain._emoji_tokens("") == []


class TestStoredKindTaxonomy:
    """Item 12: an unknown kind in a stored record is inert — archived on
    load, never surfaced, never promoted."""

    def _store_with(self, kind: str, state: str = "emerging") -> bytes:
        raw = {
            "v": 2,
            "patterns": {
                "alien:probe": {
                    "kind": kind,
                    "label": "work",
                    "occurrences": 9,
                    "state": state,
                    "first_seen": "2026-08-01",
                    "last_seen": "2026-09-01",
                    "first_qualified": "2026-08-01",
                    "last_qualified": "2026-09-01",
                    "qualification_days": ["2026-08-01", "2026-09-01"],
                    "evidence_dates": ["2026-08-01", "2026-09-01"],
                }
            },
            "history": [],
        }
        return json.dumps(raw).encode()

    def test_unknown_kind_is_archived_and_never_surfaces(self):
        state = brain.load_state(self._store_with("sentiment_hologram"))
        record = state["patterns"]["alien:probe"]
        assert record.state == "archived"
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [JournalEntry(NEUTRAL_WORK if d.weekday() == 6 else CALM, d) for d in days]
        result = brain.update(state, entries, T0)
        assert all(p.detail.get("pattern_pid") != "alien:probe" for p in result.surfaced)
        assert result.new_state["patterns"]["alien:probe"].state == "archived"

    def test_known_kinds_survive_the_load(self):
        for kind in sorted(brain.KNOWN_PATTERN_KINDS):
            state = brain.load_state(self._store_with(kind))
            assert state["patterns"]["alien:probe"].state == "emerging", kind
        # The phrase-kind literal list and PHRASE_KINDS stay in sync.
        assert brain.PHRASE_KINDS <= brain.KNOWN_PATTERN_KINDS


class TestSpanishPersonAnchoring:
    """Item 14: unambiguous Spanish possessive-relation bigrams anchor as
    people, with no capitalization dependence and no German-caps class."""

    def _es_corpus(self, relation_days_text: str) -> list[JournalEntry]:
        entries = []
        calma = "me siento tranquilo y agradecido, un dia con calma"
        for i, d in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if i % 3 == 0:
                entries.append(JournalEntry(relation_days_text, d, sentiment=-0.6 + _jitter(i)))
            else:
                entries.append(JournalEntry(calma, d, sentiment=0.3 + _jitter(i)))
        return entries

    def test_mi_madre_becomes_a_person_anchor(self):
        entries = self._es_corpus("hable con mi madre por telefono, fue un dia duro")
        first = brain.update(brain.load_state(None), entries, T0)
        grown = entries + [
            JournalEntry(
                "hable con mi madre otra vez, muy cansado", T0 + timedelta(days=1), sentiment=-0.6
            ),
            JournalEntry(
                "mi madre llamo de nuevo al dormir", T0 + timedelta(days=2), sentiment=-0.65
            ),
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
        )
        assert any(
            p.label == "mi madre" and p.detail.get("source") == "person" for p in result.surfaced
        )

    def test_no_caps_dependence_and_no_noun_harvest(self):
        # Lowercase "mi madre" mid-sentence, no capitals anywhere; common
        # non-relation nouns (mi coche) never anchor.
        entries = self._es_corpus("arregle mi coche otra vez, me dejo tirado")
        result = brain.update(brain.load_state(None), entries, T0)
        assert all(p.detail.get("source") != "person" for p in result.surfaced)
        assert all(p.label != "mi coche" for p in result.surfaced)

    def test_word_boundary_prevents_substring_matches(self):
        assert brain._mentions_es_relation("mi tiazas se cayeron", "mi tia") is False
        assert brain._mentions_es_relation("visite a mi tia", "mi tia") is True
