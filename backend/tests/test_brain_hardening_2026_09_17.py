"""2026-09-17 brain hardening wave — regression pins.

Four changes, each pinned here:

  1. LANGUAGE GATE — Latin-script non-English journals (German/French/
     Spanish) no longer produce garbage topic cards from unrecognized
     function words ("'nicht' is a steady presence"), lexicon-collision
     mood claims ("Bad" German=bath), or English-negativity rumination
     misclassification. Client mood TAGS stay trusted — they are the
     user's own report, not a translation guess.
  2. BROWN-FORSYTHE INSTABILITY — the variance-ratio F-test (iid-normal,
     kurtosis-sensitive, no autocorrelation deflation) is replaced by
     median-centered Levene with Bartlett-deflated df.
  3. DAY-LEVEL TEMPORAL — one calendar day, one Bernoulli: clustered
     journals (4 entries every Sunday) no longer count as 4 correlated
     trials; TEMPORAL_MIN_N and detail counts read in theme-DAYS.
  4. EWMA BASELINE RE-ANCHOR — a stored, established mood shift moves the
     personal baseline past itself; a months-old stable improvement stops
     qualifying cards whose copy says "lately".

Statistical kinds surface only after qualifying on >= 2 distinct recompute
days (the replication gate), so the corpus tests here run update() twice —
exactly like the recompute cadence in production.
"""

from __future__ import annotations

import math
from datetime import date, timedelta

from app.services import brain, statsig
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 17)


def _run(corpus: list[JournalEntry], today: date, prior: dict | None = None) -> brain.BrainUpdate:
    state = brain.load_state(brain.dump_state(prior)) if prior else brain.load_state(None)
    return brain.update(state, corpus, today)


def _run_twice(corpus: list[JournalEntry], today: date,
               extended: list[JournalEntry] | None = None) -> brain.BrainUpdate:
    """Qualify + surface, at the cadence the replication gate demands.

    Window-stat kinds (mood_shift, inertia, instability) need
    qualification days >= REPLICATION_MIN_SPREAD_DAYS (2) apart;
    evidence-date kinds (temporal, mood_correlation, link) need a NEW
    evidence day — pass ``extended`` (the corpus plus a fresh relevant
    day) when pinning those.
    """
    first = _run(corpus, today)
    return _run(extended if extended is not None else corpus,
                today + timedelta(days=2), first.new_state)


# ---------------------------------------------------------------------------
# 1. Language gate
# ---------------------------------------------------------------------------

GERMAN_FILLER = (
    "heute war ein guter tag ich habe viel gearbeitet und bin nicht "
    "zur ruhe gekommen das wetter war schon und ich habe viel nachgedacht"
)
FRENCH_FILLER = (
    "aujourd'hui je me sens fatigue mais je continue le travail avec "
    "beaucoup de pensees qui tournent dans ma tete toute la journee"
)


class TestLanguageGate:
    def _non_english_corpus(self, filler: str, days: int = 70) -> list[JournalEntry]:
        return [JournalEntry(filler, T0 - timedelta(days=ago)) for ago in range(days, 0, -1)]

    def test_german_journal_surfaces_no_garbage(self):
        result = _run_twice(self._non_english_corpus(GERMAN_FILLER), T0)
        labels = [p.label for p in result.surfaced]
        # The pre-fix failure: German function words surfacing as topics.
        for garbage in ("nicht", "auch", "hab", "war", "und", "schon", "viel"):
            assert garbage not in labels
        assert all(p.kind != "topic" for p in result.surfaced), labels
        # Text-derived mood is unreliable -> no mood-level claims either.
        assert all(p.kind not in ("mood_shift", "inertia", "instability")
                   for p in result.surfaced), labels

    def test_french_journal_surfaces_no_garbage(self):
        result = _run_twice(self._non_english_corpus(FRENCH_FILLER), T0)
        assert all(p.kind != "topic" for p in result.surfaced)
        assert all(p.kind != "mood_shift" for p in result.surfaced)

    def test_client_mood_tags_are_still_trusted_in_non_english(self):
        # Explicit tags are the user's own report: a planted, tagged
        # downward shift MUST still surface even in German text.
        corpus = [
            JournalEntry(GERMAN_FILLER, T0 - timedelta(days=ago),
                         sentiment=0.3 if ago > 60 else -0.45)
            for ago in range(120, 0, -1)
        ]
        result = _run_twice(corpus, T0)
        assert any(p.kind == "mood_shift" and p.detail.get("direction") == "lower"
                   for p in result.surfaced)

    def test_english_journal_passes_the_gate(self):
        english = (
            "today was a calm day at work and i walked past the old "
            "bookshop slowly thinking about my week and the coming weekend"
        )
        corpus = [JournalEntry(english, T0 - timedelta(days=ago)) for ago in range(70, 0, -1)]
        result = _run_twice(corpus, T0)
        # English function words carry the hit rate far above the floor.
        tokens = [t for e in corpus for t in brain.WORD_RE.findall(e.text.lower())]
        known = sum(1 for t in tokens if t in brain._KNOWN_TOKENS)
        assert known / len(tokens) > brain.LANGUAGE_HIT_FLOOR


# ---------------------------------------------------------------------------
# 2. Brown-Forsythe instability
# ---------------------------------------------------------------------------

class TestBrownForsythe:
    def test_equal_spreads_are_not_a_claim(self):
        xs = [0.1, -0.1, 0.12, -0.08, 0.05, -0.05, 0.09, -0.11, 0.02, -0.02]
        p = statsig.brown_forsythe_two_sided_p(xs, list(reversed(xs)))
        assert p > 0.9, p

    def test_reordering_cannot_change_the_verdict(self):
        # Same multiset, different order: identical spreads by definition.
        xs = [0.0, 0.5, 0.0, -0.5, 0.0, 0.5, 0.0, -0.5, 0.0, 0.0]
        p = statsig.brown_forsythe_two_sided_p(xs, sorted(xs))
        assert p == 1.0, p

    def test_clearly_different_spreads_are_a_claim(self):
        tight = [0.02, -0.01, 0.0, 0.01, -0.02, 0.015, -0.015, 0.005, -0.005, 0.0]
        wild = [0.8, -0.9, 0.7, -0.75, 0.85, -0.6, 0.9, -0.8, 0.65, -0.7]
        p = statsig.brown_forsythe_two_sided_p(wild, tight)
        assert p < 1e-4, p

    def test_autocorrelation_deflation_makes_claims_harder(self):
        tight = [0.02, -0.01, 0.0, 0.01, -0.02, 0.015, -0.015, 0.005, -0.005, 0.0] * 3
        wild = [0.8, -0.9, 0.7, -0.75, 0.85, -0.6, 0.9, -0.8, 0.65, -0.7] * 3
        p_iid = statsig.brown_forsythe_two_sided_p(wild, tight)
        p_autocorr = statsig.brown_forsythe_two_sided_p(wild, tight, 10.0, 10.0)
        assert p_autocorr > p_iid, (p_iid, p_autocorr)
        assert p_iid < 1e-4

    def test_degenerate_inputs_fail_closed(self):
        assert statsig.brown_forsythe_two_sided_p([], [1.0, 2.0]) == 1.0
        assert statsig.brown_forsythe_two_sided_p([1.0], [1.0, 2.0]) == 1.0
        # Constant-on-both-sides: zero within-group deviation spread.
        assert statsig.brown_forsythe_two_sided_p([3.0] * 10, [7.0] * 10) == 1.0


# ---------------------------------------------------------------------------
# 3. Day-level temporal counting
# ---------------------------------------------------------------------------

class TestTemporalDayDedup:
    def _clustered_sunday_corpus(self) -> tuple[list[JournalEntry], set[date]]:
        # ~10 Sundays x 4 entries mentioning work; every other day one
        # work-free filler entry. Entry-level counting read ~40/102 trials;
        # day-level reads ~10 theme-days of ~72 journaling days.
        entries: list[JournalEntry] = []
        sundays: set[date] = set()
        day = T0 - timedelta(days=71)
        while day <= T0:
            if day.weekday() == 6:
                sundays.add(day)
                for _ in range(4):
                    entries.append(JournalEntry("busy work day at the office again", day))
            else:
                entries.append(JournalEntry("walked by the river and read a book", day))
            day += timedelta(days=1)
        return entries, sundays

    def test_counts_are_theme_days_not_entries(self):
        entries, sundays = self._clustered_sunday_corpus()
        # temporal is an evidence-date kind: the second run needs a NEW
        # theme day, so the corpus grows one work day.
        extended = entries + [
            JournalEntry("busy work day at the office again", T0 + timedelta(days=1)),
            JournalEntry("busy work day at the office again", T0 + timedelta(days=2)),
        ]
        result = _run_twice(entries, T0, extended=extended)
        temporal = [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]
        assert temporal, "the genuine Sunday concentration must still surface"
        card = temporal[0]
        total_days = 72 + 2
        # theme-DAYS (Sundays + the 2 new days), never the ~40 entries
        assert card.occurrences == len(sundays) + 2
        assert card.detail["day_count"] == len(sundays)  # Sunday count unchanged
        # Day-level base rate: distinct Sundays / distinct journaling days.
        assert card.detail["base_rate"] == round(len(sundays) / total_days, 3)

    def test_one_theme_day_with_many_entries_cannot_reach_min_n(self):
        # A single explosive day (12 entries) is ONE observation, not 12:
        # TEMPORAL_MIN_N = 8 theme-days must not be satisfied by clustering.
        entries: list[JournalEntry] = []
        day = T0 - timedelta(days=40)
        while day <= T0:
            if day == T0 - timedelta(days=3):
                for _ in range(12):
                    entries.append(JournalEntry("work work work all day long", day))
            else:
                entries.append(JournalEntry("quiet evening with tea and a film", day))
            day += timedelta(days=1)
        result = _run_twice(entries, T0)
        assert not [p for p in result.surfaced if p.kind == "temporal" and p.label == "work"]


# ---------------------------------------------------------------------------
# 4. EWMA baseline re-anchor
# ---------------------------------------------------------------------------

class TestMoodShiftReanchor:
    def _shifted_corpus(self, shift_days_ago: int = 60, total: int = 120,
                        end: date = T0) -> list[JournalEntry]:
        return [
            JournalEntry("mood day", end - timedelta(days=ago),
                         sentiment=0.3 if ago > shift_days_ago else -0.45)
            for ago in range(total, 0, -1)
        ]

    def test_the_shift_itself_still_surfaces_first(self):
        result = _run_twice(self._shifted_corpus(), T0)
        assert any(p.kind == "mood_shift" and p.detail.get("direction") == "lower"
                   for p in result.surfaced)

    def test_an_established_shift_stops_requalifying(self):
        # The shift is flagged around T0-35 (first_seen). A month later
        # the post-shift level has been stable the whole time. WITHOUT
        # re-anchoring, the window's first quarter is still pre-shift and
        # the months-old drop keeps RE-QUALIFYING on every run; WITH it,
        # the chart re-learns the new normal and the record's
        # last_qualified stops advancing (it then ages out to fading).
        early = T0 - timedelta(days=35)
        prior = _run_twice(
            self._shifted_corpus(shift_days_ago=60, total=120, end=early), early
        ).new_state
        stored = [rec for rec in prior["patterns"].values() if rec.kind == "mood_shift"]
        assert stored, "the shift must be stored before it can anchor"
        last_qualified_before = stored[0].last_qualified

        later_corpus = self._shifted_corpus(shift_days_ago=95, total=155)
        state = prior
        for offset in (0, 2, 4, 6):
            state = _run(later_corpus, T0 + timedelta(days=offset), state).new_state
        rec = state["patterns"].get(stored[0].pid)
        assert rec is None or rec.last_qualified == last_qualified_before, \
            "an established, still-stable shift must stop re-qualifying"

        # Contrast: with the anchor disabled, the same runs keep
        # re-qualifying the months-old drop (this is the pre-fix behavior).
        import pytest
        from app.services import brain as brain_mod
        state = prior
        for offset in (0, 2, 4, 6):
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(brain_mod, "_mood_reanchor_day", lambda store, today: None)
                state = _run(later_corpus, T0 + timedelta(days=offset), state).new_state
        rec = state["patterns"].get(stored[0].pid)
        assert rec is not None and rec.last_qualified > last_qualified_before, \
            "without the anchor the old shift would keep re-qualifying (control)"

    def test_reanchor_is_idempotent_across_dump_load(self):
        prior = _run_twice(self._shifted_corpus(), T0).new_state
        anchor = brain._mood_reanchor_day(prior, T0 + timedelta(days=30))
        assert anchor is not None
        again = brain.update(brain.load_state(brain.dump_state(prior)),
                             self._shifted_corpus(), T0 + timedelta(days=30))
        assert brain._mood_reanchor_day(again.new_state, T0 + timedelta(days=30)) == anchor

    def test_a_fresh_shift_is_not_prematurely_anchored_away(self):
        # A shift flagged days ago keeps its normal baseline: the chart
        # must still see it while it genuinely is "lately".
        prior = None
        for offset in range(4):
            prior = _run(self._shifted_corpus(shift_days_ago=40, total=80),
                         T0 + timedelta(days=offset), prior).new_state
        assert any(rec.kind == "mood_shift" for rec in prior["patterns"].values()), \
            "a young shift must remain visible while it is still 'lately'"


# ---------------------------------------------------------------------------
# Cross-cutting: determinism of the new paths
# ---------------------------------------------------------------------------

def test_language_gate_is_deterministic():
    corpus = [JournalEntry(GERMAN_FILLER, T0 - timedelta(days=ago)) for ago in range(70, 0, -1)]
    a = _run(corpus, T0)
    b = _run(corpus, T0)
    assert brain.dump_state(a.new_state) == brain.dump_state(b.new_state)
    assert math.isfinite(a.stats["avg_sentiment"])


class TestAuditRemediation2026_09_17:
    """The independent-audit fixes: Spanish end-run around the language
    gate, sentence-initial person extraction, name homographs, and
    per-occurrence emoji valence."""

    def _run(self, corpus: list[JournalEntry]) -> brain.BrainUpdate:
        return _run_twice(corpus, T0)

    def test_negation_dense_spanish_is_gated(self):
        # "no"/"me"/"a" are English tokens too: counting 1-2-letter tokens
        # let this Spanish register pass at ~25% "known" and mint
        # English-lexicon rumination cards. The gate scores >=3-letter
        # tokens, so the same text now steps aside (phrases may surface;
        # rumination/mood/topic must not).
        spanish = [
            JournalEntry(
                "No me siento bien hoy. No quiero ir al trabajo y no me "
                "dejan en paz los pensamientos.",
                T0 - timedelta(days=ago),
            )
            for ago in range(70, 0, -1)
        ]
        result = self._run(spanish)
        assert all(p.kind not in ("rumination", "mood_shift", "topic",
                                  "mood_correlation", "instability", "inertia")
                   for p in result.surfaced), [p.kind for p in result.surfaced]

    def test_sentence_initial_words_are_not_person_candidates(self):
        # Telegram-style fragments: every fragment starts capitalized, but
        # only the entry's first token and post-terminator tokens are
        # sentence starts — none of these are names.
        entries = [
            JournalEntry("Woke tired. Netflix til late. Regret nothing. Stayed in bed.",
                         T0 - timedelta(days=ago))
            for ago in range(20, 0, -1)
        ]
        assert brain._person_candidates(entries) == set()

    def test_name_homographs_match_only_capitalized(self):
        # "May"/"Bill" remain eligible candidates, but "I may go" / "the
        # bill arrived" must not count as mentions of them.
        assert not brain._mentions_name("I may go tomorrow", "may")
        assert not brain._mentions_name("the bill arrived today", "bill")
        assert brain._mentions_name("I may go see May tomorrow", "may")
        assert brain._mentions_name("Bill called again", "bill")

    def test_emoji_valence_counts_per_occurrence(self):
        one = [JournalEntry("words about the day and one \U0001f62d here",
                            T0 - timedelta(days=ago)) for ago in range(60, 0, -1)]
        five = [JournalEntry("words about the day and one \U0001f62d\U0001f62d\U0001f62d\U0001f62d\U0001f62d here",
                             T0 - timedelta(days=ago)) for ago in range(60, 0, -1)]
        a = brain.update(brain.load_state(None), one, T0)
        b = brain.update(brain.load_state(None), five, T0)
        # Five sobs carry more weight than one; before the fix both scored
        # identically (membership test counted each emoji once).
        assert a.stats["avg_sentiment"] != b.stats["avg_sentiment"]
        assert b.stats["avg_sentiment"] < a.stats["avg_sentiment"]
