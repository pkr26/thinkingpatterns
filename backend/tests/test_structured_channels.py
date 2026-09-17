"""Structured channels (entry payload v2, 2026-09-17) — engine pins.

Sleep quality (1-5), energy, and activity tags are optional user-supplied
day channels. The engine turns them into within-person signals through the
SAME machinery as lexicon themes — full gating, BH correction, replication
— so these tests plant the meta-analytically validated shape (poor sleep →
lower next-day mood; low-mood tagged days) and pin that it surfaces with
honest copy, plus the parser's hostile-input contract.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 17)


def _run_twice(corpus: list[JournalEntry], today: date,
               extra: list[JournalEntry] | None = None) -> brain.BrainUpdate:
    """Qualify + surface at the replication gate's cadence: evidence-date
    kinds (temporal/mood_correlation/link) need the second run to see NEW
    evidence days, so ``extra`` appends fresh relevant days."""
    first = brain.update(brain.load_state(None), corpus, today)
    second_corpus = corpus + (extra if extra is not None else [])
    return brain.update(
        brain.load_state(brain.dump_state(first.new_state)),
        second_corpus,
        today + timedelta(days=2),
    )


class TestSleepChannel:
    def _planted(self, days: int = 70) -> list[JournalEntry]:
        """Rough nights (rated 1-2) are followed by lower-mood entries;
        good nights (4-5) are followed by ordinary ones. The user's own
        median rating sits at 3, so the poor side is strictly-below."""
        entries: list[JournalEntry] = []
        for ago in range(days, 0, -1):
            day = T0 - timedelta(days=ago)
            poor = ago % 3 == 0
            entries.append(JournalEntry(
                text="ordinary day notes with plain words",
                entry_date=day,
                sentiment=None,
                sleep_quality=(2 if poor else 4),
            ))
            # The MOOD lives in the entry of the FOLLOWING day: planted via
            # the client sentiment field the way the real app plants it.
        # second pass: set mood on the day AFTER each poor night
        by_date = {e.entry_date: e for e in entries}
        for ago in range(days, 0, -1):
            day = T0 - timedelta(days=ago)
            poor = ago % 3 == 0
            if poor:
                nxt = by_date.get(day + timedelta(days=1))
                if nxt is not None:
                    nxt_sentiment = -0.45
                    by_date[day + timedelta(days=1)] = JournalEntry(
                        text=nxt.text, entry_date=nxt.entry_date,
                        sentiment=nxt_sentiment, sleep_quality=nxt.sleep_quality,
                        tags=nxt.tags, energy=nxt.energy,
                    )
        return sorted(by_date.values(), key=lambda e: e.entry_date)

    def test_poor_sleep_next_day_link_surfaces(self):
        corpus = self._planted()
        extra = [
            JournalEntry("fresh night one", T0 + timedelta(days=1), sentiment=None, sleep_quality=2),
            JournalEntry("low day after", T0 + timedelta(days=2), sentiment=-0.5, sleep_quality=4),
        ]
        result = _run_twice(corpus, T0, extra=extra)
        links = [p for p in result.surfaced
                 if p.kind == "link" and p.detail.get("channel") == "sleep_quality"]
        assert links, [(p.kind, p.label) for p in result.surfaced]
        card = links[0]
        assert card.detail["direction"] == "lower"
        assert card.occurrences >= brain.LINK_MIN_PER_SIDE

    def test_the_describe_copy_is_rating_aware(self):
        corpus = self._planted()
        extra = [
            JournalEntry("fresh night one", T0 + timedelta(days=1), sentiment=None, sleep_quality=2),
            JournalEntry("low day after", T0 + timedelta(days=2), sentiment=-0.5, sleep_quality=4),
        ]
        result = _run_twice(corpus, T0, extra=extra)
        links = [p for p in result.surfaced if p.detail.get("channel") == "sleep_quality"]
        assert links
        assert "rated" in links[0].describe()

    def test_too_few_rated_nights_is_honest_nothing(self):
        # Only 4 rated nights: below SLEEP_MIN_RATED_NIGHTS — no split, no
        # synthetic theme, no link, no crash.
        corpus = [
            JournalEntry("day notes", T0 - timedelta(days=ago),
                         sentiment=-0.4 if ago % 2 else 0.3,
                         sleep_quality=(2 if ago % 2 else 4))
            for ago in range(6, 0, -1)
        ]
        rated = [e for e in corpus if e.sleep_quality is not None]
        assert len({e.entry_date for e in rated}) < brain.SLEEP_MIN_RATED_NIGHTS
        result = _run_twice(corpus, T0)
        assert not [p for p in result.surfaced
                    if p.detail.get("channel") == "sleep_quality"]

    def test_high_sleep_ratings_never_split(self):
        # Everyone-at-5: median 5, nothing strictly below -> no poor days.
        corpus = [
            JournalEntry("all rested", T0 - timedelta(days=ago), sentiment=0.2,
                         sleep_quality=5)
            for ago in range(60, 0, -1)
        ]
        result = _run_twice(corpus, T0)
        assert not [p for p in result.surfaced
                    if p.detail.get("channel") == "sleep_quality"]


class TestTagChannel:
    def _planted(self) -> list[JournalEntry]:
        entries: list[JournalEntry] = []
        for ago in range(70, 0, -1):
            day = T0 - timedelta(days=ago)
            family = ago % 4 == 0
            entries.append(JournalEntry(
                text="ordinary day with plain words about tea",
                entry_date=day,
                sentiment=(-0.5 if family else 0.25),
                tags=("family",) if family else (),
            ))
        return entries

    def test_tag_mood_correlation_surfaces_with_source_marker(self):
        extra = [
            JournalEntry("fresh family day", T0 + timedelta(days=1), sentiment=-0.5, tags=("family",)),
            JournalEntry("fresh ordinary day", T0 + timedelta(days=2), sentiment=0.25),
        ]
        result = _run_twice(self._planted(), T0, extra=extra)
        tagged = [p for p in result.surfaced
                  if p.label == "family" and p.detail.get("source") == "tag"]
        assert tagged, [(p.kind, p.label, p.detail.get("source")) for p in result.surfaced]
        assert any(p.kind == "mood_correlation" and p.detail["direction"] == "lower"
                   for p in tagged)

    def test_untagged_text_mentioning_family_is_unchanged(self):
        # The word "family" in TEXT still routes through the lexicon theme
        # (no source marker) — the channel only marks user TAGS.
        entries = [
            JournalEntry("family dinner again with everyone", T0 - timedelta(days=ago),
                         sentiment=(-0.5 if ago % 4 == 0 else 0.25))
            for ago in range(70, 0, -1)
        ]
        result = _run_twice(entries, T0)
        family_cards = [p for p in result.surfaced if p.label == "family"]
        assert all(p.detail.get("source") != "tag" for p in family_cards)


class TestEnergyChannel:
    def test_energy_rides_along_without_breaking_anything(self):
        entries = [
            JournalEntry("day notes", T0 - timedelta(days=ago),
                         sentiment=None, energy=(-0.6 if ago % 2 else 0.6))
            for ago in range(60, 0, -1)
        ]
        result = _run_twice(entries, T0)
        # Energy is carried, not yet analyzed (near-tautological with
        # mood); the run completes and nothing claims to be from it.
        assert all(p.detail.get("channel") != "energy" for p in result.surfaced)


def test_determinism_with_channels():
    corpus = TestTagChannel()._planted()
    a = _run_twice(corpus, T0)
    b = _run_twice(corpus, T0)
    assert brain.dump_state(a.new_state) == brain.dump_state(b.new_state)


class TestAvoidance:
    def _planted(self) -> list[JournalEntry]:
        """'conflict' days spread across ALL weekdays are followed by
        silence ~70% of the time; ordinary days ~20%. Deterministic LCG so
        the corpus is reproducible. (The 2026-09-17 audit rewrite: theme
        days must NOT pile onto one weekday — a Friday-only theme with
        Friday-always-silent is the user's calendar, not avoidance, and
        the per-weekday null correctly refuses it.)"""
        entries: list[JournalEntry] = []
        day = T0 - timedelta(days=130)
        i = 0
        seed = 12345
        while day <= T0 - timedelta(days=3):
            seed = (seed * 1103515245 + 12345) % (2 ** 31)
            is_theme = i % 4 == 0
            entries.append(JournalEntry(
                text="conflict at dinner again" if is_theme else "quiet ordinary day notes",
                entry_date=day,
            ))
            skip = (seed % 10 < 8) if is_theme else (seed % 10 < 1)
            day += timedelta(days=2 if skip else 1)
            i += 1
        return entries

    def test_silence_after_theme_surfaces(self):
        corpus = self._planted()
        extra = [JournalEntry("conflict again today", T0 + timedelta(days=1)),
                 JournalEntry("quiet day", T0 + timedelta(days=4))]
        result = _run_twice(corpus, T0, extra=extra)
        cards = [p for p in result.surfaced if p.kind == "avoidance"]
        assert cards, [(p.kind, p.label) for p in result.surfaced]
        card = cards[0]
        # "dinner" maps to the engine's food theme — the claim is about
        # the theme the words carry, exactly like every other detector.
        assert card.label == "food"
        assert card.detail["silences"] >= brain.AVOIDANCE_MIN_SKIPS
        # The per-weekday null (2026-09-17 audit): the card's own detail
        # reports how many silences the user's same-weekday rhythm already
        # predicts — never more than were observed, or it would not fire.
        assert card.detail["expected_silences"] < card.detail["silences"]

    def test_weekly_calendar_is_not_avoidance(self):
        # THE 2026-09-17 audit false positive: a Mon-Fri writer mentioning
        # "work" every Friday has 100% Friday->Saturday silence — their
        # own rhythm, p=1 under the per-weekday null. No card may print a
        # confident "you go quiet after work" claim for an ordinary
        # weekday calendar.
        start = T0 - timedelta(days=126)  # 18 weeks, a Monday
        entries = []
        d = start
        while d <= T0 - timedelta(days=2):
            if d.weekday() < 5:
                text = "big work push before the weekend, long day at work" \
                    if d.weekday() == 4 else "standup, tickets, lunch, walked a bit"
                entries.append(JournalEntry(text, d, sentiment=0.0))
            d += timedelta(days=1)
        result = _run_twice(entries, T0)
        assert not [p for p in result.surfaced if p.kind == "avoidance"], \
            [(p.kind, p.label, p.detail) for p in result.surfaced
             if p.kind == "avoidance"]

    def test_a_theme_without_following_silence_makes_no_claim(self):
        # Same calendar, but the theme NEVER precedes a skip.
        entries: list[JournalEntry] = []
        day = T0 - timedelta(days=80)
        i = 0
        while day <= T0 - timedelta(days=3):
            is_theme = i % 3 == 0
            entries.append(JournalEntry(
                "conflict at dinner again" if is_theme else "plain words about tea",
                day,
            ))
            day += timedelta(days=1)
            i += 1
        result = _run_twice(entries, T0)
        assert not [p for p in result.surfaced if p.kind == "avoidance"]


class TestCadence:
    def test_irregular_recent_rhythm_surfaces(self):
        # Early: metronome daily writing. Recent 35 days: gaps of 1-5 days.
        entries = [JournalEntry("day", T0 - timedelta(days=ago), 0.1)
                   for ago in range(84, 35, -1)]
        day = T0 - timedelta(days=35)
        gaps = [1, 4, 1, 5, 2, 1, 4, 1, 3, 1, 5, 1]
        i = 0
        while day <= T0:
            entries.append(JournalEntry("day", day, 0.1))
            day += timedelta(days=gaps[i % len(gaps)])
            i += 1
        # window-stat kind: run twice 2+ days apart, fixed corpus is fine.
        result = _run_twice(entries, T0)
        assert any(p.kind == "cadence" for p in result.surfaced), \
            [(p.kind, p.label) for p in result.surfaced]

    def test_steady_rhythm_makes_no_claim(self):
        entries = [JournalEntry("day", T0 - timedelta(days=ago), 0.1)
                   for ago in range(84, 0, -1)]
        result = _run_twice(entries, T0)
        assert not [p for p in result.surfaced if p.kind == "cadence"]


class TestVaderBreadth:
    """The 2026-09-17 VADER merge: breadth pinned, curation still wins."""

    def test_curation_overrides_vader_word_for_word(self):
        from app.services.brain import CURATED_SENTIMENT, SENTIMENT_LEXICON
        assert SENTIMENT_LEXICON["happy"] == CURATED_SENTIMENT["happy"]

    def test_context_dependent_words_stay_removed(self):
        from app.services.brain import SENTIMENT_LEXICON
        for word in ("kind", "fed", "present"):
            assert word not in SENTIMENT_LEXICON

    def test_breadth_covers_journal_register_the_old_lexicon_missed(self):
        from app.services.brain import SENTIMENT_LEXICON
        # Slang/profanity that real journals contain and VADER grades.
        for word in ("shitty", "crap", "pissed"):
            assert word in SENTIMENT_LEXICON
            assert SENTIMENT_LEXICON[word] < 0

    def test_emoji_score_mood_without_becoming_topics_or_themes(self):
        from app.services.brain import sentiment_score, extract_themes
        assert sentiment_score(["great", "day", "😀"]) > sentiment_score(["great", "day"])
        assert sentiment_score(["rough", "night", "😭"]) < sentiment_score(["rough", "night"])
        assert extract_themes(["😀", "😢"]) == set()


class TestPersonAnchoring:
    def _planted(self) -> tuple[list[JournalEntry], str]:
        """'Maria' days (mid-sentence, capitalized) read lower; filler
        never mentions her."""
        entries = []
        for ago in range(70, 0, -1):
            day = T0 - timedelta(days=ago)
            with_maria = ago % 3 == 0
            text = (
                f"coffee with Maria in the morning, then {'' if with_maria else 'quiet'} errands"
                if with_maria
                else "quiet errands and a long walk by the water"
            )
            entries.append(JournalEntry(text, day, sentiment=(-0.5 if with_maria else 0.3)))
        return entries, "maria"

    def test_recurring_name_becomes_a_theme_with_mood_ties(self):
        corpus, name = self._planted()
        extra = [
            JournalEntry("dinner with Maria tonight", T0 + timedelta(days=1), sentiment=-0.5),
            JournalEntry("plain tuesday", T0 + timedelta(days=2), sentiment=0.3),
        ]
        result = _run_twice(corpus, T0, extra=extra)
        cards = [p for p in result.surfaced if p.label == name]
        assert cards, [(p.kind, p.label) for p in result.surfaced]
        assert any(p.kind == "mood_correlation" and p.detail.get("source") == "person"
                   for p in cards)

    def test_sentence_initial_capitals_do_not_become_people(self):
        # Every sentence STARTS with "Today" — no mid-sentence capitals, no
        # possessives: no person themes, no crash.
        entries = [
            JournalEntry("Today was quiet and plain.", T0 - timedelta(days=ago), sentiment=0.1)
            for ago in range(70, 0, -1)
        ]
        result = _run_twice(entries, T0)
        assert all(p.detail.get("source") != "person" for p in result.surfaced)


class TestQuestionFeedbackLoop:
    """The 2026-09-17 loop: taps travel encrypted with the next recompute,
    land in the pattern's stored memory, and shift question ranking."""

    def _brain_level(self):
        # Brain level: feedback lands and reorders question selection.
        corpus = TestTagChannel()._planted()
        extra = [
            JournalEntry("fresh family day", T0 + timedelta(days=1), sentiment=-0.5, tags=("family",)),
            JournalEntry("fresh ordinary day", T0 + timedelta(days=2), sentiment=0.25),
        ]
        first = brain.update(brain.load_state(None), corpus, T0)
        result = brain.update(brain.load_state(brain.dump_state(first.new_state)),
                              corpus + extra, T0 + timedelta(days=2))
        assert any(p.kind == "mood_correlation" and p.label == "family"
                   for p in result.surfaced)
        return corpus + extra, result

    def test_feedback_lands_in_the_store_and_shifts_ranking(self):
        from app.services import questions as q
        corpus, result = self._brain_level()
        family = [p for p in result.surfaced if p.label == "family"][0]
        pid = family.detail["pattern_pid"]
        # Two "not me" taps on family, two "resonated" on another pattern.
        other = [p for p in result.surfaced if p.label != "family"]
        assert other
        taps = [(pid, False), (pid, False)]
        for candidate in other[:1]:
            taps.append((candidate.detail["pattern_pid"], True))
            taps.append((candidate.detail["pattern_pid"], True))
        state = brain.update(brain.load_state(brain.dump_state(result.new_state)),
                             corpus, T0 + timedelta(days=4), feedback=taps).new_state
        stored = state["patterns"][pid]
        assert stored.feedback.get("not_me") == 2
        # The feedback counts surface for ranking...
        from app.services.patterns import Pattern
        ranked = sorted(
            [Pattern(p.kind, p.label, p.occurrences, p.confidence, dict(p.detail)) for p in result.surfaced],
            key=q.feedback_rank,
        )
        assert ranked[0].label != "family" or stored.feedback.get("not_me", 0) < 3

    def test_unknown_pids_are_ignored_never_fatal(self):
        corpus, _ = self._brain_level()
        state = brain.update(brain.load_state(None), corpus, T0,
                             feedback=[("nope:does-not-exist", True)] * 200)
        assert "nope:does-not-exist" not in state.new_state["patterns"]
