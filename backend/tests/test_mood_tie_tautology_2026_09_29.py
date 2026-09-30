"""mood_correlation tautology broken (deep audit 2026-09-29, HIGH).

The mood tie test used to score a theme-bearing day's mood over the SAME
tokens that minted the theme — and the theme lexicons ARE the sentiment
lexicon's strongest words ("insomnia" -2.6, "exhausted" -2.8, "lonely"
-2.4). For a TAG-LESS journal (the default user), the engine read the
lexicon, not the person: the audit planted a corpus whose sleep days
carried nothing but sleep words and got `mood_correlation | sleep |
lower, d=1.013, p=0.00025` — a "personalized discovery" that is a
population-level lexical identity, delivered to 100% of tag-less users
who mention poor sleep.

The tie mood for UNTAGGED theme-days is now re-scored without the
theme's own tokens: the association must live in the REST of the day's
words. Explicit client tags are the user's own report and are never
re-scored.

Pins:
  1. Pure lexical overlap (theme words alone) mints NO mood_correlation.
  2. A genuine tie (theme days ALSO carry strong non-theme negative
     words, varied text) still surfaces direction=lower.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)

# All-zero-valence, no-theme filler phrases (verified against the
# lexicons): the corpora must differ ONLY in the words under test.
NEUTRALS = (
    "ordinary day notes, chores and paperwork",
    "errands and laundry day, ordinary notes",
    "paperwork day, ordinary chores and notes",
    "ordinary sunday notes and bills",
)
# Sleep-theme vocabulary with MILD unclamped valences — the shape the
# audit measured (pre-fix: mood_correlation sleep/lower, mood_delta 0.408
# vs the audit's 0.362). Strong negatives here have NO theme membership:
# they are genuine mood content the tie must still catch.
THEME_TEXTS = (
    "slept badly and woke up tired all morning",
    "restless night, drowsy and yawning by noon",
    "tossed and turned, sleepy and drained",
)
NEGATIVES = (
    "and felt awful and hopeless the whole day",
    "but grim and miserable anyway",
    "yet everything felt terrible and bleak",
)


def _corpus(with_negatives_on_theme_days: bool) -> list[JournalEntry]:
    """Theme days every third day (scattered across weekdays — an
    all-one-weekday corpus is cancelled by the engine's per-weekday
    deconfounding, which is a different, correct suppression)."""
    entries: list[JournalEntry] = []
    for i in range(104):
        d = T0 - timedelta(days=103 - i)
        if i % 3 == 1:
            extra = NEGATIVES[i % len(NEGATIVES)] if with_negatives_on_theme_days else ""
            entries.append(JournalEntry(THEME_TEXTS[i % len(THEME_TEXTS)] + extra, d))
        else:
            entries.append(JournalEntry(NEUTRALS[i % len(NEUTRALS)], d))
    return entries


def _surface(corpus: list[JournalEntry]):
    first = brain.update(brain.load_state(None), corpus, T0)
    grown = corpus + [
        JournalEntry("bad night, tired again", T0 + timedelta(days=1)),
        JournalEntry("restless and drowsy again", T0 + timedelta(days=2)),
    ]
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=2)
    )
    return second


class TestLexicalOverlapAloneMintsNoMoodTie:
    def test_sleep_words_without_a_real_tie_surfacing_no_mood_correlation(self) -> None:
        # Theme days carry ONLY mild sleep vocabulary (the audit's
        # planted corpus — this exact corpus fired sleep/lower at
        # mood_delta=0.408 pre-fix): the lexicon must not hand back
        # "entries read lower when 'sleep' comes up".
        corpus = _corpus(with_negatives_on_theme_days=False)
        result = _surface(corpus)
        ties = [p for p in result.surfaced if p.kind == "mood_correlation"]
        assert ties == [], f"lexical overlap alone must not mint a tie: {ties}"


class TestGenuineTieStillSurfaces:
    def test_theme_days_with_real_negative_content_surface_lower(self) -> None:
        # The SAME sleep theme, but the theme days genuinely read lower
        # through strong NON-theme negative words — the association lives
        # in the rest of the day's words and must survive de-contamination.
        corpus = _corpus(with_negatives_on_theme_days=True)
        result = _surface(corpus)
        ties = [p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "sleep"]
        assert ties, f"the genuine tie must surface: {[(p.kind, p.label) for p in result.surfaced]}"
        assert ties[0].detail["direction"] == "lower"
        assert ties[0].detail["p_value"] < 0.05
