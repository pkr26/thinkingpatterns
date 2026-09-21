"""Regression tests for the Spanish theme lexicon (2026-09-21).

AUDIT_2026-09-21.md Phase 2 workstream 1 demanded "ES theme lexicon
(temporal/mood_correlation/link cards in Spanish)" — delivered by the
independent verification follow-up (finding V-2). The engine's nine
canonical themes now carry a Spanish word set, and theme lookups are
LANGUAGE-GATED: "es" corpora read the Spanish map only (a union would let
English theme words misread Spanish text — "son las cinco" would mint a
family theme off "son"), and Spanish words never fire on English corpora.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)

# Spanish work-anxious / calm texts. Function-word + sentiment density is
# what language detection reads, so every sentence carries the ordinary
# Spanish glue ("por", "el", "la", "con", "y", "me") plus ES sentiment
# carriers; the theme words ("trabajo", "reunion", "jefe") ride along.
WORK_ES = "me siento ansioso por el trabajo y la reunion con el jefe"
CALM_ES = "me siento tranquilo y agradecido, paseo y leo con calma"


def consecutive(start: date, count: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(count)]


def _spanish_work_corpus(days: int = 70) -> list[JournalEntry]:
    """Work-theme Spanish text every Sunday (weekday 6), calm otherwise —
    the same shape as the English temporal:work probe corpus."""
    entries = []
    for i, day in enumerate(consecutive(T0 - timedelta(days=days - 1), days)):
        text = WORK_ES if day.weekday() == 6 else CALM_ES
        entries.append(JournalEntry(text, day))
    return entries


def _per_entry(entries):
    window = [e for e in sorted(entries, key=lambda e: e.entry_date)][-1000:]
    out = []
    for e in window:
        tokens = brain.WORD_RE.findall(brain._fold_sentiment_text(e.text.lower()))
        out.append((e, tokens, set(), 0.0))
    return out


class TestThemeLookupGating:
    def test_theme_lookup_is_language_gated(self):
        # Spanish words match only under "es"…
        assert brain.theme_for("trabajo", "es") == "work"
        assert brain.theme_for("trabajo", "en") is None
        assert brain.theme_for("fiesta", "es") == "social"
        assert brain.theme_for("fiesta", "en") is None
        # …and English words only under "en".
        assert brain.theme_for("work", "en") == "work"
        assert brain.theme_for("work", "es") is None
        # The English default (person mining, "other" corpora) is unchanged.
        assert brain.theme_for("work") == "work"
        assert brain.theme_for("trabajo") is None

    def test_folded_and_plural_forms_match(self):
        # The lexicon stores pre-folded spellings (tokenization folds
        # diacritics before [a-z']+), and word_forms' final-s strip maps
        # Spanish plurals ("trabajos" -> "trabajo").
        assert brain.theme_for("trabajos", "es") == "work"
        assert brain.theme_for("familias", "es") == "family"
        assert brain.extract_themes(["sueno", "pesadillas"], "es") == {"sleep"}

    def test_every_theme_has_spanish_words(self):
        for theme in brain.THEME_LEXICON:
            assert theme in brain.THEME_LEXICON_ES, f"no Spanish words for {theme!r}"
            assert brain.THEME_LEXICON_ES[theme], f"empty Spanish set for {theme!r}"

    def test_no_cross_theme_duplicates_within_spanish_set(self):
        seen: dict[str, str] = {}
        for theme, words in brain.THEME_LEXICON_ES.items():
            for word in words:
                assert word not in seen, (
                    f"{word!r} in both {seen[word]!r} and {theme!r}"
                )
                seen[word] = theme

    def test_english_union_trap_stays_closed(self):
        # "son" is an English family theme word AND the Spanish verb "are"
        # ("son las cinco"). Under language gating the Spanish sentence
        # mints NO family theme.
        assert brain.extract_themes(["son", "las", "cinco"], "es") == set()


class TestSpanishThemeCards:
    def test_spanish_temporal_work_card_fires(self):
        result = brain.update(brain.load_state(None), _spanish_work_corpus(), T0)
        assert result.stats["language"] == "es"
        record = result.new_state["patterns"].get("temporal:work")
        assert record is not None, (
            "Spanish work-theme text must qualify temporal:work — the ES "
            "theme lexicon feeds the same detectors as the English one"
        )
        assert record.state in ("candidate", "emerging", "confirmed")

    def test_spanish_theme_words_are_not_topics(self):
        # A recurring Spanish theme word ("trabajo", most entries) must be
        # claimed by the THEME layer and excluded from topic mining under
        # "es" — it must never surface as a redundant topic card.
        per_entry = _per_entry(_spanish_work_corpus())
        signals = brain._detect_topics(per_entry, [], "es")
        assert all("trabajo" not in s.label for s in signals)

    def test_spanish_words_do_not_fire_on_english_corpora(self):
        # An English journal that happens to say "fiesta" (or any Spanish
        # theme word) must NOT mint Spanish-map themes: the ES map only
        # reads under language "es".
        corpus = [
            JournalEntry(f"quiet day, read a book, went to a fiesta nearby {i}", T0 - timedelta(days=i))
            for i in range(70)
        ]
        result = brain.update(brain.load_state(None), corpus, T0)
        assert result.stats["language"] == "en"
        theme_pids = {
            pid
            for pid in result.new_state["patterns"]
            if pid.startswith(("temporal:", "mood_correlation:", "link:"))
        }
        assert "temporal:social" not in theme_pids
        assert "mood_correlation:social" not in theme_pids

    def test_english_theme_cards_unchanged_by_the_spanish_set(self):
        # The English Sunday-work corpus (the probe-A shape) still
        # qualifies temporal:work exactly as before — the ES set must not
        # perturb English behavior.
        corpus = []
        for i, day in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            text = "anxious about work" if day.weekday() == 6 else "felt calm and grateful today"
            corpus.append(JournalEntry(text, day))
        result = brain.update(brain.load_state(None), corpus, T0)
        assert result.stats["language"] == "en"
        assert "temporal:work" in result.new_state["patterns"]
