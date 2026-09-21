"""Regression tests for the 2026-09-21 audit, Part 1.1 (brain correctness).

Each test names its finding (audit finding IDs D-1..D-5 from
AUDIT_2026-09-21.md) and pins the fixed behavior:

* D-1: replication gate bypass via EVIDENCE_DATES_CAP eviction — a
  same-corpus recompute of a >60-evidence-day pattern must NOT satisfy
  "independent replication".
* D-2: Spanish topic mining ran with an English-only eligibility filter;
  Spanish function words must not become topic cards.
* D-3: truncated (budget-blanked) entries fabricated neutral 0.0 mood
  days; they must stay out of the mood series while still counting as
  writing days.
* D-4: person anchoring read German-style capitalized nouns as names;
  person mining is English-only now.
* D-5: a statistical claim sitting as candidate >= CONFIRM_AGE_DAYS used
  to jump candidate -> confirmed in one run; the confirm clock restarts
  at the emerging transition.
* D-6: a phrase pid anchored on the earliest cluster member churned when
  that sentence left the 180-day window, restarting a chronic pattern's
  lifecycle as a fresh candidate; the merge now re-links the rotated
  cluster to the stored record.
* D-8: the per-character fold cache is explicitly bounded.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services import brain
from app.services.patterns import JournalEntry
from app.services.sentiment_lexicon_es import LANGUAGE_FUNCTION_WORDS_ES

T0 = date(2026, 9, 4)
CALM = "felt calm and grateful today"
ANXIOUS_WORK = "anxious about work"


def consecutive(start: date, count: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(count)]


# --- D-1: replication gate vs the evidence-date cap --------------------------------


class TestReplicationCapEviction:
    def _corpus(self) -> list[JournalEntry]:
        """A 100-day daily journal with 70 anxious work days (> the 60-day
        evidence cap) interleaved with calm days — a strongly-qualifying
        mood_correlation:work candidate carrying 70 evidence days."""
        entries: list[JournalEntry] = []
        for i, day in enumerate(consecutive(T0 - timedelta(days=99), 100)):
            entries.append(JournalEntry(ANXIOUS_WORK if i % 10 < 7 else CALM, day))
        return entries

    def test_identical_corpus_recompute_never_satisfies_replication(self):
        entries = self._corpus()
        first = brain.update(brain.load_state(None), entries, T0)
        stored = first.new_state["patterns"].get("mood_correlation:work")
        assert stored is not None, "corpus must qualify the work candidate"
        assert len(stored.evidence_dates) == brain.EVIDENCE_DATES_CAP  # capped at 60 of 70
        # Zero-new-data recompute one day later: the evicted older evidence
        # days used to count as "new" (set membership in the capped list)
        # and promoted the pattern — the flagship anti-fluke gate bypassed.
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), entries, T0 + timedelta(days=1)
        )
        assert all(p.kind != "mood_correlation" for p in second.surfaced)
        record = second.new_state["patterns"]["mood_correlation:work"]
        assert record.state == "candidate"

    def test_genuinely_new_evidence_still_satisfies_replication(self):
        # Positive control for the same corpus: one FRESH work day is real
        # new evidence and must still promote the candidate.
        entries = self._corpus()
        first = brain.update(brain.load_state(None), entries, T0)
        grown = entries + [JournalEntry(ANXIOUS_WORK, T0 + timedelta(days=1))]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
        assert any(p.kind == "mood_correlation" and p.label == "work" for p in result.surfaced)


# --- D-2: Spanish topic eligibility -------------------------------------------------


class TestSpanishTopicEligibility:
    _ANIMALS = [
        "perro",
        "gato",
        "caballo",
        "conejo",
        "tigre",
        "leon",
        "cebra",
        "jirafa",
        "aguila",
        "delfin",
        "ballena",
        "tortuga",
        "loro",
        "serpiente",
        "rana",
        "araña",
        "oso",
        "lobo",
        "zorro",
        "ciervo",
        "foca",
        "morsa",
        "camello",
        "llama",
        "alpaca",
        "panda",
        "koala",
        "canguro",
        "bufalo",
        "nutria",
        "castor",
        "puerco",
        "chivo",
        "oveja",
        "vaca",
        "toro",
        "potro",
        "mula",
        "burro",
        "ganso",
    ]
    _ADJS = [
        "largo",
        "corto",
        "raro",
        "dulce",
        "amargo",
        "suave",
        "duro",
        "lento",
        "rapido",
        "tibio",
        "frio",
        "caliente",
        "gris",
        "dorado",
        "plateado",
        "roto",
        "nuevo",
        "viejo",
        "limpio",
        "sucio",
        "claro",
        "oscuro",
        "fuerte",
        "debil",
        "triste",
        "alegre",
        "serio",
        "simple",
        "complejo",
        "breve",
    ]
    _FILLERS = [
        "llueve",
        "hace sol",
        "estoy cansado",
        "descanso bien",
        "camino mucho",
        "leo un libro",
        "cocino pasta",
        "veo una pelicula",
        "hablo con ana",
        "escribo cartas",
        "ordeno la casa",
        "salgo a correr",
    ]

    def _spanish_corpus(self) -> list[JournalEntry]:
        """40 unique Spanish sentences; 30 of them carry the function word
        "cuando" (75% share, a dozen distinct followers, no repeated
        sentences) — pre-fix, a qualifying presence-topic candidate that
        only the English stopword set failed to exclude."""
        entries = []
        for i in range(40):
            day = T0 - timedelta(days=39 - i)
            animal, adj = self._ANIMALS[i], self._ADJS[i % 30]
            filler = self._FILLERS[i % 12]
            if i % 4 != 3:
                text = f"el {animal} y su sombra piensan que cuando {filler} sera un dia {adj} para caminar"
            else:
                text = (
                    f"el {animal} y su sombra piensan que {filler} sera un dia {adj} para caminar"
                )
            entries.append(JournalEntry(text, day))
        return entries

    def _per_entry(self, entries):
        window = [e for e in sorted(entries, key=lambda e: e.entry_date)][-1000:]
        out = []
        for e in window:
            tokens = brain.WORD_RE.findall(brain._fold_sentiment_text(e.text.lower()))
            out.append((e, tokens, set(), 0.0))
        return out

    def test_corpus_is_detected_as_spanish(self):
        result = brain.update(brain.load_state(None), self._spanish_corpus(), T0)
        assert result.stats["language"] == "es"

    def test_function_words_ineligible_under_spanish(self):
        # The detector itself: under language "es" the Spanish function-word
        # set joins the exclusions, so "cuando" (present in 30 of 40
        # entries, share 0.75, 12 distinct followers) never becomes a topic
        # signal — pre-fix it was the top presence candidate.
        per_entry = self._per_entry(self._spanish_corpus())
        signals = brain._detect_topics(per_entry, [], "es")
        assert all("cuando" not in s.label for s in signals)
        for signal in signals:
            for token in signal.label.split():
                assert token not in LANGUAGE_FUNCTION_WORDS_ES

    def test_content_words_stay_eligible_under_spanish(self):
        # The exclusion union must not over-restrict: real Spanish content
        # words still qualify as topic candidates under "es".
        per_entry = self._per_entry(self._spanish_corpus())
        signals = brain._detect_topics(per_entry, [], "es")
        labels = {s.label for s in signals}
        assert "sombra" in labels  # recurring content noun stays eligible

    def test_no_function_word_topic_cards_on_spanish_corpus(self):
        result = brain.update(brain.load_state(None), self._spanish_corpus(), T0)
        topics = [p for p in result.surfaced if p.kind == "topic"]
        for card in topics:
            for token in card.label.split():
                assert token not in LANGUAGE_FUNCTION_WORDS_ES, (
                    f"Spanish function word became a topic card: {card.label!r}"
                )

    def test_english_function_words_still_excluded_on_english_corpus(self):
        # The exclusion union must not change English behavior: "when" was
        # and stays ineligible on an English corpus.
        corpus = [
            JournalEntry(
                f"when i wake up i do thing number {i} and then work", T0 - timedelta(days=i)
            )
            for i in range(40)
        ]
        result = brain.update(brain.load_state(None), corpus, T0)
        assert result.stats["language"] == "en"
        assert all("when" not in p.label.split() for p in result.surfaced if p.kind == "topic")


# --- D-3: truncated entries out of the mood series ----------------------------------


class TestTruncatedEntries:
    def test_empty_text_entries_never_enter_the_mood_series(self):
        # 30 tagged days at +0.8 followed by 10 textless, untagged days
        # (the shape budget truncation produces). If the empty rows were
        # scored as 0.0 they would read as a sustained crash and mint a
        # mood_shift candidate; with them excluded, the mood machinery sees
        # exactly what the 30-day-only corpus sees.
        good_days = consecutive(T0 - timedelta(days=39), 30)
        tagged_only = [JournalEntry("ordinary day notes", d, sentiment=0.8) for d in good_days]
        empty_days = [T0 + timedelta(days=k) for k in range(10)]
        with_empties = tagged_only + [JournalEntry("", d) for d in empty_days]

        base = brain.update(brain.load_state(None), tagged_only, T0 + timedelta(days=9))
        grown = brain.update(brain.load_state(None), with_empties, T0 + timedelta(days=9))

        def mood_pids(state: dict) -> set[str]:
            return {
                pid for pid in state["patterns"] if pid.startswith(("mood_shift", "mood_dynamics"))
            }

        assert mood_pids(grown.new_state) == mood_pids(base.new_state)
        assert "mood_shift:mood" not in grown.new_state["patterns"]
        # The textless days still count as WRITING days for cadence/calendar.
        assert base.stats["active_days"] == 30
        assert grown.stats["active_days"] == 40

    def test_empty_text_with_explicit_tag_still_counts(self):
        # A mood-tagged textless entry is the user's own report and must
        # stay in the series: a single -0.9 day after 20 calm days is a
        # visible one-day plunge only if the series counted it.
        days = consecutive(T0 - timedelta(days=21), 21)
        tagged = [JournalEntry("ordinary day notes", d, sentiment=0.3) for d in days]
        empty_bad_day = JournalEntry("", T0, sentiment=-0.9)
        result = brain.update(brain.load_state(None), tagged + [empty_bad_day], T0)
        assert result.stats["active_days"] == 22
        # The plunge is in the mood series (it is the user's own report):
        # a mood day exists on T0 even though the entry has no text.
        record = result.new_state["patterns"].get("mood_shift:mood")
        assert record is None  # one day is not a sustained shift
        # avg_sentiment still reflects the reported -0.9 among the 0.3s.
        assert result.stats["avg_sentiment"] < 0.3


# --- D-4: person anchoring is English-only -------------------------------------------


class TestPersonLanguageGate:
    def _german_corpus(self) -> list[JournalEntry]:
        """German prose (language "other") with the recurring mid-sentence
        capitalized noun "Haus" on the anxious days only — far past the
        person-candidate bars (>= 8 mentions over >= 6 days) and exactly
        the shape that, pre-fix, minted a source="person"
        mood_correlation card for a common noun."""
        entries = []
        for i, day in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if day.weekday() == 6:
                entries.append(
                    JournalEntry(f"das Haus blieb sehr laut nummer {i}", day, sentiment=-0.8)
                )
            else:
                entries.append(
                    JournalEntry(
                        "heute blieb alles ruhig und ich lese viele buecher", day, sentiment=0.6
                    )
                )
        return entries

    def test_german_corpus_is_language_other(self):
        result = brain.update(brain.load_state(None), self._german_corpus(), T0)
        assert result.stats["language"] == "other"

    def test_no_person_cards_on_german_corpus(self):
        # Two runs (the second adds a fresh Haus day) — pre-fix the second
        # run surfaced mood_correlation:haus as a PERSON card; post-fix
        # "haus" is never even a candidate theme.
        entries = self._german_corpus()
        first = brain.update(brain.load_state(None), entries, T0)
        assert "mood_correlation:haus" not in first.new_state["patterns"]
        grown = entries + [
            JournalEntry(
                "das Haus blieb sehr laut nummer 70", T0 + timedelta(days=1), sentiment=-0.8
            )
        ]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
        for card in result.surfaced:
            assert card.detail.get("source") != "person"
        assert all(p.label != "haus" for p in result.surfaced)
        assert "mood_correlation:haus" not in result.new_state["patterns"]

    def test_english_person_still_anchored(self):
        # Positive control: English keeps person anchoring — a recurring
        # capitalized mid-sentence token ("Morgana") mentioned only on the
        # anxious days, so the mood_correlation carries the person origin.
        entries = []
        for i, day in enumerate(consecutive(T0 - timedelta(days=69), 70)):
            if day.weekday() == 6:
                entries.append(JournalEntry(f"argued with Morgana again {i}", day))
            else:
                entries.append(JournalEntry(CALM, day))
        first = brain.update(brain.load_state(None), entries, T0)
        grown = entries + [JournalEntry("argued with Morgana again 70", T0 + timedelta(days=1))]
        result = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )
        assert any(
            p.detail.get("source") == "person" and p.label == "morgana" for p in result.surfaced
        )


# --- D-5: confirm clock restarts at the emerging transition -------------------------


class TestConfirmClockRestart:
    def test_late_replication_surfaces_emerging_not_confirmed(self):
        # The candidate qualifies on T0 with a small (<cap) evidence set,
        # then re-qualifies daily for 22 days WITHOUT new evidence (only
        # calm entries are added — the work evidence days never grow), so
        # it sits as candidate the whole time. A fresh work entry on the
        # final day finally satisfies replication. Pre-fix the promotion
        # read the 22-day-old first_qualified and confirmed the pattern in
        # the same run; the first card the user ever saw was "confirmed".
        days = consecutive(T0 - timedelta(days=69), 70)
        entries = [JournalEntry(ANXIOUS_WORK if d.weekday() == 6 else CALM, d) for d in days]
        first = brain.update(brain.load_state(None), entries, T0)
        record = first.new_state["patterns"]["mood_correlation:work"]
        assert record.state == "candidate"
        assert record.first_qualified == T0.isoformat()

        state = first.new_state
        corpus = list(entries)
        for offset in range(1, 23):  # 22 days of calm-only growth
            corpus = corpus + [JournalEntry(CALM, T0 + timedelta(days=offset))]
            state = brain.update(
                brain.load_state(brain.dump_state(state)), corpus, T0 + timedelta(days=offset)
            ).new_state
            record = state["patterns"]["mood_correlation:work"]
            assert record.state == "candidate"  # never promoted without new evidence

        corpus = corpus + [JournalEntry(ANXIOUS_WORK, T0 + timedelta(days=23))]
        final_day = T0 + timedelta(days=23)
        result = brain.update(brain.load_state(brain.dump_state(state)), corpus, final_day)
        cards = [p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "work"]
        assert cards, "fresh evidence must finally promote the candidate"
        assert cards[0].detail["pattern_state"] == "emerging"
        assert (
            date.fromisoformat(
                result.new_state["patterns"]["mood_correlation:work"].first_qualified
            )
            == final_day
        )


# --- D-6: phrase pid anchor churn at the window edge --------------------------------


class TestPhraseAnchorRotation:
    """The pid is anchored on the earliest cluster member's TEXT. When
    that sentence rotates out of the 180-day window (or the sentence
    budget), the derivation moves to a newer member — a different digest —
    and the chronic pattern used to restart as a fresh candidate."""

    EARLY_VARIANT = "i cant sleep my mind wont stop"
    LATE_VARIANT = "i cant sleep my mind wont stop again"

    def _phase_one(self, early):
        return [JournalEntry(self.EARLY_VARIANT, early)] + [
            JournalEntry(self.LATE_VARIANT, early + timedelta(days=d))
            for d in (0, 4, 9, 15, 22)
        ]

    @staticmethod
    def _phrase_records(state) -> dict:
        return {
            pid: record
            for pid, record in state["patterns"].items()
            if record.kind in ("rumination", "recurring_phrase")
        }

    def test_lifecycle_continues_when_the_anchor_leaves_the_window(self):
        early = T0 - timedelta(days=400)
        first = brain.update(
            brain.load_state(None), self._phase_one(early), early + timedelta(days=30)
        )
        records = self._phrase_records(first.new_state)
        assert len(records) == 1, "the near-duplicate pair must form exactly one cluster"
        pid = next(iter(records))
        original_first_seen = records[pid].first_seen

        # 370 days later: the anchor sentence is long outside the window,
        # but the thought still recurs (later variant only).
        phase_two = [
            JournalEntry(self.LATE_VARIANT, early + timedelta(days=d))
            for d in (330, 350, 370)
        ]
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)),
            phase_two,
            early + timedelta(days=400),
        )
        rotated = self._phrase_records(second.new_state)
        assert list(rotated) == [pid], "the rotated cluster must reuse the stored pid"
        assert rotated[pid].first_seen == original_first_seen, "lifecycle continued, not restarted"

    def test_unrelated_phrase_does_not_adopt_a_stored_pid(self):
        early = T0 - timedelta(days=400)
        first = brain.update(
            brain.load_state(None), self._phase_one(early), early + timedelta(days=30)
        )
        sleep_pid = next(iter(self._phrase_records(first.new_state)))
        unrelated = [
            JournalEntry("i love long walks on the beach", early + timedelta(days=d))
            for d in (330, 350, 370)
        ]
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)),
            unrelated,
            early + timedelta(days=400),
        )
        beach_records = {
            pid: record
            for pid, record in second.new_state["patterns"].items()
            if record.kind in ("rumination", "recurring_phrase")
            and "beach" in record.label
        }
        assert beach_records, "the unrelated recurring phrase must still surface"
        assert all(pid != sleep_pid for pid in beach_records), (
            "a below-threshold-similarity phrase must mint its own pid, not adopt the record's"
        )


# --- D-8: the fold cache is bounded --------------------------------------------------


def test_fold_cache_is_bounded():
    brain._FOLD_CACHE.clear()
    try:
        # Distinct decomposable Latin codepoints far past the cap: the
        # cache must stay bounded for the process lifetime.
        for i in range(brain._FOLD_CACHE_LIMIT + 500):
            brain._fold_sentiment_text("x" + chr(0x100 + i))
        assert len(brain._FOLD_CACHE) <= brain._FOLD_CACHE_LIMIT
    finally:
        brain._FOLD_CACHE.clear()
