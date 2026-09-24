"""External verification checklist 2026-09-23, round 3: brain engine.

Closes the mapped gaps:

* cross-PROCESS determinism — update() digests must match between two
  fresh interpreter processes and an in-process run (a hidden clock, RNG
  seed, or dict-ordering leak would diverge them);
* the JUST-above-threshold corpus — the mapped suite had comfortably-clear
  positives and a far-below negative; here the corpus sits 0.002 above the
  residual mood-delta floor (0.2020 vs MOOD_MIN_DELTA=0.2) and its twin
  0.003 below (0.1970), pinning the gate at its exact edge;
* exact N−1 vs N minimum-sample boundaries for the kinds whose floors are
  engine constants (temporal 8 theme-days, mood_correlation 8 per side,
  recurring phrase 3 occurrences);
* adversarial inputs the engine had never been fed directly: a ~1 MB
  single entry, zero-width characters, Zalgo, null bytes, all-emoji text,
  and an interleaved bilingual corpus — no crash, finite output, bounded
  runtime.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)
CALM = "felt calm and grateful today"
WORK_TEXT = "worked on the deck quiet day"


def consecutive(start: date, count: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(count)]


def rich_corpus() -> list[JournalEntry]:
    """A corpus touching themes, graded sentiment, a repeated phrase,
    structured channels, and time-of-day buckets — deterministic."""
    phrase_day = "visited the family mom and dad were there"
    entries: list[JournalEntry] = []
    days = consecutive(T0 - timedelta(days=69), 70)
    for i, d in enumerate(days):
        if d.weekday() == 6:
            entries.append(
                JournalEntry(
                    "anxious about work but managed" if i % 3 else WORK_TEXT,
                    d,
                    energy=-0.4 if i % 2 else 0.3,
                    sleep_quality=2 if i % 2 else 4,
                    tags=("family",) if i % 4 == 0 else ("chores",),
                    tod="evening",
                )
            )
        elif i % 9 == 0:
            entries.append(JournalEntry(phrase_day, d, tod="morning"))
        elif i % 5 == 0:
            entries.append(JournalEntry("muy cansado pero feliz hoy", d))
        else:
            entries.append(JournalEntry(CALM, d, sentiment=0.3, tod="afternoon"))
    return entries


# --- 5a: cross-process determinism ------------------------------------------------


class TestCrossProcessDeterminism:
    def test_two_fresh_processes_produce_identical_state(self):
        script = r"""
import hashlib, json, os, sys
os.environ.setdefault("MINDPATTERN_ENV", "development")
sys.path.insert(0, os.getcwd())
from datetime import date, timedelta
from app.services import brain
from app.services.patterns import JournalEntry

T0 = date(2026, 9, 4)
CALM = "felt calm and grateful today"
WORK_TEXT = "worked on the deck quiet day"
phrase_day = "visited the family mom and dad were there"
entries = []
days = [T0 - timedelta(days=69) + timedelta(days=i) for i in range(70)]
for i, d in enumerate(days):
    if d.weekday() == 6:
        entries.append(JournalEntry(
            "anxious about work but managed" if i % 3 else WORK_TEXT, d,
            energy=-0.4 if i % 2 else 0.3,
            sleep_quality=2 if i % 2 else 4,
            tags=("family",) if i % 4 == 0 else ("chores",),
            tod="evening"))
    elif i % 9 == 0:
        entries.append(JournalEntry(phrase_day, d, tod="morning"))
    elif i % 5 == 0:
        entries.append(JournalEntry("muy cansado pero feliz hoy", d))
    else:
        entries.append(JournalEntry(CALM, d, sentiment=0.3, tod="afternoon"))

state = brain.load_state(None)
first = brain.update(state, entries, T0)
second = brain.update(brain.load_state(brain.dump_state(first.new_state)), entries, T0)
dump_a = brain.dump_state(first.new_state)
dump_b = brain.dump_state(second.new_state)
print(hashlib.sha256(dump_a).hexdigest())
print(hashlib.sha256(dump_b).hexdigest())
print(hashlib.sha256(json.dumps([p.to_dict() for p in first.surfaced], sort_keys=True).encode()).hexdigest())
"""
        digests = []
        for _ in range(2):
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                cwd=".",
                timeout=120,
                check=True,
            )
            digests.append(tuple(proc.stdout.split()))
        assert digests[0] == digests[1], (
            "two fresh interpreter processes produced different engine output — "
            "a hidden clock/RNG/dict-ordering leak"
        )

        # And the in-process run agrees with both processes byte-for-byte.
        state = brain.load_state(None)
        first = brain.update(state, rich_corpus(), T0)
        second = brain.update(
            brain.load_state(brain.dump_state(first.new_state)), rich_corpus(), T0
        )
        dump_a = hashlib.sha256(brain.dump_state(first.new_state)).hexdigest()
        dump_b = hashlib.sha256(brain.dump_state(second.new_state)).hexdigest()
        surfaced = hashlib.sha256(
            json.dumps([p.to_dict() for p in first.surfaced], sort_keys=True).encode()
        ).hexdigest()
        assert digests[0] == (dump_a, dump_b, surfaced)

    def test_state_roundtrip_through_json_is_stable(self):
        first = brain.update(brain.load_state(None), rich_corpus(), T0)
        blob = json.loads(brain.dump_state(first.new_state))
        again = brain.update(brain.load_state(json.dumps(blob).encode("utf-8")), rich_corpus(), T0)
        assert brain.dump_state(again.new_state) == brain.dump_state(first.new_state)


# --- 5e: the just-above-threshold corpus --------------------------------------------


class TestJustAboveThresholdCorpus:
    def _corpus(self, sunday_sentiment: float) -> list[JournalEntry]:
        days = consecutive(T0 - timedelta(days=69), 70)
        return [
            JournalEntry(
                WORK_TEXT if d.weekday() == 6 else "ordinary day notes",
                d,
                sentiment=sunday_sentiment if d.weekday() == 6 else 0.0,
            )
            for d in days
        ]

    def _recomputed(self, corpus: list[JournalEntry]):
        first = brain.update(brain.load_state(None), corpus, T0)
        grown = corpus + [
            JournalEntry(WORK_TEXT, T0 + timedelta(days=1), sentiment=corpus_sunday(corpus))
        ]
        return brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )

    def test_just_above_the_delta_floor_surfaces(self):
        # Calibrated 2026-09-23: raw Sunday sentiment −0.20 lands at residual
        # mood_delta = 0.2020 — two thousandths above MOOD_MIN_DELTA (0.2).
        result = self._recomputed(self._corpus(-0.20))
        surfaced = [
            p for p in result.surfaced if p.kind == "mood_correlation" and p.label == "work"
        ]
        assert surfaced, "0.002 above the floor must surface"
        detail = surfaced[0].detail
        assert detail["mood_delta"] == pytest.approx(0.2020, abs=0.0005)
        assert abs(detail["cohens_d"]) > brain.MOOD_MIN_EFFECT

    def test_just_below_the_delta_floor_stores_nothing(self):
        # Its twin, 0.003 below the floor: not surfaced, not even stored.
        result = self._recomputed(self._corpus(-0.195))
        surfaced = [p for p in result.surfaced if p.kind == "mood_correlation"]
        stored = [s for s in result.new_state["patterns"] if s.startswith("mood_correlation:")]
        assert surfaced == []
        assert stored == []

    def test_noise_inflation_trips_the_delta_gate_before_the_d_floor_binds(self):
        # Calibrated defense-in-depth finding: adding within-person noise
        # (k=0.45 → k=0.50 around the same means) deflates the RESIDUAL
        # delta below its floor long before Cohen's d approaches 0.5 —
        # the two gates are conjunctive and the delta gate binds first,
        # so "just above d but below delta" corpora cannot fire at all.
        noise = [1.0, -0.6, 0.3, -0.9, 0.7, -0.2, 0.5, -0.8]

        def corpus(k: float) -> list[JournalEntry]:
            days = consecutive(T0 - timedelta(days=69), 70)
            return [
                JournalEntry(
                    WORK_TEXT if d.weekday() == 6 else "ordinary day notes",
                    d,
                    sentiment=(-0.45 + k * noise[i % 8]) if d.weekday() == 6 else k * noise[i % 8],
                )
                for i, d in enumerate(days)
            ]

        louder = self._recomputed_raw(corpus(0.45))
        assert any(p.kind == "mood_correlation" and p.label == "work" for p in louder.surfaced)
        blocked = self._recomputed_raw(corpus(0.50))
        assert not any(p.kind == "mood_correlation" for p in blocked.surfaced)

    @staticmethod
    def _recomputed_raw(corpus: list[JournalEntry]):
        first = brain.update(brain.load_state(None), corpus, T0)
        grown = corpus + [JournalEntry(WORK_TEXT, T0 + timedelta(days=1), sentiment=-0.45)]
        return brain.update(
            brain.load_state(brain.dump_state(first.new_state)), grown, T0 + timedelta(days=1)
        )


def corpus_sunday(corpus: list[JournalEntry]) -> float:
    return next(e.sentiment for e in corpus if e.text == WORK_TEXT and e.sentiment)


# --- 5g: exact N−1 vs N minimum-sample boundaries ------------------------------------


class TestMinimumNBoundaries:
    def test_temporal_at_seven_theme_days_never_qualifies_at_eight_it_does(self):
        # A daily journaler whose first N Sundays mention work (and nothing
        # else does): N−1 = TEMPORAL_MIN_N−1 theme-days → no temporal pid
        # stored at all; N = 8 → the candidate exists (surfacing still
        # waits on replication, which the main suite pins separately).
        assert brain.TEMPORAL_MIN_N == 8

        def corpus(work_sundays: int) -> list[JournalEntry]:
            days = consecutive(T0 - timedelta(days=69), 70)
            sundays = [d for d in days if d.weekday() == 6]
            chosen = set(sundays[:work_sundays])
            return [JournalEntry(WORK_TEXT if d in chosen else CALM, d) for d in days]

        below = brain.update(brain.load_state(None), corpus(7), T0)
        assert not [s for s in below.new_state["patterns"] if s.startswith("temporal:work")]

        at_n = brain.update(brain.load_state(None), corpus(8), T0)
        stored = [s for s in at_n.new_state["patterns"] if s.startswith("temporal:work")]
        assert stored, "8 theme-days is the engine's own floor and must qualify"
        assert all(p.kind != "temporal" for p in at_n.surfaced), "no card before replication"

    def test_mood_correlation_at_seven_per_side_never_qualifies_at_eight_it_does(self):
        assert brain.MOOD_MIN_PER_SIDE == 8

        def corpus(theme_sundays: int) -> list[JournalEntry]:
            days = consecutive(T0 - timedelta(days=69), 70)
            sundays = [d for d in days if d.weekday() == 6]
            chosen = set(sundays[:theme_sundays])
            return [
                JournalEntry(
                    "anxious about work" if d in chosen else CALM,
                    d,
                    sentiment=-0.5 if d in chosen else 0.3,
                )
                for d in days
            ]

        below = brain.update(brain.load_state(None), corpus(7), T0)
        assert not [s for s in below.new_state["patterns"] if s.startswith("mood_correlation:work")]

        at_n = brain.update(brain.load_state(None), corpus(8), T0)
        stored = [s for s in at_n.new_state["patterns"] if s.startswith("mood_correlation:work")]
        assert stored, "8 per side is the engine's own floor and must qualify"

    def test_recurring_phrase_at_two_mentions_never_fires_at_three_it_does(self):
        assert brain.PHRASE_MIN_OCCURRENCES == 3
        phrase = "visited the family mom and dad were there"

        def corpus(occurrences: int) -> list[JournalEntry]:
            days = consecutive(T0 - timedelta(days=29), 30)
            phrase_days = [days[2], days[10], days[20]]  # 3 distinct days, 18-day span
            chosen = phrase_days[:occurrences]
            return [
                JournalEntry(phrase, d) if d in chosen else JournalEntry(f"filler {i}", d)
                for i, d in enumerate(days)
            ]

        def family_records(result):
            return [
                rec
                for rec in result.new_state["patterns"].values()
                if rec.kind == "recurring_phrase" and rec.label == phrase
            ]

        below = brain.update(brain.load_state(None), corpus(2), T0)
        assert family_records(below) == [], "2 mentions is below the phrase floor"

        at_n = brain.update(brain.load_state(None), corpus(3), T0)
        records = family_records(at_n)
        assert records, "3 occurrences on 3 distinct days spanning 18 days must register"
        assert records[0].occurrences == 3
        assert records[0].detail["distinct_days"] == 3


# --- 5k: adversarial inputs ------------------------------------------------------------


class TestAdversarialInputs:
    def _assert_sane(self, result) -> None:
        blob = brain.dump_state(result.new_state)
        assert isinstance(blob, bytes) and blob
        reloaded = brain.load_state(blob)
        assert reloaded is not None

    def test_one_megabyte_single_entry_is_bounded_and_sane(self):
        # The API's 2 MiB body cap means the engine can legitimately see
        # blobs this large from a legacy/native client; it must neither
        # crash nor run unbounded.
        huge = "deadline dread and worry " * 45_000  # ~1.1 MB
        assert len(huge.encode()) > 1_000_000
        start = time.monotonic()
        result = brain.update(
            brain.load_state(None),
            [JournalEntry(huge, T0 - timedelta(days=i)) for i in range(3)],
            T0,
        )
        elapsed = time.monotonic() - start
        self._assert_sane(result)
        assert elapsed < 30.0, f"1 MB entries took {elapsed:.1f}s — pathological runtime"

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "x",
            "​nothing to see here​​",  # zero-width spaces and joiners
            "Z̴̡̢̬̗̞̈͛a̷l̸g̵o̷ ̶t̸e̸x̶t̵ ̶e̷v̸e̵r̶y̸w̷h̵e̸r̷e̵",
            "null\x00bytes\x00inside\x00the\x00entry",
            "😀😃🤔😇🙃😴🥳",  # all-emoji
            "hello mundo hoy me siento muy cansado pero feliz goodbye",
            "٩(◕‿◕｡)۶ ﷽ ௵ ⌘⌥⇧⌫",  # symbol soup
        ],
        ids=[
            "empty",
            "single-char",
            "zero-width",
            "zalgo",
            "null-bytes",
            "all-emoji",
            "mixed-en-es",
            "symbol-soup",
        ],
    )
    def test_hostile_text_never_crashes_the_engine(self, text):
        start = time.monotonic()
        result = brain.update(
            brain.load_state(None),
            [JournalEntry(text, T0 - timedelta(days=i)) for i in range(35)],
            T0,
        )
        elapsed = time.monotonic() - start
        self._assert_sane(result)
        assert elapsed < 5.0
        # Scores stay finite — no NaN/inf can leak into confidence fields.
        for pattern in result.surfaced:
            assert pattern.confidence == pattern.confidence  # NaN check
            assert abs(pattern.confidence) <= 1.0

    def test_megabyte_zalgo_hybrid_within_time_budget(self):
        zalgo = "Z̴̡̢̬̗̞̈͛a̷l̸g̵o̷ " * 30_000
        start = time.monotonic()
        result = brain.update(
            brain.load_state(None),
            [JournalEntry(zalgo, T0 - timedelta(days=i)) for i in range(2)],
            T0,
        )
        elapsed = time.monotonic() - start
        self._assert_sane(result)
        assert elapsed < 30.0, f"Zalgo scaling took {elapsed:.1f}s"
