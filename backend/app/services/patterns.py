"""The "mini-brain": deterministic pattern extraction over decrypted entries.

v1 ships the rule-based analyzer (lexicon themes, weekday histogram, mood
deltas, recurring phrases). It is fully deterministic, which is what makes
both product claims testable and mutation testing meaningful. An
LLM-backed analyzer implementing the same interface can be enabled via
MINDPATTERN_LLM_URL (see llm.py); it never runs in tests.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from statistics import fmean
from typing import Iterable

WORD_RE = re.compile(r"[a-z']+")
SENTENCE_RE = re.compile(r"[^.!?]+")

DAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

THEME_LEXICON: dict[str, tuple[str, ...]] = {
    "work": (
        "work",
        "job",
        "boss",
        "deadline",
        "meeting",
        "office",
        "project",
        "client",
        "interview",
        "presentation",
        "colleague",
        "shift",
        "overtime",
        "career",
        "manager",
    ),
    "sleep": (
        "sleep",
        "insomnia",
        "tired",
        "exhausted",
        "nightmare",
        "restless",
        "fatigue",
        "nap",
        "awake",
        "bed",
    ),
    "social": ("friend", "friends", "party", "social", "lonely", "alone", "gathered", "hangout"),
    "family": (
        "family",
        "mom",
        "dad",
        "mother",
        "father",
        "sister",
        "brother",
        "parents",
        "partner",
        "wife",
        "husband",
        "kids",
        "home",
    ),
    "health": (
        "health",
        "gym",
        "exercise",
        "workout",
        "run",
        "running",
        "sick",
        "ill",
        "doctor",
        "headache",
        "pain",
    ),
    "money": ("money", "bills", "rent", "debt", "salary", "budget", "expensive", "broke", "afford"),
    "study": (
        "school",
        "exam",
        "exams",
        "study",
        "studying",
        "class",
        "college",
        "university",
        "homework",
        "assignment",
    ),
    "food": ("eat", "eating", "food", "meal", "cook", "appetite", "hungry"),
    "weather": ("rain", "rainy", "cold", "grey", "gray", "sunny", "storm", "winter", "summer"),
}
THEME_WORDS: dict[str, str] = {
    word: theme for theme, words in THEME_LEXICON.items() for word in words
}

POSITIVE_WORDS = frozenset(
    {
        "good",
        "great",
        "happy",
        "calm",
        "relaxed",
        "joy",
        "excited",
        "grateful",
        "proud",
        "hopeful",
        "content",
        "peaceful",
        "energetic",
        "loved",
        "confident",
        "better",
        "relieved",
        "pleasant",
        "smiled",
        "laughed",
    }
)
NEGATIVE_WORDS = frozenset(
    {
        "bad",
        "sad",
        "anxious",
        "anxiety",
        "stressed",
        "stress",
        "angry",
        "depressed",
        "worried",
        "nervous",
        "exhausted",
        "tired",
        "lonely",
        "afraid",
        "scared",
        "hopeless",
        "guilty",
        "ashamed",
        "irritated",
        "overwhelmed",
        "numb",
        "empty",
        "cry",
        "crying",
        "panic",
        "hate",
        "awful",
        "terrible",
        "worse",
        "dread",
    }
)

MIN_THEME_OCCURRENCES = 4
TEMPORAL_DAY_FRACTION = 0.5
MOOD_DELTA_THRESHOLD = 0.3
PHRASE_MIN_OCCURRENCES = 3
PHRASE_MIN_SPAN_DAYS = 7
MIN_SENTENCE_TOKENS = 3
MAX_PATTERNS = 20


@dataclass(frozen=True)
class JournalEntry:
    text: str
    entry_date: date
    sentiment: float | None = None  # optional client-computed override
    # --- structured channels (entry payload v2, 2026-09-17) ------------------
    # Optional, client-supplied, within-person by construction: the user's
    # own ratings/tags for the day, never a model inference. All optional —
    # a v1 payload simply leaves them None/empty and the engine behaves
    # exactly as before.
    energy: float | None = None  # [-1, 1]: drained → energized
    sleep_quality: int | None = None  # 1..5: rough → rested
    tags: tuple[str, ...] = ()  # short activity tags ("family", "run")
    # P3 (2026-09-21): coarse LOCAL writing window ("morning"/"afternoon"/
    # "evening"/"night") — a bucket, never a clock time. Powers the
    # "Sunday evening" temporal refinement; None on v1 payloads (the
    # engine behaves exactly as before).
    tod: str | None = None


@dataclass(frozen=True)
class Pattern:
    kind: str  # the engine's kind taxonomy lives in brain.py (see
    # STATISTICAL_KINDS and the _Signal constructions); 17 kinds as of
    # 2026-09-20 — never enumerate them here, this field only carries them
    label: str
    occurrences: int
    confidence: float
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "occurrences": self.occurrences,
            "confidence": round(self.confidence, 3),
            "detail": self.detail,
        }

    def describe(self) -> str:
        # Structured-channel copy (2026-09-17): sleep-quality patterns are
        # about the user's own RATING, not a word they wrote — quoting it as
        # a phrase would read wrong.
        if self.detail.get("channel") == "sleep_quality":
            if self.kind == "link":
                direction = self.detail.get("direction", "lower")
                return (
                    "The day after a night you rated as rougher than your own "
                    f"usual, your entries read {direction} than usual for you."
                )
            if self.kind == "mood_correlation":
                direction = self.detail.get("direction", "lower")
                return (
                    "On nights you rated as rougher than your own usual, "
                    f"your entries read {direction} the same day."
                )
            if self.kind == "temporal":
                day = self.detail.get("day", "the same day")
                return f"Your rougher nights (by your own ratings) fall most often on {day}s."
        if self.kind == "temporal":
            day = self.detail.get("day", "the same day")
            if self.detail.get("source") == "tag":
                return f"You tagged '{self.label}' {self.occurrences} times, most often on {day}s."
            return (
                f"You've mentioned '{self.label}' {self.occurrences} times, most often on {day}s."
            )
        if self.kind == "mood_correlation":
            delta = self.detail.get("mood_delta", 0.0)
            # Old blobs carry no direction: derive it from the delta's sign,
            # defaulting to "lower" (the conservative reading) at exactly 0.
            direction = self.detail.get("direction") or ("higher" if delta < 0 else "lower")
            shift = "drop" if direction == "lower" else "lift"
            if self.detail.get("source") == "tag":
                return (
                    f"Your entries read {direction} on days you tag '{self.label}' "
                    f"(mood {shift} of {abs(delta):.1f})."
                )
            return (
                f"Your entries read {direction} on days when '{self.label}' comes up "
                f"(mood {shift} of {abs(delta):.1f})."
            )
        if self.kind == "avoidance":
            silences = self.detail.get("silences", self.occurrences)
            share = self.detail.get("share", 0.0)
            base = self.detail.get("base_rate", 0.0)
            return (
                f"The day after '{self.label}' comes up, you tend not to write "
                f"({silences} of the observable such days, versus your usual "
                f"{base * 100:.0f}% silent days overall — {share * 100:.0f}% here)."
            )
        if self.kind == "cadence":
            return (
                "Your writing rhythm has been less regular than it used to be "
                "for you — longer stretches of silence between writing days."
            )
        if self.kind == "recurring_phrase":
            return f'The phrase "{self.label}" keeps returning — {self.occurrences} times so far.'
        if self.kind == "mood_shift":
            direction = self.detail.get("direction", "lower")
            shift = self.detail.get("shift", 0.0)
            return (
                f"Your entries have read {direction} than your usual "
                f"baseline lately (a shift of {shift:.1f})."
            )
        if self.kind == "link":
            if self.detail.get("source") == "tag":
                direction = self.detail.get("direction", "lower")
                return (
                    f"The day after you tag '{self.label}', your entries read "
                    f"{direction} than usual for you."
                )
            direction = self.detail.get("direction", "lower")
            lag = self.detail.get("lag_days", 1)
            # The lag reported is the MODAL exposed gap (see brain._detect_links);
            # "the day after" is only said when the data says it.
            if lag == 1:
                return f"The day after '{self.label}' comes up, your entries read {direction}."
            return (
                f"In the days after '{self.label}' comes up, your entries "
                f"read {direction} (about {lag} days later)."
            )
        if self.kind == "inertia":
            return "Your mood has been carrying over from day to day more than usual for you."
        if self.kind == "energy_inertia":
            return "Your energy has been carrying over from day to day more than usual for you."
        if self.kind == "pa_inertia":
            return "Your positive feelings have been carrying over from day to day more than usual for you."
        if self.kind == "na_inertia":
            return "Your negative feelings have been carrying over from day to day more than usual for you."
        if self.kind == "energy_mood_coupling":
            return "Your energy and your mood have been moving together more closely than usual for you."
        if self.kind == "sense_making":
            return (
                "Your writing has leaned more on sense-making words — like "
                "'because' and 'realize' — than it used to."
            )
        if self.kind == "activity_diversity":
            direction = self.detail.get("direction", "widened")
            if direction == "narrowed":
                return "The variety in your tagged activities has narrowed compared with your own usual."
            return "The variety in your tagged activities has widened compared with your own usual."
        if self.kind == "instability":
            return "Your daily mood has swung more widely than usual for you these past weeks."
        if self.kind == "rumination":
            return (
                f'The thought "{self.label}" keeps returning — '
                f"{self.occurrences} times across different days."
            )
        if self.kind == "topic":
            trend = self.detail.get("trend", "steady")
            share = self.detail.get("share")
            share_txt = f" ({share:.0%} of entries)" if isinstance(share, (int, float)) else ""
            if trend == "rising":
                return (
                    f"'{self.label}' has been taking up more space in your "
                    f"writing lately{share_txt}."
                )
            return f"'{self.label}' is a steady presence in your writing{share_txt}."
        return f"'{self.label}' appeared {self.occurrences} times."


@dataclass(frozen=True)
class Analysis:
    total_entries: int
    active_days: int
    avg_sentiment: float
    first_date: date | None
    last_date: date | None
    patterns: list[Pattern]

    def to_dict(self, include_patterns: bool = True) -> dict:
        payload: dict = {
            "total_entries": self.total_entries,
            "active_days": self.active_days,
            "avg_sentiment": round(self.avg_sentiment, 3),
            "first_date": self.first_date.isoformat() if self.first_date else None,
            "last_date": self.last_date.isoformat() if self.last_date else None,
        }
        if include_patterns:
            payload["patterns"] = [p.to_dict() for p in self.patterns]
        return payload


def normalize(text: str) -> str:
    return " ".join(WORD_RE.findall(text.lower()))


def tokenize(text: str) -> list[str]:
    return WORD_RE.findall(text.lower())


def sentiment_score(text: str) -> float:
    """Lexicon sentiment in [-1, 1]; 0 when no sentiment words are present."""
    words = tokenize(text)
    if not words:
        return 0.0
    positive = sum(1 for w in words if w in POSITIVE_WORDS)
    negative = sum(1 for w in words if w in NEGATIVE_WORDS)
    if positive + negative == 0:
        return 0.0
    return (positive - negative) / (positive + negative)


def extract_themes(text: str) -> set[str]:
    return {THEME_WORDS[w] for w in tokenize(text) if w in THEME_WORDS}


def _dominant_weekday(dates_: Iterable[date]) -> tuple[int, float]:
    """Most common weekday and its fraction; ties break to earliest weekday."""
    dates_list = list(dates_)
    if not dates_list:
        raise ValueError("no dates to analyze")
    histogram = Counter(d.weekday() for d in dates_list)
    best_day, best_count = max(histogram.items(), key=lambda kv: (kv[1], -kv[0]))
    return best_day, best_count / len(dates_list)


def _sentences(text: str) -> set[str]:
    """Normalized distinct sentences of at least MIN_SENTENCE_TOKENS tokens."""
    out: set[str] = set()
    for raw in SENTENCE_RE.findall(text):
        tokens = tokenize(raw)
        if len(tokens) >= MIN_SENTENCE_TOKENS:
            out.add(" ".join(tokens))
    return out


def recurring_phrases(
    entries: list[JournalEntry],
    min_count: int = PHRASE_MIN_OCCURRENCES,
    min_span_days: int = PHRASE_MIN_SPAN_DAYS,
) -> list[Pattern]:
    """Sentences that keep coming back across separated days.

    Sentence granularity (not sliding n-grams) is deliberate: a repeated
    sentence yields exactly one pattern instead of a dozen overlapping
    n-gram fragments that drown out theme-level signals.
    """
    appearances: dict[str, list[date]] = {}
    for entry in entries:
        for sentence in _sentences(entry.text):
            appearances.setdefault(sentence, []).append(entry.entry_date)
    found: list[Pattern] = []
    for sentence, dates_ in appearances.items():
        if len(dates_) < min_count:
            continue
        span = (max(dates_) - min(dates_)).days
        if span < min_span_days:
            continue
        found.append(
            Pattern(
                kind="recurring_phrase",
                label=sentence,
                occurrences=len(dates_),
                confidence=min(1.0, len(dates_) / 8),
                detail={
                    "span_days": span,
                    "first": min(dates_).isoformat(),
                    "last": max(dates_).isoformat(),
                },
            )
        )
    return found


def analyze(entries: list[JournalEntry]) -> Analysis:
    """TEST-ONLY v1 reference implementation — never call from production.

    The v1 statistics (pooled moods, no within-person residuals, no
    multiple-comparison control) are the documented false-positive failure
    mode the deterministic brain (services/brain.py) replaced. This
    function survives for test comparison and historical reference only;
    tests/test_llm.py greps app/ to keep it out of the production import
    graph, and llm.py has had its analyzer interface (which fell back to
    this) removed for the same reason (2026-09-17).
    """
    per_entry: list[tuple[JournalEntry, float, set[str]]] = []
    for entry in entries:
        sentiment = entry.sentiment if entry.sentiment is not None else sentiment_score(entry.text)
        per_entry.append((entry, sentiment, extract_themes(entry.text)))

    patterns: list[Pattern] = []

    all_themes = {theme for _, _, themes in per_entry for theme in themes}
    for theme in sorted(all_themes):
        with_theme = [(e, s) for e, s, themes in per_entry if theme in themes]
        without_theme = [(e, s) for e, s, themes in per_entry if theme not in themes]
        count = len(with_theme)
        if count < MIN_THEME_OCCURRENCES:
            continue

        day, fraction = _dominant_weekday(e.entry_date for e, _ in with_theme)
        if fraction >= TEMPORAL_DAY_FRACTION:
            patterns.append(
                Pattern(
                    kind="temporal",
                    label=theme,
                    occurrences=count,
                    confidence=min(1.0, count / 12 * (0.5 + fraction / 2)),
                    detail={"day": DAY_NAMES[day], "day_fraction": round(fraction, 3)},
                )
            )

        if without_theme:
            mood_with = fmean(s for _, s in with_theme)
            mood_without = fmean(s for _, s in without_theme)
            delta = mood_without - mood_with
            if delta >= MOOD_DELTA_THRESHOLD:
                patterns.append(
                    Pattern(
                        kind="mood_correlation",
                        label=theme,
                        occurrences=count,
                        confidence=min(1.0, count / 12 * delta),
                        detail={"mood_delta": round(delta, 3)},
                    )
                )

    patterns.extend(recurring_phrases(entries))
    patterns.sort(key=lambda p: (-p.confidence, -p.occurrences, p.label))
    patterns = patterns[:MAX_PATTERNS]

    sentiments = [s for _, s, _ in per_entry]
    dates_seen = sorted({e.entry_date for e, _, _ in per_entry})
    return Analysis(
        total_entries=len(per_entry),
        active_days=len(dates_seen),
        avg_sentiment=fmean(sentiments) if sentiments else 0.0,
        first_date=dates_seen[0] if dates_seen else None,
        last_date=dates_seen[-1] if dates_seen else None,
        patterns=patterns,
    )
