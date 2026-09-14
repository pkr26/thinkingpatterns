"""Analyzer interface: deterministic rule-based default, optional LLM backend.

The product brief calls the analyzer the "mini-brain". v1 ships
RuleBasedAnalyzer (deterministic, offline, testable). If MINDPATTERN_LLM_URL
is configured AND the user has explicitly opted in (account-level consent,
re-authenticated), LLMAnalyzer sends decrypted entries to an OpenAI-compatible
endpoint and falls back to the rule-based analyzer on failure.

Guardrails (this is the module that can ship journal plaintext off-server,
so it gets no benefit of the doubt):
  * The caller (insights API) only reaches this path post-threshold and
    with consent recorded — enforced there, not trusted here.
  * Model output is treated as hostile: labels are length-capped and
    control-character-stripped, recurring-phrase labels must actually occur
    in the corpus, numeric fields are clamped, counts capped.
"""

from __future__ import annotations

import json
import math
import re
from typing import Protocol

from ..config import Settings
from . import patterns
from .patterns import Analysis, JournalEntry, Pattern

MAX_LABEL_CHARS = 80
MAX_OCCURRENCES = 100_000
# The kinds the model may claim. The analyze()/extract_patterns() prompt is
# BUILT from this tuple, so the endpoint can never be asked for (or
# rewarded for) a kind the sanitizer would drop.
_ALLOWED_KINDS = ("temporal", "mood_correlation", "recurring_phrase", "mood_shift")
_PATTERNS_PROMPT = (
    "You extract behavioral patterns from journal entries. Return strict "
    "JSON: {\"patterns\": [{\"kind\": \"" + "|".join(_ALLOWED_KINDS) + "\", "
    "\"label\": str, \"occurrences\": int, \"confidence\": 0..1, \"detail\": {}}]}. "
    "No advice, no diagnosis."
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_URL_OR_PHONE = re.compile(r"https?://|www\.|\d{5,}", re.IGNORECASE)
# Tokens allowed in labels even when the corpus never contains them:
# function words + the fixed UI vocabulary the kinds talk about.
_GROUNDING_ALLOWLIST = {
    "your", "the", "a", "an", "and", "or", "for", "with", "that", "this",
    "you", "was", "were", "are", "is", "be", "been", "when", "what", "from",
    "into", "than", "more", "less", "most", "lately", "usual", "baseline",
    "mood", "day", "days", "entry", "entries", "writing", "read", "reads",
    "reading", "lower", "higher", "after", "before", "near", "lately",
    "appears", "present", "mostly", "often", "several", "times", "keeps",
    "returning", "returned", "shows", "up",
}
# Display-bound numeric fields: model floats must be finite AND clamped —
# NaN/Infinity survive float() and json.dumps would write invalid JSON
# literals into the insights blob (JS JSON.parse then cannot render it).
_NUMERIC_BOUNDS = {
    "mood_delta": (-1.0, 1.0),
    "day_fraction": (0.0, 1.0),
    "span_days": (0.0, 3650.0),
    "shift": (-1.0, 1.0),
    "baseline": (-1.0, 1.0),
    "current": (-1.0, 1.0),
}


def _clean_label(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    label = _CONTROL_CHARS.sub(" ", raw).strip()
    if not label or len(label) > MAX_LABEL_CHARS:
        return None
    if _URL_OR_PHONE.search(label):
        return None
    return label


def _corpus_tokens(corpus_lower: list[str]) -> set[str]:
    """The user's own vocabulary: word tokens across every entry."""
    tokens: set[str] = set()
    for text in corpus_lower:
        tokens.update(patterns.WORD_RE.findall(text))
    return tokens


def _label_grounded(label: str, corpus_vocab: set[str]) -> bool:
    """Every content token of the label must occur in the user's own text.

    Model output is hostile: without corpus grounding, a prompt-injected
    journal entry turns into an arbitrary label ("URGENT: call 555-0134")
    rendered on pattern cards and interpolated into the daily question.
    Function words are exempt; everything else must be the user's wording.
    Matching is on WORD TOKENS, never substrings — "rage" is not grounded
    by "forage".
    """
    for token in label.lower().split():
        stripped = token.strip(".,!?;:'\"()[]")
        if len(stripped) < 3 or stripped in _GROUNDING_ALLOWLIST:
            continue
        if stripped not in corpus_vocab:
            return False
    return True


class Analyzer(Protocol):
    name: str

    def analyze(self, entries: list[JournalEntry]) -> Analysis: ...


class RuleBasedAnalyzer:
    name = "rules"

    def analyze(self, entries: list[JournalEntry]) -> Analysis:
        return patterns.analyze(entries)


def sanitize_pattern(item: object, corpus_texts: list[str]) -> Pattern | None:
    """Coerce one untrusted model output into a Pattern, or drop it."""
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    if kind not in _ALLOWED_KINDS:
        return None
    label = _clean_label(item.get("label"))
    if label is None:
        return None
    lowered = [t.lower() for t in corpus_texts]
    # EVERY kind's label is corpus-grounded, not just recurring_phrase: an
    # injected label rides onto cards and into the daily question whatever
    # its kind. recurring_phrase keeps its stricter verbatim-substring rule.
    if not _label_grounded(label, _corpus_tokens(lowered)):
        return None
    if kind == "recurring_phrase":
        # A "recurring phrase" the user never wrote is model fiction (or a
        # prompt-injection payload) — it must exist in the corpus verbatim.
        if not any(label.lower() in text for text in lowered):
            return None
    try:
        occurrences_raw = item.get("occurrences", 0)
        if isinstance(occurrences_raw, bool):
            raise TypeError
        occurrences = max(0, min(int(occurrences_raw), MAX_OCCURRENCES))
    except (TypeError, ValueError):
        occurrences = 0
    try:
        confidence = min(1.0, max(0.0, float(item.get("confidence", 0.5))))
        if not math.isfinite(confidence):
            raise ValueError
    except (TypeError, ValueError):
        confidence = 0.5
    detail_raw = item.get("detail", {})
    detail: dict = {}
    if isinstance(detail_raw, dict):
        if detail_raw.get("day") in patterns.DAY_NAMES:
            detail["day"] = detail_raw["day"]
        direction = detail_raw.get("direction")
        if direction in ("lower", "higher"):
            detail["direction"] = direction
        for numeric, (lo, hi) in _NUMERIC_BOUNDS.items():
            try:
                value = float(detail_raw[numeric])
            except (KeyError, TypeError, ValueError):
                continue
            # Non-finite floats (NaN/Infinity parse fine in Python json)
            # are dropped entirely: json.dumps would emit bare Infinity /
            # NaN literals and the stored insights blob stops being valid
            # JSON for strict parsers (JS, Swift).
            if math.isfinite(value):
                detail[numeric] = min(hi, max(lo, value))
        # detail.first/last are DROPPED: they are free-text fields that
        # cannot be corpus-grounded (a date is not a word in the text), and
        # the deterministic brain computes its own evidence dates — the
        # model adds nothing trustworthy there.
    return Pattern(
        kind=kind, label=label, occurrences=occurrences, confidence=confidence, detail=detail
    )


class LLMAnalyzer:
    # The rule-based analyzer sees the full corpus; the LLM path sends the
    # most recent entries within a character budget so prompt size (and cost)
    # stays bounded no matter how long someone has been journaling.
    MAX_ENTRIES = 200
    MAX_TOTAL_CHARS = 150_000

    name = "llm"

    def __init__(self, url: str, api_key: str, model: str = "gpt-4o-mini") -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def _post(self, payload: dict) -> dict:
        """HTTP call isolated for testability (tests monkeypatch this)."""
        import httpx  # imported lazily; keeps the dependency off the unit-test path

        response = httpx.post(f"{self.url}/chat/completions", json=payload, timeout=30,
                              headers={"Authorization": f"Bearer {self.api_key}"})
        response.raise_for_status()
        return response.json()

    def _recent_payload(self, entries: list[JournalEntry]) -> list[dict]:
        user_payload = []
        budget = self.MAX_TOTAL_CHARS
        for entry in entries[-self.MAX_ENTRIES :]:
            if budget <= 0:
                break
            text = entry.text[:budget]
            budget -= len(text)
            user_payload.append(
                {"date": entry.entry_date.isoformat(), "sentiment": entry.sentiment, "text": text}
            )
        return user_payload

    def _fetch_patterns(self, entries: list[JournalEntry]) -> list[Pattern]:
        """One endpoint round-trip + sanitize; raises on ANY failure.

        The single shared path behind extract_patterns() and analyze() —
        the two used to carry their own (drifting) prompt copies.
        """
        body = self._post({
            "model": self.model,
            "messages": [
                {"role": "system", "content": _PATTERNS_PROMPT},
                {"role": "user", "content": json.dumps(self._recent_payload(entries))},
            ],
        })
        content = body["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        corpus = [entry.text for entry in entries]
        return [
            pattern
            for item in parsed.get("patterns", [])
            if (pattern := sanitize_pattern(item, corpus)) is not None
        ]

    def extract_patterns(self, entries: list[JournalEntry]) -> list[Pattern]:
        """Sanitized patterns from the model ([] on ANY failure).

        The v2 brain calls this inside the secure processing context as
        an enrichment layer on top of its deterministic core: the model
        may add patterns it can defend, and every field is coerced as
        hostile before it is trusted. Empty result simply means "no
        model additions" — the brain's own patterns stand.
        """
        try:
            return self._fetch_patterns(entries)
        except Exception:
            return []

    def analyze(self, entries: list[JournalEntry]) -> Analysis:
        try:
            found = self._fetch_patterns(entries)
        except Exception:
            # One rule-based pass, computed once, used for both the fallback
            # and the envelope fields below — never two full corpus passes.
            return RuleBasedAnalyzer().analyze(entries)
        base = RuleBasedAnalyzer().analyze(entries)
        return Analysis(
            total_entries=base.total_entries,
            active_days=base.active_days,
            avg_sentiment=base.avg_sentiment,
            first_date=base.first_date,
            last_date=base.last_date,
            patterns=found[: patterns.MAX_PATTERNS],
        )


def get_analyzer(settings: Settings, llm_consent: bool = False) -> Analyzer:
    # Consent is decided per-user at the account level; without it the LLM
    # endpoint being configured changes nothing for that user.
    if settings.llm_url and llm_consent:
        return LLMAnalyzer(settings.llm_url, settings.llm_api_key, settings.llm_model)
    return RuleBasedAnalyzer()
