"""Optional consent-gated LLM ENRICHMENT layer on top of the deterministic brain.

2026-09-17 rework (audit finding): this module previously also carried the
v1 analyzer interface (``RuleBasedAnalyzer``/``LLMAnalyzer.analyze``, whose
failure fallback ran the v1 ``patterns.analyze`` statistics — the pooled,
uncorrected pre-brain engine). That path was dead in production (recompute
calls ``brain.update`` + ``extract_patterns``) but remained importable and
one wiring mistake away from surfacing v1's demonstrated false-positive-
prone correlations to a consented user. It is gone: the only production
surface is ``get_enricher()`` → ``LLMAnalyzer.extract_patterns``, and an
endpoint failure now means "no model additions" — logged, and reported to
the caller via ``last_error`` so the recompute response never claims the
LLM ran when it did not.

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
import logging
import math
import re

from ..config import Settings
from . import patterns
from .patterns import JournalEntry, Pattern

logger = logging.getLogger("mindpattern.llm")

MAX_LABEL_CHARS = 80
MAX_OCCURRENCES = 100_000
# The kinds the model may claim. The analyze()/extract_patterns() prompt is
# BUILT from this tuple, so the endpoint can never be asked for (or
# rewarded for) a kind the sanitizer would drop.
_ALLOWED_KINDS = ("temporal", "mood_correlation", "recurring_phrase", "mood_shift")
_BASE_PROMPT = (
    "You REFINE deterministic statistical findings about a journal, never "
    "discover new ones. Return strict JSON: {\"patterns\": [{\"kind\": "
    "\"" + "|".join(_ALLOWED_KINDS) + "\", \"label\": str (EXACTLY one of the "
    "provided findings' labels), \"narrative\": str (<= 240 chars)}]}. The "
    "narrative is one calm, plain sentence reframing the finding for its "
    "author: observational, no advice, no diagnosis, no questions. "
    "Findings you cannot improve, omit."
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_URL_OR_PHONE = re.compile(r"https?://|www\.|\d{5,}", re.IGNORECASE)
# Word-spelled contact channels and addresses ("visit evil dot com", "call
# five five five zero one three four"). The 2026-09-16 red-team corpus
# showed the URL/digit regex alone cannot see these, and corpus grounding
# is satisfied by construction when the payload words were planted in an
# entry first — so the SHAPE is rejected regardless of grounding.
_SPELLED_CONTACT = re.compile(
    r"\bdot\s+(?:com|net|org|io|app|dev|co|uk|edu|gov|xyz|me|tv|info)\b"
    r"|\bat\s+(?:gmail|hotmail|yahoo|outlook|icloud|proton)\b"
    r"|\b(?:text|call|phone|dial|ring)\s+me\s+at\b",
    re.IGNORECASE,
)
_NUMBER_WORDS = {
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "oh",
}
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
    if _URL_OR_PHONE.search(label) or _SPELLED_CONTACT.search(label):
        return None
    # Digit-word runs ("five five five zero one three four") are phone
    # numbers spelled out — three or more consecutive number-words is never
    # legitimate pattern vocabulary.
    run = 0
    for token in label.lower().replace("-", " ").split():
        run = run + 1 if token in _NUMBER_WORDS else 0
        if run >= 3:
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


MAX_NARRATIVE_CHARS = 240


def _clean_narrative(raw: object) -> str | None:
    """One calm sentence, or None. Hostile-input rules: control characters
    stripped, length capped, URLs/phones/spelled contacts rejected — the
    narrative renders under pattern cards, so it gets label treatment."""
    if not isinstance(raw, str):
        return None
    text = _CONTROL_CHARS.sub(" ", raw).strip()
    if not text or len(text) > MAX_NARRATIVE_CHARS:
        return None if not text else text[:MAX_NARRATIVE_CHARS].rstrip()
    if _URL_OR_PHONE.search(text) or _SPELLED_CONTACT.search(text):
        return None
    return text


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
        # Honest-failure state (2026-09-17): the exception CLASS of the
        # last failed call, or None. Consumed by the recompute response so
        # `analyzer: "llm"` is only ever reported for a call that actually
        # succeeded. Never carries entry content — class name only.
        self.last_error: str | None = None

    def _post(self, payload: dict) -> dict:
        """HTTP call isolated for testability (tests monkeypatch this)."""
        import httpx  # imported lazily; keeps the dependency off the unit-test path

        response = httpx.post(f"{self.url}/chat/completions", json=payload, timeout=10,
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

    def _fetch_patterns(self, entries: list[JournalEntry],
                        findings: list[Pattern] | None = None) -> list[Pattern]:
        """One endpoint round-trip + sanitize; raises on ANY failure.

        2026-09-17 INVERSION: the model no longer discovers patterns (its
        output bypassed every statistical safeguard — no p-value, no BH
        correction, no replication gate). It receives the deterministic
        brain's findings and may only NARRATE them: any returned
        (kind, label) outside the provided findings is dropped by
        construction, and the only new field is a short reframing
        sentence, sanitized like everything else.
        """
        findings = findings or []
        findings_summary = [
            {"kind": f.kind, "label": f.label,
             **({"direction": f.detail["direction"]} if isinstance(f.detail, dict) and "direction" in f.detail else {})}
            for f in findings
        ]
        body = self._post({
            "model": self.model,
            # Bounded generation (2026-09-16 remediation): without these the
            # endpoint alone decides output length and sampling — a cost-
            # amplification and jailbreak surface for zero product value.
            "max_tokens": 512,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": _BASE_PROMPT},
                {"role": "user", "content": json.dumps({
                    "findings": findings_summary,
                    "recent_entries": self._recent_payload(entries),
                })},
            ],
        })
        content = body["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        corpus = [entry.text for entry in entries]
        allowed = {(f.kind, f.label): f for f in findings}
        refined: list[Pattern] = []
        for item in parsed.get("patterns", []):
            pattern = sanitize_pattern(item, corpus)
            if pattern is None:
                continue
            original = allowed.get((pattern.kind, pattern.label))
            if original is None:
                continue  # not a brain finding: model discovery is dropped
            narrative = _clean_narrative(item.get("narrative"))
            if narrative is not None:
                detail = dict(original.detail)
                detail["narrative"] = narrative
                refined.append(Pattern(pattern.kind, pattern.label,
                                       original.occurrences, original.confidence, detail))
            else:
                refined.append(original)
        return refined

    def extract_patterns(self, entries: list[JournalEntry],
                          findings: list[Pattern] | None = None) -> list[Pattern]:
        """Sanitized pattern NARRATIVES from the model ([] on ANY failure).

        The brain calls this inside the secure processing context with its
        own deterministic findings: the model may only reframe those
        (label-restricted by construction — see _fetch_patterns). Empty
        result means "no model additions" — the brain's own patterns
        stand. A FAILED call (network, status, unparseable output) is
        logged and recorded in ``last_error`` so operators can tell "the
        model had nothing" from "the endpoint is down" and the recompute
        response never claims the LLM ran.
        """
        self.last_error = None
        try:
            return self._fetch_patterns(entries, findings=findings)
        except Exception as exc:  # noqa: BLE001 — every failure mode is one outcome
            self.last_error = type(exc).__name__
            logger.warning(
                "llm enrichment failed (%s); continuing with deterministic patterns only",
                type(exc).__name__,
            )
            return []


def get_enricher(settings: Settings, llm_consent: bool = False) -> LLMAnalyzer | None:
    """The optional consent-gated enrichment extractor, or None.

    Consent is decided per-user at the account level; without it the LLM
    endpoint being configured changes nothing for that user. None means
    deterministic-only — there is no analyzer fallback to select instead
    (the v1 rule-based fallback was removed 2026-09-17: it surfaced the
    pre-brain pooled statistics, the exact false-positive failure mode
    the deterministic engine was built to eliminate).
    """
    if settings.llm_url and llm_consent:
        return LLMAnalyzer(settings.llm_url, settings.llm_api_key, settings.llm_model)
    return None
