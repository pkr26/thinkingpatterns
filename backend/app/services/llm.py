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

import asyncio
import json
import hashlib
import logging
import math
import re

from ..config import Settings
from . import patterns
from .patterns import JournalEntry, Pattern

logger = logging.getLogger("mindpattern.llm")

MAX_LABEL_CHARS = 80
MAX_OCCURRENCES = 100_000
# The enrichment endpoint handles decrypted journal text, so inherited
# process-level proxy/CA configuration is not an acceptable implicit egress
# policy.  The request is also deliberately bounded twice: HTTPX's per-I/O
# timeouts prevent a dead socket from waiting forever, while asyncio.timeout
# enforces one wall-clock budget even when a peer drips a byte before every
# individual read timeout.
LLM_CONNECT_TIMEOUT_SECONDS = 3.0
LLM_TOTAL_TIMEOUT_SECONDS = 10.0
# Version of the disclosure copy the client shows in the consent flow.
# Recorded on every enable so the account can demonstrate WHICH text it
# agreed to (GDPR Art. 7); bump it whenever that copy changes — a consent
# recorded against an older version is the honest answer, not a bug. It is
# also part of processing_policy_fingerprint, so bumping it makes persisted
# consent inert until the account re-opts-in.
LLM_DISCLOSURE_VERSION = "v1"
# A completion containing a handful of short narratives should be only a few
# KiB.  One MiB leaves generous room for provider envelope changes while
# preventing a compromised endpoint from making a processing worker buffer an
# arbitrarily large (including chunked or decompressed) response.
LLM_MAX_RESPONSE_BYTES = 1 * 1024 * 1024


class LLMResponseTooLarge(ValueError):
    """The configured enrichment endpoint exceeded its response contract."""


# The kinds the model may claim. The analyze()/extract_patterns() prompt is
# BUILT from this tuple, so the endpoint can never be asked for (or
# rewarded for) a kind the sanitizer would drop.
_ALLOWED_KINDS = ("temporal", "mood_correlation", "recurring_phrase", "mood_shift")
_BASE_PROMPT = (
    "You REFINE deterministic statistical findings about a journal, never "
    'discover new ones. Return strict JSON: {"patterns": [{"kind": '
    '"' + "|".join(_ALLOWED_KINDS) + '", "label": str (EXACTLY one of the '
    'provided findings\' labels), "narrative": str (<= 240 chars)}]}. The '
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
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "oh",
}
# Tokens allowed in labels even when the corpus never contains them:
# function words + the fixed UI vocabulary the kinds talk about.
_GROUNDING_ALLOWLIST = {
    "your",
    "the",
    "a",
    "an",
    "and",
    "or",
    "for",
    "with",
    "that",
    "this",
    "you",
    "was",
    "were",
    "are",
    "is",
    "be",
    "been",
    "when",
    "what",
    "from",
    "into",
    "than",
    "more",
    "less",
    "most",
    "lately",
    "usual",
    "baseline",
    "mood",
    "day",
    "days",
    "entry",
    "entries",
    "writing",
    "read",
    "reads",
    "reading",
    "lower",
    "higher",
    "after",
    "before",
    "near",
    "lately",
    "appears",
    "present",
    "mostly",
    "often",
    "several",
    "times",
    "keeps",
    "returning",
    "returned",
    "shows",
    "up",
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


def processing_policy_fingerprint(settings: Settings) -> str | None:
    """Stable, non-secret identity of the configured external processing.

    A boolean consent cannot safely survive an operator switching vendors,
    endpoints, models, or retention terms. The fingerprint deliberately
    excludes the API key but includes every user-relevant declaration —
    including the human-facing disclosure version, so re-worded consent
    copy invalidates persisted consent even when the operator forgets to
    bump MINDPATTERN_LLM_POLICY_VERSION (2026-09-18 audit fix). A changed
    value makes persisted consent inert until the account explicitly opts
    in again. JSON avoids delimiter ambiguity and sorted keys keeps the
    result stable across process restarts.
    """
    if not settings.llm_url.strip():
        return None
    policy = {
        # Strip BEFORE normalizing the trailing slash (2026-09-20 audit
        # fix L-20): "https://host/ " and "https://host" are the same
        # provider and must not mint different fingerprints — a stray
        # trailing space used to silently invalidate every persisted
        # consent (conservative direction, but still operator-hostile
        # drift).
        "url": settings.llm_url.strip().rstrip("/"),
        "model": settings.llm_model,
        "provider": settings.llm_provider_name.strip(),
        "retention": settings.llm_data_retention.strip(),
        "version": settings.llm_policy_version.strip(),
        "disclosure": LLM_DISCLOSURE_VERSION,
    }
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def consent_is_current(user, settings: Settings) -> bool:
    """Whether this user has accepted the current external policy exactly."""
    current = processing_policy_fingerprint(settings)
    return bool(current and user.llm_consent and user.llm_consent_policy == current)


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
        confidence = float(item.get("confidence", 0.5))
        if not math.isfinite(confidence):
            raise ValueError
        confidence = min(1.0, max(0.0, confidence))
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

# Bare domains without scheme or www ("helpnow.example.com") — the URL
# regex can't see these, and a calm reframing sentence has no reason to
# contain one.
_DOMAIN_LIKE = re.compile(
    r"\b[a-z0-9][a-z0-9-]{1,30}(?:\.(?:com|net|org|io|app|dev|co|uk|edu|gov|xyz|me|tv|info))+\b",
    re.IGNORECASE,
)

# Clinical/advice vocabulary a calm reframe has no reason to contain: the
# model must not tell a vulnerable user anything about medication, dosage
# or diagnosis ("stop taking your medication", "take twice the dose").
_CLINICAL_TERMS = frozenset(
    {
        "dose",
        "dosage",
        "medication",
        "medications",
        "meds",
        "medicine",
        "medicines",
        "pill",
        "pills",
        "prescription",
        "prescriptions",
        "prescribe",
        "prescribed",
        "diagnosis",
        "diagnose",
        "diagnosed",
    }
)

# Advice and imperative guardrails (2026-09-20 audit fix M-6): a narrative
# is ONE calm observational sentence about a finding the brain already
# established. The module's threat model treats model output as hostile,
# and the audit demonstrated that prompt-injected journals can land
# second-person advice verbatim ("You should stop reaching out to your
# friends; they are tired of you.") — manipulative isolation/self-blame
# content rendered under pattern cards for vulnerable users. The SHAPES
# are rejected, not a sentiment guess: an observation has no reason to
# command its reader or to tell them what they should do.
_SECOND_PERSON_ADVICE = re.compile(
    r"\byou\s+(?:should|shouldn'?t|must|mustn'?t|need(?:\s+to)?|ought(?:\s+to)?"
    r"|have\s+to|would\s+have\s+to|might\s+want\s+to|could\s+try)\b"
    r"|\byou'?d\s+better\b"
    r"|\bwhy\s+don'?t\s+you\b"
    r"|\bit\s+(?:would|might)\s+help\s+(?:if|to)\s+you\b",
    re.IGNORECASE,
)
# Sentence-LEADING command verbs ("Stop reaching out...", "Take a break
# from..."). Anchored to a sentence boundary so ordinary past-tense prose
# ("you stopped", "it started") is untouched; only the imperative mood is
# refused. "never"/"always" lead absolutist commands, not observations.
_IMPERATIVE_OPENERS = re.compile(
    r"(?:^|[.;:!?]\s+)(?:stop|start|quit|try|remember|consider|make\s+sure"
    r"|be\s+sure|don'?t|do\s+not|never|always|take|call|text|visit"
    r"|reach\s+out|hold\s+on|let\s+go|focus|avoid|block|delete)\b",
    re.IGNORECASE,
)
# Manipulative isolation / self-blame content has no observational use even
# embedded mid-sentence; substring match on the lowercased text.
_MANIPULATION_PHRASES = (
    "tired of you",
    "burden",
    "better off without you",
    "nobody cares",
    "no one cares",
    "not worth it",
    "your fault",
    "the problem is you",
    "push them away",
)

# Spelled-out domains with ANY second word ("quietplace dot online"): the
# finite TLD list in _SPELLED_CONTACT only knows common suffixes, so an
# attacker-chosen TLD sailed through. A "word dot word" join between
# alphabetic runs is never legitimate reframe vocabulary, whatever the
# suffix (2026-09-20 audit fix M-6, widening the TLD handling).
_SPELLED_DOMAIN = re.compile(r"[a-z]\s+dot\s+[a-z]", re.IGNORECASE)


def _clean_narrative(raw: object) -> str | None:
    """One calm sentence, or None. Hostile-input rules: control characters
    stripped, length capped, URLs/domains/phones/spelled contacts rejected,
    NO digits at all (statistics live in the brain's own record — a digit
    in a narrative is a minted claim, a dosage, or a phone fragment),
    second-person advice / imperative / manipulative-isolation constructions
    rejected (2026-09-20 audit fix M-6 — a reframe observes, it never
    instructs), and crisis language rejected (the narrative must never
    quote or echo what the suppress tier exists to keep unquoted). The
    narrative renders under pattern cards, so it gets stricter-than-label
    treatment."""
    from . import crisis

    if not isinstance(raw, str):
        return None
    text = _CONTROL_CHARS.sub(" ", raw).strip()
    if not text or len(text) > MAX_NARRATIVE_CHARS:
        return None if not text else text[:MAX_NARRATIVE_CHARS].rstrip()
    if _URL_OR_PHONE.search(text) or _SPELLED_CONTACT.search(text) or _SPELLED_DOMAIN.search(text):
        return None
    if _SECOND_PERSON_ADVICE.search(text) or _IMPERATIVE_OPENERS.search(text):
        return None
    lowered_text = text.lower()
    if any(phrase in lowered_text for phrase in _MANIPULATION_PHRASES):
        return None
    # Any digit: minted statistics ("87% of Sundays"), phone fragments
    # ("555-0134" defeats the \d{5,} rule via the hyphen), dates, dosages.
    if any(ch.isdigit() for ch in text):
        return None
    if _DOMAIN_LIKE.search(text):
        return None
    # Two number words in a row assembles a spoken phone number or address
    # ("five five five..."); a lone "one calm pattern" is ordinary prose.
    words = text.lower().split()
    if any(a in _NUMBER_WORDS and b in _NUMBER_WORDS for a, b in zip(words, words[1:])):
        return None
    if any(w.strip(".,;:!?\"'()") in _CLINICAL_TERMS for w in words):
        return None
    if crisis.matches_dialog(text) or crisis.matches_suppress(text):
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
        """Make one bounded, non-ambient HTTP request.

        This stays synchronous because ``extract_patterns`` runs inside the
        dedicated analysis worker.  Keeping the small method as the seam also
        preserves the existing test and integration convention of replacing
        ``analyzer._post`` with a deterministic callable.
        """
        return asyncio.run(self._post_async(payload))

    async def _post_async(self, payload: dict) -> dict:
        """Stream a capped LLM response under a true total deadline.

        ``httpx.Timeout`` is per socket operation, so it alone permits a
        slow peer to keep a request alive forever by delivering a trickle of
        bytes.  The enclosing ``asyncio.timeout`` cancels the entire client
        operation at the wall-clock deadline.  ``trust_env=False`` avoids
        silently routing consented plaintext through HTTP(S)_PROXY or trusting
        an ambient CA bundle; redirects remain explicitly disabled as another
        defence-in-depth boundary around the configured provider URL.
        """
        import httpx  # imported lazily; keeps the dependency off the unit-test path

        timeout = httpx.Timeout(
            connect=LLM_CONNECT_TIMEOUT_SECONDS,
            read=LLM_TOTAL_TIMEOUT_SECONDS,
            write=LLM_TOTAL_TIMEOUT_SECONDS,
            pool=LLM_TOTAL_TIMEOUT_SECONDS,
        )
        response_bytes = bytearray()
        async with asyncio.timeout(LLM_TOTAL_TIMEOUT_SECONDS):
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self.url}/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                ) as response:
                    response.raise_for_status()
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared_length = int(content_length)
                        except ValueError as exc:
                            raise ValueError("LLM response has invalid Content-Length") from exc
                        if declared_length < 0 or declared_length > LLM_MAX_RESPONSE_BYTES:
                            raise LLMResponseTooLarge("LLM response exceeds size limit")
                    # aiter_bytes yields decoded bytes, so the cap also holds
                    # for a gzip/brotli expansion that a deceptive
                    # Content-Length alone would miss.
                    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                        if len(response_bytes) + len(chunk) > LLM_MAX_RESPONSE_BYTES:
                            raise LLMResponseTooLarge("LLM response exceeds size limit")
                        response_bytes.extend(chunk)
        return json.loads(bytes(response_bytes))

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

    def _fetch_patterns(
        self, entries: list[JournalEntry], findings: list[Pattern] | None = None
    ) -> list[Pattern]:
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
            {
                "kind": f.kind,
                "label": f.label,
                **(
                    {"direction": f.detail["direction"]}
                    if isinstance(f.detail, dict) and "direction" in f.detail
                    else {}
                ),
            }
            for f in findings
        ]
        body = self._post(
            {
                "model": self.model,
                # Bounded generation (2026-09-16 remediation): without these the
                # endpoint alone decides output length and sampling — a cost-
                # amplification and jailbreak surface for zero product value.
                "max_tokens": 512,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": _BASE_PROMPT},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "findings": findings_summary,
                                "recent_entries": self._recent_payload(entries),
                            }
                        ),
                    },
                ],
            }
        )
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
                refined.append(
                    Pattern(
                        pattern.kind,
                        pattern.label,
                        original.occurrences,
                        original.confidence,
                        detail,
                    )
                )
            else:
                refined.append(original)
        return refined

    def extract_patterns(
        self, entries: list[JournalEntry], findings: list[Pattern] | None = None
    ) -> list[Pattern]:
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
