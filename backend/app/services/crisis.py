"""Canonical crisis-language phrase contract, embedded for the backend.

shared/crisis_phrases.json is the cross-platform source of truth — the
mobile client reads it directly for its pre-encryption dialog tier. The
backend CANNOT load it at runtime (the Docker image ships only backend/),
so the lists are embedded here as literals and pinned to the JSON by
tests/test_crisis.py — the same sync-test idiom as shared/vectors.json:
editing one side without the other fails CI.

Two tiers (see the JSON's own description):
  * dialog — conservative; a false positive costs one gentle dialog.
    Client-side only; the backend never renders it.
  * suppress — dialog + suppress_extra; deliberately broader, because a
    false positive here only means a pattern is not quoted back as a card
    or reflective question.

Pattern rules (from the JSON): must compile under BOTH Python re and
ECMAScript RegExp, no lookaround, \\s+ for whitespace, ['\\u2019]? for
optional apostrophes, \\b boundaries, matched case-insensitively against
normalized text.
"""

from __future__ import annotations

import re

DIALOG_PATTERNS: tuple[str, ...] = (
    "\\bsuicid(?:e|al)\\b",
    "\\bkill(?:ing)?\\s+myself\\b",
    "\\b(?:wants?|wanted|wanting)\\s+to\\s+die\\b",
    "\\bwanna\\s+(?:to\\s+)?die\\b",
    "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+dead\\b",
    "\\bwish\\s+(?:i\\s+)?could\\s+die\\b",
    "\\bfeel(?:s|ing)?\\s+like\\s+dying\\b",
    "\\bend(?:ing)?\\s+it\\s+all\\b",
    "\\b(?:end|ending|take|taking)\\s+my\\s+(?:own\\s+)?life\\b",
    "\\bself[-\\s]?harm(?:ing)?\\b",
    "\\bhurt(?:ing)?\\s+myself\\b",
    "\\bharm(?:ing)?\\s+myself\\b",
    "\\bcut(?:ting)?\\s+myself\\b",
    "\\bno\\s+reason\\s+to\\s+(?:live|go\\s+on)\\b",
    "\\bnothing\\s+to\\s+live\\s+for\\b",
    "\\b(?:can['\\u2019]?t|cannot)\\s+go\\s+on\\b",
    "\\bbetter\\s+off\\s+without\\s+me\\b",
    "\\b(?:don['\\u2019]?t|do\\s+not)\\s+want\\s+to\\s+(?:be\\s+here|live|exist|be\\s+alive|wake\\s+up)\\b",
    "\\bwant(?:s|ed|ing)?\\s+to\\s+disappear\\b",
    "\\bend(?:ing)?\\s+everything\\b",
    "\\bno\\s+point\\s+(?:in\\s+)?going\\s+on\\b",
    "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+never\\s+born\\b",
    "\\bunalive\\b",
    "\\bkys\\b",
    "\\bno\\s+way\\s+out\\b",
    "\\bsleep\\s+forever\\b",
    "\\b(?:can['\\u2019]?t|cannot)\\s+do\\s+this\\s+anymore\\b",
)

SUPPRESS_EXTRA_PATTERNS: tuple[str, ...] = (
    "\\bsuicid\\w+",
    "\\bkill(?:ing)?\\s+me\\b",
    "\\bwant(?:s|ed|ing)?\\s+to\\s+be\\s+dead\\b",
    "\\brather\\s+be\\s+dead\\b",
    "\\bbetter\\s+off\\s+dead\\b",
    "\\boverdose(?:d)?\\b",
    "\\beveryone\\s+would\\s+be\\s+better\\s+off\\b",
    "\\bnot\\s+want(?:ing)?\\s+to\\s+(?:live|be\\s+here)\\b",
    # Bare self-harm / ED topic words and non-first-person-anchored
    # ideation: suppress-tier ONLY (a false positive costs one gentle
    # non-quoting card, never a dialog — the dialog tier stays
    # conservative). "\\bcutting\\b" closes the re-audit's quoted-topic hole
    # ("the urge for cutting was loud" surfaced as a quoted rising topic).
    "\\bcutting\\b",
    "\\bself[-\\s]?loathing\\b",
    "\\bburn(?:ing|ed)?\\s+myself\\b",
    "\\bstarv(?:e|ing|ed)\\s+myself\\b",
    "\\bmake\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
    "\\b(?:made|making)\\s+myself\\s+(?:throw\\s+up|puke|vomit)\\b",
)

# The effective suppression tier: dialog + suppress_extra (per the JSON).
SUPPRESS_PATTERNS: tuple[str, ...] = DIALOG_PATTERNS + SUPPRESS_EXTRA_PATTERNS


def _compile_tier(patterns: tuple[str, ...]) -> re.Pattern[str]:
    # One alternation per tier; each branch keeps its own \b anchors inside
    # a non-capturing group, so the union matches exactly what any single
    # pattern would.
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


DIALOG_RE = _compile_tier(DIALOG_PATTERNS)
SUPPRESS_RE = _compile_tier(SUPPRESS_PATTERNS)


def matches_dialog(text: str) -> bool:
    """True when the (conservative) client dialog tier fires."""
    return DIALOG_RE.search(text) is not None


def matches_suppress(text: str) -> bool:
    """True when the (broader) suppression tier fires: never quote this
    back as a pattern card or reflective question."""
    return SUPPRESS_RE.search(text) is not None
