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
optional apostrophes, \\b boundaries (Latin-script patterns only),
matched case-insensitively against NORMALIZED text (see
normalize_crisis_text — added by the 2026-09-16 red-team remediation
after leetspeak/homoglyph/zero-width/punctuation-split/non-English
samples bypassed the raw matcher on both engines).

2026-09-17 hardening (both engines, pinned by the shared fixtures):
  * DUAL-VARIANT MATCHING — the matchers additionally test an
    orphan-join variant where a run of 1-3 single-letter tokens glues
    onto the FOLLOWING word ("k ill myself" -> "kill myself"), closing
    the partial-split bypass the red-team corpus documented. Ordinary
    prose cannot lose a match: the unjoined variant always runs too.
  * BENIGN-COMPOUND MASKING — movie/band titles and prevention-campaign
    phrases (BENIGN_COMPOUNDS) are masked out of both variants before
    either tier matches, so "that movie was suicide squad" no longer
    fires the dialog tier. Any first-person ideation phrasing around
    them still matches on its own words.
"""

from __future__ import annotations

import re
import unicodedata

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
    # --- 2026-09-16 red-team remediation: unlisted plain-English phrasing ---
    "\\boff(?:ing)?\\s+myself\\b",
    "\\bput\\s+me\\s+out\\s+of\\s+my\\s+misery\\b",
    # --- 2026-09-16 red-team remediation: non-English (Latin script) --------
    "\\bquiero\\s+morir\\b",
    "\\bme\\s+quiero\\s+matar\\b",
    "\\bquitarme\\s+la\\s+vida\\b",
    "\\bje\\s+veux\\s+mourir\\b",
    "\\bme\\s+suicider\\b",
    "\\bsuizid\\w*",
    "\\bich\\s+will\\s+sterben\\b",
    "\\bbringe\\s+mich\\s+um\\b",
    "\\bvoglio\\s+morire\\b",
    "\\bquero\\s+morrer\\b",
    "\\bme\\s+matar\\b",
    # --- non-Latin scripts: plain substrings (\\b never fires next to
    #     CJK/Arabic/Devanagari in ECMAScript) --------------------------------
    "我想死",
    "自杀",
    "死にたい",
    "自殺",
    "أريد أن أموت",
    "मरना चाहता",
    "मरना चाहती",
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
    # --- 2026-09-16 red-team remediation: hopelessness phrasing -------------
    "\\bdon['\\u2019]?t\\s+see\\s+(?:a\\s+|any\\s+)?future\\b",
    "\\bno\\s+future\\s+for\\s+me\\b",
    "\\bhappier\\s+(?:if|when)\\s+(?:i['\\u2019]?m|i\\s+am|i\\s+was)\\s+gone\\b",
    "\\bhappier\\s+without\\s+me\\b",
    "\\beveryone\\s+would\\s+be\\s+happier\\b",
)

# The effective suppression tier: dialog + suppress_extra (per the JSON).
SUPPRESS_PATTERNS: tuple[str, ...] = DIALOG_PATTERNS + SUPPRESS_EXTRA_PATTERNS

# Multiword titles/causes masked from BOTH tiers before matching: the bare
# topic word inside them is not first-person ideation ("that movie was
# suicide squad" must not fire the dialog tier; "we discussed suicide
# prevention in class" either). Masked on the normalized text, plain
# lowercase substring, longest-first by the caller. Any genuine crisis
# phrasing around them ("...makes me want to die") matches on its own.
BENIGN_COMPOUNDS: tuple[str, ...] = (
    "suicide squad",
    "suicide silence",
    "suicideboys",
    "suicide prevention",
    "suicide awareness",
)


def _compile_tier(patterns: tuple[str, ...]) -> re.Pattern[str]:
    # One alternation per tier; each branch keeps its own \b anchors inside
    # a non-capturing group, so the union matches exactly what any single
    # pattern would.
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


DIALOG_RE = _compile_tier(DIALOG_PATTERNS)
SUPPRESS_RE = _compile_tier(SUPPRESS_PATTERNS)


# ---------------------------------------------------------------------------
# Normalization pipeline (shared contract with mobile/src/crisisDetect.ts —
# pinned cross-engine by the JSON fixtures in tests/test_crisis.py and
# mobile/tests/crisisDetect.test.ts).
#
# The 2026-09-16 red-team corpus showed the raw matcher missed: leetspeak
# ("su1c1de"), Cyrillic/Greek homoglyphs ("ѕuicide"), zero-width/soft-hyphen
# injection ("su\u200bicide"), intra-word punctuation ("s.u.i.c.i.d.e"),
# spelled-out splitting ("s u i c i d e"), and every non-English phrase.
# ---------------------------------------------------------------------------

# Format/invisible characters that carry no meaning: soft hyphen, Mongolian
# vowel separator, zero-width joiner/non-joiner/spacer, LRM/RLM, the bidi
# embedding/override/isolate controls, word joiner, invisible separators,
# and the BOM.
_INVISIBLE = dict.fromkeys(map(ord, (
    "\u00ad\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff"
)))

# Latin lookalikes from Cyrillic/Greek (the confusables an attacker can
# actually type on any keyboard). Keys are the post-NFKC lowercase forms;
# the sigma family (final/lunate) is spelled by codepoint — ς, σ and ϲ all
# look like "s".
_HOMOGLYPHS = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ԛ": "q",
    "ԝ": "w", "ѵ": "v", "з": "3",  # з folds to 3, then leet-folds to e
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
    "υ": "u", "ν": "v", "μ": "m", "η": "n", "ω": "w",
    "\u03c2": "s", "\u03c3": "s",  # final/regular sigma: "s"-shaped
    "\u03f2": "c",  # lunate sigma: crescent, impersonates "c"
})

# Leet substitutions applied ONLY between two letters ("k1ll"->"kill" but
# "1 want" keeps its digit, and no date or phone number is rewritten).
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
         "8": "b", "@": "a", "!": "i", "$": "s"}
_LEET_RE = re.compile(r"([a-z])([0-9@!$34578])([a-z])")

# A single-letter token run this long is a spelled-out word ("s u i c i d e"),
# not prose — ordinary English never strings 4+ one-letter words together
# ("i am so sad" keeps its shape; "u s a won gold" is only 3).
_SINGLE_LETTER_JOIN = 4

_PUNCT_TO_SPACE_RE = re.compile(r"[^0-9a-z'\-\s\u00c0-\u02af\u0370-\u03ff"
                                r"\u0400-\u04ff\u0600-\u06ff\u0900-\u097f"
                                r"\u1e00-\u1fff\u3040-\u30ff\u3400-\u9fff"
                                r"\uf900-\ufaff\uff66-\uff9f]")


def _leet_fold(text: str) -> str:
    # Loop until stable: "su1c1de" needs two passes (each replacement makes
    # the next digit newly adjacent to letters).
    while True:
        folded = _LEET_RE.sub(
            lambda m: m.group(1) + _LEET[m.group(2)] + m.group(3), text)
        if folded == text:
            return text
        text = folded


def _normalize_to_tokens(text: str) -> list[str]:
    """The shared pipeline up to (but not including) single-letter joining."""
    out = text.lower()
    out = out.translate(_INVISIBLE)
    # Homoglyphs BEFORE NFKC: NFKC collapses U+03F2 (lunate sigma, "c"-like)
    # into U+03C2 (final sigma, "s"-like) — only the raw codepoints can
    # still tell the two confusable families apart.
    out = out.translate(_HOMOGLYPHS)
    out = unicodedata.normalize("NFKC", out)
    # Curly apostrophe to ASCII before punctuation folding (the patterns'
    # ['\u2019]? classes accept both, but only ASCII ' survives the fold).
    out = out.replace("\u2019", "'")
    out = _leet_fold(out)
    out = _PUNCT_TO_SPACE_RE.sub(" ", out)
    return [t for t in re.split(r"[\s\-]+", out) if t]


def _is_ascii_single(token: str) -> bool:
    # ASCII single letters only — the mobile engine's rule; non-Latin
    # single characters (CJK etc.) never join (parity pinned by tests).
    return len(token) == 1 and "a" <= token <= "z"


def _emit_run(run: list[str], joined: list[str]) -> None:
    if len(run) >= _SINGLE_LETTER_JOIN:
        joined.append("".join(run))
    else:
        joined.extend(run)


def _primary_join(tokens: list[str]) -> str:
    """Join runs of >=4 single-letter tokens: "s u i c i d e" ->
    "suicide" (whitespace- AND hyphen-separated; "c-u-t-t-i-n-g" arrives
    here as single-letter tokens after punctuation folding)."""
    joined: list[str] = []
    run: list[str] = []
    for token in tokens:
        if _is_ascii_single(token):
            run.append(token)
            continue
        _emit_run(run, joined)
        run = []
        joined.append(token)
    _emit_run(run, joined)
    return " ".join(joined)


def normalize_crisis_text(text: str) -> str:
    """Canonical matching form — MUST stay byte-compatible with the mobile
    engine's normalizeCrisisText (the JSON fixtures pin both)."""
    return _primary_join(_normalize_to_tokens(text))


def _orphan_glue(tokens: list[str]) -> str:
    """Evasion variant: a run of 1-3 single-letter tokens glues onto the
    FOLLOWING word ("k ill myself" -> "kill myself", "k i ll myself" ->
    "kill myself"), catching partial splits the >=4 threshold misses.
    Runs of >=4 join as their own word, exactly like the primary variant.
    Safe against ordinary prose ("i am so sad" -> "iam so sad") because
    the result is only ever matched IN ADDITION to the unjoined variant:
    a real crisis phrase still matches there, and no benign sentence
    turns into one ("iwant to diet" matches nothing either way).
    """
    out: list[str] = []
    run: list[str] = []
    for token in tokens:
        if _is_ascii_single(token):
            run.append(token)
            continue
        if len(run) >= _SINGLE_LETTER_JOIN:
            out.append("".join(run))
            out.append(token)
        elif run:
            out.append("".join(run) + token)
        else:
            out.append(token)
        run = []
    out.extend(run)  # a trailing run has nothing to glue onto
    return " ".join(out)


def _mask_benign(variant: str) -> str:
    for compound in BENIGN_COMPOUNDS:
        variant = variant.replace(compound, " ")
    return variant


def _match_variants(text: str) -> tuple[str, ...]:
    """Every normalized form the tiers match against, benign compounds
    masked. MUST stay behavior-compatible with the mobile engine's
    matchVariants (the shared fixtures pin both)."""
    tokens = _normalize_to_tokens(text)
    return (
        _mask_benign(_primary_join(tokens)),
        _mask_benign(_orphan_glue(tokens)),
    )


def matches_dialog(text: str) -> bool:
    """True when the (conservative) client dialog tier fires."""
    return any(DIALOG_RE.search(v) for v in _match_variants(text))


def matches_suppress(text: str) -> bool:
    """True when the (broader) suppression tier fires: never quote this
    back as a pattern card or reflective question."""
    return any(SUPPRESS_RE.search(v) for v in _match_variants(text))
