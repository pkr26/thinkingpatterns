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

2026-09-17 audit remediation (both engines, pinned by the shared corpus):
  * Masking is applied to the PRE-punctuation-fold text and only matches
    compounds whose words are joined by whitespace/hyphens — punctuation
    between the words ("thinking about suicide, silence and pain") is
    NOT the compound, so real ideation adjacent to a masked word can no
    longer be silenced by the mask.
  * CONCAT VARIANT — a third matching form with all whitespace removed,
    matched against space-free copies of the tier patterns. This closes
    every residual split family ("su icide", "ki ll myself",
    "kill my self", "end i t all", "k y s") and plain concatenation
    ("killmyself", "i will killmyself tonight"). Concat patterns ending
    in an extendable word (die/diet, dead/deadline, on/online, ...) keep
    a trailing (?![a-z]) so benign "i wanna diet" cannot fire.
  * Homoglyph map gains Cyrillic к/м and Turkish dotless ı; Latin
    diacritics fold to their base letter (é -> e — "suicidé" fires on
    both engines, not just one); a script boundary between ASCII and
    non-ASCII letters becomes a space so \\b behaves identically under
    Python re (Unicode \\w) and ECMAScript (ASCII \\w).
  * Variation selectors FE00-FE0F, U+034F and the Arabic Letter Mark
    join the invisible set; leet digits also fold at a word's leading
    edge ("5uicide", "$uicide").
"""

from __future__ import annotations

import re
import unicodedata

DIALOG_PATTERNS: tuple[str, ...] = (
    "\\bsuicid(?:e|al)\\b",
    "\\bkill(?:ed|ing)?\\s+myself\\b",
    "\\b(?:wants?|wanted|wanting)\\s+to\\s+die\\b",
    "\\bwanna\\s+(?:to\\s+)?die\\b",
    "\\bwish\\s+(?:i\\s+)?(?:was|were)\\s+dead\\b",
    "\\bwish\\s+(?:i\\s+)?could\\s+die\\b",
    "\\bfeel(?:s|ing)?\\s+like\\s+dying\\b",
    "\\bend(?:ing)?\\s+it\\s+all\\b",
    "\\b(?:end|ended|ending|take|took|taking)\\s+my\\s+(?:own\\s+)?life\\b",
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
    # --- 2026-09-26 full-codebase audit H-1: the EN worth-living family,
    # "no longer want to live", "tired of living", first-person overdose
    # intent, and suicidality — textbook ideation phrasings that matched
    # neither tier (the semantically identical "no reason to live" did). --
    "\\b(?:life|living)(?:['\\u2019]?s)?\\s+(?:(?:is|was|feels?|seems?|sounds?)\\s*)?(?:n['\\u2019]?t|not)\\s+worth\\s+(?:living|it)\\b",
    "\\b(?:life|living)(?:['\\u2019]?s)?\\s+(?:do(?:es)?|did)n['\\u2019]?t\\s+(?:feel|seem|sound)\\s+worth\\s+(?:living|it)\\b",
    "\\bno\\s+longer\\s+want(?:s|ed|ing)?\\s+to\\s+(?:live|be\\s+here|be\\s+alive|exist|wake\\s+up)\\b",
    "\\btired\\s+of\\s+(?:living|life)\\b",
    "\\bwant(?:s|ed|ing)?\\s+to\\s+overdose\\b",
    "\\bsuicidality\\b",
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
    # --- 2026-09-20 audit H-7: the Romance-language suicidio family
    # (suicidio/suicidios/suicidarme/suicidarmi — German suizid fired, the
    # cognates didn't) and Spanish hopelessness phrasing ------------------
    "\\bsuicid(?:io|ios|arme|armi)\\b",
    "\\bno\\s+quiero\\s+vivir\\b",
    "\\bcansad[oa]s?\\s+de\\s+vivir\\b",
    # --- 2026-09-26 full-codebase audit H-1: the Spanish self-harm and
    # hopelessness families — only six ES ideation phrases existed, so
    # "me quiero cortar", "no vale la pena vivir", the conjugated
    # quitar-la-vida forms and a dozen other first-person phrasings fired
    # nothing and could be quoted back on pattern cards. Accented spellings
    # (estarían/mía/más) are written post-fold (é->e normalization). ------
    "\\bno\\s+vale\\s+la\\s+pena\\s+(?:vivir|seguir)\\b",
    "\\bla\\s+vida\\s+no\\s+vale\\s+la\\s+pena\\b",
    "\\b(?:me\\s+)?(?:quiero|quisiera|deberia|podria)\\s+quitar(?:me)?\\s+la\\s+vida\\b",
    "\\bme\\s+voy\\s+a\\s+quitar\\s+la\\s+vida\\b",
    "\\bme\\s+quiero\\s+(?:cortar|lastimar|quemar|ahogar)\\b",
    "\\bquiero\\s+(?:matarme|cortarme|lastimarme|quemarme|ahogarme)\\b",
    "\\bme\\s+(?:lastimo|hago\\s+da[nñ]o|corto\\s+la\\s+piel|quemo\\s+la\\s+piel)\\b",
    "\\b(?:quiero|quisiera)\\s+hacerme\\s+da[nñ]o\\b",
    "\\bno\\s+hay\\s+salida\\b",
    "\\b(?:quiero|quisiera)\\s+desaparecer\\b",
    "\\b(?:todos|el\\s+mundo)\\s+estarian\\s+mejor\\s+sin\\s+mi\\b",
    "\\bno\\s+tengo\\s+ganas\\s+de\\s+vivir\\b",
    "\\bhart[oa]s?\\s+de\\s+(?:la\\s+)?vida\\b",
    "\\b(?:solo\\s+)?quiero\\s+dormir\\s+para\\s+siempre\\b",
    "\\bno\\s+(?:puedo|aguanto)\\s+mas\\b",
    "\\bno\\s+quiero\\s+(?:despertar|despertarme|seguir\\s+viviendo)\\b",
    # --- non-Latin scripts: plain substrings (\\b never fires next to
    #     CJK/Arabic/Devanagari in ECMAScript) --------------------------------
    "我想死",
    "我想去死",
    "自杀",
    "死にたい",
    "自殺",
    "자살하고 싶다",
    "죽고 싶다",
    "أريد أن أموت",
    "أريد أن أنتحر",
    "मरना चाहता",
    "मरना चाहती",
    # --- Turkish (Latin script; 2026-09-17 audit: ı/é parity pinned) --------
    "\\bintihar\\s+etmek\\s+istiyorum\\b",
    "\\bcanını\\s+almak\\s+istiyorum\\b",
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
    # --- 2026-09-26 audit H-1: suppress-only counterparts (broader, never
    # the dialog) for the worth-living and Spanish families ---------------
    "\\bnot\\s+worth\\s+living\\b",
    "\\bno\\s+vale\\s+la\\s+pena\\b",
    "\\bquitar(?:le|me|se)?\\s+la\\s+vida\\b",
    "\\bhacer(?:le|me|se)\\s+da[nñ]o\\b",
)

# The effective suppression tier: dialog + suppress_extra (per the JSON).
SUPPRESS_PATTERNS: tuple[str, ...] = DIALOG_PATTERNS + SUPPRESS_EXTRA_PATTERNS

# Multiword titles/causes masked from BOTH tiers before matching: the bare
# topic word inside them is not first-person ideation ("that movie was
# suicide squad" must not fire the dialog tier; "we discussed suicide
# prevention in class" either). Masked on the pre-punctuation-fold text as
# whole words joined by whitespace/hyphens (see _match_variants) — a comma
# between the words is NOT the compound, so "...suicide, silence and pain"
# still fires. Any genuine crisis phrasing around them ("...makes me want
# to die") matches on its own.
BENIGN_COMPOUNDS: tuple[str, ...] = (
    "suicide squad",
    "suicide silence",
    "suicideboys",
    "suicide prevention",
    "suicide awareness",
    # 2026-09-20 audit L-23: the prevention-campaign mask was English-only —
    # "我们讨论了自杀预防" (we discussed suicide prevention) fired, and
    # Spanish classroom mentions had no mask at all. Post-fold spellings
    # (no diacritics): masking runs after Latin-mark folding. Other
    # languages keep the accepted-FP posture (documented trade-off).
    "自杀预防",
    "prevencion del suicidio",
    "prevencion de suicidio",
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
# the BOM — plus (2026-09-17 audit) the combining grapheme joiner, the
# Arabic Letter Mark, and the variation selectors (FE0F rides along with
# emoji, so it lands inside typed words).
_INVISIBLE = dict.fromkeys(
    [
        ord(c)
        for c in (
            "\u00ad\u034f\u061c\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b"
            "\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u2065\u2066\u2067"
            "\u2068\u2069\ufeff"
        )
    ]
    + list(range(0xFE00, 0xFE10))
)

# Latin lookalikes from Cyrillic/Greek (the confusables an attacker can
# actually type on any keyboard), plus (2026-09-17 audit) Cyrillic к/м and
# the Turkish dotless ı — without ı, Python's Unicode case-insensitive re
# fires on "kıll myself" while ECMAScript does not, splitting the engines.
# Keys are the post-NFKC lowercase forms; the sigma family (final/lunate)
# is spelled by codepoint — ς, σ and ϲ all look like "s".
#
# 2026-09-26 audit L-2: the two exotic Latin "s" lookalikes that NFKC does
# NOT fold — U+0282 ʂ (s with hook) and U+1D74 ᵴ (s with middle tilde) —
# so "ʂuicide"/"ᵴuicide" read as plain "suicide". Deliberately NOT added:
# U+1D62 ᵢ and U+1D69 ᵩ — both NFKC-decompose (to "i" and Greek φ
# respectively), so the normalize step below already handles them and a
# map entry would be redundant; each candidate here was verified with
# unicodedata to have no NFKC decomposition.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "с": "c",
        "е": "e",
        "о": "o",
        "р": "p",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "ј": "j",
        "һ": "h",
        "ԁ": "d",
        "ɡ": "g",
        "ԛ": "q",
        "ԝ": "w",
        "ѵ": "v",
        "з": "3",  # з folds to 3, then leet-folds to e
        "к": "k",
        "м": "m",
        "ı": "i",
        "ο": "o",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "ν": "v",
        "μ": "m",
        "η": "n",
        "ω": "w",
        "\u03c2": "s",
        "\u03c3": "s",  # final/regular sigma: "s"-shaped
        "\u03f2": "c",  # lunate sigma: crescent, impersonates "c"
        "\u0282": "s",  # ʂ s with hook (2026-09-26 audit L-2; no NFKC fold)
        "\u1d74": "s",  # ᵴ s with middle tilde (2026-09-26 audit L-2; no NFKC fold)
    }
)

# Leet substitutions applied ONLY between two letters ("k1ll"->"kill" but
# "1 want" keeps its digit, and no date or phone number is rewritten), or
# at a word's leading edge ("5uicide" -> "suicide") — a leading digit is
# never part of a number the way a trailing one can be. The regex classes
# list EXACTLY the mapped characters: 2, 6 and 9 are deliberately unmapped
# (each is ambiguous leet: 2=z, 6=b/g, 9=g/q), and a class wider than the
# map would look the unmapped digit up and crash (2026-09-17 audit: the
# old [0-9@!$34578] class matched them — "grade6test" raised KeyError and
# bricked every recompute for the account).
_LEET = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "!": "i",
    "$": "s",
}
_LEET_RE = re.compile(r"([a-z])([0134578@!$])([a-z])")
_LEET_EDGE_RE = re.compile(r"(^|\s)([0134578@!$])([a-z])")
# 2026-09-20 audit H-7: mapped digits also fold at a word's TRAILING edge
# ("suicid3" -> "suicide"; "d13" -> "die" inside a phrase). The lookahead
# accepts any non-letter or end-of-string so "suicid3!" folds too (punctuation
# is folded to spaces only later). The class still lists exactly the mapped
# characters — 2/6/9 stay digits ("grade6test" is untouched).
_LEET_TRAIL_RE = re.compile(r"([a-z])([0134578@!$]+)(?=[^a-z]|$)")

# A single-letter token run this long is a spelled-out word ("s u i c i d e"),
# not prose — ordinary English never strings 4+ one-letter words together
# ("i am so sad" keeps its shape; "u s a won gold" is only 3).
_SINGLE_LETTER_JOIN = 4

_PUNCT_TO_SPACE_RE = re.compile(
    r"[^0-9a-z'\-\s\u00c0-\u02af\u0370-\u03ff"
    r"\u0400-\u04ff\u0600-\u06ff\u0900-\u097f"
    r"\u1e00-\u1fff\u3040-\u30ff\u3400-\u9fff"
    r"\uac00-\ud7af\uf900-\ufaff\uff66-\uff9f]"
)


def _leet_fold(text: str) -> str:
    # Loop until stable: "su1c1de" needs two passes (each replacement makes
    # the next digit newly adjacent to letters).
    while True:
        folded = _LEET_RE.sub(lambda m: m.group(1) + _LEET[m.group(2)] + m.group(3), text)
        folded = _LEET_EDGE_RE.sub(lambda m: m.group(1) + _LEET[m.group(2)] + m.group(3), folded)
        folded = _LEET_TRAIL_RE.sub(
            lambda m: m.group(1) + "".join(_LEET[c] for c in m.group(2)), folded
        )
        if folded == text:
            return text
        text = folded


def _fold_latin_marks(text: str) -> str:
    """é -> e, but only for Latin: a mark folded off a Devanagari letter
    would break the non-Latin patterns, so only a decomposable char whose
    BASE is Latin (below U+0250) and whose remainder is combining marks
    in the U+0300 block is reduced. Without this, "suicidé" fires the
    Python suppress tier but not the ECMAScript one (é is \\w in re,
    non-word in JS)."""
    out: list[str] = []
    for ch in text:
        decomposed = unicodedata.normalize("NFKD", ch)
        base = decomposed[0]
        if (
            len(decomposed) > 1
            and ord(base) < 0x0250
            and all("\u0300" <= c <= "\u036f" for c in decomposed[1:])
        ):
            out.append(base)
        else:
            out.append(ch)
    return "".join(out)


# A letter/digit sitting directly against a non-ASCII letter is a script
# boundary: separate them with a space so \b means the same thing under
# Python re (Unicode \w: "suicideम" has NO boundary after "suicide") and
# ECMAScript (ASCII \w: it does). Both engines then agree on every input.
_SCRIPT_BOUNDARY_RE = re.compile(r"([a-z0-9])([^\x00-\x7f])")
_SCRIPT_BOUNDARY_RE2 = re.compile(r"([^\x00-\x7f])([a-z0-9])")


def _normalize_pre_punct(text: str) -> str:
    """The shared pipeline up to (but not including) the punctuation fold.
    Benign-compound masking runs HERE (see _match_variants): at this point
    a comma between two words is still a comma, so "suicide, silence"
    cannot be mistaken for the compound "suicide silence"."""
    out = text.lower()
    out = out.translate(_INVISIBLE)
    # Homoglyphs BEFORE NFKC: NFKC collapses U+03F2 (lunate sigma, "c"-like)
    # into U+03C2 (final sigma, "s"-like) — only the raw codepoints can
    # still tell the two confusable families apart.
    out = out.translate(_HOMOGLYPHS)
    out = unicodedata.normalize("NFKC", out)
    out = _fold_latin_marks(out)
    # Curly apostrophe to ASCII before punctuation folding (the patterns'
    # ['\u2019]? classes accept both, but only ASCII ' survives the fold).
    out = out.replace("\u2019", "'")
    out = _SCRIPT_BOUNDARY_RE.sub(r"\1 \2", out)
    out = _SCRIPT_BOUNDARY_RE2.sub(r"\1 \2", out)
    out = _leet_fold(out)
    return out


def _normalize_to_tokens(text: str) -> list[str]:
    out = _PUNCT_TO_SPACE_RE.sub(" ", _normalize_pre_punct(text))
    tokens = [t for t in re.split(r"[\s\-]+", out) if t]
    # 2026-09-20 audit H-7: SMS shorthand — a standalone "2" token IS "to"
    # ("i want 2 die", "no reason 2 live"). Folded at the TOKEN level, so 2
    # stays an unmapped leet digit everywhere else (2=z is ambiguous).
    return ["to" if t == "2" else t for t in tokens]


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
    A TRAILING run (no following word to glue onto) joins into its own
    word — "k y s" -> "kys". Safe against ordinary prose ("i am so sad"
    -> "iam so sad") because the result is only ever matched IN ADDITION
    to the unjoined variant: a real crisis phrase still matches there,
    and no benign sentence turns into one ("iwant to diet" matches
    nothing either way).
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
    if run:
        out.append("".join(run))
    return " ".join(out)


def _concat_join(tokens: list[str]) -> str:
    """Evasion variant: every token joined with no separator at all.
    Splits leave the fragments ("su icide"), and plain concatenation
    ("killmyself"), as recoverable substrings; matched against
    space-free copies of the tier patterns (see _concat_pattern)."""
    return "".join(tokens)


# Concat-pattern endings that must keep a trailing boundary: these words
# extend into benign ones once the spaces are gone (die->diet,
# dead->deadline, on->online, up->upon, out->outfield, cutting->cutting
# board), so an unanchored substring match would fire on ordinary text.
# Every other ending ("myself", "suicide", "everything", ...) has no
# benign extension worth fearing, and the anchor would only create misses.
_CONCAT_ANCHORED_ENDINGS: tuple[str, ...] = (
    "die",
    "dead",
    "cutting",
    "gone",
    "on",
    "up",
    "out",
)


def _concat_pattern(pattern: str) -> str:
    """The space-free twin of a tier pattern: \\s+ and \\b removed (a
    boundary can never fire inside concatenated text), plus a trailing
    (?![a-z]) when the pattern's final literal word is extendable."""
    src = pattern.replace(r"\s+", "").replace(r"\b", "")
    m = re.search(r"([a-z]+)\)?$", src)
    if m and m.group(1).endswith(_CONCAT_ANCHORED_ENDINGS):
        src += "(?![a-z])"
    return src


DIALOG_CONCAT_RE = _compile_tier(tuple(_concat_pattern(p) for p in DIALOG_PATTERNS))
SUPPRESS_CONCAT_RE = _compile_tier(tuple(_concat_pattern(p) for p in SUPPRESS_PATTERNS))


# Benign compounds are masked on the PRE-punctuation-fold text, matched as
# whole words joined by whitespace/hyphens only: punctuation between the
# words ("suicide, silence") is not the compound, so real ideation next to
# a masked word cannot be silenced. Longest-first so "suicide squad" can
# never eat only half of a longer entry. Non-ASCII compounds (CJK, 2026-09
# -20 audit L-23) are masked as plain substrings: \b never fires next to
# CJK in either engine, so the anchored form would never match at all.
def _benign_mask(compound: str) -> re.Pattern[str]:
    words = compound.split()
    if all(word.isascii() for word in words):
        return re.compile(
            r"\b" + r"[\s\-]+".join(re.escape(word) for word in words) + r"\b",
            re.IGNORECASE,
        )
    return re.compile(re.escape(" ".join(words)), re.IGNORECASE)


_BENIGN_MASK_RES: tuple[re.Pattern[str], ...] = tuple(
    _benign_mask(compound) for compound in sorted(BENIGN_COMPOUNDS, key=len, reverse=True)
)


def _mask_benign(text: str) -> str:
    for mask in _BENIGN_MASK_RES:
        text = mask.sub(" ", text)
    return text


# --- 2026-09-20 audit H-7: letter-doubling ---------------------------------
# "kiill myself" / "suiccide" (a letter typed twice) matched NO tier and no
# variant: the doubled run is not a split, not leet, not a homoglyph. The
# fix is a fourth matching channel folded on BOTH sides: the normalized
# text with same-letter runs collapsed ("kiill myself" -> "kil myself")
# matched against tier twins folded the same way ("kill(?:ed|ing)?
# myself" -> "kil(?:ed|ing)? myself"). Folding both sides is what keeps
# canonically double-lettered words working ("kill", "sleep", "cannot"
# fold on the pattern side exactly as the text does). ASCII letters only:
# regex metacharacters, \s/\b escapes, classes and non-Latin scripts are
# never part of a collapsed run, so a folded pattern stays a valid
# pattern with unchanged anchors.
_LETTER_RUN_RE = re.compile(r"([a-z])\1+")


def _dedup_fold(text: str) -> str:
    return _LETTER_RUN_RE.sub(r"\1", text)


# The one pattern exempt from the folded tier: "off(?:ing)? myself" folds
# to "of(?:ing)? myself", which matches ordinary prose ("ashamed of
# myself", "tired of myself"). Its unfolded form keeps matching as
# before; doubled spellings of it ("offfing myself") stay accepted misses
# rather than risk a dialog false positive on a benign sentence.
_FOLD_EXEMPT: frozenset[str] = frozenset({"\\boff(?:ing)?\\s+myself\\b"})

DIALOG_FOLDED_RE = _compile_tier(
    tuple(_dedup_fold(p) for p in DIALOG_PATTERNS if p not in _FOLD_EXEMPT)
)
SUPPRESS_FOLDED_RE = _compile_tier(
    tuple(_dedup_fold(p) for p in SUPPRESS_PATTERNS if p not in _FOLD_EXEMPT)
)
DIALOG_FOLDED_CONCAT_RE = _compile_tier(
    tuple(_concat_pattern(_dedup_fold(p)) for p in DIALOG_PATTERNS if p not in _FOLD_EXEMPT)
)
SUPPRESS_FOLDED_CONCAT_RE = _compile_tier(
    tuple(_concat_pattern(_dedup_fold(p)) for p in SUPPRESS_PATTERNS if p not in _FOLD_EXEMPT)
)

# The benign compounds re-mask on the FOLDED text with their own folded
# spellings ("awareness" -> "awarenes"): bare "suicide" is a dialog
# pattern, so "suicide awareness" must stay masked in the folded channel
# — including when the doubling is what hid it ("suiciide squaad").
_BENIGN_MASK_FOLDED_RES: tuple[re.Pattern[str], ...] = tuple(
    _benign_mask(folded)
    for folded in sorted((_dedup_fold(c) for c in BENIGN_COMPOUNDS), key=len, reverse=True)
)


def _folded_variants(text: str) -> tuple[str, ...]:
    """The letter-run-collapsed twins of the three canonical variants
    (audit H-7). Matched only against the FOLDED tier twins above — the
    canonical channel is untouched, so every pre-existing verdict keeps
    its exact form."""
    pre = _mask_benign(_normalize_pre_punct(text))
    folded = _dedup_fold(pre)
    for mask in _BENIGN_MASK_FOLDED_RES:
        folded = mask.sub(" ", folded)
    tokens = _normalize_to_tokens(folded)
    return (
        _primary_join(tokens),
        _orphan_glue(tokens),
        _concat_join(tokens),
    )


def _match_variants(text: str) -> tuple[str, ...]:
    """Every normalized form the tiers match against. MUST stay
    behavior-compatible with the mobile engine's matchVariants (the shared
    fixtures pin both)."""
    tokens = _normalize_to_tokens(_mask_benign(_normalize_pre_punct(text)))
    return (
        _primary_join(tokens),
        _orphan_glue(tokens),
        _concat_join(tokens),
    )


def matches_dialog(text: str) -> bool:
    """True when the (conservative) client dialog tier fires."""
    variants = _match_variants(text)
    if any(DIALOG_RE.search(v) for v in variants[:2]) or DIALOG_CONCAT_RE.search(variants[2]):
        return True
    # H-7 letter-doubling channel: only reached when the canonical forms
    # are clean, so it can only ever ADD a catch.
    folded = _folded_variants(text)
    return bool(
        any(DIALOG_FOLDED_RE.search(v) for v in folded[:2])
        or DIALOG_FOLDED_CONCAT_RE.search(folded[2])
    )


def matches_suppress(text: str) -> bool:
    """True when the (broader) suppression tier fires: never quote this
    back as a pattern card or reflective question."""
    variants = _match_variants(text)
    if any(SUPPRESS_RE.search(v) for v in variants[:2]) or SUPPRESS_CONCAT_RE.search(variants[2]):
        return True
    folded = _folded_variants(text)
    return bool(
        any(SUPPRESS_FOLDED_RE.search(v) for v in folded[:2])
        or SUPPRESS_FOLDED_CONCAT_RE.search(folded[2])
    )
