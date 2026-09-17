/**
 * On-device crisis-language detection.
 *
 * Entries are encrypted before anything leaves the phone, so the server
 * CANNOT notice a crisis — detection has to happen here, client-side and
 * pre-encryption, or it does not happen at all. This matcher runs in
 * memory over the plaintext the user just typed. Nothing is sent, stored,
 * or logged: the caller shows support resources and forgets the result.
 *
 * The phrase lists come from src/crisisPhrases.ts, the embedded copy of
 * shared/crisis_phrases.json (the cross-platform source of truth — see
 * that file's header for the embed + parity-test pattern). Two tiers:
 *
 *  - detectCrisisLanguage (the DIALOG tier) is deliberately conservative:
 *    it fires on high-signal phrases and errs toward false positives over
 *    misses (a false positive costs one gentle dialog; a miss costs a
 *    life). It stays phrase-based — not single common words — so everyday
 *    journaling ("the assessment was brutal", "that killed my mood") does
 *    not trip it.
 *
 *  - matchesCrisisSuppress (the SUPPRESS tier = dialog + suppress_extra)
 *    is deliberately broader: it powers non-quoting rendering for
 *    crisis-adjacent patterns (a card that acknowledges the pattern
 *    without quoting the phrase back) and question suppression. A false
 *    positive there only means a pattern is not quoted.
 *
 * Accepted false positives of the dialog tier (documented, not shipped as
 *  sloppy regexes):
 *  - Any use of the word "suicide"/"suicidal" in first-person or bare
 *    context. Multiword benign compounds are masked first (see
 *    CRISIS_BENIGN_COMPOUNDS: "suicide squad", "suicide prevention",
 *    ...), so everyday pop-culture and classroom mentions stay silent;
 *    every other mention still fires.
 *  - "cut myself" / "cutting myself" fires even in benign grooming or
 *    kitchen contexts ("I cut myself shaving"). Enumerating benign
 *    follow-up contexts with a lookahead would be an incomplete blocklist
 *    pretending to be precision; in a private journal the bare statement
 *    is high-signal, and the cost is one gentle dialog.
 *  - "feel like dying" fires on "dying of embarrassment/laughter"-style
 *    hyperbole when written with "feel like" ("I feel like dying after
 *    that workout"). Without the "feel like" anchor, "dying of laughter"
 *    does NOT fire.
 *
 * iOS Smart Punctuation note: iOS keyboards substitute the curly
 * apostrophe U+2019 for ASCII ' by default, so every apostrophe-tolerant
 * pattern accepts BOTH characters (the ['’]? classes in the shared
 * list) — otherwise "I can't go on" typed on an iPhone silently missed
 * detection.
 */
import { CRISIS_BENIGN_COMPOUNDS, CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS } from "./crisisPhrases";

/** Compiled once at module load; every pattern in the shared contract is
 *  guaranteed lookahead-free and dual-engine (Python re + ECMAScript). */
const DIALOG_PATTERNS: readonly RegExp[] = CRISIS_DIALOG_PATTERNS.map((pattern) => new RegExp(pattern, "i"));

/** The suppress tier is dialog + suppress_extra — one compiled list. */
const SUPPRESS_PATTERNS: readonly RegExp[] = [
  ...CRISIS_DIALOG_PATTERNS,
  ...CRISIS_SUPPRESS_EXTRA_PATTERNS,
].map((pattern) => new RegExp(pattern, "i"));

// ---------------------------------------------------------------------------
// Normalization pipeline — the shared contract with the backend's
// app/services/crisis.py (pinned cross-engine by shared/crisis_phrases.json
// fixtures replayed in both test suites). Added by the 2026-09-16 red-team
// remediation: leetspeak ("su1c1de"), homoglyphs ("ѕuicide"), zero-width
// and soft-hyphen injection, and intra-word separators ("s.u.i.c.i.d.e")
// all bypassed the raw matcher on BOTH engines.
// ---------------------------------------------------------------------------

/** Format/invisible characters that carry no meaning (zero-width, bidi,
 *  soft hyphen, BOM, ...), plus the 2026-09-17 audit additions: the
 *  combining grapheme joiner, the Arabic Letter Mark, and the variation
 *  selectors (FE0F rides along with emoji, so it lands inside typed
 *  words). */
const INVISIBLE = /[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufe00-\ufe0f\ufeff]/g;

/** Latin lookalikes from Cyrillic/Greek, by codepoint. NOTE: sigmas are
 *  mapped BEFORE NFKC — NFKC collapses U+03F2 (lunate sigma, "c"-shaped)
 *  into U+03C2 (final sigma, "s"-shaped), and only the raw codepoints can
 *  tell the two confusable families apart. 2026-09-17 audit: Cyrillic к/м
 *  and the Turkish dotless ı join the map — without ı, Python's Unicode
 *  case-insensitive re fires on "kıll myself" while ECMAScript does not. */
const HOMOGLYPHS: Record<string, string> = {
  "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p",
  "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
  "\u04bb": "h", "\u0501": "d", "\u0261": "g", "\u051b": "q", "\u051d": "w",
  "\u0475": "v", "\u0437": "3", // з folds to 3, then leet-folds to e
  "\u043a": "k", "\u043c": "m", "\u0131": "i",
  "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
  "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03bd": "v", "\u03bc": "m",
  "\u03b7": "n", "\u03c9": "w",
  "\u03c2": "s", "\u03c3": "s", // final/regular sigma: "s"-shaped
  "\u03f2": "c",                // lunate sigma: crescent, impersonates "c"
};

/** Leet substitutions applied ONLY between two letters ("k1ll" -> "kill"
 *  but "1 want" keeps its digit), or at a word's leading edge
 *  ("5uicide" -> "suicide") — a leading digit is never part of a number
 *  the way a trailing one can be. */
const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
  "@": "a", "!": "i", $: "s",
};
const LEET_RE = /([a-z])([0-9@!$34578])([a-z])/g;
const LEET_EDGE_RE = /(^|\s)([0-9@!$34578])([a-z])/g;

/** Punctuation becomes a space; letters (any script), digits, ASCII
 *  apostrophes and hyphens survive (Hangul syllables included — a Korean
 *  journal must not fold to blank space). */
const PUNCT_TO_SPACE =
  /[^0-9a-z'\-\s\u00c0-\u02af\u0370-\u04ff\u0600-\u06ff\u0900-\u097f\u1e00-\u1fff\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af\uf900-\ufaff\uff66-\uff9f]/g;

/** A single-letter token run this long is a spelled-out word ("s u i c i d
 *  e"), not prose — ordinary English never strings 4+ one-letter words
 *  together ("i am so sad" keeps its shape; "u s a won gold" is only 3). */
const SINGLE_LETTER_JOIN = 4;

function leetFold(text: string): string {
  // Loop until stable: "su1c1de" needs two passes (each replacement makes
  // the next digit newly adjacent to letters).
  for (;;) {
    let folded = text.replace(LEET_RE, (_m, a: string, d: string, b: string) => a + LEET[d] + b);
    folded = folded.replace(LEET_EDGE_RE, (_m, ws: string, d: string, c: string) => ws + LEET[d] + c);
    if (folded === text) return text;
    text = folded;
  }
}

/** é -> e, but only for Latin: a mark folded off a Devanagari letter would
 *  break the non-Latin patterns, so only a decomposable char whose BASE is
 *  Latin (below U+0250) and whose remainder is combining marks in the
 *  U+0300 block is reduced. Without this, "suicidé" fires the Python
 *  suppress tier but not this engine (é is \w in Python re, non-word in
 *  ECMAScript). */
function foldLatinMarks(text: string): string {
  let out = "";
  for (const ch of text) {
    const decomposed = ch.normalize("NFKD");
    const base = decomposed[0];
    if (
      decomposed.length > 1 && base !== undefined && base < "\u0250" &&
      /^[\u0300-\u036f]+$/.test(decomposed.slice(1))
    ) {
      out += base;
    } else {
      out += ch;
    }
  }
  return out;
}

// A letter/digit sitting directly against a non-ASCII letter is a script
// boundary: separate them with a space so \b means the same thing under
// Python re (Unicode \w: "suicideम" has NO boundary after "suicide") and
// ECMAScript (ASCII \w: it does). Both engines then agree on every input.
const SCRIPT_BOUNDARY_1 = /([a-z0-9])([^\x00-\x7f])/g;
const SCRIPT_BOUNDARY_2 = /([^\x00-\x7f])([a-z0-9])/g;

/** The shared pipeline up to (but not including) the punctuation fold.
 *  Benign-compound masking runs HERE (see matchVariants): at this point a
 *  comma between two words is still a comma, so "suicide, silence" cannot
 *  be mistaken for the compound "suicide silence". */
function normalizePrePunct(text: string): string {
  let out = text
    .toLowerCase()
    .replace(INVISIBLE, "")
    .replace(/[\u0131\u0250-\u02ff\u0370-\u052f]/g, (ch) => HOMOGLYPHS[ch] ?? ch)
    .normalize("NFKC")
    .replace(/\u2019/g, "'");
  out = foldLatinMarks(out);
  out = out.replace(SCRIPT_BOUNDARY_1, "$1 $2").replace(SCRIPT_BOUNDARY_2, "$1 $2");
  return leetFold(out);
}

/** Canonical matching form — MUST stay byte-compatible with the backend's
 *  normalize_crisis_text (the JSON fixtures pin both engines). Exported for
 *  tests and for the phrase-contract parity suite. */
export function normalizeCrisisText(text: string): string {
  return primaryJoin(normalizeToTokens(text));
}

/** The shared pipeline from pre-punct form to tokens. */
function normalizeToTokens(text: string): string[] {
  const out = normalizePrePunct(text).replace(PUNCT_TO_SPACE, " ");
  return out.split(/[\s-]+/).filter((t) => t.length > 0);
}

/** ASCII single letters only — the backend engine's rule; non-Latin
 *  single characters (CJK etc.) never join (parity pinned by tests). */
function isAsciiSingle(token: string): boolean {
  return token.length === 1 && token >= "a" && token <= "z";
}

/** Join runs of >=4 single-letter tokens: "s u i c i d e" -> "suicide". */
function primaryJoin(tokens: string[]): string {
  const joined: string[] = [];
  let run: string[] = [];
  const flush = () => {
    if (run.length >= SINGLE_LETTER_JOIN) joined.push(run.join(""));
    else joined.push(...run);
    run = [];
  };
  for (const token of tokens) {
    if (isAsciiSingle(token)) {
      run.push(token);
      continue;
    }
    flush();
    joined.push(token);
  }
  flush();
  return joined.join(" ").trim();
}

/** Evasion variant: a run of 1-3 single-letter tokens glues onto the
 *  FOLLOWING word ("k ill myself" -> "kill myself", "k i ll myself" ->
 *  "kill myself"), catching partial splits the >=4 threshold misses.
 *  Runs of >=4 join as their own word, exactly like the primary variant.
 *  A TRAILING run (no following word to glue onto) joins into its own
 *  word — "k y s" -> "kys". Safe against ordinary prose ("i am so sad"
 *  -> "iam so sad") because the result is only ever matched IN ADDITION
 *  to the unjoined variant: a real crisis phrase still matches there,
 *  and no benign sentence turns into one ("iwant to diet" matches
 *  nothing either way). */
function orphanGlue(tokens: string[]): string {
  const out: string[] = [];
  let run: string[] = [];
  for (const token of tokens) {
    if (isAsciiSingle(token)) {
      run.push(token);
      continue;
    }
    if (run.length >= SINGLE_LETTER_JOIN) {
      out.push(run.join(""), token);
    } else if (run.length > 0) {
      out.push(run.join("") + token);
    } else {
      out.push(token);
    }
    run = [];
  }
  if (run.length > 0) out.push(run.join("")); // a trailing run joins into its own word
  return out.join(" ").trim();
}

/** Evasion variant: every token joined with no separator at all. Splits
 *  leave the fragments ("su icide"), and plain concatenation
 *  ("killmyself"), as recoverable substrings; matched against space-free
 *  copies of the tier patterns (see concatPattern). */
function concatJoin(tokens: string[]): string {
  return tokens.join("");
}

/** Concat-pattern endings that must keep a trailing boundary: these words
 *  extend into benign ones once the spaces are gone (die->diet,
 *  dead->deadline, on->online, up->upon, out->outfield, cutting->cutting
 *  board), so an unanchored substring match would fire on ordinary text.
 *  Every other ending ("myself", "suicide", ...) has no benign extension
 *  worth fearing, and the anchor would only create misses. */
const CONCAT_ANCHORED_ENDINGS = ["die", "dead", "cutting", "gone", "on", "up", "out"];

/** The space-free twin of a tier pattern: \s+ and \b removed (a boundary
 *  can never fire inside concatenated text), plus a trailing (?![a-z])
 *  when the pattern's final literal word is extendable. MUST mirror the
 *  backend's _concat_pattern. */
function concatPattern(pattern: string): string {
  let src = pattern.split("\\s+").join("").split("\\b").join("");
  const m = src.match(/([a-z]+)\)?$/);
  const lastWord = m?.[1];
  if (lastWord !== undefined && CONCAT_ANCHORED_ENDINGS.some((e) => lastWord.endsWith(e))) {
    src += "(?![a-z])";
  }
  return src;
}

/** Concat-tier matchers: the third variant matched against space-free
 *  pattern twins. Compiled once at module load. */
const DIALOG_CONCAT_PATTERNS: readonly RegExp[] = CRISIS_DIALOG_PATTERNS.map(
  (p) => new RegExp(concatPattern(p), "i"),
);
const SUPPRESS_CONCAT_PATTERNS: readonly RegExp[] = [
  ...CRISIS_DIALOG_PATTERNS,
  ...CRISIS_SUPPRESS_EXTRA_PATTERNS,
].map((p) => new RegExp(concatPattern(p), "i"));

/** Benign compounds are masked on the PRE-punctuation-fold text, matched
 *  as whole words joined by whitespace/hyphens only: punctuation between
 *  the words ("suicide, silence") is not the compound, so real ideation
 *  next to a masked word cannot be silenced. Longest-first so
 *  "suicide squad" can never eat only half of a longer entry. */
const BENIGN_MASKS: readonly RegExp[] = [...CRISIS_BENIGN_COMPOUNDS]
  .sort((a, b) => b.length - a.length)
  .map((compound) =>
    new RegExp(`\\b${compound.split(/\s+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[\\s\\-]+")}\\b`, "gi"),
  );

function maskBenign(text: string): string {
  let out = text;
  for (const mask of BENIGN_MASKS) out = out.replace(mask, " ");
  return out;
}

/** Every normalized form the tiers match against — MUST stay
 *  behavior-compatible with the backend's _match_variants (the shared
 *  fixtures pin both engines). Exported for the parity suite. */
export function matchVariants(text: string): [string, string, string] {
  const tokens = normalizeToTokens(maskBenign(normalizePrePunct(text)));
  return [primaryJoin(tokens), orphanGlue(tokens), concatJoin(tokens)];
}

/** True when `text` contains crisis language (dialog tier — fire the
 *  gentle support dialog). Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  const [primary, orphan, concat] = matchVariants(text);
  return (
    DIALOG_PATTERNS.some((p) => p.test(primary) || p.test(orphan)) ||
    DIALOG_CONCAT_PATTERNS.some((p) => p.test(concat))
  );
}

/** True when `text` belongs to the broader suppression tier — the caller
 *  renders a NON-QUOTING card (or suppresses a generated question) for
 *  crisis-adjacent patterns. Pure: no I/O, no state. */
export function matchesCrisisSuppress(text: string): boolean {
  const [primary, orphan, concat] = matchVariants(text);
  return (
    SUPPRESS_PATTERNS.some((p) => p.test(primary) || p.test(orphan)) ||
    SUPPRESS_CONCAT_PATTERNS.some((p) => p.test(concat))
  );
}
