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
 *  soft hyphen, BOM, ...). */
const INVISIBLE = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;

/** Latin lookalikes from Cyrillic/Greek, by codepoint. NOTE: sigmas are
 *  mapped BEFORE NFKC — NFKC collapses U+03F2 (lunate sigma, "c"-shaped)
 *  into U+03C2 (final sigma, "s"-shaped), and only the raw codepoints can
 *  tell the two confusable families apart. */
const HOMOGLYPHS: Record<string, string> = {
  "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p",
  "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
  "\u04bb": "h", "\u0501": "d", "\u0261": "g", "\u051b": "q", "\u051d": "w",
  "\u0475": "v", "\u0437": "3", // з folds to 3, then leet-folds to e
  "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
  "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03bd": "v", "\u03bc": "m",
  "\u03b7": "n", "\u03c9": "w",
  "\u03c2": "s", "\u03c3": "s", // final/regular sigma: "s"-shaped
  "\u03f2": "c",                // lunate sigma: crescent, impersonates "c"
};

/** Leet substitutions applied ONLY between two letters ("k1ll" -> "kill"
 *  but "1 want" keeps its digit). */
const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
  "@": "a", "!": "i", $: "s",
};
const LEET_RE = /([a-z])([0-9@!$34578])([a-z])/g;

/** Punctuation becomes a space; letters (any script), digits, ASCII
 *  apostrophes and hyphens survive. */
const PUNCT_TO_SPACE =
  /[^0-9a-z'\-\s\u00c0-\u02af\u0370-\u04ff\u0600-\u06ff\u0900-\u097f\u1e00-\u1fff\u3040-\u30ff\u3400-\u9fff\uf900-\ufaff\uff66-\uff9f]/g;

/** A single-letter token run this long is a spelled-out word ("s u i c i d
 *  e"), not prose — ordinary English never strings 4+ one-letter words
 *  together ("i am so sad" keeps its shape; "u s a won gold" is only 3). */
const SINGLE_LETTER_JOIN = 4;

function leetFold(text: string): string {
  // Loop until stable: "su1c1de" needs two passes (each replacement makes
  // the next digit newly adjacent to letters).
  for (;;) {
    const folded = text.replace(LEET_RE, (_m, a: string, d: string, b: string) => a + LEET[d] + b);
    if (folded === text) return text;
    text = folded;
  }
}

/** Canonical matching form — MUST stay byte-compatible with the backend's
 *  normalize_crisis_text (the JSON fixtures pin both engines). Exported for
 *  tests and for the phrase-contract parity suite. */
export function normalizeCrisisText(text: string): string {
  return primaryJoin(normalizeToTokens(text));
}

/** The shared pipeline up to (but not including) single-letter joining. */
function normalizeToTokens(text: string): string[] {
  let out = text
    .toLowerCase()
    .replace(INVISIBLE, "")
    .replace(/[\u0250-\u02ff\u0370-\u052f]/g, (ch) => HOMOGLYPHS[ch] ?? ch)
    .normalize("NFKC")
    .replace(/\u2019/g, "'");
  out = leetFold(out);
  out = out.replace(PUNCT_TO_SPACE, " ");
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
 *  Safe against ordinary prose ("i am so sad" -> "iam so sad") because
 *  the result is only ever matched IN ADDITION to the unjoined variant:
 *  a real crisis phrase still matches there, and no benign sentence
 *  turns into one ("iwant to diet" matches nothing either way). */
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
  out.push(...run); // a trailing run has nothing to glue onto
  return out.join(" ").trim();
}

/** Benign compounds (movie/band titles, prevention campaigns) masked out
 *  of both variants before either tier matches. */
function maskBenign(variant: string): string {
  for (const compound of CRISIS_BENIGN_COMPOUNDS) {
    variant = variant.split(compound).join(" ");
  }
  return variant;
}

/** Every normalized form the tiers match against — MUST stay
 *  behavior-compatible with the backend's _match_variants (the shared
 *  fixtures pin both engines). Exported for the parity suite. */
export function matchVariants(text: string): [string, string] {
  const tokens = normalizeToTokens(text);
  return [maskBenign(primaryJoin(tokens)), maskBenign(orphanGlue(tokens))];
}

/** True when `text` contains crisis language (dialog tier — fire the
 *  gentle support dialog). Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  return matchVariants(text).some((v) => DIALOG_PATTERNS.some((p) => p.test(v)));
}

/** True when `text` belongs to the broader suppression tier — the caller
 *  renders a NON-QUOTING card (or suppresses a generated question) for
 *  crisis-adjacent patterns. Pure: no I/O, no state. */
export function matchesCrisisSuppress(text: string): boolean {
  return matchVariants(text).some((v) => SUPPRESS_PATTERNS.some((p) => p.test(v)));
}
