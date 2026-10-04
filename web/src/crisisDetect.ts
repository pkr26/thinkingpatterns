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
// @ts-nocheck

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
  // 2026-09-26 audit follow-up (N-4): the backend map gained these two
  // s-impersonators (no NFKC fold exists for either); the TS engines had
  // not been mirrored, so "ʂuicide" folded server-side but fired no
  // client dialog. Pinned by the shared dialog_fires fixtures.
  "\u0282": "s",                // ʂ s with hook
  "\u1d74": "s",                // ᵴ s with middle tilde
  // 2026-09-28 deep audit: the small-capital Latin lookalikes NFKC does
  // NOT fold — social-media styling ("ꜱuicide", "kɪll myself", "kiʟʟ
  // myself") read as broken fragments without these. Pinned by the
  // shared dialog_fires fixtures.
  "\ua731": "s",                // ꜱ latin letter small capital s
  "\u1d1c": "u",                // ᴜ small capital u
  "\u026a": "i",                // ɪ small capital i
  "\u029f": "l",                // ʟ small capital l
};

/** Leet substitutions applied ONLY between two letters ("k1ll" -> "kill"
 * but "1 want" keeps its digit), or at a word's leading edge
 * ("5uicide" -> "suicide") — a leading digit is never part of a number
 * the way a trailing one can be. The regex classes list EXACTLY the
 * mapped characters: 2, 6 and 9 are deliberately unmapped (ambiguous
 * leet: 2=z, 6=b/g, 9=g/q), and a wider class would look an unmapped
 * digit up and splice "undefined" into the normalized text (2026-09-17
 * audit — the Python twin of that bug raised KeyError instead). */
const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
  "@": "a", "!": "i", $: "s",
};
const LEET_RE = /([a-z])([0134578@!$])([a-z])/g;
const LEET_EDGE_RE = /(^|\s)([0134578@!$])([a-z])/g;
/** 2026-09-20 audit H-7: mapped digits also fold at a word's TRAILING edge
 *  ("suicid3" -> "suicide"; "d13" -> "die" inside a phrase). The lookahead
 *  accepts any non-letter or end-of-string so "suicid3!" folds too
 *  (punctuation folds to spaces only later). The class still lists exactly
 *  the mapped characters — 2/6/9 stay digits ("grade6test" untouched). */
const LEET_TRAIL_RE = /([a-z])([0134578@!$]+)(?=[^a-z]|$)/g;

/** Punctuation becomes a space; letters (any script), digits, ASCII
 *  apostrophes and hyphens survive (Hangul syllables included — a Korean
 *  journal must not fold to blank space). */
const PUNCT_TO_SPACE =
  /[^0-9a-z'\-\s\u00c0-\u02af\u0370-\u04ff\u0600-\u06ff\u0900-\u097f\u1e00-\u1fff\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af\uf900-\ufaff\uff66-\uff9f]/g;

const PUNCT_RUN = new RegExp(PUNCT_TO_SPACE.source + "+", "g");
const KEPT_CHAR = new RegExp(PUNCT_TO_SPACE.source);

// 2026-10-01 deep audit C2 (emoji-inside-word bypass): "k😊ll" folds to
// "kll" when the intra-word symbol is dropped — the emoji REPLACED a
// letter, and the information is gone. Vowel reinsertion recovers exactly
// this class: the dropped position is retried with each ASCII vowel
// ("k😊ll" -> "kill"), matched only against the EXISTING tier patterns,
// so a variant fires only when the reinserted text forms a full crisis
// phrase. MUST mirror the backend's _punct_variants (same cap).
const VOWEL_REINSERTION = ["a", "e", "i", "o", "u"] as const;
const VOWEL_REINSERTION_RUN_CAP = 2;
const VOWEL_MARK = "\x00";

/** Punctuation-fold variants of the pre-punct form. The CANONICAL variant
 *  (first) drops every intra-word non-kept run ("k😊ll" -> "kll",
 *  "s.u.i.c.i.d.e" -> "suicide") and spaces token-edge runs. Each
 *  intra-word run (up to the cap) additionally yields a variant with ONE
 *  vowel reinserted at the dropped position ("k😊ll" -> "kill"). MUST
 *  stay behavior-identical to the backend's _punct_variants. */
function punctVariants(text: string): string[] {
  const kept = (c: string | undefined) => c !== undefined && !KEPT_CHAR.test(c);
  const marked = text.replace(PUNCT_RUN, (run: string, offset: number) => {
    if (kept(text[offset - 1]) && kept(text[offset + run.length])) return VOWEL_MARK;
    return " ";
  });
  const base = marked.split(VOWEL_MARK).join("");
  if (!marked.includes(VOWEL_MARK)) return [base];
  const variants = [base];
  let seenMarks = 0;
  let basePos = 0;
  for (const ch of marked) {
    if (ch === VOWEL_MARK) {
      if (seenMarks < VOWEL_REINSERTION_RUN_CAP) {
        for (const vowel of VOWEL_REINSERTION) {
          variants.push(base.slice(0, basePos) + vowel + base.slice(basePos));
        }
      }
      seenMarks += 1;
    } else {
      basePos += ch.length;
    }
  }
  return variants;
}

/** A single-letter token run this long is a spelled-out word ("s u i c i d
 *  e"), not prose — ordinary English never strings 4+ one-letter words
 *  together ("i am so sad" keeps its shape; "u s a won gold" is only 3). */
const SINGLE_LETTER_JOIN = 4;

function leetFold(text: string): string {
  // Loop until stable: "su1c1de" needs two passes (each replacement makes
  // the next digit newly adjacent to letters).
  for (;;) {
    // 2026-09-28 deep audit: "1" is contextually ambiguous — "i" in
    // "k1ll" but "l" in "myse1f". The between-letters rule maps a "1" to
    // "l" when the letter it feeds is "f"; every other mapped char keeps
    // its table value.
    let folded = text.replace(
      LEET_RE,
      (_m, a: string, d: string, b: string) =>
        a + (d === "1" && b === "f" ? "l" : LEET[d]) + b,
    );
    folded = folded.replace(LEET_EDGE_RE, (_m, ws: string, d: string, c: string) => ws + LEET[d] + c);
    folded = folded.replace(
      LEET_TRAIL_RE,
      (_m, a: string, run: string) => a + [...run].map((d) => LEET[d]).join(""),
    );
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

// A letter/digit sitting directly against a non-ASCII LETTER is a script
// boundary: separate them with a space so \b means the same thing under
// Python re (Unicode \w: "suicideम" has NO boundary after "suicide") and
// ECMAScript (ASCII \w: it does). Both engines then agree on every input.
// 2026-10-01 deep audit C2: only LETTERS (Unicode category L*) get the
// boundary — a non-letter symbol (emoji, math, symbols) directly between
// ASCII letters stays intra-word so the punctuation fold can DROP it
// ("k😊ll" must reach the fold as one token, not be pre-split into
// "k 😊 ll" where the drop can no longer see both kept neighbors).
const NONASCII_LETTER = /\p{L}/u;

function insertScriptBoundaries(text: string): string {
  const asciiAlnum = (c: string) => (c >= "0" && c <= "9") || (c >= "a" && c <= "z");
  // Iterate by code POINT ([...text]) so an astral letter is one unit on
  // both engines (Python iterates code points natively).
  const cps = [...text];
  let out = "";
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i] as string;
    if (ch.charCodeAt(0) > 0x7f && NONASCII_LETTER.test(ch)) {
      const prev = i > 0 ? (cps[i - 1] as string) : "";
      const next = i + 1 < cps.length ? (cps[i + 1] as string) : "";
      const prevBound = prev.length === 1 && asciiAlnum(prev);
      const nextBound = next.length === 1 && asciiAlnum(next);
      if (prevBound) out += " ";
      out += ch;
      if (nextBound) out += " ";
    } else {
      out += ch;
    }
  }
  return out;
}

/** The shared pipeline up to (but not including) the punctuation fold.
 *  Benign-compound masking runs HERE (see matchVariants): at this point a
 *  comma between two words is still a comma, so "suicide, silence" cannot
 *  be mistaken for the compound "suicide silence". */
function normalizePrePunct(text: string): string {
  let out = text
    .toLowerCase()
    .replace(INVISIBLE, "")
    .replace(/[\u0131\u0250-\u02ff\u1d00-\u1d7f\u0370-\u052f\ua731]/g, (ch) => HOMOGLYPHS[ch] ?? ch)
    // 2026-09-26 audit follow-up (N-4): the lookup class must cover the
// Phonetic Extensions block (U+1D00-1D7F) - U+1D74 sat in the map
// but outside the class, so the entry could never fire.
    .normalize("NFKC")
    .replace(/\u2019/g, "'");
  out = foldLatinMarks(out);
  out = insertScriptBoundaries(out);
  return leetFold(out);
}

/** Canonical matching form — MUST stay byte-compatible with the backend's
 *  normalize_crisis_text (the JSON fixtures pin both engines). Exported for
 *  tests and for the phrase-contract parity suite. */
export function normalizeCrisisText(text: string): string {
  return primaryJoin(normalizeToTokens(text));
}

/** Tokens of one already-punct-folded form. */
function tokensFromFolded(form: string): string[] {
  // 2026-09-20 audit H-7: SMS shorthand — a standalone "2" token IS "to"
  // ("i want 2 die", "no reason 2 live"). Folded at the TOKEN level, so 2
  // stays an unmapped leet digit everywhere else (2=z is ambiguous).
  return form
    .split(/[\s-]+/)
    .filter((t) => t.length > 0)
    .map((t) => (t === "2" ? "to" : t));
}

/** The shared pipeline from pre-punct form to tokens (canonical variant). */
function normalizeToTokens(text: string): string[] {
  return tokensFromFolded(punctVariants(normalizePrePunct(text))[0] as string);
}

/** Token lists for EVERY punctuation-fold variant of a pre-punct form.
 *  MUST stay behavior-compatible with the backend's _variant_token_sets. */
function variantTokenSets(pre: string): string[][] {
  return punctVariants(pre).map((v) => tokensFromFolded(v));
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

/** Evasion variant (2026-09-28 deep audit): tokens joined with a "|"
 *  sentinel MARK between them. The channel used to join with no separator
 *  at all, which made benign spaced text and true no-space evasion
 *  indistinguishable ("weekend it all" and "i will endit all" both contain
 *  "enditall" once spaces are gone). Marking the ORIGINAL token boundaries
 *  lets the concat twins (see concatPattern) require a boundary at the
 *  phrase start while still matching every no-separator spacing combo
 *  inside the phrase. The sentinel is "|" — a non-letter that can never
 *  appear inside a token. MUST mirror the backend's _concat_join. */
function concatJoin(tokens: string[]): string {
  return tokens.join("|");
}

/** Concat-pattern endings that must keep a trailing boundary: these words
 *  extend into benign ones once the spacing is gone (die->diet,
 *  dead->deadline, on->online, up->upon, out->outfield, cutting->cutting
 *  board), so an unanchored suffix would fire on ordinary text. Every
 *  other ending ("myself", "suicide", ...) has no benign extension worth
 *  fearing, and the anchor would only create misses. */
const CONCAT_ANCHORED_ENDINGS = ["die", "dead", "cutting", "gone", "on", "up", "out"];

const isLiteralChar = (ch: string): boolean =>
  /^[0-9a-z]$/.test(ch) || (ch > "\u007f" && /\p{L}/u.test(ch));

/** Insert "\|?" between adjacent literal characters of a twin so a phrase
 *  SPLIT across tokens ("su icide" -> marked "su|icide") still matches.
 *  Only at top level: nothing is inserted inside groups or character
 *  classes, only at seams between literals and at group boundaries.
 *  Non-ASCII (CJK) literals interleave too — a spaced "自 杀" was
 *  recoverable in the old channel and stays recoverable now. MUST mirror
 *  the backend's _interleave_optional_marks. */
function interleaveOptionalMarks(src: string): string {
  const out: string[] = [];
  let depth = 0;
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i]!;
    out.push(ch);
    if (ch === "(" || ch === "[") {
      depth += 1;
      continue;
    }
    if (ch === ")" || ch === "]") {
      depth = Math.max(0, depth - 1);
      const nxt = src[i + 1];
      if (depth === 0 && nxt !== undefined && (nxt === "(" || isLiteralChar(nxt))) {
        out.push("\\|?");
      }
      continue;
    }
    if (depth > 0) continue;
    const nxt = src[i + 1];
    if (nxt !== undefined && isLiteralChar(ch) && (nxt === "(" || isLiteralChar(nxt))) {
      out.push("\\|?");
    }
  }
  return out.join("");
}

/** Count literal ASCII letters outside groups/classes — the shortness test
 *  for whether a twin may carry internal optional marks. MUST mirror the
 *  backend's _toplevel_literal_letters. */
function toplevelLiteralLetters(pattern: string): number {
  let depth = 0;
  let count = 0;
  let escaped = false;
  for (const ch of pattern) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "(" || ch === "[") {
      depth += 1;
      continue;
    }
    if (ch === ")" || ch === "]") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth === 0 && ch >= "a" && ch <= "z") count += 1;
  }
  return count;
}

/** The marked-concatenation twin of a tier pattern (2026-09-28 deep
 *  audit), matched against concatJoin's "|" -marked text: every internal
 *  \s+ becomes an OPTIONAL mark; LONG patterns additionally interleave
 *  "\|?" between literal letters (word-split evasion stays recoverable);
 *  SHORT patterns (<=4 literal letters: "kys") never take internal marks
 *  (a 3-letter mark-tolerant twin would match the "rocky sunset"
 *  "-ky"+"s-" junction again); the phrase start is pinned to a token
 *  boundary ("(?:^|\|)") — the fix for the "-end"-word false positives
 *  ("weekend it all"); a trailing (?![a-z]) is kept for extendable
 *  endings. MUST mirror the backend's _concat_pattern. */
function concatPattern(pattern: string): string {
  let src = pattern.split("\\s+").join("\\|?");
  src = src.split("\\b").join("");
  // The extendable-ending test runs on the PRE-interleave src: after
  // interleaving, the ending word is fragmented by \|? seams.
  const m = src.match(/([a-z]+)\)?$/);
  const lastWord = m?.[1];
  const anchored =
    lastWord !== undefined && CONCAT_ANCHORED_ENDINGS.some((e) => lastWord.endsWith(e));
  if (toplevelLiteralLetters(pattern) > 4) {
    src = interleaveOptionalMarks(src);
  }
  src = "(?:^|\\|)" + src;
  if (anchored) {
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
 *  "suicide squad" can never eat only half of a longer entry. Non-ASCII
 *  compounds (CJK, 2026-09-20 audit L-23) are masked as plain substrings:
 *  \b never fires next to CJK in either engine, so the anchored form
 *  would never match at all. */
const escapeRe = (w: string) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const benignMask = (compound: string): RegExp => {
  const words = compound.split(/\s+/);
  if (/^[\x00-\x7f\s]*$/.test(compound)) {
    return new RegExp(`\\b${words.map(escapeRe).join("[\\s\\-]+")}\\b`, "gi");
  }
  return new RegExp(words.map(escapeRe).join("[\\s\\-]+"), "gi");
};
const BENIGN_MASKS: readonly RegExp[] = [...CRISIS_BENIGN_COMPOUNDS]
  .sort((a, b) => b.length - a.length)
  .map(benignMask);

function maskBenign(text: string): string {
  let out = text;
  for (const mask of BENIGN_MASKS) out = out.replace(mask, " ");
  return out;
}

// --- 2026-09-20 audit H-7: letter-doubling ---------------------------------
// "kiill myself" / "suiccide" (a letter typed twice) matched NO tier and no
// variant: the doubled run is not a split, not leet, not a homoglyph. The
// fix is a fourth matching channel folded on BOTH sides: the normalized
// text with same-letter runs collapsed ("kiill myself" -> "kil myself")
// matched against tier twins folded the same way ("kill(?:ed|ing)?
// myself" -> "kil(?:ed|ing)? myself"). Folding both sides is what keeps
// canonically double-lettered words working ("kill", "sleep", "cannot"
// fold on the pattern side exactly as the text does). ASCII letters only:
// regex metacharacters, \s/\b escapes, classes and non-Latin scripts are
// never part of a collapsed run, so a folded pattern stays a valid
// pattern with unchanged anchors.
const DEDUP_RUNS = /([a-z])\1+/g;

function dedupFold(text: string): string {
  return text.replace(DEDUP_RUNS, "$1");
}

// The one pattern exempt from the folded tier: "off(?:ing)? myself" folds
// to "of(?:ing)? myself", which matches ordinary prose ("ashamed of
// myself", "tired of myself"). Its unfolded form keeps matching as
// before; doubled spellings of it ("offfing myself") stay accepted misses
// rather than risk a dialog false positive on a benign sentence. MUST
// mirror the backend's _FOLD_EXEMPT (same pattern string as the JSON).
const FOLD_EXEMPT = "\\boff(?:ing)?\\s+myself\\b";

const isFoldable = (p: string) => p !== FOLD_EXEMPT;

/** Folded tier twins (audit H-7): the dialog/suppress patterns with
 *  same-letter runs collapsed, matched only against the folded variants
 *  below. Compiled once at module load. */
const DIALOG_FOLDED_PATTERNS: readonly RegExp[] = CRISIS_DIALOG_PATTERNS.filter(isFoldable).map(
  (p) => new RegExp(dedupFold(p), "i"),
);
const SUPPRESS_FOLDED_PATTERNS: readonly RegExp[] = [
  ...CRISIS_DIALOG_PATTERNS,
  ...CRISIS_SUPPRESS_EXTRA_PATTERNS,
]
  .filter(isFoldable)
  .map((p) => new RegExp(dedupFold(p), "i"));
const DIALOG_FOLDED_CONCAT_PATTERNS: readonly RegExp[] = CRISIS_DIALOG_PATTERNS.filter(isFoldable).map(
  (p) => new RegExp(concatPattern(dedupFold(p)), "i"),
);
const SUPPRESS_FOLDED_CONCAT_PATTERNS: readonly RegExp[] = [
  ...CRISIS_DIALOG_PATTERNS,
  ...CRISIS_SUPPRESS_EXTRA_PATTERNS,
]
  .filter(isFoldable)
  .map((p) => new RegExp(concatPattern(dedupFold(p)), "i"));

// The benign compounds re-mask on the FOLDED text with their own folded
// spellings ("awareness" -> "awarenes"): bare "suicide" is a dialog
// pattern, so "suicide awareness" must stay masked in the folded channel
// — including when the doubling is what hid it ("suiciide squaad").
const BENIGN_MASKS_FOLDED: readonly RegExp[] = [...CRISIS_BENIGN_COMPOUNDS]
  .map(dedupFold)
  .sort((a, b) => b.length - a.length)
  .map(benignMask);

/** The letter-run-collapsed twins of every canonical variant (audit
 *  H-7). MUST mirror the backend's _folded_variants. Groups of
 *  (primary, orphan, concat) per punctuation-fold variant; exported for
 *  the parity suite. */
export function foldedVariants(text: string): string[] {
  let folded = dedupFold(maskBenign(normalizePrePunct(text)));
  for (const mask of BENIGN_MASKS_FOLDED) folded = folded.replace(mask, " ");
  const out: string[] = [];
  for (const tokens of variantTokenSets(normalizePrePunct(folded))) {
    out.push(primaryJoin(tokens), orphanGlue(tokens), concatJoin(tokens));
  }
  return out;
}

/** Every normalized form the tiers match against, grouped as
 *  (primary, orphan, concat) triples per punctuation-fold variant — MUST
 *  stay behavior-compatible with the backend's _match_variants (the
 *  shared fixtures pin both engines). Exported for the parity suite. */
export function matchVariants(text: string): string[] {
  const pre = maskBenign(normalizePrePunct(text));
  const out: string[] = [];
  for (const tokens of variantTokenSets(pre)) {
    out.push(primaryJoin(tokens), orphanGlue(tokens), concatJoin(tokens));
  }
  return out;
}

/** A tier fires when ANY variant group's primary/orphan form matches the
 *  tier, or its concat form matches the tier's concat twin. MUST mirror
 *  the backend's _tier_matches. */
function tierMatches(
  patterns: readonly RegExp[],
  concatPatterns: readonly RegExp[],
  variants: readonly string[],
): boolean {
  for (let i = 0; i + 2 < variants.length; i += 3) {
    const primary = variants[i] as string;
    const orphan = variants[i + 1] as string;
    const concat = variants[i + 2] as string;
    if (patterns.some((p) => p.test(primary) || p.test(orphan))) return true;
    if (concatPatterns.some((p) => p.test(concat))) return true;
  }
  return false;
}

/** True when `text` contains crisis language (dialog tier — fire the
 *  gentle support dialog). Pure: no I/O, no state. */
export function detectCrisisLanguage(text: string): boolean {
  if (tierMatches(DIALOG_PATTERNS, DIALOG_CONCAT_PATTERNS, matchVariants(text))) return true;
  // H-7 letter-doubling channel: only reached when the canonical forms
  // are clean, so it can only ever ADD a catch.
  return tierMatches(DIALOG_FOLDED_PATTERNS, DIALOG_FOLDED_CONCAT_PATTERNS, foldedVariants(text));
}

/** True when `text` belongs to the broader suppression tier — the caller
 *  renders a NON-QUOTING card (or suppresses a generated question) for
 *  crisis-adjacent patterns. Pure: no I/O, no state. */
export function matchesCrisisSuppress(text: string): boolean {
  if (tierMatches(SUPPRESS_PATTERNS, SUPPRESS_CONCAT_PATTERNS, matchVariants(text))) return true;
  return tierMatches(
    SUPPRESS_FOLDED_PATTERNS,
    SUPPRESS_FOLDED_CONCAT_PATTERNS,
    foldedVariants(text),
  );
}
