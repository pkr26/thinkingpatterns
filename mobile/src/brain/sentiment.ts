/**
 * On-device sentiment scoring, ported from the Python brain's token walk.
 * Tokenization, emoji occurrences, morphological candidates, intensifiers,
 * negation, and contrast weighting use the shared graded lexicon.
 *
 * Scoring is deterministic. tests/brainVectors.test.ts verifies the output
 * against Python-generated shared/brain_vectors.json with explicit floating-
 * point tolerances. Full pattern analysis remains a server operation; see
 * PORT.md for the remaining on-device work.
 */
import { LEXICON } from "./lexicon";

/** Lazily-derived engine tables. Module-scope derivation proved fragile
 * under the app's transform stack (an interop quirk left the derived
 * bindings undefined at call time while the source module was complete);
 * deriving on first use makes the behavior independent of any transform's
 * module-evaluation order. The structures are tiny; building them once
 * per process is free.
 */
interface Tables {
  scalars: {
    negation_scalar: number;
    sentiment_scale: number;
    booster_scope: number;
    strong_negation_abs: number;
  };
  butWords: Set<string>;
  negators: Set<string>;
  negatorsEn: Set<string>;
  /** 2026-10-01 deep audit (stats M5): frames whose presence in a negator
   *  window means the negated state IS ongoing — suppress the flip. */
  perseverativeFrames: Set<string>;
  intensifiers: Record<string, number>;
  irregularForms: Record<string, string>;
  sentimentLexicon: Record<string, number>;
  sentimentLexiconEs: Record<string, number>;
  languageDetection: { minTokens: number; hitFloor: number; knownEn: Set<string>; knownEs: Set<string> };
  emojiValences: Record<string, number>;
  emojiOrder: string[];
  /** independent audit 2026-09-27: the VS16-canonicalizing emoji scanner
   *  (brain._EMOJI_SCAN_RE / _EMOJI_BASE_TO_KEY) — see emojiTokens. */
  emojiScanRegex: RegExp | null;
  emojiBaseToKey: Record<string, string>;
}
let tables: Tables | null = null;
/** Null-prototype copies for every lexicon table used as a Record lookup
 *  (2026-09-20 audit H-18): a plain object literal resolves inherited
 *  Object.prototype names, so the all-lowercase token "constructor"
 *  (the only inherited name matching WORD_RE) returned the inherited
 *  FUNCTION — arithmetic yielded NaN, NaN rode into the mood log, and
 *  the log's sanitizer dropped the whole day. With null prototypes the
 *  lookup is undefined like any unknown word, and the server parity
 *  (score 0.0) holds. */
function nullProto<T>(src: Record<string, T>): Record<string, T> {
  return Object.assign(Object.create(null) as Record<string, T>, src);
}
function T(): Tables {
  if (tables === null) {
    const lex = LEXICON as unknown as Record<string, never> & {
      scalars: Tables["scalars"];
      word_sets: {
      but_words: string[];
      negators: string[];
      negators_en: string[];
      perseverative_frames: string[];
    };
      intensifiers: Record<string, number>;
      irregular_forms: Record<string, string>;
      sentiment_lexicon: Record<string, number>;
      sentiment_lexicon_es: Record<string, number>;
      language_detection: {
        min_tokens: number;
        hit_floor: number;
        known_tokens_en: string[];
        known_tokens_es: string[];
      };
      emoji_valences: Record<string, number>;
      emoji_order: string[];
    };
    // independent audit 2026-09-27: brain._EMOJI_BASE_TO_KEY — each map key
    // with its optional trailing U+FE0F stripped is a BASE; a
    // fully-qualified (VS16-bearing) key is the canonical spelling of a
    // shared base and displaces a bare one (insertion-order stable
    // otherwise — one spelling per base today).
    const VS16 = "\ufe0f";
    const emojiBaseToKey: Record<string, string> = Object.create(null);
    for (const key of lex.emoji_order) {
      const base = key.endsWith(VS16) ? key.slice(0, -1) : key;
      if (!(base in emojiBaseToKey) || key.endsWith(VS16)) {
        emojiBaseToKey[base] = key;
      }
    }
    // brain._EMOJI_SCAN_RE: one alternation of every base with an OPTIONAL
    // trailing U+FE0F, LONGEST bases first so no base can eat another's
    // prefix. (Only prefix-related bases can both match at one position,
    // and both length metrics — code points and UTF-16 units — order those
    // identically, so unit-length sorting is behaviorally identical to the
    // server's (-len, base) tuple sort.)
    const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const bases = Object.keys(emojiBaseToKey).sort((a, b) => b.length - a.length);
    const emojiScanRegex =
      bases.length > 0
        ? new RegExp(bases.map((base) => escapeRe(base) + "\ufe0f?").join("|"), "g")
        : null;
    tables = {
      scalars: lex.scalars,
      butWords: new Set(lex.word_sets.but_words),
      negators: new Set(lex.word_sets.negators),
      negatorsEn: new Set(lex.word_sets.negators_en),
      perseverativeFrames: new Set(lex.word_sets.perseverative_frames),
      intensifiers: nullProto(lex.intensifiers),
      irregularForms: nullProto(lex.irregular_forms),
      sentimentLexicon: nullProto(lex.sentiment_lexicon),
      sentimentLexiconEs: nullProto(lex.sentiment_lexicon_es),
      languageDetection: {
        minTokens: lex.language_detection.min_tokens,
        hitFloor: lex.language_detection.hit_floor,
        knownEn: new Set(lex.language_detection.known_tokens_en),
        knownEs: new Set(lex.language_detection.known_tokens_es),
      },
      emojiValences: nullProto(lex.emoji_valences),
      emojiOrder: lex.emoji_order,
      emojiScanRegex,
      emojiBaseToKey,
    };
  }
  return tables;
}

/** The engine's word tokenizer: [a-z']+ on lowered text (patterns.WORD_RE). */
const WORD_RE = /[a-z']+/g;

/** Fold Latin diacritics to base letters and U+2019 to ASCII ' before
 *  tokenization (2026-09-20 audit H-8) — brain._fold_sentiment_text,
 *  behavior-identical (the brain-vector fixtures pin both engines).
 *  Without it [a-z']+ mangles every accented word ("depresión" ->
 *  "depresi" + "n") and iOS Smart Punctuation's U+2019 splits "don't",
 *  defeating every contraction negator. Same Latin-only rule as the
 *  crisis engine's foldLatinMarks: Devanagari/Arabic marks survive. */
export function foldSentimentText(text: string): string {
  // Fast path: pure-ASCII English (the common case) needs no folding.
  if (/^[\x00-\x7f]*$/.test(text)) return text;
  let lowered = text.replace(/\u2019/g, "'");
  // Compose FIRST: a decomposed (NFD) accent is a BARE combining mark,
  // which per-char folding cannot see — "depresió n" (NFD) must fold
  // exactly like the precomposed "depresión" (the crisis engine's
  // pipeline composes for the same reason).
  lowered = lowered.normalize("NFKC");
  let out = "";
  for (const ch of lowered) {
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

/** Deterministic morphological candidates — brain.word_forms, verbatim. */
export function wordForms(token: string): string[] {
  const forms = [token];
  const irregular = T().irregularForms[token];
  if (irregular !== undefined) forms.push(irregular);
  const t = token;
  if (t.length > 4 && t.endsWith("ies")) forms.push(t.slice(0, -3) + "y");
  if (t.length > 3 && t.endsWith("es")) forms.push(t.slice(0, -2));
  if (t.length > 3 && t.endsWith("s") && !t.endsWith("ss")) forms.push(t.slice(0, -1));
  if (t.length > 5 && t.endsWith("ing")) {
    const base = t.slice(0, -3);
    forms.push(base);
    if (base.length > 3 && base[base.length - 1] === base[base.length - 2] && !"aeiouy".includes(base[base.length - 1]!)) {
      forms.push(base.slice(0, -1));
    }
    forms.push(base + "e");
  }
  if (t.length > 4 && t.endsWith("ed")) {
    const base = t.slice(0, -2);
    forms.push(base);
    if (base.length > 3 && base[base.length - 1] === base[base.length - 2] && !"aeiouy".includes(base[base.length - 1]!)) {
      forms.push(base.slice(0, -1));
    }
    forms.push(base + "e");
  }
  const seen = new Set<string>();
  const deduplicated: string[] = [];
  for (const form of forms) {
    if (!seen.has(form)) {
      seen.add(form);
      deduplicated.push(form);
    }
  }
  return deduplicated;
}

/** brain._negators_for (L-3, 2026-09-26): the negator set is
 *  language-SCOPED at scoring time. The union stays the default (the
 *  cross-platform sentiment vectors pin it byte-identical); "en" excludes
 *  the ES-only negators ("sin", "ni", ...) that are English letter
 *  strings too — "washed away my sin and guilt" must not negate. */
function negatorsFor(language: string | undefined): Set<string> {
  return language === "en" ? T().negatorsEn : T().negators;
}

function wordValence(token: string, language: string | undefined): number {
  // Emoji are their own tokens (extracted alongside WORD_RE matches).
  const emoji = T().emojiValences[token];
  if (emoji !== undefined) return emoji;
  // L-3 (2026-09-26): "es" text scores against the ES-winning mirror
  // merge; every other language (and the undefined default of the
  // vector callers) keeps the pinned EN-winning merge unchanged.
  const lexicon = language === "es" ? T().sentimentLexiconEs : T().sentimentLexicon;
  for (const form of wordForms(token)) {
    const valence = lexicon[form];
    if (valence !== undefined) return valence;
  }
  return 0.0;
}

/** The per-word graded valences of the sentiment walk — brain._valence_walk.
 *  L-3 (2026-09-26): the optional language selects the scoring merge and
 *  scopes the negator set (undefined keeps the historical default). */
export function valenceWalk(tokens: string[], language?: string): number[] {
  const sentiments: number[] = [];
  let split = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (T().butWords.has(tokens[i]!)) split = i;
  }
  const segments: Array<[string[], number]> =
    split >= 0
      ? [
          [tokens.slice(0, split), 0.5],
          [tokens.slice(split + 1), 1.5],
        ]
      : [[tokens, 1.0]];

  for (const [seg, segWeight] of segments) {
    for (let i = 0; i < seg.length; i++) {
      // 2026-09-29 deep audit: a negator DOING NEGATION WORK (a scored
      // NON-negator within booster scope ahead) carries no valence of its
      // own; a STRANDED negator ("no.", "no no no") is content — it keeps
      // its own valence and is never flipped by a preceding negator.
      // Mirrors brain._valence_walk exactly.
      const token = seg[i]!;
      const negs = negatorsFor(language);
      if (negs.has(token)) {
        const ahead = seg.slice(i + 1, i + 1 + T().scalars.booster_scope);
        const working = ahead.some((t) => !negs.has(t!) && wordValence(t!, language) !== 0.0);
        if (working) continue;
        const own = wordValence(token, language);
        if (own !== 0.0) {
          let boost = 1.0;
          for (const prev of seg.slice(Math.max(0, i - T().scalars.booster_scope), i)) {
            const intensifier = T().intensifiers[prev];
            if (intensifier !== undefined) boost *= intensifier;
          }
          sentiments.push(Math.max(-4.0, Math.min(4.0, own * boost)) * segWeight);
        }
        continue;
      }
      let valence = wordValence(token, language);
      if (valence === 0.0) continue;
      const window = seg.slice(Math.max(0, i - T().scalars.booster_scope), i);
      let boost = 1.0;
      let negated = false;
      let perseverative = false;
      for (const prev of window) {
        const intensifier = T().intensifiers[prev];
        if (intensifier !== undefined) boost *= intensifier;
        if (negatorsFor(language).has(prev)) negated = true;
        if (T().perseverativeFrames.has(prev)) perseverative = true;
      }
      valence *= boost;
      if (negated && !perseverative) {
        // A negated STRONG negative is the ABSENCE of the state: "i am
        // not suicidal" must never score positive (it measured +0.5).
        if (valence <= -T().scalars.strong_negation_abs) continue;
        valence *= T().scalars.negation_scalar;
      }
      valence = Math.max(-4.0, Math.min(4.0, valence)) * segWeight;
      sentiments.push(valence);
    }
  }
  return sentiments;
}

/** brain._emoji_tokens (independent audit 2026-09-27): the entry's emoji
 *  as canonical EMOJI_VALENCES keys, one per occurrence, counted on a
 *  VS16-CANONICALIZED view of the raw text — each distinct base matched
 *  with an OPTIONAL trailing U+FE0F (longest bases first, so no base can
 *  eat another's prefix), each occurrence emitted once as the map's
 *  canonical key. Bare ("❤") and fully-qualified ("❤️") spellings score
 *  identically, and shared bases count once — byte-identical to the
 *  server's engine (the old per-key text.count loop missed every bare
 *  base spelling and would double-count shared bases). */
function emojiTokens(text: string): string[] {
  const t = T();
  if (t.emojiScanRegex === null) return [];
  const out: string[] = [];
  for (const match of text.match(t.emojiScanRegex) ?? []) {
    const base = match.endsWith("\ufe0f") ? match.slice(0, -1) : match;
    const canonical = t.emojiBaseToKey[base];
    if (canonical !== undefined) out.push(canonical);
  }
  return out;
}

/** Tokenize text exactly as the server does: lowered, folded [a-z']+
 *  plus every emoji occurrence as its own token (VS16-canonicalized,
 *  appended in the order they appear in the text — the same occurrence
 *  sequence brain._emoji_tokens produces). */
export function tokenize(text: string): string[] {
  // Lowercase FIRST, then fold — the server's exact order. The fold is
  // what keeps accented words and iOS U+2019 contractions whole (H-8).
  const tokens = (foldSentimentText(text.toLowerCase()).match(WORD_RE) ?? []) as string[];
  tokens.push(...emojiTokens(text));
  return tokens;
}

/** Graded lexicon sentiment in [-1, 1] — brain.sentiment_score.
 *  L-3 (2026-09-26): the optional language is forwarded to the walk;
 *  callers that pass none keep the pinned default behavior. */
export function sentimentScore(text: string, language?: string): number {
  const sentiments = valenceWalk(tokenize(text), language);
  if (sentiments.length === 0) return 0.0;
  const total = sentiments.reduce((a, b) => a + b, 0);
  return Math.max(-1.0, Math.min(1.0, total / T().scalars.sentiment_scale));
}

/** (positive, negative) affect magnitudes, each in [0, 1] — the PA/NA
 *  split of the same walk (brain.sentiment_components). */
export function sentimentComponents(text: string, language?: string): [number, number] {
  const sentiments = valenceWalk(tokenize(text), language);
  if (sentiments.length === 0) return [0.0, 0.0];
  let positive = 0;
  let negative = 0;
  for (const v of sentiments) {
    if (v > 0) positive += v;
    else if (v < 0) negative += v;
  }
  return [
    Math.max(0.0, Math.min(1.0, positive / T().scalars.sentiment_scale)),
    Math.max(0.0, Math.min(1.0, -negative / T().scalars.sentiment_scale)),
  ];
}

/** brain's language-detection heuristic (L-3 follow-up, 2026-09-26):
 *  shares of scored tokens (len >= 3) against the EN/ES detection sets;
 *  "es" only when its share clears the floor AND beats English, "en"
 *  when English clears the floor, otherwise "other". The share rule runs
 *  whenever ANY token scored (audit 2026-09-28, brain parity HIGH): the
 *  server's 2026-09-26 statistical review retired the min-token English
 *  default because short Spanish windows (nearly all journal entries)
 *  then scored with EN weights and SIGN-FLIPPED against the corpus
 *  verdict ("nunca estoy bien": EN default +0.40, ES share rule -0.296).
 *  Only a corpus where NOTHING scored keeps the historical English
 *  default — exactly the server's empty-corpus branch. The server applies
 *  this per CORPUS window; the on-device estimate classifies the single
 *  text, which converges to the same answer for monolingual journals. */
export function detectLanguage(text: string): "en" | "es" | "other" {
  const scored = tokenize(text).filter((t) => t.length >= 3);
  const det = T().languageDetection;
  // 2026-10-01 audit LOW (parity): the server (and the web twin) report
  // "other" when ANY text exists but nothing scored — only a fully EMPTY
  // corpus keeps the English default. The old unconditional "en" made the
  // on-device mood estimate score CJK/emoji-only text against the EN
  // lexicon from nothing.
  if (scored.length === 0) return text.length === 0 ? "en" : "other";
  let enHits = 0;
  let esHits = 0;
  for (const t of scored) {
    if (det.knownEn.has(t)) enHits += 1;
    if (det.knownEs.has(t)) esHits += 1;
  }
  const enShare = enHits / scored.length;
  const esShare = esHits / scored.length;
  if (esShare >= det.hitFloor && esShare > enShare) return "es";
  if (enShare >= det.hitFloor) return "en";
  return "other";
}
