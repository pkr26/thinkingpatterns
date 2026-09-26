/**
 * The on-device graded sentiment engine (2026-09-19): a faithful port of
 * backend/app/services/brain.py's sentiment walk — tokenization, emoji
 * valences counted per occurrence, deterministic morphological candidates
 * ("working"→"work"), intensifier boosting, damped negation (VADER's
 * x-0.74), "but" re-weighting — over the SAME merged lexicon the server
 * looks up (mobile/src/brain/lexicon.ts, generated from
 * shared/brain_lexicon.json by tests on both sides).
 *
 * Why this exists: it is the first slice of the on-device brain. The
 * device-local mood estimate used to be a 20-word regex hack; it now runs
 * the real engine, byte-identical to the server's scoring (pinned by
 * shared/brain_vectors.json). The full port — themes, phrases, lifecycle —
 * is the roadmap; the contract this file establishes is that the pieces
 * that DO run locally are the same deterministic math, not an
 * approximation.
 *
 * Pinned behaviors (tests/brainVectors.test.ts + tests/brainPort.test.ts):
 *  - sentimentScore returns the Python compound exactly (float equality
 *    after the same rounding points),
 *  - sentimentComponents sums the same walk by sign,
 *  - both are pure functions of the input string.
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
  scalars: { negation_scalar: number; sentiment_scale: number; booster_scope: number };
  butWords: Set<string>;
  negators: Set<string>;
  negatorsEn: Set<string>;
  intensifiers: Record<string, number>;
  irregularForms: Record<string, string>;
  sentimentLexicon: Record<string, number>;
  sentimentLexiconEs: Record<string, number>;
  languageDetection: { minTokens: number; hitFloor: number; knownEn: Set<string>; knownEs: Set<string> };
  emojiValences: Record<string, number>;
  emojiOrder: string[];
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
      word_sets: { but_words: string[]; negators: string[]; negators_en: string[] };
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
    tables = {
      scalars: lex.scalars,
      butWords: new Set(lex.word_sets.but_words),
      negators: new Set(lex.word_sets.negators),
      negatorsEn: new Set(lex.word_sets.negators_en),
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
      let valence = wordValence(seg[i]!, language);
      if (valence === 0.0) continue;
      const window = seg.slice(Math.max(0, i - T().scalars.booster_scope), i);
      let boost = 1.0;
      let negated = false;
      for (const prev of window) {
        const intensifier = T().intensifiers[prev];
        if (intensifier !== undefined) boost *= intensifier;
        if (negatorsFor(language).has(prev)) negated = true;
      }
      valence *= boost;
      if (negated) valence *= T().scalars.negation_scalar;
      valence = Math.max(-4.0, Math.min(4.0, valence)) * segWeight;
      sentiments.push(valence);
    }
  }
  return sentiments;
}

/** Tokenize text exactly as the server does: lowered, folded [a-z']+
 *  plus every emoji occurrence as its own token, appended in the
 *  engine's own emoji-map iteration order. */
export function tokenize(text: string): string[] {
  // Lowercase FIRST, then fold — the server's exact order. The fold is
  // what keeps accented words and iOS U+2019 contractions whole (H-8).
  const tokens = (foldSentimentText(text.toLowerCase()).match(WORD_RE) ?? []) as string[];
  for (const emoji of T().emojiOrder) {
    const count = text.split(emoji).length - 1;
    for (let i = 0; i < count; i++) tokens.push(emoji);
  }
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
 *  when English clears the floor, otherwise "other". Below min-tokens
 *  the server keeps the historical English default — mirrored here by
 *  returning "en" so the walk falls back to the pinned default tables
 *  exactly like a language-neutral caller. The server applies this per
 *  CORPUS window; the on-device estimate classifies the single text,
 *  which converges to the same answer for monolingual journals. */
export function detectLanguage(text: string): "en" | "es" | "other" {
  const scored = tokenize(text).filter((t) => t.length >= 3);
  const det = T().languageDetection;
  if (scored.length < det.minTokens) return "en";
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
