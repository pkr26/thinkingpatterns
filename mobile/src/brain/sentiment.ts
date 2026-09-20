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
  intensifiers: Record<string, number>;
  irregularForms: Record<string, string>;
  sentimentLexicon: Record<string, number>;
  emojiValences: Record<string, number>;
  emojiOrder: string[];
}
let tables: Tables | null = null;
function T(): Tables {
  if (tables === null) {
    const lex = LEXICON as unknown as Record<string, never> & {
      scalars: Tables["scalars"];
      word_sets: { but_words: string[]; negators: string[] };
      intensifiers: Record<string, number>;
      irregular_forms: Record<string, string>;
      sentiment_lexicon: Record<string, number>;
      emoji_valences: Record<string, number>;
      emoji_order: string[];
    };
    tables = {
      scalars: lex.scalars,
      butWords: new Set(lex.word_sets.but_words),
      negators: new Set(lex.word_sets.negators),
      intensifiers: lex.intensifiers,
      irregularForms: lex.irregular_forms,
      sentimentLexicon: lex.sentiment_lexicon,
      emojiValences: lex.emoji_valences,
      emojiOrder: lex.emoji_order,
    };
  }
  return tables;
}

/** The engine's word tokenizer: [a-z']+ on lowered text (patterns.WORD_RE). */
const WORD_RE = /[a-z']+/g;

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

function wordValence(token: string): number {
  // Emoji are their own tokens (extracted alongside WORD_RE matches).
  const emoji = T().emojiValences[token];
  if (emoji !== undefined) return emoji;
  for (const form of wordForms(token)) {
    const valence = T().sentimentLexicon[form];
    if (valence !== undefined) return valence;
  }
  return 0.0;
}

/** The per-word graded valences of the sentiment walk — brain._valence_walk. */
export function valenceWalk(tokens: string[]): number[] {
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
      let valence = wordValence(seg[i]!);
      if (valence === 0.0) continue;
      const window = seg.slice(Math.max(0, i - T().scalars.booster_scope), i);
      let boost = 1.0;
      let negated = false;
      for (const prev of window) {
        const intensifier = T().intensifiers[prev];
        if (intensifier !== undefined) boost *= intensifier;
        if (T().negators.has(prev)) negated = true;
      }
      valence *= boost;
      if (negated) valence *= T().scalars.negation_scalar;
      valence = Math.max(-4.0, Math.min(4.0, valence)) * segWeight;
      sentiments.push(valence);
    }
  }
  return sentiments;
}

/** Tokenize text exactly as the server does: lowered [a-z']+ plus every
 *  emoji occurrence as its own token, appended in the engine's own
 *  emoji-map iteration order. */
export function tokenize(text: string): string[] {
  const tokens = (text.toLowerCase().match(WORD_RE) ?? []) as string[];
  for (const emoji of T().emojiOrder) {
    const count = text.split(emoji).length - 1;
    for (let i = 0; i < count; i++) tokens.push(emoji);
  }
  return tokens;
}

/** Graded lexicon sentiment in [-1, 1] — brain.sentiment_score. */
export function sentimentScore(text: string): number {
  const sentiments = valenceWalk(tokenize(text));
  if (sentiments.length === 0) return 0.0;
  const total = sentiments.reduce((a, b) => a + b, 0);
  return Math.max(-1.0, Math.min(1.0, total / T().scalars.sentiment_scale));
}

/** (positive, negative) affect magnitudes, each in [0, 1] — the PA/NA
 *  split of the same walk (brain.sentiment_components). */
export function sentimentComponents(text: string): [number, number] {
  const sentiments = valenceWalk(tokenize(text));
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
