import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { beforeEach, describe, expect, it, vi } from "vitest";

let brain: typeof import("../src/brain/sentiment");
beforeEach(async () => {
  // The engine tables initialize after the runner has activated the mutant.
  // Fresh module state also prevents one language case's caches influencing another.
  vi.resetModules();
  brain = await import("../src/brain/sentiment");
});

type Corpus = {
  sentiment: [string, string | null, number, number, number][];
  language: [string, "en" | "es" | "other"][];
  tokenize: [string, string[]][];
  word_forms: [string, string[]][];
  fold: [string, string][];
  valence_walk: [string[], string | null, number[]][];
};
// Expected results come from independent backend component APIs. The tests
// exercise consumer behavior without reading the frontend's engine tables.
const corpus = JSON.parse(gunzipSync(readFileSync(join(import.meta.dirname, "../../shared/frontend_brain_behavior.json.gz"))).toString()) as Corpus;

describe("independent on-device brain consumer parity", () => {
  it("preserves direct token-walk valences including raw accented vocabulary", () => {
    for (const [tokens, language, expected] of corpus.valence_walk) {
      const actual = brain.valenceWalk(tokens, language ?? undefined);
      if (actual.length !== expected.length || actual.some((value, i) => !Number.isFinite(value) || Math.abs(value - expected[i]!) > 1e-12)) throw new Error(JSON.stringify({ tokens, language, expected, actual }));
    }
  });
  it("preserves scored mood and positive/negative components across the full bilingual vocabulary", () => {
    for (const [text, language, score, positive, negative] of corpus.sentiment) {
      const label = `${language ?? "default"}: ${text}`;
      const actualScore = brain.sentimentScore(text, language ?? undefined);
      const [actualPositive, actualNegative] = brain.sentimentComponents(text, language ?? undefined);
      for (const [actual, expected, component] of [[actualScore, score, "score"], [actualPositive, positive, "positive"], [actualNegative, negative, "negative"]] as const) {
        if (!Number.isFinite(actual) || Math.abs(actual - expected) > 1e-12) {
          throw new Error(`${label} ${component}: expected ${expected}, received ${actual}`);
        }
      }
    }
  });

  it("preserves supported-language eligibility including mixed scripts and token boundaries", () => {
    for (const [text, language] of corpus.language) {
      const actual = brain.detectLanguage(text);
      if (actual !== language) throw new Error(`${text}: expected ${language}, received ${actual}`);
    }
  });

  it("preserves tokenization for emoji, accents, punctuation and unsupported scripts", () => {
    for (const [text, tokens] of corpus.tokenize) expect(brain.tokenize(text), text).toEqual(tokens);
  });

  it("preserves public normalization output for Latin, combining marks and other scripts", () => {
    for (const [text, folded] of corpus.fold) expect(brain.foldSentimentText(text), text).toBe(folded);
  });

  it("preserves the ordered morphological candidates callers score", () => {
    for (const [word, forms] of corpus.word_forms) expect(brain.wordForms(word), word).toEqual(forms);
  });
});
