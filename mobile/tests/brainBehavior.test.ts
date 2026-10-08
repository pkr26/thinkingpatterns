import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { describe, it } from "vitest";

// These are public outputs of the independent Python backend component APIs.
// The generator/provenance live beside the shared corpus, rather than being
// copied from the frontend implementation or its private lexicon values.
const corpus = JSON.parse(gunzipSync(readFileSync(new URL("../../shared/frontend_brain_behavior.json.gz", import.meta.url))).toString("utf8")) as {
  sentiment: Array<[string, "en" | "es" | null, number, number, number]>;
  language: Array<[string, "en" | "es" | "other"]>;
  tokenize: Array<[string, string[]]>;
  word_forms: Array<[string, string[]]>;
  fold: Array<[string, string]>;
  valence_walk: Array<[string[], "en" | "es" | null, number[]]>;
};

describe("on-device public brain behavior agrees with the backend", () => {
  it("scores journals, selects language, and tokenizes the complete backend corpus", async () => {
    const { detectLanguage, sentimentComponents, sentimentScore, tokenize, wordForms, foldSentimentText, valenceWalk } = await import("../src/brain/sentiment");
    for (const [tokens, language, expected] of corpus.valence_walk) {
      const actual = valenceWalk(tokens, language ?? undefined);
      if (actual.length !== expected.length || actual.some((value, i) => !Number.isFinite(value) || Math.abs(value - expected[i]!) > 1e-12)) throw new Error(JSON.stringify({ tokens, language, expected, actual }));
    }
    for (const [text, language, score, positive, negative] of corpus.sentiment) {
      const actualScore = sentimentScore(text, language ?? undefined);
      const [pa, na] = sentimentComponents(text, language ?? undefined);
      if (!Number.isFinite(actualScore) || Math.abs(actualScore - score) > 5e-13 || !Number.isFinite(pa) || Math.abs(pa - positive) > 5e-7 || !Number.isFinite(na) || Math.abs(na - negative) > 5e-7) {
        throw new Error(`Sentiment mismatch for ${JSON.stringify([text, language])}: expected ${JSON.stringify([score, positive, negative])}, received ${JSON.stringify([actualScore, pa, na])}`);
      }
    }

    for (const [text, expected] of corpus.language) {
      const actual = detectLanguage(text);
      if (actual !== expected) throw new Error(`Language mismatch for ${JSON.stringify(text)}: expected ${expected}, received ${actual}`);
    }

    for (const [text, tokens] of corpus.tokenize) {
      const actual = tokenize(text);
      if (JSON.stringify(actual) !== JSON.stringify(tokens)) throw new Error(`Token mismatch for ${JSON.stringify(text)}: expected ${JSON.stringify(tokens)}, received ${JSON.stringify(actual)}`);
    }

    for (const [word, forms] of corpus.word_forms) {
      const actual = wordForms(word);
      if (JSON.stringify(actual) !== JSON.stringify(forms)) throw new Error(`Word form mismatch for ${JSON.stringify(word)}: expected ${JSON.stringify(forms)}, received ${JSON.stringify(actual)}`);
    }
    for (const [text, expected] of corpus.fold) {
      const actual = foldSentimentText(text);
      if (actual !== expected) throw new Error(`Normalization mismatch for ${JSON.stringify(text)}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
    }
  });
});
