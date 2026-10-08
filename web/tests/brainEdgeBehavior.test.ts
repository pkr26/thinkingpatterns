import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { beforeEach, expect, it, vi } from "vitest";

let brain: typeof import("../src/brain/sentiment");
beforeEach(async () => { vi.resetModules(); brain = await import("../src/brain/sentiment"); });
const corpus = JSON.parse(gunzipSync(readFileSync(new URL("../../shared/frontend_brain_behavior.json.gz", import.meta.url))).toString()) as {
  sentiment: [string, string | null, number, number, number][], language: [string, string][], tokenize: [string, string[]][], fold: [string, string][], word_forms: [string, string[]][]
};
const scoringTexts = new Set(["very no", "very not", "very never", "muy no", "muy nunca", "good but very no", "very no but good", "no but very no", "happy", "sad", "feliz", "triste", "not happy", "not terrible", "not suicidal", "", "constructor", "__proto__", "quiet day", "don't feel good", "don’t feel good"]);

it("preserves independent scoring at negation, boost and contrast boundaries with both public components", () => {
  const selected = corpus.sentiment.filter(([text]) => scoringTexts.has(text));
  expect(selected.length).toBeGreaterThan(20);
  for (const [text, language, expected, positive, negative] of selected) {
    const actual = brain.sentimentScore(text, language ?? undefined), parts = brain.sentimentComponents(text, language ?? undefined);
    for (const [value, wanted] of [[actual, expected], [parts[0], positive], [parts[1], negative]]) expect(value, `${language}: ${text}`).toBeCloseTo(wanted!, 12);
  }
});
it("preserves supported-language eligibility and the exact script/known-token boundaries", () => {
  for (const [text, expected] of corpus.language.slice(-22)) expect(brain.detectLanguage(text), text).toBe(expected);
});
it("preserves public Unicode folding, tokenization and morphology without depending on engine cache representation", () => {
  for (const [text, expected] of corpus.fold) expect(brain.foldSentimentText(text), text).toBe(expected);
  for (const [text, expected] of corpus.tokenize) expect(brain.tokenize(text), text).toEqual(expected);
  for (const [text, expected] of corpus.word_forms.filter(([text]) => text.length < 10).slice(0, 354)) expect(brain.wordForms(text), text).toEqual(expected);
});
