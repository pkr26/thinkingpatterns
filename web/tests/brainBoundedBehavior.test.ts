import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { beforeEach, expect, it, vi } from "vitest";
let brain: typeof import("../src/brain/sentiment");
beforeEach(async () => { vi.resetModules(); brain = await import("../src/brain/sentiment"); });
const corpus = JSON.parse(gunzipSync(readFileSync(new URL("../../shared/frontend_brain_behavior.json.gz", import.meta.url))).toString()) as { sentiment: [string, string | null, number, number, number][], language: [string, string][], word_forms: [string, string[]][], tokenize: [string, string[]][] };
it("preserves independent public results across repeated calls without assigning meaning to cache representation", () => {
  const sample = corpus.sentiment.find(([text, language]) => text === "happy" && language === "en")!;
  for (let n = 0; n < 2; n++) {
    expect(brain.sentimentScore(sample[0], "en")).toBeCloseTo(sample[2], 12);
    expect(brain.sentimentComponents(sample[0], "en")).toEqual([sample[3], sample[4]]);
  }
  const emoji = corpus.sentiment.find(([text, language]) => /[\u{1f600}-\u{1f64f}]/u.test(text) && language === "en")!;
  expect(brain.sentimentScore(emoji[0], "en")).toBeCloseTo(emoji[2], 12);
  expect(brain.sentimentScore(emoji[0], "en")).toBeCloseTo(emoji[2], 12);
});
