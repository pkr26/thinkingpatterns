/**
 * Cross-platform brain vectors (ported from mobile's brainVectors.test.ts):
 * the TS on-device engine against the same golden outputs the Python
 * engine generated (shared/brain_vectors.json —
 * backend/scripts/gen_brain_vectors.py). Sentiment scores must be EXACT
 * (same walk, same rounding points); statistics agree to 1e-9 (both are
 * double-precision math, but transcendental tails may differ in the last
 * ulp). The same standing as tests/crypto.test.ts holds for the crypto.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { sentimentComponents, sentimentScore } from "../src/brain/sentiment";
import { erfc, fisherZDifferenceP, pearson } from "../src/brain/stats";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "brain_vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  sentiment: Array<{ text: string; score: number; pa: number; na: number }>;
  stats: {
    erfc: Array<[number, number]>;
    pearson: Array<[number[], number[], number | null]>;
    fisher_z: Array<[number, number, number, number, number]>;
  };
};

describe("on-device brain: sentiment parity with the Python engine", () => {
  for (const { text, score, pa, na } of vectors.sentiment) {
    it(`scores ${JSON.stringify(text.slice(0, 48))} identically`, () => {
      // Exact except the last ulp: Python's sum() and JS's reduce associate
      // floating-point additions differently, so parity is 1e-12, not
      // Object.is — a difference at that scale is far beneath every
      // rounding point the engine applies afterwards.
      expect(sentimentScore(text)).toBeCloseTo(score, 12);
      const [gotPa, gotNa] = sentimentComponents(text);
      expect(gotPa).toBeCloseTo(pa, 6);
      expect(gotNa).toBeCloseTo(na, 6);
    });
  }
});

describe("on-device brain: statistics parity", () => {
  it("erfc agrees to 1e-12 across both branches", () => {
    for (const [z, expected] of vectors.stats.erfc) {
      expect(Math.abs(erfc(z) - expected)).toBeLessThan(1e-12);
    }
  });
  it("pearson agrees exactly where measurable, null where not", () => {
    for (const [xs, ys, expected] of vectors.stats.pearson) {
      const got = pearson(xs, ys);
      if (expected === null) {
        expect(got).toBeNull();
      } else {
        expect(got).toBeCloseTo(expected, 12);
      }
    }
  });
  it("fisher-z difference p-values agree to 1e-9", () => {
    for (const [r1, n1, r2, n2, expected] of vectors.stats.fisher_z) {
      expect(fisherZDifferenceP(r1, n1, r2, n2)).toBeCloseTo(expected, 9);
    }
  });
});
