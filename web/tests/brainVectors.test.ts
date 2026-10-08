/**
 * Cross-platform brain vectors (ported from mobile's brainVectors.test.ts):
 * the TS on-device engine against the same golden outputs the Python
 * engine generated (shared/brain_vectors.json —
 * backend/scripts/gen_brain_vectors.py). Sentiment scores agree to 1e-12
 * (both engines accumulate left-to-right, but a pathological order can
 * still differ in the last ulp — far beneath every rounding point the
 * engine applies afterwards); statistics agree to 1e-9. The one row that
 * EXISTS to pin the accumulation ORDER is asserted with float equality
 * (see the E-7 case below). The same standing as tests/crypto.test.ts
 * holds for the crypto.
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

/** E-7 (2026-09-26 audit follow-up): the one vector row that pins the
 *  accumulation ORDER — both engines accumulate naively left-to-right, so
 *  float equality HOLDS here and a regression back to Python 3.12+'s
 *  Neumaier-compensated sum() (0.44999999999999996) fails on BOTH
 *  platforms. Asserting only toBeCloseTo here was vacuous: the row cannot
 *  drift within 1e-12 without the order itself changing (audit 2026-09-28,
 *  MEDIUM — now a hard pin). */
const SENTIMENT_SUM_ORDER_CASE = "smuggled opportunist stammerer wisdom regretfulness respected harmonising fearsome jw";

describe("on-device brain: sentiment parity with the Python engine", () => {
  for (const { text, score, pa, na } of vectors.sentiment) {
    it(`scores ${JSON.stringify(text.slice(0, 48))} identically`, () => {
      if (text === SENTIMENT_SUM_ORDER_CASE) {
        // The order pin: EXACT equality (see above).
        expect(Object.is(sentimentScore(text), score)).toBe(true);
      } else {
        // Exact except the last ulp: Python's sum() and JS's reduce associate
        // floating-point additions differently, so parity is 1e-12, not
        // Object.is — a difference at that scale is far beneath every
        // rounding point the engine applies afterwards.
        expect(sentimentScore(text)).toBeCloseTo(score, 12);
      }
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
