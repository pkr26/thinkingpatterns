/**
 * Component parity only: ported TS sentiment/statistics against the
 * golden outputs the Python engine generated (shared/brain_vectors.json —
 * backend/scripts/gen_brain_vectors.py). The full-engine `updates` cases
 * have no mobile runner yet; see src/brain/PORT.md. Sentiment scores must be EXACT
 * (same walk, same rounding points); statistics agree to 1e-9 (both are
 * double-precision math, but transcendental tails may differ in the last
 * ulp). The same standing as tests/vectors.test.ts holds for the crypto.
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
      expect(Math.abs(fisherZDifferenceP(r1, n1, r2, n2) - expected)).toBeLessThan(1e-9);
    }
  });
});

// --- independent audit 2026-09-27: VS16 emoji canonicalization ------------------
//
// brain._emoji_tokens (item 10) canonicalizes the raw text's emoji before
// counting: each distinct base matched with an OPTIONAL trailing U+FE0F,
// every occurrence emitted once as the map's CANONICAL key, in TEXT order.
// The mobile tokenizer now mirrors it — a bare "❤" scores exactly like
// "❤️" (same grapheme, same valence). The shared vectors gain bare-VS16
// entries afterwards; these unit pins hold independently of them.
const { tokenize } = await import("../src/brain/sentiment");

describe("VS16 emoji canonicalization (brain._emoji_tokens parity)", () => {

  it("a bare base spelling yields the canonical (VS16-bearing) map key", async () => {
    const tokens = tokenize("❤");
    expect(tokens).toEqual(["❤️"]);
    expect(tokens[0]).toBe("❤\ufe0f");
  });

  it("bare and fully-qualified spellings tokenize IDENTICALLY", async () => {
    expect(tokenize("feeling ☹ today")).toEqual(tokenize("feeling ☹️ today"));
    expect(tokenize("feeling ☹ today")).toEqual(["feeling", "today", "☹\ufe0f"]);
  });

  it("every occurrence counts, in TEXT order, mixed spellings included", async () => {
    expect(tokenize("❤ and ❤️ and ❤")).toEqual(["and", "and", "❤\ufe0f", "❤\ufe0f", "❤\ufe0f"]);
  });

  it("VS16 keys without a bare twin keep scoring exactly as before", async () => {
    // ☀️ lives in the map ONLY as the VS16 spelling; it must still count.
    expect(tokenize("☀️")).toEqual(["☀\ufe0f"]);
    expect(sentimentScore("☀️")).not.toBe(0);
  });

  it("a bare VS16-map emoji scores the same as its fully-qualified twin", async () => {
    expect(sentimentScore("☹")).toBe(sentimentScore("☹\ufe0f"));
    expect(sentimentScore("☹")).not.toBe(0);
    // The score is the map's valence through the same walk: identical
    // components too, not just the clamped compound.
    const bare = sentimentComponents("☹");
    const full = sentimentComponents("☹\ufe0f");
    expect(bare).toEqual(full);
  });

  it("non-emoji VS16 usage is inert (the scanner only knows map bases)", () => {
    // A VS16 attached to a base with no map entry (the keycap text-style
    // "#\uFE0F") produces no token at all: "#" is not a [a-z']+ word and
    // the emoji scanner only knows the map's bases.
    expect(tokenize("\u0023\ufe0f")).toEqual([]);
  });
});
