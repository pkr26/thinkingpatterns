import { expect, it } from "vitest";
import reference from "./fixtures/statistical-public-output.json";

function agrees(actual: number, expected: number, context: string, tolerance = 1e-12) {
  if (!Number.isFinite(actual) || Math.abs(actual - expected) > tolerance * Math.max(1, Math.abs(expected))) {
    throw new Error(`${context}: expected ${expected}, received ${actual}`);
  }
}

it("computes measurable correlations, sample dispersion, and normal/Fisher tails", async () => {
  const { erfc, pearson, sampleSd, fisherZDifferenceP } = await import("../src/brain/stats");
  for (const [x, expected] of reference.erfc) agrees(erfc(x!), expected!, `erfc(${x})`);
  expect(erfc(Number.NaN)).toBeNaN();
  expect(erfc(Number.POSITIVE_INFINITY)).toBe(0);
  expect(erfc(Number.NEGATIVE_INFINITY)).toBe(2);
  expect(fisherZDifferenceP(0.8, Number.POSITIVE_INFINITY, 0.2, Number.POSITIVE_INFINITY)).toBe(1);
  for (const [xs, ys, expected] of reference.pearson as [number[], number[], number | null][]) {
    const actual = pearson(xs, ys);
    if (expected === null) expect(actual).toBeNull();
    else agrees(actual!, expected, `pearson(${JSON.stringify([xs, ys])})`);
  }
  for (const [values, expected] of reference.sd as [number[], number][]) agrees(sampleSd(values), expected, `sampleSd(${JSON.stringify(values)})`);
  for (const [recent, recentCount, earlier, earlierCount, expected] of reference.fisher) {
    agrees(fisherZDifferenceP(recent!, recentCount!, earlier!, earlierCount!), expected!, `fisher(${JSON.stringify([recent, recentCount, earlier, earlierCount])})`, 1e-9);
  }
});
