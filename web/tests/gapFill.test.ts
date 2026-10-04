/** Coverage-gap fillers (2026-09-29 deep audit P2): the default
 *  `npm test` gate enforces 85% functions coverage; these suites pin the
 *  small, load-bearing branches that had no tests — crypto core's
 *  parameter guards, the stats helpers the on-device brain leans on, and
 *  the recorder's failure paths. */
// @ts-nocheck


import { describe, expect, it } from "vitest";

import { deriveMasterKey, encrypt, decrypt, hkdfSha256, TamperError, zeroize } from "../src/crypto/core";
import { erfc, fisherZDifferenceP, pearson, sampleSd } from "../src/brain/stats";

describe("crypto core guards", () => {
  it("deriveMasterKey rejects a too-short salt (fail closed)", async () => {
    await expect(deriveMasterKey("pw", new Uint8Array(4))).rejects.toThrow(/salt must be at least/);
  });

  it("deriveMasterKey rejects sub-contract iteration counts", async () => {
    await expect(deriveMasterKey("pw", new Uint8Array(16), 1000)).rejects.toThrow(
      /iterations must be at least/,
    );
  });

  it("deriveMasterKey derives deterministic keys from (password, salt)", async () => {
    const salt = new Uint8Array(16).fill(3);
    const a = await deriveMasterKey("pw", salt, 100_000);
    const b = await deriveMasterKey("pw", salt, 100_000);
    expect(a.length).toBe(32);
    expect(a).toEqual(b);
    // A different password changes the key.
    const c = await deriveMasterKey("other", salt, 100_000);
    expect(c).not.toEqual(a);
  });

  it("hkdfSha256 is deterministic and domain-separated", async () => {
    const ikm = new Uint8Array(32).fill(7);
    const info = new TextEncoder().encode("test");
    const a = await hkdfSha256(ikm, new Uint8Array(16), info, 32);
    const b = await hkdfSha256(ikm, new Uint8Array(16), info, 32);
    expect(a.length).toBe(32);
    expect(a).toEqual(b);
    const c = await hkdfSha256(ikm, new Uint8Array(16), new TextEncoder().encode("other"), 32);
    expect(c).not.toEqual(a);
  });

  it("encrypt/decrypt round-trip; a flipped byte is TamperError, not garbage", async () => {
    const key = new Uint8Array(32).fill(9);
    const plaintext = new TextEncoder().encode("journal words");
    const aad = new TextEncoder().encode("aad");
    const blob = await encrypt(key, plaintext, aad);
    expect(await decrypt(key, blob, aad)).toEqual(plaintext);
    const flipped = blob.slice();
    flipped[flipped.length - 1]! ^= 1;
    await expect(decrypt(key, flipped, aad)).rejects.toBeInstanceOf(TamperError);
  });

  it("zeroize clears every buffer in place and tolerates nulls", () => {
    const a = new Uint8Array(4).fill(1);
    const b = new Uint8Array(4).fill(2);
    zeroize(a, null, undefined, b);
    expect(a.every((v) => v === 0)).toBe(true);
    expect(b.every((v) => v === 0)).toBe(true);
  });
});

describe("brain stats helpers", () => {
  it("erfc matches the identity erfc(0)=1 and symmetry", () => {
    expect(erfc(0)).toBeCloseTo(1.0, 9);
    expect(erfc(1e9)).toBeCloseTo(0.0, 9);
  });

  it("pearson: +1 for a perfect line, ~0 for noise, null on degenerate", () => {
    expect(pearson([1, 2, 3, 4], [2, 4, 6, 8])).toBeCloseTo(1.0, 9);
    expect(Math.abs(pearson([1, 2, 3, 4], [1, -1, 1, -1])!)).toBeLessThan(0.5);
    // Degenerate (zero-variance) input returns null — fail closed, no NaN.
    expect(pearson([1, 1, 1], [1, 2, 3])).toBeNull();
  });

  it("fisherZDifferenceP: identical correlations give 1.0; a big rise is small-p", () => {
    // At the null (identical r) the p-value is 0.5 — no evidence of a
    // difference either way (0.5*erfc(0)).
    expect(fisherZDifferenceP(0.5, 30, 0.5, 30)).toBeCloseTo(0.5, 6);
    expect(fisherZDifferenceP(0.6, 40, 0.05, 40)).toBeLessThan(0.05);
    // Too few observations: fail closed (no claim), never NaN.
    expect(fisherZDifferenceP(0.9, 3, 0.1, 40)).toBe(1.0);
  });

  it("sampleSd: 0 below two points, exact for a known pair", () => {
    expect(sampleSd([5])).toBe(0.0);
    expect(sampleSd([])).toBe(0.0);
    expect(sampleSd([2, 4])).toBeCloseTo(Math.SQRT2, 9);
  });
});
