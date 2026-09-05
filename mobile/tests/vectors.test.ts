/**
 * Cross-platform crypto verification — the REAL modules, not a re-derivation.
 *
 * These tests import the shipping src/crypto code (node engine behind the
 * same interface) and prove byte-for-byte agreement with the backend
 * reference values in shared/vectors.json, including the non-ASCII and
 * astral AAD vectors that pin the ensure_ascii canonicalization contract.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { deriveMasterKey, deriveAuthKey, deriveDataKey } from "../src/crypto/kdf";
import { buildAad, decrypt } from "../src/crypto/envelope";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("shared/vectors.json against the real TS crypto stack", () => {
  it("has vectors to check", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(4);
  });

  for (const [i, v] of vectors.entries()) {
    it(`vector ${i}: KDF + envelope agree with the backend`, () => {
      const salt = Buffer.from(v.salt, "base64");
      const master = deriveMasterKey(v.password, salt, v.iterations);
      expect(master.toString("base64")).toBe(v.master_key);

      const authKey = deriveAuthKey(master);
      expect(authKey.toString("base64")).toBe(v.auth_key);

      const dataKey = deriveDataKey(master);
      expect(dataKey.toString("base64")).toBe(v.data_key);

      const aad = Buffer.from(v.aad, "base64");
      const blob = Buffer.from(v.blob, "base64");
      const plaintext = decrypt(dataKey, blob, aad);
      expect(plaintext.toString("base64")).toBe(v.plaintext);
    });

    it(`vector ${i}: AAD tampering fails closed`, () => {
      const salt = Buffer.from(v.salt, "base64");
      const dataKey = deriveDataKey(deriveMasterKey(v.password, salt, v.iterations));
      const blob = Buffer.from(v.blob, "base64");
      expect(() => decrypt(dataKey, blob, buildAad("entry", "other-user", "x"))).toThrow();
    });
  }
});

describe("AAD canonicalization (ensure_ascii contract)", () => {
  // Expected bytes pinned from Python:
  // json.dumps([...], separators=(",",":"), ensure_ascii=True)
  it("matches Python for non-ASCII, astral, DEL and control characters", () => {
    const expected = '["\\u00fcn\\u00efcode","\\ud83e\\udde0-brain","del\\u007f","back\\bfeed\\f"]';
    expect(
      buildAad("ünïcode", "🧠-brain", "del\u007f", "back\bfeed\f").toString("utf8"),
    ).toBe(expected);
  });

  it("is collision-free across split positions (no concatenation ambiguity)", () => {
    expect(buildAad("a", "b").toString("utf8")).not.toBe(buildAad("ab", "").toString("utf8"));
    expect(buildAad("1", "23").toString("utf8")).not.toBe(buildAad("12", "3").toString("utf8"));
  });
});
