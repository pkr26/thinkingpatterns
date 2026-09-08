/**
 * Cross-platform crypto verification — the REAL modules, not a re-derivation.
 *
 * These tests import the shipping src/crypto code (node engine behind the
 * same interface) and prove byte-for-byte agreement with the backend
 * reference values in shared/vectors.json, including the non-ASCII and
 * astral AAD vectors that pin the ensure_ascii canonicalization contract.
 *
 * DEVICE-ENGINE GAP: everything here runs on the `node:crypto` engine
 * fallback (see src/crypto/engine.ts) — the shipping on-device engine,
 * react-native-quick-crypto, is never exercised by any automated test. Its
 * AES-GCM/PBKDF2/HKDF paths are assumed to match node:crypto byte-for-byte.
 * To pin these vectors on-device in the future, run this same suite inside
 * the RN app (e.g. an in-app dev screen or e2e harness that loads
 * shared/vectors.json and executes the same assertions through the real
 * engine); do not reimplement the vectors in native code.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { deriveMasterKey, deriveAuthKey, deriveDataKey } from "../src/crypto/kdf";
import { buildAad, decrypt, encrypt } from "../src/crypto/envelope";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { vectors, encrypt_vectors: encryptVectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));

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

describe("fixed-nonce encrypt vectors (mobile -> backend direction)", () => {
  // The decrypt-only vectors above pin Python's output; this family pins what
  // THIS client emits, byte-for-byte, so the backend test can independently
  // decrypt it. AAD is rebuilt from the vector's PARTS — never the stored
  // bytes — which also exercises buildAad against every vector part set.
  it("has encrypt vectors to check, including a no-AAD case", () => {
    expect(encryptVectors.length).toBeGreaterThanOrEqual(2);
    // Pins the families beyond 3-part 'entry': 2-part moodlog/unlockproof
    // AADs, an empty plaintext, and the AAD-less secureStore path.
    expect(encryptVectors.some((v) => v.aad_parts === null)).toBe(true);
    expect(encryptVectors.some((v) => v.plaintext === "")).toBe(true);
    expect(encryptVectors.some((v) => v.aad_parts?.[0] === "moodlog")).toBe(true);
    expect(encryptVectors.some((v) => v.aad_parts?.[0] === "unlockproof")).toBe(true);
  });

  for (const [i, v] of encryptVectors.entries()) {
    it(`encrypt vector ${i}: fixed-nonce encrypt reproduces the blob byte-for-byte`, () => {
      const salt = Buffer.from(v.salt, "base64");
      const dataKey = deriveDataKey(deriveMasterKey(v.password, salt, v.iterations));
      const aad = v.aad_parts ? buildAad(...v.aad_parts) : undefined;
      const nonce = Buffer.from(v.nonce, "base64");
      const blob = encrypt(dataKey, Buffer.from(v.plaintext, "base64"), aad, nonce);
      expect(blob.toString("base64")).toBe(v.blob);
    });

    it(`encrypt vector ${i}: mobile decrypts the pinned blob (backend's encrypt output)`, () => {
      const salt = Buffer.from(v.salt, "base64");
      const dataKey = deriveDataKey(deriveMasterKey(v.password, salt, v.iterations));
      const aad = v.aad_parts ? buildAad(...v.aad_parts) : undefined;
      const plaintext = decrypt(dataKey, Buffer.from(v.blob, "base64"), aad);
      expect(plaintext.toString("base64")).toBe(v.plaintext);
    });
  }

  it("nonce seam: wrong-size nonce fails loudly, omission stays random", () => {
    const key = Buffer.alloc(32, 7);
    expect(() => encrypt(key, Buffer.from("data"), undefined, Buffer.alloc(8))).toThrow();
    const a = encrypt(key, Buffer.from("data"));
    const b = encrypt(key, Buffer.from("data"));
    expect(a.equals(b)).toBe(false);
  });
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
