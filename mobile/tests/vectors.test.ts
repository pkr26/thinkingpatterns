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
import { buildAad, decrypt, encrypt, encryptWithFixedNonce } from "../src/crypto/envelope";
import {
  envelopeAad,
  envelopeKek,
  unwrapDataKey,
  wrapDataKeyWithFixedNonce,
} from "../src/crypto/keyEnvelope";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const parsed = JSON.parse(readFileSync(vectorsPath, "utf8"));
const { vectors, encrypt_vectors: encryptVectors, envelope_vectors: envelopeVectors } = parsed;

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
      const blob = encryptWithFixedNonce(dataKey, Buffer.from(v.plaintext, "base64"), aad, nonce);
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
    expect(() => encryptWithFixedNonce(key, Buffer.from("data"), undefined, Buffer.alloc(8))).toThrow();
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

describe("AAD edge-case vectors (promoted 2026-09-17 from redteam/a_crypto.py A6)", () => {
  // Surrogates, DEL/control chars, CJK, RTL, combining marks, empty parts —
  // pinned byte-for-byte on backend, mobile, portal and by verify_vectors.mjs.
  const edge = (JSON.parse(readFileSync(vectorsPath, "utf8")) as { aad_edge_cases: { name: string; parts: string[]; aad_b64: string }[] }).aad_edge_cases;

  it("has the full 16-vector corpus", () => {
    expect(edge.length).toBeGreaterThanOrEqual(16);
  });

  it.each(edge)("buildAad matches the pinned bytes for %s", (v) => {
    expect(buildAad(...v.parts).toString("base64")).toBe(v.aad_b64);
  });

  it("lone surrogates escape identically to Python (never raw UTF-8)", () => {
    const lone = edge.find((v) => v.name === "lone-high-surrogate");
    expect(lone).toBeDefined();
    const raw = buildAad(...(lone!.parts)).toString("utf8");
    expect(raw).toContain("\\u");
    expect(raw).toBe(Buffer.from(lone!.aad_b64, "base64").toString("utf8"));
  });
});

// --- v2 key-envelope vectors (2026-09-26) ------------------------------------
//
// Four entries: the version-bound v2 entry AAD (positive + tamper), and the
// password-wrapped random data key (positive + tamper) — the exact wrap the
// v2 registration/upgrade/password-change paths emit. All replayed through
// the REAL shipping modules, like every family above.
describe("shared/vectors.json envelope_vectors against the real v2 key-envelope stack", () => {
  it("has the 4-entry corpus including both tamper negatives", () => {
    expect(envelopeVectors.length).toBeGreaterThanOrEqual(4);
    expect(envelopeVectors.filter((v: { expect?: string }) => v.expect === "tamper").length).toBeGreaterThanOrEqual(2);
  });

  it("has both families (version-bound entry AAD + key-envelope wrap)", () => {
    expect(envelopeVectors.some((v: { kind: string }) => v.kind === "entry-aad-v2")).toBe(true);
    expect(envelopeVectors.some((v: { kind: string }) => v.kind === "key-envelope-wrap")).toBe(true);
  });

  for (const [i, v] of envelopeVectors.entries()) {
    if (v.kind === "entry-aad-v2" || v.kind === "entry-aad-v2-tampered") {
      it(`envelope vector ${i} (${v.kind}): v2-bound entry AAD decrypts / fails as pinned`, () => {
        const salt = Buffer.from(v.salt, "base64");
        const dataKey = deriveDataKey(deriveMasterKey(v.password, salt, v.iterations));
        const aad = buildAad(...v.aad_parts);
        const blob = Buffer.from(v.blob, "base64");
        if (v.expect === "tamper") {
          expect(() => decrypt(dataKey, blob, aad)).toThrow();
        } else {
          expect(decrypt(dataKey, blob, aad).toString("base64")).toBe(v.plaintext);
          // The 4-part builder reproduces the pinned blob byte-for-byte at
          // the pinned nonce (the mobile -> backend direction).
          expect(
            encryptWithFixedNonce(dataKey, Buffer.from(v.plaintext, "base64"), aad, Buffer.from(v.nonce, "base64")).toString("base64"),
          ).toBe(v.blob);
        }
      });
    } else if (v.kind === "key-envelope-wrap" || v.kind === "key-envelope-wrap-tampered") {
      it(`envelope vector ${i} (${v.kind}): KEK + AAD + wrap agree with the backend`, () => {
        // The KEK input is the PBKDF2 master key the client already derives;
        // derive it from the vector's own password/salt to prove the whole
        // chain, and separately confirm the pinned master_key matches.
        const salt = Buffer.from(v.salt, "base64");
        const master = deriveMasterKey(v.password, salt, v.iterations);
        expect(master.toString("base64")).toBe(v.master_key);
        const kek = envelopeKek(master, salt);
        expect(kek.toString("base64")).toBe(v.kek);
        // AAD: canonical OBJECT form — {context, kdf_params (canonical order:
        // algorithm, version, iterations), username}, compact, ensure_ascii.
        expect(envelopeAad(v.username, v.kdf_params).toString("base64")).toBe(v.aad);
        const wrapped = Buffer.from(v.wrapped, "base64");
        if (v.expect === "tamper") {
          expect(() => unwrapDataKey(wrapped, kek, v.username, v.kdf_params)).toThrow();
        } else {
          // Exactly 60 bytes on the wire: nonce(12) || ct(32) || tag(16).
          expect(wrapped).toHaveLength(60);
          expect(unwrapDataKey(wrapped, kek, v.username, v.kdf_params).toString("base64")).toBe(v.data_key);
          // The mobile -> backend direction reproduces the pinned wrap at
          // the pinned nonce (the fixed-nonce seam is vector-only).
          expect(
            wrapDataKeyWithFixedNonce(
              Buffer.from(v.data_key, "base64"),
              kek,
              v.username,
              v.kdf_params,
              Buffer.from(v.nonce, "base64"),
            ).toString("base64"),
          ).toBe(v.wrapped);
        }
      });
    }
  }

  it("a wrong password fails the wrap's GCM authentication (TamperError, not garbage)", () => {
    const v = envelopeVectors.find((x: { kind: string }) => x.kind === "key-envelope-wrap");
    expect(v).toBeDefined();
    const salt = Buffer.from(v.salt, "base64");
    const wrongMaster = deriveMasterKey("not-the-password", salt, v.iterations);
    const kek = envelopeKek(wrongMaster, salt);
    expect(() => unwrapDataKey(Buffer.from(v.wrapped, "base64"), kek, v.username, v.kdf_params)).toThrow(
      expect.objectContaining({ name: "TamperError" }),
    );
  });

  it("the AAD binds the username: another account's name fails authentication", () => {
    const v = envelopeVectors.find((x: { kind: string }) => x.kind === "key-envelope-wrap");
    expect(v).toBeDefined();
    const salt = Buffer.from(v.salt, "base64");
    const kek = envelopeKek(deriveMasterKey(v.password, salt, v.iterations), salt);
    expect(() => unwrapDataKey(Buffer.from(v.wrapped, "base64"), kek, "other-user", v.kdf_params)).toThrow();
  });
});
