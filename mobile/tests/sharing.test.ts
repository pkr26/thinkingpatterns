/**
 * Therapist-sharing wrap: the REAL shipping module (node engine behind the
 * same seam) against the cross-platform vectors in shared/vectors.json,
 * plus the negative space (wrong ids, malformed keys) vectors cannot
 * express.
 *
 * The vectors carry fixed TEST keys for both sides, so this file can run
 * the therapist side too (node:crypto directly): wrap with the patient
 * code, unwrap with the vector's private key, land back on the data key.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import nodeCrypto from "node:crypto";
import { describe, expect, it } from "vitest";

import { deriveWrapKek, wrapDataKeyForTherapist, WRAP_CONTEXT } from "../src/crypto/sharing";
import { buildAad, decrypt, encryptWithFixedNonce, TamperError } from "../src/crypto/envelope";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { wrap_vectors: wrapVectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));

/** The therapist side of the vector, straight through node:crypto. */
function unwrapWith(
  therapistPrivPkcs8B64: string,
  ephemeralPubB64: string,
  wrapped: Buffer,
  userId: string,
  therapistId: string,
  therapistPubB64: string,
): Buffer {
  const priv = nodeCrypto.createPrivateKey({
    key: Buffer.from(therapistPrivPkcs8B64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const pub = nodeCrypto.createPublicKey({
    key: Buffer.from(ephemeralPubB64, "base64"),
    format: "der",
    type: "spki",
  });
  const shared = nodeCrypto.diffieHellman({ privateKey: priv, publicKey: pub });
  const kek = deriveWrapKek(
    shared,
    Buffer.from(ephemeralPubB64, "base64"),
    Buffer.from(therapistPubB64, "base64"),
  );
  return decrypt(kek, wrapped, buildAad(WRAP_CONTEXT, userId, therapistId));
}

describe("shared wrap vectors against the real TS sharing stack", () => {
  it("has vectors to check", () => {
    expect(wrapVectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const [i, v] of wrapVectors.entries()) {
    it(`vector ${i}: the pinned KEK reproduces the pinned wrap bytes`, () => {
      // Derive the KEK from the vector's own fixed inputs — this is the
      // exact construction wrapDataKeyForTherapist runs on device.
      const priv = nodeCrypto.createPrivateKey({
        key: Buffer.from(v.ephemeral_priv_pkcs8, "base64"),
        format: "der",
        type: "pkcs8",
      });
      const pub = nodeCrypto.createPublicKey({
        key: Buffer.from(v.therapist_pub_spki, "base64"),
        format: "der",
        type: "spki",
      });
      const shared = nodeCrypto.diffieHellman({ privateKey: priv, publicKey: pub });
      const kek = deriveWrapKek(
        shared,
        Buffer.from(v.ephemeral_pub_spki, "base64"),
        Buffer.from(v.therapist_pub_spki, "base64"),
      );
      const aad = buildAad(WRAP_CONTEXT, v.user_id, v.therapist_id);
      const blob = encryptWithFixedNonce(kek, Buffer.from(v.data_key, "base64"), aad, Buffer.from(v.nonce, "base64"));
      expect(blob.toString("base64")).toBe(v.wrapped);
    });

    it(`vector ${i}: a fresh on-device wrap decrypts on the therapist side`, () => {
      const dataKey = Buffer.from(v.data_key, "base64");
      const wrap = wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, v.user_id, v.therapist_id);
      // Fresh ephemeral every grant — never the vector's.
      expect(wrap.ephemeralPubB64).not.toBe(v.ephemeral_pub_spki);
      const unwrapped = unwrapWith(
        v.therapist_priv_pkcs8,
        wrap.ephemeralPubB64,
        Buffer.from(wrap.wrappedKeyB64, "base64"),
        v.user_id,
        v.therapist_id,
        v.therapist_pub_spki,
      );
      expect(unwrapped.equals(dataKey)).toBe(true);
    });
  }
});

describe("wrap negative space", () => {
  const v = wrapVectors[0];

  it("two wraps of the same key differ (fresh ephemeral)", () => {
    const dataKey = Buffer.alloc(32, 9);
    const a = wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, v.user_id, v.therapist_id);
    const b = wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, v.user_id, v.therapist_id);
    expect(a.ephemeralPubB64).not.toBe(b.ephemeralPubB64);
    expect(a.wrappedKeyB64).not.toBe(b.wrappedKeyB64);
  });

  it("a wrap bound to the wrong patient does not unwrap", () => {
    const dataKey = Buffer.alloc(32, 5);
    const wrap = wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, "OTHER", v.therapist_id);
    expect(() =>
      unwrapWith(
        v.therapist_priv_pkcs8,
        wrap.ephemeralPubB64,
        Buffer.from(wrap.wrappedKeyB64, "base64"),
        v.user_id,
        v.therapist_id,
        v.therapist_pub_spki,
      ),
    ).toThrow(TamperError);
  });

  it("a wrap made for therapist A does not unwrap as therapist B", () => {
    const other = wrapVectors[1];
    const dataKey = Buffer.alloc(32, 6);
    // Wrapped to A's public key…
    const wrap = wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, v.user_id, v.therapist_id);
    // …but opened with B's private key: the ECDH secret differs.
    expect(() =>
      unwrapWith(
        other.therapist_priv_pkcs8,
        wrap.ephemeralPubB64,
        Buffer.from(wrap.wrappedKeyB64, "base64"),
        v.user_id,
        v.therapist_id,
        v.therapist_pub_spki,
      ),
    ).toThrow(TamperError);
  });

  it("rejects wrong-size data keys and malformed public keys", () => {
    expect(() =>
      wrapDataKeyForTherapist(Buffer.alloc(31), v.therapist_pub_spki, v.user_id, v.therapist_id),
    ).toThrow(/data key must be 32 bytes/);
    expect(() =>
      wrapDataKeyForTherapist(Buffer.alloc(32), "short", v.user_id, v.therapist_id),
    ).toThrow(/wrong format/);
    // 124 chars of base64 that decode to the wrong byte length.
    expect(() =>
      wrapDataKeyForTherapist(Buffer.alloc(32), "AAAA", v.user_id, v.therapist_id),
    ).toThrow(/wrong format/);
    // Exactly 124 chars (right b64 LENGTH) decoding to the wrong byte
    // count: the decoded-length check is the one that fires.
    expect(() =>
      wrapDataKeyForTherapist(Buffer.alloc(32), "A".repeat(124), v.user_id, v.therapist_id),
    ).toThrow(/wrong format/);
    // Valid-length b64, wrong bytes: ECDH with a non-point must throw.
    expect(() =>
      wrapDataKeyForTherapist(
        Buffer.alloc(32),
        Buffer.alloc(91, 1).toString("base64"),
        v.user_id,
        v.therapist_id,
      ),
    ).toThrow();
  });
});
