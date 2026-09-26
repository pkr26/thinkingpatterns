/**
 * Cross-platform crypto verification — the REAL web modules under Node's
 * WebCrypto against shared/vectors.json (the same standing as the mobile
 * and portal vector suites). Everything the patient web client must get
 * byte-right is pinned here: the key schedule (BOTH patient subkeys),
 * the AES-GCM envelope (decrypt AND deterministic encrypt), the therapist
 * wrap in BOTH directions, the AAD canonicalization edge cases, and the
 * payload-layer contracts (entry v1/v2, insights v2 + state_seq,
 * question).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildAad } from "../src/crypto/aad";
import {
  decrypt,
  deriveMasterKey,
  encryptWithFixedNonce,
  fromBase64,
  toBase64,
  type Bytes,
} from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import {
  decryptEntry,
  decryptInsights,
  decryptQuestion,
  encryptEntry,
  timeOfDayBucket,
} from "../src/crypto/patient";
import {
  deriveWrapKek,
  keyFingerprint,
  unwrapDataKey,
  wrapDataKeyForTherapist,
  wrapWithEphemeralPrivate,
} from "../src/crypto/sharing";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const {
  vectors,
  encrypt_vectors: encryptVectors,
  wrap_vectors: wrapVectors,
  aad_edge_cases: aadEdgeCases,
} = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  vectors: {
    password: string;
    salt: string;
    iterations: number;
    master_key: string;
    auth_key: string;
    data_key: string;
    plaintext: string;
    aad: string;
    nonce: string;
    blob: string;
  }[];
  encrypt_vectors: {
    data_key: string;
    plaintext: string;
    aad_parts: string[] | null;
    nonce: string;
    blob: string;
  }[];
  wrap_vectors: {
    therapist_priv_pkcs8: string;
    therapist_pub_spki: string;
    ephemeral_priv_pkcs8: string;
    ephemeral_pub_spki: string;
    data_key: string;
    user_id: string;
    therapist_id: string;
    nonce: string;
    wrapped: string;
  }[];
  aad_edge_cases: { name: string; parts: string[]; aad_b64: string }[];
};

const importPriv = (pkcs8B64: string): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    "pkcs8",
    fromBase64(pkcs8B64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

describe("key schedule vectors", () => {
  for (const [i, v] of vectors.entries()) {
    it(`vector ${i}: master + auth + data keys match the backend`, async () => {
      const master = await deriveMasterKey(v.password, fromBase64(v.salt), v.iterations);
      expect(toBase64(master)).toBe(v.master_key);
      const keys = await derivePatientKeys(master);
      expect(toBase64(keys.authKey)).toBe(v.auth_key);
      expect(toBase64(keys.dataKey)).toBe(v.data_key);
    });
  }
});

describe("envelope vectors", () => {
  for (const [i, v] of encryptVectors.entries()) {
    // aad_parts: null is the deliberate no-AAD binding case (vector 5) —
    // the envelope must open with additionalData undefined, not "[]".
    const aad = v.aad_parts ? buildAad(...v.aad_parts) : undefined;

    it(`vector ${i}: decrypts backend-encrypted blobs`, async () => {
      const plain = await decrypt(fromBase64(v.data_key), fromBase64(v.blob), aad);
      expect(toBase64(plain)).toBe(v.plaintext);
    });

    it(`vector ${i}: deterministic construction reproduces the exact blob`, async () => {
      const blob = await encryptWithFixedNonce(
        fromBase64(v.data_key),
        fromBase64(v.plaintext),
        fromBase64(v.nonce),
        aad,
      );
      expect(toBase64(blob)).toBe(v.blob);
    });
  }

  it("the master vectors' blobs pin the same envelope", async () => {
    const v = vectors[0]!;
    const blob = await encryptWithFixedNonce(
      fromBase64(v.data_key),
      fromBase64(v.plaintext),
      fromBase64(v.nonce),
      fromBase64(v.aad),
    );
    expect(toBase64(blob)).toBe(v.blob);
  });
});

describe("wrap vectors — the patient wrap direction", () => {
  for (const [i, v] of wrapVectors.entries()) {
    it(`vector ${i}: the full construction reproduces 'wrapped' byte-for-byte`, async () => {
      // shared = ECDH(ephemeral_priv, therapist_pub) — the exact secret the
      // patient-side wrap computes; derive the KEK with the shipping code
      // and reproduce the vector's envelope with its fixed nonce.
      const ephPriv = await importPriv(v.ephemeral_priv_pkcs8);
      const therapistPub = await crypto.subtle.importKey(
        "spki",
        fromBase64(v.therapist_pub_spki),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: therapistPub }, ephPriv, 256);
      const kek = await deriveWrapKek(new Uint8Array(sharedBits), fromBase64(v.ephemeral_pub_spki), fromBase64(v.therapist_pub_spki));
      const wrapped = await encryptWithFixedNonce(
        kek,
        fromBase64(v.data_key),
        fromBase64(v.nonce),
        buildAad("consent-wrap", v.user_id, v.therapist_id),
      );
      expect(toBase64(wrapped)).toBe(v.wrapped);
    });

    it(`vector ${i}: wrapWithEphemeralPrivate output opens to the data key`, async () => {
      const ephPriv = await importPriv(v.ephemeral_priv_pkcs8);
      const { wrappedKeyB64 } = await wrapWithEphemeralPrivate(
        ephPriv,
        fromBase64(v.ephemeral_pub_spki),
        fromBase64(v.data_key),
        v.therapist_pub_spki,
        v.user_id,
        v.therapist_id,
      );
      const therapistPriv = await importPriv(v.therapist_priv_pkcs8);
      const opened = await unwrapDataKey(
        therapistPriv,
        v.therapist_pub_spki,
        v.ephemeral_pub_spki,
        wrappedKeyB64,
        v.user_id,
        v.therapist_id,
      );
      expect(toBase64(opened)).toBe(v.data_key);
    });

    it(`vector ${i}: the vector's own wrap unwraps to the data key`, async () => {
      const therapistPriv = await importPriv(v.therapist_priv_pkcs8);
      const opened = await unwrapDataKey(
        therapistPriv,
        v.therapist_pub_spki,
        v.ephemeral_pub_spki,
        v.wrapped,
        v.user_id,
        v.therapist_id,
      );
      expect(toBase64(opened)).toBe(v.data_key);
    });

    it(`vector ${i}: a wrap bound to another patient does not unwrap`, async () => {
      const therapistPriv = await importPriv(v.therapist_priv_pkcs8);
      await expect(
        unwrapDataKey(
          therapistPriv,
          v.therapist_pub_spki,
          v.ephemeral_pub_spki,
          v.wrapped,
          "OTHER-PATIENT",
          v.therapist_id,
        ),
      ).rejects.toThrow("blob failed authentication");
    });
  }

  it("wrapDataKeyForTherapist round-trips against a fresh therapist keypair", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const thSpkiB64 = toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
    const dataKey = fromBase64(wrapVectors[0]!.data_key);
    const wrap = await wrapDataKeyForTherapist(dataKey, thSpkiB64, "user-1", "therapist-2");
    const priv = await crypto.subtle.importKey(
      "pkcs8",
      new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const opened = await unwrapDataKey(priv, thSpkiB64, wrap.ephemeralPubB64, wrap.wrappedKeyB64, "user-1", "therapist-2");
    expect(toBase64(opened)).toBe(wrapVectors[0]!.data_key);
  });

  it("refuses a wrong-format therapist public key", async () => {
    await expect(
      wrapDataKeyForTherapist(fromBase64(wrapVectors[0]!.data_key), "AAAA", "u", "t"),
    ).rejects.toThrow("wrong format");
  });
});

describe("fingerprint (the out-of-band pairing check)", () => {
  it("formats identically to mobile and the portal", async () => {
    // Precomputed from wrap_vectors[0].therapist_pub_spki: SHA-256 over the
    // SPKI DER, first 16 bytes, eight spaced uppercase hex groups.
    expect(await keyFingerprint(wrapVectors[0]!.therapist_pub_spki)).toBe(
      "CB54 DE22 C976 DF43 08B6 7F8F 112B D4D7",
    );
  });
});

describe("AAD canonicalization (ensure_ascii contract)", () => {
  for (const c of aadEdgeCases) {
    it(`case ${c.name}: byte-identical to the backend`, () => {
      expect(toBase64(buildAad(...c.parts))).toBe(c.aad_b64);
    });
  }
});

describe("entry payload layer", () => {
  const dataKey = fromBase64(encryptVectors[0]!.data_key);
  const userId = "user-777";
  const entryId = "entry-2026-09-25-a";

  it("emits the v1 shape byte-compatibly when no structured channels are given", async () => {
    const { blobB64 } = await encryptEntry(dataKey, userId, entryId, "A calm evening.", "2026-09-25T20:11:00Z", 1.5);
    const payload = await decryptEntry(dataKey, userId, entryId, blobB64);
    expect(payload.v).toBe(1);
    expect(payload.text).toBe("A calm evening.");
    expect(payload.sentiment).toBe(1.5);
    expect(payload.created_at).toBe("2026-09-25T20:11:00Z");
  });

  it("emits v2 with the structured channels present", async () => {
    const { blobB64 } = await encryptEntry(dataKey, userId, entryId, "Text", "2026-09-25T08:00:00Z", 0, {
      energy: 3,
      sleep: 4,
      tags: ["work", "walk"],
      tod: "morning",
    });
    const payload = await decryptEntry(dataKey, userId, entryId, blobB64);
    expect(payload.v).toBe(2);
    expect(payload.energy).toBe(3);
    expect(payload.sleep).toBe(4);
    expect(payload.tags).toEqual(["work", "walk"]);
    expect(payload.tod).toBe("morning");
  });

  it("binds the version-bound v2 AAD; a legacy blob still opens via the fallback", async () => {
    const { blobB64 } = await encryptEntry(dataKey, userId, entryId, "v", "2026-09-25T09:00:00Z", null, undefined, 2);
    // Declared version matches the 4-part binding:
    expect((await decryptEntry(dataKey, userId, entryId, blobB64, 2)).text).toBe("v");
    // The version-bound blob must NOT open without the declared version:
    // the legacy 3-part AAD is a different binding by design (M-2).
    await expect(decryptEntry(dataKey, userId, entryId, blobB64)).rejects.toThrow("blob failed authentication");
    // The fallback direction: a pre-M-2 blob (legacy binding) still opens
    // when the row metadata declares version 1 — try 4-part, fall back.
    const legacy = await encryptEntry(dataKey, userId, entryId, "legacy", "2026-09-25T09:00:00Z", null);
    expect((await decryptEntry(dataKey, userId, entryId, legacy.blobB64, 1)).text).toBe("legacy");
  });

  it("fails closed on relocation (another user or entry id)", async () => {
    const { blobB64 } = await encryptEntry(dataKey, userId, entryId, "mine", "2026-09-25T10:00:00Z", null);
    await expect(decryptEntry(dataKey, "user-999", entryId, blobB64)).rejects.toThrow("blob failed authentication");
    await expect(decryptEntry(dataKey, userId, "entry-other", blobB64)).rejects.toThrow("blob failed authentication");
  });

  it("throws loudly on an unknown payload version", async () => {
    const v3 = new TextEncoder().encode(JSON.stringify({ v: 3, text: "future" }));
    const blob = await encryptWithFixedNonce(dataKey, v3, fromBase64(encryptVectors[0]!.nonce), buildAad("entry", userId, entryId));
    await expect(decryptEntry(dataKey, userId, entryId, toBase64(blob))).rejects.toThrow(
      "unsupported entry payload version: 3",
    );
  });

  it("pins the time-of-day bucket boundaries", () => {
    expect(timeOfDayBucket(0)).toBe("night");
    expect(timeOfDayBucket(4)).toBe("night");
    expect(timeOfDayBucket(5)).toBe("morning");
    expect(timeOfDayBucket(11)).toBe("morning");
    expect(timeOfDayBucket(12)).toBe("afternoon");
    expect(timeOfDayBucket(16)).toBe("afternoon");
    expect(timeOfDayBucket(17)).toBe("evening");
    expect(timeOfDayBucket(22)).toBe("evening");
    expect(timeOfDayBucket(23)).toBe("night");
  });
});

describe("insights + question payload layer", () => {
  const dataKey = fromBase64(encryptVectors[0]!.data_key);
  const userId = "user-777";

  it("decrypts a v2 insights payload with its analysis generation", async () => {
    const payload = { v: 2, stats: { patterns: [] }, state_seq: 41 };
    const blob = await encryptWithFixedNonce(
      dataKey,
      new TextEncoder().encode(JSON.stringify(payload)),
      fromBase64(encryptVectors[0]!.nonce),
      buildAad("insights", userId, "patterns"),
    );
    const got = await decryptInsights(dataKey, userId, toBase64(blob));
    expect(got.v).toBe(2);
    expect(got.state_seq).toBe(41);
  });

  it("throws loudly on an unknown insights version", async () => {
    const blob = await encryptWithFixedNonce(
      dataKey,
      new TextEncoder().encode(JSON.stringify({ v: 3 })),
      fromBase64(encryptVectors[0]!.nonce),
      buildAad("insights", userId, "patterns"),
    );
    await expect(decryptInsights(dataKey, userId, toBase64(blob))).rejects.toThrow(
      "unsupported insights payload version: 3",
    );
  });

  it("decrypts the daily question with its pattern routing", async () => {
    const payload = { for_date: "2026-09-25", question: "What gave you energy today?", pattern_pid: "temporal:work" };
    const blob = await encryptWithFixedNonce(
      dataKey,
      new TextEncoder().encode(JSON.stringify(payload)),
      fromBase64(encryptVectors[0]!.nonce),
      buildAad("question", userId, "2026-09-25"),
    );
    const got = await decryptQuestion(dataKey, userId, "2026-09-25", toBase64(blob));
    expect(got.question).toBe("What gave you energy today?");
    expect(got.pattern_pid).toBe("temporal:work");
    // A question served for another date does not open under this binding.
    await expect(decryptQuestion(dataKey, userId, "2026-09-24", toBase64(blob))).rejects.toThrow(
      "blob failed authentication",
    );
  });
});
