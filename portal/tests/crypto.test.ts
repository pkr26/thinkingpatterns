/**
 * Cross-platform crypto verification — the REAL portal modules under
 * Node's WebCrypto against shared/vectors.json (the same standing as the
 * mobile vectors suite). Everything the portal must get byte-right is
 * pinned here: the key schedule, the AES-GCM envelope, the AAD
 * canonicalization, and the patient-data-key unwrap.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildAad } from "../src/aad";
import {
  decrypt,
  decryptEntry,
  decryptInsights,
  decryptNote,
  deriveMasterKey,
  derivePortalKeys,
  encrypt,
  encryptNote,
  generateTherapistKeyPair,
  sealPrivateKeyForUpload,
  TamperError,
  unlockWrapPrivateKey,
  unwrapPatientDataKey,
} from "../src/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { vectors, encrypt_vectors: encryptVectors, wrap_vectors: wrapVectors } = JSON.parse(
  readFileSync(vectorsPath, "utf8"),
) as {
  vectors: { password: string; salt: string; iterations: number; auth_key: string; data_key: string }[];
  encrypt_vectors: { data_key: string; plaintext: string; aad_parts: string[]; blob: string }[];
  wrap_vectors: {
    therapist_priv_pkcs8: string;
    therapist_pub_spki: string;
    ephemeral_pub_spki: string;
    data_key: string;
    user_id: string;
    therapist_id: string;
    wrapped: string;
  }[];
};

const unb64 = (t: string): Uint8Array<ArrayBuffer> => {
  const bin = atob(t);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const toB64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};

describe("key schedule vectors", () => {
  for (const [i, v] of vectors.entries()) {
    it(`vector ${i}: master -> auth key matches the backend`, async () => {
      const master = await deriveMasterKey(v.password, unb64(v.salt));
      const keys = await derivePortalKeys(master);
      expect(keys.authKeyB64).toBe(v.auth_key);
    });
  }
});

describe("envelope vectors", () => {
  for (const [i, v] of encryptVectors.slice(0, 3).entries()) {
    it(`vector ${i}: the portal decrypts backend-encrypted blobs`, async () => {
      const plain = await decrypt(unb64(v.data_key), unb64(v.blob), buildAad(...v.aad_parts));
      expect(toB64(plain)).toBe(v.plaintext);
    });
  }
});

describe("wrap vectors — the portal unwrap path", () => {
  for (const [i, v] of wrapVectors.entries()) {
    it(`vector ${i}: unwrap lands on the patient's data key`, async () => {
      const priv = await crypto.subtle.importKey(
        "pkcs8",
        unb64(v.therapist_priv_pkcs8),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      );
      const dataKey = await unwrapPatientDataKey(
        priv,
        v.ephemeral_pub_spki,
        v.wrapped,
        v.user_id,
        v.therapist_id,
        v.therapist_pub_spki,
      );
      expect(toB64(dataKey)).toBe(v.data_key);
    });

    it(`vector ${i}: a wrap bound to another patient does not unwrap`, async () => {
      const priv = await crypto.subtle.importKey(
        "pkcs8",
        unb64(v.therapist_priv_pkcs8),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      );
      await expect(
        unwrapPatientDataKey(
          priv,
          v.ephemeral_pub_spki,
          v.wrapped,
          "OTHER-PATIENT",
          v.therapist_id,
          v.therapist_pub_spki,
        ),
      ).rejects.toThrow(TamperError);
    });
  }
});

describe("AAD canonicalization", () => {
  it("escapes non-ASCII and astral characters like Python ensure_ascii", () => {
    const aad = buildAad("entry", "café", "🎉");
    expect(new TextDecoder().decode(aad)).toBe(
      '["entry","caf\\u00e9","\\ud83c\\udf89"]',
    );
  });

  it("keeps ASCII parts compact", () => {
    expect(new TextDecoder().decode(buildAad("insights", "abc123", "patterns"))).toBe(
      '["insights","abc123","patterns"]',
    );
  });
});

describe("envelope behavior", () => {
  it("roundtrips and refuses tampered blobs", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const aad = buildAad("note", "t", "u", "n1");
    const blob = await encrypt(key, new TextEncoder().encode("hello"), aad);
    const plain = await decrypt(key, blob, aad);
    expect(new TextDecoder().decode(plain)).toBe("hello");
    const tampered = blob.slice();
    tampered.set([tampered[5]! ^ 1], 5);
    await expect(decrypt(key, tampered, aad)).rejects.toThrow(TamperError);
    await expect(decrypt(key, blob, buildAad("note", "t", "u", "n2"))).rejects.toThrow(TamperError);
  });

  it("rejects wrong key sizes and too-short blobs", async () => {
    await expect(encrypt(new Uint8Array(31), new TextEncoder().encode("x"))).rejects.toThrow(/32 bytes/);
    await expect(decrypt(new Uint8Array(32), new Uint8Array(10))).rejects.toThrow(TamperError);
  });
});

describe("therapist key custody", () => {
  it("seals the private key for upload and unlocks it after login", async () => {
    const master = await deriveMasterKey("portal-pass-1", crypto.getRandomValues(new Uint8Array(16)));
    const keys = await derivePortalKeys(master);
    const pair = await generateTherapistKeyPair();
    expect(pair.publicKeySpkiB64).toHaveLength(124);
    const sealed = await sealPrivateKeyForUpload(keys.wrapKek, pair.privateKeyPkcs8B64, "drportal");
    // What the server sees is opaque; what the right password yields is a
    // usable ECDH key.
    await expect(unlockWrapPrivateKey(keys.wrapKek, sealed, "other-name")).rejects.toThrow(TamperError);
    const unlocked = await unlockWrapPrivateKey(keys.wrapKek, sealed, "drportal");
    expect(unlocked.algorithm.name).toBe("ECDH");
  });
});

describe("notes", () => {
  it("roundtrips note text under the AAD binding", async () => {
    const master = await deriveMasterKey("portal-pass-2", crypto.getRandomValues(new Uint8Array(16)));
    const { noteKey } = await derivePortalKeys(master);
    const sealed = await encryptNote(noteKey, "t1", "u1", "note-1", "Session 42: steady progress.");
    const text = await decryptNote(noteKey, "t1", "u1", "note-1", sealed.blobB64);
    expect(text).toBe("Session 42: steady progress.");
    await expect(decryptNote(noteKey, "t1", "u1", "note-2", sealed.blobB64)).rejects.toThrow(TamperError);
  });
});

describe("payload decryption helpers", () => {
  it("decrypts an insights payload and entry blobs with the right AAD", async () => {
    const dataKey = crypto.getRandomValues(new Uint8Array(32));
    const userId = "user-9";
    const insights = { stats: { patterns: [{ kind: "topic", label: "guitar", occurrences: 5, confidence: 0.9, detail: { evidence_dates: ["2026-09-01"] } }] } };
    const insightsBlob = await encrypt(
      dataKey,
      new TextEncoder().encode(JSON.stringify(insights)),
      buildAad("insights", userId, "patterns"),
    );
    const payload = await decryptInsights(
      dataKey,
      userId,
      toB64(insightsBlob),
    );
    expect(payload.stats.patterns[0]!.label).toBe("guitar");

    const entryPayload = { v: 1, text: "played guitar all evening", sentiment: 0.4, created_at: "2026-09-01" };
    const entryBlob = await encrypt(
      dataKey,
      new TextEncoder().encode(JSON.stringify(entryPayload)),
      buildAad("entry", userId, "e-1"),
    );
    const entry = await decryptEntry(dataKey, userId, { client_entry_id: "e-1", blob: toB64(entryBlob) });
    expect(entry.text).toBe("played guitar all evening");
    expect(entry.sentiment).toBeCloseTo(0.4);
    // A malformed plaintext (no text field) is a hard error, not undefined.
    const badBlob = await encrypt(dataKey, new TextEncoder().encode('{"v":1}'), buildAad("entry", userId, "e-2"));
    await expect(
      decryptEntry(dataKey, userId, { client_entry_id: "e-2", blob: toB64(badBlob) }),
    ).rejects.toThrow(/malformed/);
  });
});
