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
import { describe, expect, it, vi } from "vitest";

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

function expectWiped(bytes: Uint8Array): void {
  expect([...bytes]).toEqual(new Array<number>(bytes.length).fill(0));
}

/** Capture the exact ArrayBuffer returned by WebCrypto decrypt. The portal
 * wraps it in a Uint8Array, so a later fill(0) must also erase this view. */
function captureDecryptBuffer(): { bytes: () => Uint8Array; restore: () => void } {
  const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  let captured: ArrayBuffer | null = null;
  const spy = vi.spyOn(crypto.subtle, "decrypt").mockImplementation(
    async (...args: Parameters<SubtleCrypto["decrypt"]>) => {
      const result = await nativeDecrypt(...args);
      captured = result;
      return result;
    },
  );
  return {
    bytes: () => {
      if (captured === null) throw new Error("expected WebCrypto decrypt to run");
      return new Uint8Array(captured);
    },
    restore: () => spy.mockRestore(),
  };
}

/** The raw input view passed to importKey is the same mutable view the portal
 * owns. Capturing it lets these tests prove finally blocks run after both a
 * successful import and a rejected one. */
function captureImportedKey(format: KeyFormat): { bytes: () => Uint8Array[]; restore: () => void } {
  const nativeImportKey = crypto.subtle.importKey.bind(crypto.subtle);
  const captured: Uint8Array[] = [];
  const spy = vi.spyOn(crypto.subtle, "importKey").mockImplementation(
    async (...args: Parameters<SubtleCrypto["importKey"]>) => {
      const [actualFormat, keyData] = args;
      if (actualFormat === format && keyData instanceof Uint8Array) captured.push(keyData);
      return nativeImportKey(...args);
    },
  );
  return { bytes: () => captured, restore: () => spy.mockRestore() };
}

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

  it("zeroizes ECDH DER, shared-secret, and KEK input buffers on every unwrap path", async () => {
    const v = wrapVectors[0]!;
    const privateDer = unb64(v.therapist_priv_pkcs8);
    const priv = await crypto.subtle.importKey(
      "pkcs8",
      privateDer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    privateDer.fill(0);

    // The SPKI view belongs to the portal during unwrap and is scrubbed as
    // soon as WebCrypto has made its public-key handle.
    const publicInput = captureImportedKey("spki");
    try {
      const dataKey = await unwrapPatientDataKey(
        priv,
        v.ephemeral_pub_spki,
        v.wrapped,
        v.user_id,
        v.therapist_id,
        v.therapist_pub_spki,
      );
      dataKey.fill(0);
      expect(publicInput.bytes()).toHaveLength(1);
      publicInput.bytes().forEach(expectWiped);
    } finally {
      publicInput.restore();
    }

    // HKDF imports the ECDH shared secret and AES imports the derived KEK.
    // A rejected authenticated decrypt must still run the same finally wipe.
    const secretInputs = captureImportedKey("raw");
    try {
      await expect(
        unwrapPatientDataKey(
          priv,
          v.ephemeral_pub_spki,
          v.wrapped,
          "different-patient",
          v.therapist_id,
          v.therapist_pub_spki,
        ),
      ).rejects.toThrow(TamperError);
      expect(secretInputs.bytes()).toHaveLength(2);
      secretInputs.bytes().forEach(expectWiped);
    } finally {
      secretInputs.restore();
    }
  });
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

  it("zeroizes decrypted PKCS#8 bytes after both import outcomes", async () => {
    const master = await deriveMasterKey("portal-pass-3", crypto.getRandomValues(new Uint8Array(16)));
    const keys = await derivePortalKeys(master);
    const pair = await generateTherapistKeyPair();
    const sealed = await sealPrivateKeyForUpload(keys.wrapKek, pair.privateKeyPkcs8B64, "drportal");

    const successInput = captureImportedKey("pkcs8");
    try {
      await unlockWrapPrivateKey(keys.wrapKek, sealed, "drportal");
      expect(successInput.bytes()).toHaveLength(1);
      successInput.bytes().forEach(expectWiped);
    } finally {
      successInput.restore();
    }

    // It decrypts successfully, then importKey rejects the deliberately
    // malformed DER. The raw decrypted buffer must not survive that error.
    const malformedBlob = await encrypt(
      keys.wrapKek,
      new Uint8Array([1, 2, 3]),
      buildAad("therapist-key", "drportal"),
    );
    const failureInput = captureImportedKey("pkcs8");
    try {
      await expect(
        unlockWrapPrivateKey(keys.wrapKek, toB64(malformedBlob), "drportal"),
      ).rejects.toThrow();
      expect(failureInput.bytes()).toHaveLength(1);
      failureInput.bytes().forEach(expectWiped);
    } finally {
      failureInput.restore();
    }
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

  it("wipes raw note plaintext after parsing and after a malformed payload", async () => {
    const noteKey = crypto.getRandomValues(new Uint8Array(32));
    const good = await encryptNote(noteKey, "t1", "u1", "note-1", "private session note");
    const goodPlain = captureDecryptBuffer();
    try {
      await expect(decryptNote(noteKey, "t1", "u1", "note-1", good.blobB64)).resolves.toBe("private session note");
      expectWiped(goodPlain.bytes());
    } finally {
      goodPlain.restore();
    }

    const malformed = await encrypt(
      noteKey,
      new TextEncoder().encode('{"v":1}'),
      buildAad("note", "t1", "u1", "bad-note"),
    );
    const badPlain = captureDecryptBuffer();
    try {
      await expect(decryptNote(noteKey, "t1", "u1", "bad-note", toB64(malformed))).rejects.toThrow(/malformed/);
      expectWiped(badPlain.bytes());
    } finally {
      badPlain.restore();
    }
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

  it("wipes decrypted insights and entry plaintext on success and validation errors", async () => {
    const dataKey = crypto.getRandomValues(new Uint8Array(32));
    const userId = "user-wipe";
    const insightsBlob = await encrypt(
      dataKey,
      new TextEncoder().encode('{"stats":{"patterns":[]}}'),
      buildAad("insights", userId, "patterns"),
    );
    const insightsPlain = captureDecryptBuffer();
    try {
      await expect(decryptInsights(dataKey, userId, toB64(insightsBlob))).resolves.toEqual({
        stats: { patterns: [] },
      });
      expectWiped(insightsPlain.bytes());
    } finally {
      insightsPlain.restore();
    }

    const entryBlob = await encrypt(
      dataKey,
      new TextEncoder().encode('{"v":1,"text":"private entry"}'),
      buildAad("entry", userId, "entry-good"),
    );
    const entryPlain = captureDecryptBuffer();
    try {
      await expect(
        decryptEntry(dataKey, userId, { client_entry_id: "entry-good", blob: toB64(entryBlob) }),
      ).resolves.toMatchObject({ text: "private entry" });
      expectWiped(entryPlain.bytes());
    } finally {
      entryPlain.restore();
    }

    const malformedBlob = await encrypt(
      dataKey,
      new TextEncoder().encode('{"v":1}'),
      buildAad("entry", userId, "entry-bad"),
    );
    const malformedPlain = captureDecryptBuffer();
    try {
      await expect(
        decryptEntry(dataKey, userId, { client_entry_id: "entry-bad", blob: toB64(malformedBlob) }),
      ).rejects.toThrow(/malformed/);
      expectWiped(malformedPlain.bytes());
    } finally {
      malformedPlain.restore();
    }
  });
});

// AAD edge-case vectors (promoted 2026-09-17 from redteam/a_crypto.py A6):
// the portal's buildAad must agree with backend + mobile on surrogates,
// DEL/control chars, CJK, RTL, combining marks and empty parts.
describe("AAD edge-case vectors", () => {
  const edgeCases = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  aad_edge_cases: { name: string; parts: string[]; aad_b64: string }[];
};
const edge = edgeCases.aad_edge_cases ?? [];

  it("the contract file carries the corpus", () => {
    expect(edge.length).toBeGreaterThanOrEqual(16);
  });

  it.each(edge)("buildAad matches pinned bytes for %s", (v) => {
    const got = buildAad(...v.parts);
    const want = Buffer.from(v.aad_b64, "base64");
    expect(Buffer.compare(Buffer.from(got), want)).toBe(0);
  });
});

// Pairing key fingerprint (2026-09-17 audit): the portal's WebCrypto
// fingerprint must equal the mobile app's node:crypto one byte for byte —
// both suites pin this constant against the shared wrap vector's fixed
// therapist key, so the two humans always read the same string.
describe("pairing key fingerprint", () => {
  const wrapVectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
    wrap_vectors: { therapist_pub_spki: string }[];
  };
  const firstWrap = wrapVectors.wrap_vectors[0];
  const FIXED_SPKI_B64 = firstWrap ? firstWrap.therapist_pub_spki : "";
  const EXPECTED = "CB54 DE22 C976 DF43"; // sha256(spk)[0:8], hex groups — mobile-pinned

  it("formats the shared-vector key identically to the mobile app", async () => {
    const { keyFingerprint } = await import("../src/crypto");
    expect(await keyFingerprint(FIXED_SPKI_B64)).toBe(EXPECTED);
  });
});

// --- caseload summaries (2026-09-19) -------------------------------------------

describe("decryptCaseloadSummary", () => {
  // Fixture generated by the BACKEND reference implementation
  // (app.security.sharing.wrap_summary_payload): a summary wrapped for
  // (user-42, therapist-7). The cross-implementation check that matters —
  // the same standing as the wrap vectors above.
  const FIXTURE = {
    priv_b64:
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9tDqAAC8xZczPWVzd8XqknA6QhA5C2phXXWVRCgcB4ehRANCAASNFmLbGd9zjQ4nF2mAnShR12Zom8uyquWi5bb/ITy3VXaIOYFz9UjPsNTvBFwhzwdgiJd8phV3/RnBs3odijov",
    pub_b64:
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjRZi2xnfc40OJxdpgJ0oUddmaJvLsqrlouW2/yE8t1V2iDmBc/VIz7DU7wRcIc8HYIiXfKYVd/0ZwbN6HYo6Lw==",
    eph_b64:
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZU50k/IWWVLXWvV9r8CknbXFHjJLijiWrvzxA2L4zjtT4jBuB5V3QU+rmicM/S3e7Ty3jjnxt+jfXIC8vqXiAg==",
    wrapped_b64:
      "9E1Kbf2fKtHFyI5R5uavoC1wOanqLYFThgZac7g36ikqPmGBbV6/1cS9d9rV2YvAwRJePHXWqFIVTmSdOJUl+ol0reBDPvzCRAOZ2huDPBjofjS3CqmpH/haL6w2HgN4O+nnzY31IFf67iXLDnr4",
  };

  async function fixtureKey(): Promise<CryptoKey> {
    const der = Uint8Array.from(atob(FIXTURE.priv_b64), (c) => c.charCodeAt(0));
    return crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
  }

  it("opens a backend-wrapped summary to its sanitized fields", async () => {
    const { decryptCaseloadSummary } = await import("../src/crypto");
    const key = await fixtureKey();
    const summary = await decryptCaseloadSummary(
      key,
      FIXTURE.pub_b64,
      FIXTURE.eph_b64,
      FIXTURE.wrapped_b64,
      "user-42",
      "therapist-7",
    );
    expect(summary).not.toBeNull();
    expect(summary!.patterns).toBe(7);
    expect(summary!.sensitive).toBe(true);
    expect(summary!.newest).toBe("2026-09-18");
    expect(summary!.forDate).toBe("2026-09-19");
  });

  it("relocation between pairs fails closed to null (AAD binds the pair)", async () => {
    const { decryptCaseloadSummary } = await import("../src/crypto");
    const key = await fixtureKey();
    const summary = await decryptCaseloadSummary(
      key,
      FIXTURE.pub_b64,
      FIXTURE.eph_b64,
      FIXTURE.wrapped_b64,
      "user-42",
      "someone-else",
    );
    expect(summary).toBeNull();
  });

  it("garbage input degrades to null, never a throw", async () => {
    const { decryptCaseloadSummary } = await import("../src/crypto");
    const key = await fixtureKey();
    expect(
      await decryptCaseloadSummary(key, FIXTURE.pub_b64, "AAAA", "BBBB", "u", "t"),
    ).toBeNull();
  });

  it("L-73 (2026-09-20): the decrypted summary plaintext is zeroized after parsing", async () => {
    // Every sibling decrypt wipes its WebCrypto plaintext buffer in a
    // finally; decryptCaseloadSummary used to leave the caseload overview
    // (pattern counts, sensitive presence) in the heap.  The captured
    // ArrayBuffer behind the returned Uint8Array view must be all zeros
    // once the call resolves.
    const { decryptCaseloadSummary } = await import("../src/crypto");
    const key = await fixtureKey();
    const capture = captureDecryptBuffer();
    try {
      await expect(
        decryptCaseloadSummary(
          key,
          FIXTURE.pub_b64,
          FIXTURE.eph_b64,
          FIXTURE.wrapped_b64,
          "user-42",
          "therapist-7",
        ),
      ).resolves.toMatchObject({ patterns: 7, sensitive: true });
      expectWiped(capture.bytes());
    } finally {
      capture.restore();
    }
  });
});

// --- measures (MBC, 2026-09-19) -------------------------------------------------

describe("decryptMeasure", () => {
  // Fixture generated by the backend reference (app.security.crypto.encrypt
  // under a fixed data key, AAD ("measure","user-42","m-fix-1")): the same
  // cross-implementation standing as the caseload-summary fixture.
  const KEY = new Uint8Array(32).map((_, i) => i);
  const BLOB =
    "tS1qbjXtyzCyUm+fFwCgIPLnz407hURsH68TPUhMvvRck811g8zth1KAzggxTHjaKN8PI5JdfqVOw1utabKL/JPkL0mUpA3UideUFWLZTO6z28VVHZ+SzHwN1hjCi/rOm7Y=";

  it("opens a backend-encrypted measure to its sanitized fields", async () => {
    const { decryptMeasure } = await import("../src/crypto");
    const reading = await decryptMeasure(KEY, "user-42", {
      client_measure_id: "m-fix-1",
      blob: BLOB,
      measure_date: "2026-09-18",
    });
    expect(reading).not.toBeNull();
    expect(reading!.measure).toBe("phq9");
    expect(reading!.score).toBe(14);
    expect(reading!.completedAt).toBe("2026-09-18");
    expect(reading!.measureDate).toBe("2026-09-18");
  });

  it("relocation between patients fails closed to null (AAD binds the pair)", async () => {
    const { decryptMeasure } = await import("../src/crypto");
    const reading = await decryptMeasure(KEY, "user-43", {
      client_measure_id: "m-fix-1",
      blob: BLOB,
      measure_date: "2026-09-18",
    });
    expect(reading).toBeNull();
  });

  it("wrong-key and garbage blobs degrade to null, never a throw", async () => {
    const { decryptMeasure } = await import("../src/crypto");
    expect(
      await decryptMeasure(new Uint8Array(32), "user-42", {
        client_measure_id: "m-fix-1",
        blob: BLOB,
        measure_date: "2026-09-18",
      }),
    ).toBeNull();
    expect(
      await decryptMeasure(KEY, "user-42", {
        client_measure_id: "m-fix-1",
        blob: "AAAA",
        measure_date: "2026-09-18",
      }),
    ).toBeNull();
  });
});
