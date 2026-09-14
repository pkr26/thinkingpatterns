/**
 * Unit coverage for the client crypto stack beyond the shared vectors:
 * validation branches, envelope failure modes, and the payload-level
 * encrypt/decrypt helpers (including AAD relocation resistance).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { deriveMasterKey, deriveMasterKeyAsync, deriveAuthKey, deriveDataKey, zeroize, KDF_ITERATIONS } from "../src/crypto/kdf";
import { decrypt, encrypt, generateKey, TamperError, NONCE_SIZE } from "../src/crypto/envelope";
import { buildAad } from "../src/crypto/aad";
import {
  deriveKeys,
  deriveKeysAsync,
  encryptEntry,
  decryptEntry,
  decryptInsights,
  decryptQuestion,
  type Keys,
} from "../src/crypto/MindPatternCrypto";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "..", "shared", "vectors.json"), "utf8")).vectors;

const SALT = Buffer.alloc(12, 3);

describe("kdf validation", () => {
  it("rejects salts shorter than the 8-byte floor", () => {
    for (const bad of ["", "1234567"]) {
      expect(() => deriveMasterKey("pw", Buffer.from(bad, "utf8"))).toThrow(/salt must be at least 8 bytes/);
    }
    // 8 bytes is the accepted boundary.
    expect(deriveMasterKey("pw", Buffer.alloc(8, 1), 1).length).toBe(32);
  });

  it("rejects non-positive iteration counts", () => {
    expect(() => deriveMasterKey("pw", SALT, 0)).toThrow(/iterations must be positive/);
    expect(() => deriveMasterKey("pw", SALT, -5)).toThrow(/iterations must be positive/);
  });

  it("defaults to the pinned 600k production iteration count", () => {
    expect(KDF_ITERATIONS).toBe(600_000);
    expect(deriveMasterKey("pw", SALT, 1).toString("hex")).toBe(
      deriveMasterKey("pw", SALT, 1).toString("hex"),
    );
  });

  it("derives independent auth/data keys from the same master", () => {
    const master = deriveMasterKey("pw", SALT, 1);
    const auth = deriveMasterKey("pw", SALT, 1); // deterministic
    expect(master.equals(auth)).toBe(true);
    const keys = deriveKeys("pw", SALT);
    // One fast sanity anchor without burning another 600k PBKDF2 run.
    expect(keys.masterKey.length).toBe(32);
    expect(keys.authKey.length).toBe(32);
    expect(keys.dataKey.length).toBe(32);
    expect(keys.authKey.equals(keys.dataKey)).toBe(false);
  });

  it("pins the exact PBKDF2 and HKDF labels against the shared backend vector", () => {
    const v = vectors[0];
    const salt = Buffer.from(v.salt, "base64");
    const master = deriveMasterKey(v.password, salt, v.iterations);
    expect(master.toString("base64")).toBe(v.master_key);
    // The HKDF info strings ("mindpattern/auth/v1" / "mindpattern/data/v1")
    // are a cross-platform contract — a single changed byte diverges the
    // keys from every backend-derived value.
    expect(deriveAuthKey(master).toString("base64")).toBe(v.auth_key);
    expect(deriveDataKey(master).toString("base64")).toBe(v.data_key);
  });
});

describe("async PBKDF2 (JS-thread-friendly derivation)", () => {
  it("derives byte-identical keys to the sync path (vector-pinned)", async () => {
    const v = vectors[0];
    const salt = Buffer.from(v.salt, "base64");
    const master = await deriveMasterKeyAsync(v.password, salt, v.iterations);
    expect(master.toString("base64")).toBe(v.master_key);
    const keys = await deriveKeysAsync(v.password, salt);
    expect(keys.authKey.toString("base64")).toBe(v.auth_key);
    expect(keys.dataKey.toString("base64")).toBe(v.data_key);
  });

  it("applies the same validation as the sync path", async () => {
    await expect(deriveMasterKeyAsync("pw", Buffer.alloc(7, 1))).rejects.toThrow(/salt must be at least 8 bytes/);
    await expect(deriveMasterKeyAsync("pw", SALT, 0)).rejects.toThrow(/iterations must be positive/);
  });

  it("rejects when the engine reports an error or no key", async () => {
    // kdf.ts's "./engine" import is aliased to the node:crypto-backed test
    // engine, so the failure injection must patch THAT module's object.
    const { engine } = await import("./helpers/nodeEngine");
    const original = engine.pbkdf2.bind(engine);
    try {
      engine.pbkdf2 = ((_p: unknown, _s: unknown, _i: unknown, _k: unknown, _d: unknown, cb: (e: Error | null, k?: Buffer) => void) =>
        cb(new Error("native failure"))) as typeof engine.pbkdf2;
      await expect(deriveMasterKeyAsync("pw", SALT, 1)).rejects.toThrow("native failure");
      engine.pbkdf2 = ((_p: unknown, _s: unknown, _i: unknown, _k: unknown, _d: unknown, cb: (e: Error | null, k?: Buffer) => void) =>
        cb(null, undefined)) as typeof engine.pbkdf2;
      await expect(deriveMasterKeyAsync("pw", SALT, 1)).rejects.toThrow("pbkdf2 produced no key");
    } finally {
      engine.pbkdf2 = original;
    }
  });
});

describe("AAD canonicalization pins (ensure_ascii contract)", () => {
  it("escapes non-ASCII to \\uXXXX exactly like Python json.dumps", () => {
    // Pinned from Python: json.dumps([...], separators=(",",":"), ensure_ascii=True)
    expect(
      buildAad("ünïcode", "🧠-brain", "del\u007f", "back\bfeed\f").toString("utf8"),
    ).toBe('["\\u00fcn\\u00efcode","\\ud83e\\udde0-brain","del\\u007f","back\\bfeed\\f"]');
  });

  it("keeps ASCII passthrough byte-identical (no escaping below 0x7f)", () => {
    expect(buildAad("plain", "ids", "here").toString("utf8")).toBe('["plain","ids","here"]');
  });

  it("is collision-free across split positions", () => {
    expect(buildAad("a", "b").toString("utf8")).not.toBe(buildAad("ab", "").toString("utf8"));
    expect(buildAad("1", "23").toString("utf8")).not.toBe(buildAad("12", "3").toString("utf8"));
  });
});

describe("zeroize", () => {
  it("overwrites every provided buffer with zeros", () => {
    const a = Buffer.alloc(6, 0xaa);
    const b = Buffer.alloc(9, 0x11);
    zeroize(a, b);
    expect(a.equals(Buffer.alloc(6))).toBe(true);
    expect(b.equals(Buffer.alloc(9))).toBe(true);
  });

  it("tolerates undefined and null slots", () => {
    const a = Buffer.alloc(4, 0xff);
    expect(() => zeroize(a, undefined, null)).not.toThrow();
    expect(a.equals(Buffer.alloc(4))).toBe(true);
  });
});

describe("envelope", () => {
  it("generates fresh 32-byte keys", () => {
    const k1 = generateKey();
    const k2 = generateKey();
    expect(k1.length).toBe(32);
    expect(k1.equals(k2)).toBe(false);
  });

  it("round-trips with and without AAD; nonce is 12 bytes", () => {
    const key = generateKey();
    const aad = buildAad("entry", "u", "e1");
    for (const blob of [encrypt(key, Buffer.from("secret"), aad), encrypt(key, Buffer.from("secret"))]) {
      expect(blob.length).toBeGreaterThanOrEqual(NONCE_SIZE + 16);
    }
    expect(decrypt(key, encrypt(key, Buffer.from("hello"), aad), aad).toString()).toBe("hello");
    expect(decrypt(key, encrypt(key, Buffer.from("hello"))).toString()).toBe("hello");
  });

  it("accepts the smallest valid blob: nonce + tag with empty plaintext (28 bytes)", () => {
    const key = generateKey();
    const blob = encrypt(key, Buffer.alloc(0), buildAad("entry", "u", "e"));
    expect(blob.length).toBe(NONCE_SIZE + 16);
    expect(decrypt(key, blob, buildAad("entry", "u", "e"))).toHaveLength(0);
    // One byte SHORTER is tampering.
    expect(() => decrypt(key, blob.subarray(0, blob.length - 1))).toThrow(TamperError);
  });

  it("refuses keys that are not exactly 32 bytes", () => {
    const short = Buffer.alloc(31, 1);
    const long = Buffer.alloc(33, 1);
    expect(() => encrypt(short, Buffer.from("x"))).toThrow(/key must be 32 bytes/);
    expect(() => encrypt(long, Buffer.from("x"))).toThrow(/key must be 32 bytes/);
    expect(() => decrypt(short, Buffer.alloc(40))).toThrow(/key must be 32 bytes/);
    expect(() => decrypt(long, Buffer.alloc(40))).toThrow(/key must be 32 bytes/);
  });

  it("flags truncated blobs as tampering", () => {
    const key = generateKey();
    const blob = encrypt(key, Buffer.from("hello"), buildAad("entry", "u", "e"));
    for (const bad of [blob.subarray(0, NONCE_SIZE + 15), blob.subarray(0, 5), Buffer.alloc(0)]) {
      expect(() => decrypt(key, bad)).toThrow(TamperError);
    }
  });

  it("maps cipher failures (bit flips, wrong AAD, wrong key) to TamperError", () => {
    const key = generateKey();
    const aad = buildAad("entry", "u", "e");
    const blob = encrypt(key, Buffer.from("hello"), aad);

    const flipped = Buffer.from(blob);
    flipped[NONCE_SIZE + 2] ^= 0x01;
    expect(() => decrypt(key, flipped, aad)).toThrow(TamperError);

    expect(() => decrypt(key, blob, buildAad("entry", "u", "other"))).toThrow(TamperError);
    expect(() => decrypt(generateKey(), blob, aad)).toThrow(TamperError);

    const err = new TamperError();
    expect(err.name).toBe("TamperError");
    expect(err.message).toBe("blob failed authentication");
  });
});

describe("MindPatternCrypto payload helpers", () => {
  // Derived lazily INSIDE tests: a module- or suite-scope derivation would
  // turn many crypto mutants into collection-time failures, which mutation
  // runners classify as "no tests ran" rather than kills.
  let cache: Keys | null = null;
  const keys = () => (cache ??= deriveKeys("correct horse battery staple", SALT));

  it("round-trips an entry and pins the wire payload shape", () => {
    const { blobB64 } = encryptEntry(keys(), "user-9", "e-1", "worried about work", "2026-09-01", -0.5);
    const payload = decryptEntry(keys(), "user-9", "e-1", blobB64);
    expect(payload).toEqual({ v: 1, text: "worried about work", sentiment: -0.5, created_at: "2026-09-01" });
  });

  it("binds entries to (user, entry id): relocation fails authentication", () => {
    const { blobB64 } = encryptEntry(keys(), "user-9", "e-1", "text", "2026-09-01", 0);
    expect(() => decryptEntry(keys(), "user-OTHER", "e-1", blobB64)).toThrow(TamperError);
    expect(() => decryptEntry(keys(), "user-9", "e-OTHER", blobB64)).toThrow(TamperError);
  });

  it("round-trips insight and question payloads with their AAD contracts", () => {
    const k = keys();
    const insightsBlob = encrypt(k.dataKey, Buffer.from(JSON.stringify({ v: 2, stats: { patterns: [] } })), buildAad("insights", "user-9", "patterns"));
    expect(decryptInsights(k, "user-9", insightsBlob.toString("base64"))).toEqual({ v: 2, stats: { patterns: [] } });
    expect(() => decryptInsights(k, "user-OTHER", insightsBlob.toString("base64"))).toThrow(TamperError);

    const qBlob = encrypt(k.dataKey, Buffer.from(JSON.stringify({ for_date: "2026-09-03", question: "What changed?" })), buildAad("question", "user-9", "2026-09-03"));
    expect(decryptQuestion(k, "user-9", "2026-09-03", qBlob.toString("base64"))).toEqual({
      for_date: "2026-09-03",
      question: "What changed?",
    });
    // AAD uses the server-reported date, not the local clock.
    expect(() => decryptQuestion(k, "user-9", "2026-09-02", qBlob.toString("base64"))).toThrow(TamperError);
  });

  it("rejects insights payloads whose version this client does not understand", () => {
    const k = keys();
    const blobOf = (payload: unknown) =>
      encrypt(k.dataKey, Buffer.from(JSON.stringify(payload)), buildAad("insights", "user-9", "patterns")).toString("base64");
    // A future schema roll must fail LOUDLY, not be misread as v2.
    expect(() => decryptInsights(k, "user-9", blobOf({ v: 3, stats: { patterns: [] } }))).toThrow(
      /unsupported insights payload version: 3/,
    );
    // A pre-versioning (or hostile) payload without v is unknown too.
    expect(() => decryptInsights(k, "user-9", blobOf({ stats: { patterns: [] } }))).toThrow(
      /unsupported insights payload version: undefined/,
    );
    // The accepted version round-trips.
    expect(decryptInsights(k, "user-9", blobOf({ v: 2, stats: { patterns: [] } }))).toEqual({
      v: 2,
      stats: { patterns: [] },
    });
  });
});
