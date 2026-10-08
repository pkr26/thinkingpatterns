import nodeCrypto from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { engine } from "./helpers/nodeEngine";
import * as journal from "../src/crypto/journalCrypto";
import * as keyEnvelope from "../src/crypto/keyEnvelope";
import * as recovery from "../src/crypto/recovery";
import { serverFingerprintMatches, wrapDataKeyForTherapist } from "../src/crypto/sharing";
import { encryptWithFixedNonce } from "../src/crypto/envelope";

afterEach(() => vi.restoreAllMocks());
const KEY = Buffer.alloc(32, 7), USER = "dddddddddddddddddddddddddddddddd", ID = "journal-one";
function wireAad(...parts: string[]) { return Buffer.from(JSON.stringify(parts), "ascii"); }
function wireOpen(blob: Buffer, key: Buffer, aad: Buffer): Buffer {
  const decipher = nodeCrypto.createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
  decipher.setAAD(aad); decipher.setAuthTag(blob.subarray(-16));
  return Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]);
}
function wireSeal(payload: unknown, aad: Buffer): string {
  const nonce = Buffer.alloc(12, 6), cipher = nodeCrypto.createCipheriv("aes-256-gcm", KEY, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([nonce, cipher.update(Buffer.from(JSON.stringify(payload))), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

it("writes optional structured channels and version bindings for an independent wire reader", () => {
  for (const structured of [undefined, {}, { energy: 0 }, { sleep: 0 }, { tags: ["work"] }, { tod: "night" }, { energy: 3, sleep: 4, tags: ["family"], tod: "morning" }]) {
    for (const version of [undefined, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1, 2]) {
      const { blobB64 } = journal.encryptEntry({ dataKey: KEY }, USER, ID, "edited", "2026-10-05T12:00:00Z", 0, structured, version);
      const aad = Number.isSafeInteger(version) && version! >= 1 ? wireAad("entry", USER, ID, String(version)) : wireAad("entry", USER, ID);
      const actual = JSON.parse(wireOpen(Buffer.from(blobB64, "base64"), KEY, aad).toString());
      expect(actual).toEqual({ v: structured && Object.keys(structured).length ? 2 : 1, text: "edited", sentiment: 0, created_at: "2026-10-05T12:00:00Z", ...(structured ?? {}) });
    }
  }
});

it("preserves additive authenticated fields while clearing old optional channels on a typed edit", () => {
  const original = { v: 3 as const, text: "old", sentiment: -1, created_at: "old-date", energy: 4, sleep: 5, tags: ["work"], tod: "night", input_mode: "voice" as const, transcript_lang: "es", english_text: "old translation", future_field: { retained: true } };
  const { blobB64 } = journal.encryptEntry({ dataKey: KEY }, USER, ID, "edited", "new-date", null, undefined, undefined, undefined, original);
  expect(JSON.parse(wireOpen(Buffer.from(blobB64, "base64"), KEY, wireAad("entry", USER, ID)).toString())).toEqual({ v: 1, text: "edited", sentiment: null, created_at: "new-date", future_field: { retained: true } });
});

it("notifies the consumer only for independently authenticated version-bound entries", () => {
  const payload = { v: 1, text: "stored", sentiment: null, created_at: "date" };
  for (const version of [1, 2, 8]) {
    const bound = vi.fn();
    const blob = wireSeal(payload, wireAad("entry", USER, ID, String(version)));
    expect(journal.decryptEntry({ dataKey: KEY }, USER, ID, blob, version, { onV2Bound: bound })).toEqual(payload);
    expect(bound).toHaveBeenCalledTimes(1);
    expect(() => journal.decryptEntry({ dataKey: KEY }, USER, ID, blob, version + 1, { forbidLegacyAad: true })).toThrow();
  }
  const legacy = wireSeal(payload, wireAad("entry", USER, ID));
  for (const version of [undefined, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1, 8]) {
    const bound = vi.fn();
    expect(journal.decryptEntry({ dataKey: KEY }, USER, ID, legacy, version, { onV2Bound: bound })).toEqual(payload);
    expect(bound).not.toHaveBeenCalled();
  }
});

it("erases the plaintext buffer passed to the encryption consumer", () => {
  const original = engine.createCipheriv;
  const observed: Buffer[] = [];
  vi.spyOn(engine, "createCipheriv").mockImplementation(((...args: Parameters<typeof original>) => {
    const cipher = original(...args), update = cipher.update.bind(cipher);
    cipher.update = ((data: Buffer) => { observed.push(data); return update(data); }) as typeof cipher.update;
    return cipher;
  }) as typeof original);
  journal.encryptEntry({ dataKey: KEY }, USER, ID, "private journal", "date", null);
  expect(observed).toHaveLength(1); expect(observed[0]!.every(byte => byte === 0)).toBe(true);
  expect(KEY.equals(Buffer.alloc(32, 7))).toBe(true);
});

it("validates declared password envelope costs and refuses unknown or malformed wire fields", () => {
  expect(keyEnvelope.defaultKdfParams()).toEqual({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 });
  const valid = { algorithm: "pbkdf2-sha256", version: 1, iterations: 100000 };
  for (const iterations of [100000, 100001, 600000, 10000000]) expect(keyEnvelope.validateKdfParams({ ...valid, iterations })).toEqual({ ...valid, iterations });
  const invalid: unknown[] = [null, false, 1, "params", [], {}, { ...valid, extra: true }, { ...valid, algorithm: "sha256" }, { ...valid, version: 2 }, { ...valid, version: "1" }, { ...valid, version: 1.5 }];
  for (const iterations of [undefined, "100000", 99999, 10000001, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) invalid.push({ ...valid, iterations });
  for (const value of invalid) expect(keyEnvelope.validateKdfParams(value), JSON.stringify(value)).toBeNull();
  expect(keyEnvelope.generateDataKey()).toHaveLength(32);
  for (const [data, kek] of [[Buffer.alloc(31), KEY], [KEY, Buffer.alloc(31)]] as [Buffer, Buffer][]) expect(() => keyEnvelope.wrapDataKey(data, kek, "alice", valid)).toThrow(/32/);
  expect(() => keyEnvelope.envelopeKek(Buffer.alloc(15), Buffer.alloc(16))).toThrow();
  expect(keyEnvelope.envelopeKek(Buffer.alloc(16, 1), Buffer.alloc(16))).toHaveLength(32);
  expect(() => keyEnvelope.unwrapDataKey(Buffer.alloc(59), KEY, "alice", valid)).toThrow();
});

it("matches the independent server fingerprint and treats unsupported legacy representations as undecidable", () => {
  const { publicKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = publicKey.export({ format: "der", type: "spki" }), encoded = der.toString("base64");
  const honest = nodeCrypto.createHash("sha256").update(der).digest("hex").slice(0, 16);
  expect(serverFingerprintMatches(encoded, honest)).toBe(true);
  expect(serverFingerprintMatches(encoded, honest === "0000000000000000" ? "1111111111111111" : "0000000000000000")).toBe(false);
  for (const unsupported of ["", honest.toUpperCase(), `x${honest}`, `${honest}x`, honest.slice(1), `${honest}${honest}`]) expect(serverFingerprintMatches(encoded, unsupported)).toBeNull();
});

it("reads both generations of recovery kits without giving the server's verifier a decryption key", () => {
  const kit = Buffer.alloc(32, 3), data = Buffer.alloc(32, 4), b64 = kit.toString("base64");
  expect(recovery.recoveryKeyToB64(kit)).toBe(b64);
  expect(recovery.recoveryKitText(kit)).toBe(`mindpattern-recovery:v2:${b64}`);
  for (const input of [b64, `mindpattern-recovery:v1:${b64}`, `mindpattern-recovery:v2:${b64}`, ` \n${b64.slice(0, 20)}\t${b64.slice(20)} `]) expect(recovery.recoveryKeyFromB64(input)).toEqual(kit);
  for (const input of ["", `x${b64}`, `${b64}x`, b64.slice(1), b64.replace(/=$/, ""), `mindpattern-recovery:v3:${b64}`, `${b64.slice(0, 20)}mindpattern-recovery:v2:${b64.slice(20)}`, b64.slice(0, -2) + "B="]) expect(recovery.recoveryKeyFromB64(input)).toBeNull();
  expect(recovery.generateRecoveryKey()).toHaveLength(32);
  const verifier = Buffer.from(nodeCrypto.hkdfSync("sha256", kit, Buffer.alloc(32), Buffer.from("mindpattern/recovery-verifier/v2"), 32));
  expect(recovery.recoveryVerifierKeyV2(kit)).toEqual(verifier);
  for (const scheme of ["v1", "v2"] as const) {
    const label = scheme === "v1" ? "mindpattern/recovery/v1" : "mindpattern/recovery-seal/v2";
    const kek = Buffer.from(nodeCrypto.hkdfSync("sha256", kit, Buffer.alloc(32), Buffer.from(label), 32));
    const sealed = scheme === "v1" ? recovery.sealDataKeyForRecovery(kit, data, USER) : recovery.sealDataKeyForRecoveryV2(kit, data, USER);
    expect(wireOpen(sealed, kek, wireAad("recovery", USER, "data-key"))).toEqual(data);
    expect(recovery.unsealDataKeyWithRecoveryScheme(kit, sealed, USER, scheme)).toEqual(data);
    expect(recovery.unsealDataKeyWithRecoveryScheme(kit, sealed, "other-user", scheme)).toBeNull();
  }
});

it("clears explicitly removed nullable and empty structured fields in the authenticated wire payload", () => {
  // Older decoded draft records can contain explicit null for an optional time-of-day value.
  const variants = [{ energy: null, sleep: 2 }, { sleep: null, energy: 2 }, { tags: [], energy: 2 }, { tod: null as unknown as string, energy: 2 }];
  for (const structured of variants) {
    const { blobB64 } = journal.encryptEntry({ dataKey: KEY }, USER, ID, "text", "date", null, structured);
    const actual = JSON.parse(wireOpen(Buffer.from(blobB64, "base64"), KEY, wireAad("entry", USER, ID)).toString());
    expect(actual).toEqual({ v: 2, text: "text", sentiment: null, created_at: "date", ...(structured.energy != null ? { energy: structured.energy } : {}), ...(structured.sleep != null ? { sleep: structured.sleep } : {}) });
  }
});

it("refuses a known legacy replay and never interprets invalid generations as a valid binding", () => {
  const payload = { v: 1, text: "stored", sentiment: null, created_at: "date" };
  const legacy = wireSeal(payload, wireAad("entry", USER, ID));
  expect(() => journal.decryptEntry({ dataKey: KEY }, USER, ID, legacy, 2, { forbidLegacyAad: true })).toThrow("blob failed authentication");
  for (const invalid of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    const malformedBinding = wireSeal(payload, wireAad("entry", USER, ID, String(invalid)));
    const onV2Bound = vi.fn();
    expect(() => journal.decryptEntry({ dataKey: KEY }, USER, ID, malformedBinding, invalid, { onV2Bound })).toThrow("blob failed authentication");
    expect(onV2Bound).not.toHaveBeenCalled();
  }
});

it("provides actionable envelope validation errors before cryptographic work", () => {
  const params = { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 100000 };
  expect(keyEnvelope.validateKdfParams(Object.assign([], params))).toBeNull();
  expect(keyEnvelope.validateKdfParams(Object.assign(() => undefined, params))).toBeNull();
  expect(() => keyEnvelope.envelopeKek(Buffer.alloc(15), Buffer.alloc(16))).toThrow("password-derived key material must be at least 16 bytes");
  expect(() => keyEnvelope.wrapDataKey(KEY, Buffer.alloc(31), "alice", params)).toThrow("kek must be 32 bytes");
  expect(() => keyEnvelope.wrapDataKeyWithFixedNonce(Buffer.alloc(31), KEY, "alice", params, Buffer.alloc(12))).toThrow("data_key must be 32 bytes");
  expect(() => keyEnvelope.wrapDataKeyWithFixedNonce(KEY, Buffer.alloc(31), "alice", params, Buffer.alloc(12))).toThrow("kek must be 32 bytes");
  expect(() => keyEnvelope.wrapDataKeyWithFixedNonce(KEY, KEY, "alice", params, Buffer.alloc(11))).toThrow("nonce must be 12 bytes");
  expect(() => keyEnvelope.unwrapDataKey(Buffer.alloc(59), KEY, "alice", params)).toThrow("wrapped data key must be exactly 60 bytes");
  expect(() => keyEnvelope.unwrapDataKey(Buffer.alloc(60), Buffer.alloc(31), "alice", params)).toThrow("kek must be 32 bytes");
  expect(() => encryptWithFixedNonce(KEY, Buffer.from("text"), undefined, Buffer.alloc(11))).toThrow("nonce must be 12 bytes");
});

it("erases engine-held HKDF output after returning an independent envelope key", () => {
  const original = engine.hkdfSync, observed: ArrayBuffer[] = [];
  vi.spyOn(engine, "hkdfSync").mockImplementation((...args) => { const bytes = original(...args); observed.push(bytes); return bytes; });
  const output = keyEnvelope.envelopeKek(Buffer.alloc(32, 4), Buffer.alloc(16, 3));
  const expected = Buffer.from(original("sha256", Buffer.alloc(32, 4), Buffer.alloc(16, 3), Buffer.from("mindpattern/envelope/v2"), 32));
  expect(output).toEqual(expected); expect(observed).toHaveLength(1);
  expect(new Uint8Array(observed[0]!).every(byte => byte === 0)).toBe(true);
});

it.each([false, true])("erases recovery sealing keys after a consumer finishes (failure=%s)", fail => {
  const originalCipher = engine.createCipheriv, originalDecipher = engine.createDecipheriv;
  const keys: Buffer[] = [], error = new Error("encryption backend unavailable");
  const kit = Buffer.alloc(32, 3), data = Buffer.alloc(32, 4);
  vi.spyOn(engine, "createCipheriv").mockImplementation((...args) => {
    keys.push(args[1]); if (fail) throw error; return originalCipher(...args);
  });
  if (fail) expect(() => recovery.sealDataKeyForRecoveryV2(kit, data, USER)).toThrow(error);
  else {
    const sealed = recovery.sealDataKeyForRecoveryV2(kit, data, USER);
    vi.spyOn(engine, "createDecipheriv").mockImplementation((...args) => { keys.push(args[1]); return originalDecipher(...args); });
    expect(recovery.unsealDataKeyWithRecoveryScheme(kit, sealed, USER, "v2")).toEqual(data);
    expect(recovery.unsealDataKeyWithRecoveryScheme(kit, sealed, "wrong-user", "v2")).toBeNull();
  }
  expect(keys.length).toBe(fail ? 1 : 3);
  for (const key of keys) expect(key.every(byte => byte === 0)).toBe(true);
  expect(kit).toEqual(Buffer.alloc(32, 3)); expect(data).toEqual(Buffer.alloc(32, 4));
});

it("returns null if recovery parsing cannot allocate decoded bytes, and erases rejected noncanonical bytes", () => {
  const original = Buffer.from, b64 = Buffer.alloc(32, 3).toString("base64"), observed: Buffer[] = [];
  vi.spyOn(Buffer, "from").mockImplementation(((value: unknown, encoding?: unknown) => {
    if (encoding === "base64" && value === b64) throw new Error("decoder unavailable");
    const raw = original(value as string, encoding as BufferEncoding); if (encoding === "base64") observed.push(raw); return raw;
  }) as typeof Buffer.from);
  expect(recovery.recoveryKeyFromB64(b64)).toBeNull();
  expect(recovery.recoveryKeyFromB64(b64.slice(0, -2) + "B=")).toBeNull();
  expect(observed).toHaveLength(1); expect(observed[0]!.every(byte => byte === 0)).toBe(true);
});

it.each([false, true])("erases ephemeral therapist wrapping secrets even when encryption fails (failure=%s)", fail => {
  const { publicKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  expect(() => wrapDataKeyForTherapist(KEY, publicB64 + "=", USER, "therapist")).toThrow("therapist public key has the wrong format");
  const originalDh = engine.diffieHellman, originalCipher = engine.createCipheriv;
  const observed: Buffer[] = [], failure = new Error("native wrapping failed");
  vi.spyOn(engine, "diffieHellman").mockImplementation((...args) => { const shared = originalDh(...args); observed.push(shared); return shared; });
  vi.spyOn(engine, "createCipheriv").mockImplementation((...args) => { observed.push(args[1]); if (fail) throw failure; return originalCipher(...args); });
  if (fail) expect(() => wrapDataKeyForTherapist(KEY, publicB64, USER, "therapist")).toThrow(failure);
  else expect(wrapDataKeyForTherapist(KEY, publicB64, USER, "therapist").wrappedKeyB64).not.toBe("");
  expect(observed).toHaveLength(2); for (const value of observed) expect(value.every(byte => byte === 0)).toBe(true);
  expect(KEY).toEqual(Buffer.alloc(32, 7));
});
