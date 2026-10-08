import { createDecipheriv, hkdfSync } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { createRegistrationEnvelope, envelopeKek, rewrapDataKey, unwrapDataKey, validateKdfParams, wrapDataKey, type KdfParams } from "../src/crypto/envelope";
import * as core from "../src/crypto/core";
const bytes = (length = 32, value = 3): Uint8Array<ArrayBuffer> => new Uint8Array(new ArrayBuffer(length)).fill(value);
const pbkdf = { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 100000 };
const argon = { algorithm: "argon2id" as const, version: 1, iterations: 2, memory_kib: 19456, parallelism: 1 };
afterEach(() => vi.restoreAllMocks());

it("canonicalizes all supported password-cost boundaries and refuses unsupported or malformed costs with actionable copy", () => {
  for (const iterations of [100000, 100001, 600000, 10000000]) expect(validateKdfParams({ iterations, version: 1, algorithm: "pbkdf2-sha256" })).toEqual({ ...pbkdf, iterations });
  for (const iterations of [2, 3, 10000000]) for (const memory_kib of [19456, 19457, 262144]) for (const parallelism of [1, 2, 4]) {
    expect(validateKdfParams({ parallelism, memory_kib, iterations, version: 1, algorithm: "argon2id" })).toEqual({ ...argon, iterations, memory_kib, parallelism });
  }
  for (const value of [null, [], false, 1, "params"]) expect(() => validateKdfParams(value)).toThrow("kdf_params must be a JSON object");
  expect(() => validateKdfParams({ ...pbkdf, zeta: true, alpha: true, beta: true })).toThrow("kdf_params has unknown fields: alpha, beta, zeta");
  for (const algorithm of [undefined, "argon2", "sha256", 1]) expect(() => validateKdfParams({ ...pbkdf, algorithm })).toThrow("kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'");
  for (const version of [undefined, 0, 2, 1.5, "1"]) expect(() => validateKdfParams({ ...pbkdf, version })).toThrow("kdf_params.version must be 1");
  for (const extra of [{ memory_kib: undefined }, { parallelism: undefined }]) expect(() => validateKdfParams({ ...pbkdf, ...extra })).toThrow("pbkdf2-sha256 kdf_params carry iterations only");
  for (const iterations of [undefined, "100000", 99999, 10000001, 1.5, Number.NaN, Infinity]) expect(() => validateKdfParams({ ...pbkdf, iterations })).toThrow("kdf_params.iterations must be 100000-10000000 for pbkdf2-sha256");
  for (const field of ["iterations", "memory_kib", "parallelism"]) for (const value of [undefined, "2", 1.5, Number.NaN, Infinity]) expect(() => validateKdfParams({ ...argon, [field]: value })).toThrow(`argon2id kdf_params require ${field}`);
  for (const iterations of [0, 1, 10000001]) expect(() => validateKdfParams({ ...argon, iterations })).toThrow("kdf_params.iterations must be 2-10000000 for argon2id");
  for (const memory_kib of [19455, 262145]) expect(() => validateKdfParams({ ...argon, memory_kib })).toThrow("kdf_params.memory_kib must be 19456-262144");
  for (const parallelism of [0, 5]) expect(() => validateKdfParams({ ...argon, parallelism })).toThrow("kdf_params.parallelism must be 1-4");
});
it("validates password material, AES strengths and the exact envelope size before interpreting authentication", async () => {
  await expect(envelopeKek(bytes(15), bytes(16))).rejects.toThrow("password-derived key material must be at least 16 bytes");
  expect(await envelopeKek(bytes(16), bytes(16))).toHaveLength(32);
  await expect(wrapDataKey(bytes(31), bytes(), "alice", pbkdf)).rejects.toThrow("data_key must be 32 bytes");
  await expect(wrapDataKey(bytes(), bytes(31), "alice", pbkdf)).rejects.toThrow("kek must be 32 bytes");
  await expect(unwrapDataKey(bytes(59), bytes(), "alice", pbkdf)).rejects.toThrow("wrapped data key must be exactly 60 bytes");
  await expect(unwrapDataKey(bytes(60), bytes(31), "alice", pbkdf)).rejects.toThrow("kek must be 32 bytes");
});
function open(blobB64: string, kek: Uint8Array, params: KdfParams, usernameJson: string): Uint8Array {
  const blob = Buffer.from(blobB64, "base64"), cipher = createDecipheriv("aes-256-gcm", kek, blob.subarray(0, 12));
  cipher.setAAD(Buffer.from(`{"context":"envelope","kdf_params":${JSON.stringify(params)},"username":${usernameJson}}`, "ascii")); cipher.setAuthTag(blob.subarray(-16));
  return new Uint8Array(Buffer.concat([cipher.update(blob.subarray(12, -16)), cipher.final()]));
}
it("writes a registration and a password rewrap that an independent wire consumer can open with Unicode-safe account binding", async () => {
  const master = bytes(), salt = bytes(16, 4), username = "alicé\x7f";
  const kek = new Uint8Array(hkdfSync("sha256", master, salt, "mindpattern/envelope/v2", 32));
  const registration = await createRegistrationEnvelope(master, salt, username);
  expect(open(registration.wrappedDataKeyB64, kek, { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, '"alic\\u00e9\\u007f"')).toEqual(registration.dataKey);
  const wrapped = await rewrapDataKey(registration.dataKey, master, salt, username, argon);
  expect(open(wrapped, kek, argon, '"alic\\u00e9\\u007f"')).toEqual(registration.dataKey);
});
it("clears secret KEKs actually consumed by real cryptography after both wrapping and authentication failure", async () => {
  const realEncrypt = core.encryptWithFixedNonce, realDecrypt = core.decrypt; const secrets: Uint8Array[] = [];
  vi.spyOn(core, "encryptWithFixedNonce").mockImplementation(async (...args) => { secrets.push(args[0]); return realEncrypt(...args); });
  vi.spyOn(core, "decrypt").mockImplementation(async (...args) => { secrets.push(args[0]); return realDecrypt(...args); });
  const master = bytes(), salt = bytes(16, 4), envelope = await createRegistrationEnvelope(master, salt, "alice");
  await rewrapDataKey(envelope.dataKey, master, salt, "alice");
  const { unwrapEnvelope } = await import("../src/crypto/envelope");
  await expect(unwrapEnvelope(master, salt, "wrong-account", envelope.wrappedDataKeyB64, envelope.kdfParams)).rejects.toThrow();
  expect(secrets.length).toBeGreaterThan(0); for (const secret of secrets) expect(secret.every(b => b === 0)).toBe(true);
  expect(envelope.dataKey.every(b => b === 0)).toBe(false); expect(master).toEqual(bytes());
});
it("clears a generated registration secret when its failed operation never transfers custody to the vault", async () => {
  const native = crypto.getRandomValues.bind(crypto), observed: Uint8Array[] = [];
  vi.spyOn(crypto, "getRandomValues").mockImplementation((value => { const result = native(value); if (result instanceof Uint8Array && result.length === 32) observed.push(result); return result; }) as typeof crypto.getRandomValues);
  await expect(createRegistrationEnvelope(bytes(15), bytes(16), "alice")).rejects.toThrow("password-derived key material");
  expect(observed).toHaveLength(1); expect(observed[0]!.every(b => b === 0)).toBe(true);
});
