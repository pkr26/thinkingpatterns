import { afterEach, expect, it, vi } from "vitest";
import { unwrapDataKey, validateKdfParams, wrapDataKey } from "../src/crypto/envelope";
import { type Bytes } from "../src/crypto/core";

const bytes = (length: number, value: number): Bytes => new Uint8Array(new ArrayBuffer(length)).fill(value);
const params = { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 100000 };
afterEach(() => vi.restoreAllMocks());

it.each(["iterations", "memory_kib", "parallelism"] as const)("refuses negative Argon2 %s as a malformed cost before selecting a supported range", field => {
  expect(() => validateKdfParams({ algorithm: "argon2id", version: 1, iterations: 2, memory_kib: 19456, parallelism: 1, [field]: -1 }))
    .toThrow(`argon2id kdf_params require ${field}`);
});

it.each(["fixed", "generated"] as const)("releases the %s wrap's browser BufferSource custody after a decryptable receipt", async kind => {
  const encrypt = crypto.subtle.encrypt.bind(crypto.subtle), observed: Array<{ aad: Bytes; nonce: Bytes }> = [];
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (algorithm, key, plaintext) => {
    const gcm = algorithm as AesGcmParams;
    observed.push({ aad: gcm.additionalData as Bytes, nonce: gcm.iv as Bytes });
    return encrypt(algorithm, key, plaintext);
  });
  const dataKey = bytes(32, 31), kek = bytes(32, 47), nonce = kind === "fixed" ? bytes(12, 59) : undefined;
  const wrapped = await wrapDataKey(dataKey, kek, "alice", params, nonce);
  expect(await unwrapDataKey(wrapped, kek, "alice", params)).toEqual(dataKey);
  expect(observed).toHaveLength(1);
  expect(observed[0]!.aad.every(value => value === 0)).toBe(true);
  if (nonce) expect(nonce).toEqual(bytes(12, 59));
  else expect(observed[0]!.nonce.every(value => value === 0)).toBe(true);
  expect(dataKey).toEqual(bytes(32, 31)); expect(kek).toEqual(bytes(32, 47));
});

it.each(["accepted", "wrong-account"] as const)("releases the browser authentication BufferSource after an %s envelope receipt", async outcome => {
  const dataKey = bytes(32, 31), kek = bytes(32, 47), wrapped = await wrapDataKey(dataKey, kek, "alice", params);
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle), observed: Bytes[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (algorithm, key, ciphertext) => {
    observed.push((algorithm as AesGcmParams).additionalData as Bytes);
    return decrypt(algorithm, key, ciphertext);
  });
  const pending = unwrapDataKey(wrapped, kek, outcome === "accepted" ? "alice" : "other-account", params);
  if (outcome === "accepted") expect(await pending).toEqual(dataKey);
  else await expect(pending).rejects.toThrow("blob failed authentication");
  expect(observed).toHaveLength(1);
  expect(observed[0]!.every(value => value === 0)).toBe(true);
  expect(kek).toEqual(bytes(32, 47));
});
