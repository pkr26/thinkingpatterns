import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { decrypt, deriveMasterKey, encryptWithFixedNonce, fromBase64, hkdfSha256, TamperError, toBase64, zeroize } from "../src/crypto/core";
import { deriveWrapKek, keyFingerprint, unwrapDataKey, wrapDataKeyForTherapist, wrapWithEphemeralPrivate } from "../src/crypto/sharing";

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const bytes = (value: BufferSource) => value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
const clear = (value: Uint8Array) => expect(value).toEqual(new Uint8Array(value.length));
const key = new Uint8Array(32).fill(31);

it.each([undefined, {}])("reports unavailable browser cryptography through both public crypto surfaces: %s", async provider => {
  vi.stubGlobal("crypto", provider);
  await expect(deriveMasterKey("password", new Uint8Array(16), 100_000)).rejects.toThrow("WebCrypto is unavailable in this browser");
  await expect(keyFingerprint("AA==")).rejects.toThrow("WebCrypto is unavailable in this browser");
});

it.each([false, true])("releases the password buffer accepted by WebCrypto after derivation settles, including failure: %s", async fail => {
  const realImport = crypto.subtle.importKey.bind(crypto.subtle);
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle);
  const held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "importKey").mockImplementation(async (...args) => {
    if (args[0] === "raw" && args[2] === "PBKDF2") held.push(bytes(args[1] as BufferSource));
    return realImport(...args);
  });
  if (fail) vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { await realDerive(...args); throw new Error("derivation failed"); });
  const salt = new Uint8Array(8).fill(9);
  const operation = deriveMasterKey("private café password", salt, 100_000);
  if (fail) await expect(operation).rejects.toThrow("derivation failed");
  else expect(await operation).toEqual(new Uint8Array(pbkdf2Sync("private café password", salt, 100_000, 32, "sha256")));
  expect(held).toHaveLength(1); clear(held[0]!); expect(salt).toEqual(new Uint8Array(8).fill(9));
});

it("preserves the caller's key, plaintext, nonce and AAD while producing an independently authenticated AES envelope", async () => {
  const nonce = new Uint8Array(12).fill(5), plain = new TextEncoder().encode("caller-owned private journal"), aad = new TextEncoder().encode("account and entry binding");
  const originals = [key, plain, nonce, aad].map(value => value.slice());
  const encrypted = await encryptWithFixedNonce(key, plain, nonce, aad);
  const decipher = createDecipheriv("aes-256-gcm", key, encrypted.subarray(0, 12));
  decipher.setAAD(aad); decipher.setAuthTag(encrypted.subarray(-16));
  expect(Buffer.concat([decipher.update(encrypted.subarray(12, -16)), decipher.final()])).toEqual(Buffer.from(plain));
  expect(await decrypt(key, encrypted, aad)).toEqual(plain);
  [key, plain, nonce, aad].forEach((value, index) => expect(value).toEqual(originals[index]));
  expect(new TamperError()).toMatchObject({ name: "TamperError", message: "blob failed authentication" });
  await expect(decrypt(key, new Uint8Array(27))).rejects.toBeInstanceOf(TamperError);
  await expect(encryptWithFixedNonce(new Uint8Array(31), plain, nonce)).rejects.toThrow("key must be 32 bytes");
  await expect(decrypt(new Uint8Array(31), encrypted)).rejects.toThrow("key must be 32 bytes");
  await expect(encryptWithFixedNonce(key, plain, new Uint8Array(11))).rejects.toThrow("nonce must be 12 bytes");
});

it("returns a caller-owned HKDF output with the declared byte length and erases every explicitly transferred buffer", async () => {
  const secret = new Uint8Array(41).fill(17), salt = new Uint8Array(13).fill(7), info = new TextEncoder().encode("consumer protocol label");
  expect(await hkdfSha256(secret, salt, info, 47)).toEqual(new Uint8Array(hkdfSync("sha256", secret, salt, info, 47)));
  const first = new Uint8Array([1, 2]), second = new Uint8Array([3, 4, 5]);
  zeroize(first, undefined, null, second); clear(first); clear(second);
  for (const value of ["", "a", "private café", "\u0000\u00ff"]) expect(new TextDecoder().decode(fromBase64(toBase64(new TextEncoder().encode(value))))).toBe(value);
});

it("rejects an undersized salt and a downgraded work factor with actionable minimums", async () => {
  await expect(deriveMasterKey("password", new Uint8Array(7), 100_000)).rejects.toThrow("salt must be at least 8 bytes");
  await expect(deriveMasterKey("password", new Uint8Array(8), 99_999)).rejects.toThrow("iterations must be at least 100000 (got 99999; the cross-platform contract is 600000)");
});

it("keeps imported secret AES handles non-extractable at the real WebCrypto boundary", async () => {
  const realImport = crypto.subtle.importKey.bind(crypto.subtle), handles: CryptoKey[] = [];
  vi.spyOn(crypto.subtle, "importKey").mockImplementation(async (...args) => {
    const handle = await realImport(...args); if (args[2] === "AES-GCM") handles.push(handle); return handle;
  });
  const encrypted = await encryptWithFixedNonce(key, new Uint8Array([1, 2]), new Uint8Array(12));
  expect(await decrypt(key, encrypted)).toEqual(new Uint8Array([1, 2]));
  expect(handles).toHaveLength(2);
  for (const handle of handles) await expect(crypto.subtle.exportKey("raw", handle)).rejects.toThrow();
});

function therapist() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { ...pair, spki: pair.publicKey.export({ format: "der", type: "spki" }) };
}
async function privateHandle(pair: ReturnType<typeof therapist>) {
  return crypto.subtle.importKey("pkcs8", pair.privateKey.export({ format: "der", type: "pkcs8" }), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}
function openWrap(pair: ReturnType<typeof therapist>, ephemeral: string, wrapped: string) {
  const ephemeralDer = Buffer.from(ephemeral, "base64");
  const shared = diffieHellman({ privateKey: pair.privateKey, publicKey: createPublicKey({ key: ephemeralDer, format: "der", type: "spki" }) });
  const kek = hkdfSync("sha256", shared, Buffer.concat([ephemeralDer, pair.spki]), Buffer.from("mindpattern/wrap/v1"), 32);
  const wire = Buffer.from(wrapped, "base64");
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(kek), wire.subarray(0, 12));
  decipher.setAAD(Buffer.from('["consent-wrap","patient","therapist"]')); decipher.setAuthTag(wire.subarray(-16));
  return Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
}
function captureSecrets() {
  const held: Uint8Array[] = [];
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle);
  const realExport = crypto.subtle.exportKey.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { const result = await realDerive(...args); held.push(new Uint8Array(result)); return result; });
  vi.spyOn(crypto.subtle, "exportKey").mockImplementation(async (...args) => { const result = await realExport(...args); if (args[0] === "pkcs8") held.push(new Uint8Array(result as ArrayBuffer)); return result; });
  return held;
}

it.each([false, true])("scrubs WebCrypto-owned ECDH, HKDF and exported ephemeral secret buffers after wrapping settles: failure=%s", async fail => {
  const pair = therapist(), held = captureSecrets();
  const original = key.slice();
  if (fail) {
    const realEncrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { await realEncrypt(...args); throw new Error("wrap transport failed"); });
    await expect(wrapDataKeyForTherapist(key, pair.spki.toString("base64"), "patient", "therapist")).rejects.toThrow("wrap transport failed");
  } else {
    const wrap = await wrapDataKeyForTherapist(key, pair.spki.toString("base64"), "patient", "therapist");
    expect(openWrap(pair, wrap.ephemeralPubB64, wrap.wrappedKeyB64)).toEqual(Buffer.from(original));
  }
  expect(held).toHaveLength(3); held.forEach(clear); expect(key).toEqual(original);
});

it("clears a secret passed to the public KEK consumer while returning an independently derived live key", async () => {
  const shared = new Uint8Array(32).fill(4), ephemeral = new Uint8Array(91).fill(7), peer = new Uint8Array(91).fill(8);
  const expected = new Uint8Array(hkdfSync("sha256", shared, Buffer.concat([ephemeral, peer]), Buffer.from("mindpattern/wrap/v1"), 32));
  const result = await deriveWrapKek(shared, ephemeral, peer);
  expect(result).toEqual(expected); clear(shared); expect(ephemeral).toEqual(new Uint8Array(91).fill(7)); expect(peer).toEqual(new Uint8Array(91).fill(8));
});

it.each([false, true])("scrubs actual derived shared secrets and KEKs after unwrapping, leaving the returned key in caller custody: tamper=%s", async tamper => {
  const pair = therapist(), privateKey = await privateHandle(pair);
  const wrap = await wrapDataKeyForTherapist(key, pair.spki.toString("base64"), "patient", "therapist");
  const held = captureSecrets();
  const operation = unwrapDataKey(privateKey, pair.spki.toString("base64"), wrap.ephemeralPubB64, wrap.wrappedKeyB64, tamper ? "another patient" : "patient", "therapist");
  if (tamper) await expect(operation).rejects.toBeInstanceOf(TamperError);
  else expect(await operation).toEqual(key);
  expect(held).toHaveLength(2); held.forEach(clear);
});

it("rejects malformed sharing inputs before granting a wrap", async () => {
  const pair = therapist(), privateKey = await privateHandle(pair), spki = new Uint8Array(pair.spki);
  await expect(wrapWithEphemeralPrivate(privateKey, spki, new Uint8Array(31), pair.spki.toString("base64"), "patient", "therapist")).rejects.toThrow("data key must be 32 bytes");
  await expect(wrapWithEphemeralPrivate(privateKey, spki, key, Buffer.alloc(90).toString("base64") + "AAAA", "patient", "therapist")).rejects.toThrow("therapist public key has the wrong format");
  await expect(wrapWithEphemeralPrivate(privateKey, spki, key, "\n" + pair.spki.toString("base64") + " ", "patient", "therapist")).rejects.toThrow("therapist public key has the wrong format");
});

it("keeps the reimported ephemeral private handle non-extractable at the real WebCrypto boundary", async () => {
  const pair = therapist(), realImport = crypto.subtle.importKey.bind(crypto.subtle), handles: CryptoKey[] = [];
  vi.spyOn(crypto.subtle, "importKey").mockImplementation(async (...args) => { const handle = await realImport(...args); if (args[0] === "pkcs8") handles.push(handle); return handle; });
  const wrap = await wrapDataKeyForTherapist(key, pair.spki.toString("base64"), "patient", "therapist");
  expect(openWrap(pair, wrap.ephemeralPubB64, wrap.wrappedKeyB64)).toEqual(Buffer.from(key));
  expect(handles).toHaveLength(1);
  await expect(crypto.subtle.exportKey("pkcs8", handles[0]!)).rejects.toThrow();
});
