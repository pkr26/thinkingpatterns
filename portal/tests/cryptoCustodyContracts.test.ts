import { afterEach, expect, it, vi } from "vitest";
import { decryptCaseloadSummary, decryptMeasure, deriveMasterKey, encrypt, encryptNote, fromBase64, generateTherapistKeyPair, keyFingerprint, openNotesKeyring, openSealedPrivateKey, sealNotesKeyring, serverWrapKeyFingerprint, TamperError, toBase64 } from "../src/crypto";
const key = new Uint8Array(32).fill(21);
const context = (...parts: string[]) => new TextEncoder().encode(JSON.stringify(parts));
const bytes = (value: BufferSource) => value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
let sequence = 0;
async function measure(payload: unknown) {
  const id = `custody-measure-${++sequence}`;
  const blob = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(payload)), context("measure", "custody-patient", id)));
  return decryptMeasure(key, "custody-patient", { client_measure_id: id, blob, measure_date: "2026-09-30T13:30:00Z" });
}
it.each(["constructor", "toString", "__proto__", "hasOwnProperty", ["phq9"]])("rejects unsupported or coercible member %s as a clinical instrument", async name => {
  await expect(measure({ v: 1, measure: name, score: 1 })).resolves.toBeNull();
});
it.each([{ name: "phq9", max: 27 }, { name: "gad7", max: 21 }, { name: "phq2", max: 6 }])("keeps the maximum supported $name score and its completed date", async ({ name, max }) => {
  await expect(measure({ v: 1, measure: name, score: max, completed_at: "2026-09-29T13:30:00Z" })).resolves.toEqual({ measure: name, score: max, item9: null, completedAt: "2026-09-29", measureDate: "2026-09-30" });
});
it.each(["phq9", "gad7", "phq2"])("preserves explicit absence of item nine for supported %s readings", async name => {
  await expect(measure({ v: 1, measure: name, score: 0 })).resolves.toEqual({ measure: name, score: 0, item9: null, completedAt: null, measureDate: "2026-09-30" });
});
it.each([{ v: 1, measure: "phq9", score: 3 }, { v: 1, measure: "phq9", score: -1 }])("releases host-held measure plaintext after a supported or rejected reading", async payload => {
  const rawDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  const held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const result = await rawDecrypt(...args); held.push(new Uint8Array(result)); return result;
  });
  await measure(payload);
  expect(held).toHaveLength(1);
  expect(held[0]).toEqual(new Uint8Array(held[0]!.length));
});

async function serverSummary(payload: unknown, rawJson?: string) {
  const therapist = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const therapistDer = new Uint8Array(await crypto.subtle.exportKey("spki", therapist.publicKey));
  const ephemeralDer = new Uint8Array(await crypto.subtle.exportKey("spki", ephemeral.publicKey));
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: therapist.publicKey }, ephemeral.privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const salt = new Uint8Array(ephemeralDer.length + therapistDer.length); salt.set(ephemeralDer); salt.set(therapistDer, ephemeralDer.length);
  const wrap = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("mindpattern/wrap/v1") }, hkdf, 256));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", wrap, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: context("caseload-summary", "summary-patient", "summary-therapist") }, aes, new TextEncoder().encode(rawJson ?? JSON.stringify(payload)));
  const sealed = new Uint8Array(12 + ciphertext.byteLength); sealed.set(nonce); sealed.set(new Uint8Array(ciphertext), 12);
  return decryptCaseloadSummary(therapist.privateKey, toBase64(therapistDer), toBase64(ephemeralDer), toBase64(sealed), "summary-patient", "summary-therapist");
}
it.each([7, "summary", true, null, [], [{ patterns: 7 }]])("declines authenticated non-record summary %s", async payload => {
  await expect(serverSummary(payload)).resolves.toBeNull();
});
it.each(["1e400", "-1e400"])("does not render non-finite patterns from authenticated JSON literal %s", async value => {
  await expect(serverSummary(null, `{"patterns":${value}}`)).resolves.toEqual({ patterns: 0, sensitive: false, newest: null, forDate: null });
});
it.each([undefined, {}])("reports unavailable browser cryptography through the public error contract %#", async provider => {
  vi.stubGlobal("crypto", provider);
  await expect(deriveMasterKey("password", new Uint8Array(16))).rejects.toMatchObject({ message: "WebCrypto is unavailable in this browser" });
});
it("preserves recognizable authentication failure identity and copy", () => {
  expect(new TamperError()).toMatchObject({ name: "TamperError", message: "blob failed authentication" });
});
it.each([
  { input: { patterns: "7", sensitive: "true", newest: 42 }, output: { patterns: 0, sensitive: false, newest: null, forDate: null } },
  { input: { patterns: -2.7 }, output: { patterns: 0, sensitive: false, newest: null, forDate: null } },
  { input: { patterns: 7.9, sensitive: true, newest: "2026-09-29T14:00:00Z", for_date: "2026-09-30T14:00:00Z" }, output: { patterns: 7, sensitive: true, newest: "2026-09-29", forDate: "2026-09-30" } },
])("sanitizes a server-authenticated overview without inventing clinical facts $input", async ({ input, output }) => {
  await expect(serverSummary(input)).resolves.toEqual(output);
});

it("formats both public pairing fingerprints from the published SHA-256 representation including leading zeroes", async () => {
  let der: Uint8Array<ArrayBuffer>, digest: Uint8Array<ArrayBuffer>;
  do {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    der = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  } while (!digest.subarray(0, 8).some(value => value < 16));
  const hex = Array.from(digest, value => value.toString(16).padStart(2, "0")).join("");
  await expect(serverWrapKeyFingerprint(toBase64(der))).resolves.toBe(hex.slice(0, 16));
  await expect(keyFingerprint(toBase64(der))).resolves.toBe(hex.slice(0, 32).toUpperCase().match(/.{4}/g)!.join(" "));
});

it("releases host-held note and custody serialization after their sealed output is produced", async () => {
  const rawEncrypt = crypto.subtle.encrypt.bind(crypto.subtle);
  const held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (algorithm, cryptoKey, data) => {
    held.push(bytes(data)); return rawEncrypt(algorithm, cryptoKey, data);
  });
  const note = await encryptNote(key, "custody-therapist", "custody-patient", "custody-note", "Private clinical note");
  const ring = { active: new Uint8Array(32).fill(3), historical: [new Uint8Array(32).fill(4)] };
  const sealed = await sealNotesKeyring(key, "custody-therapist", ring);
  expect(note.blobB64).not.toBe("");
  expect(held).toHaveLength(2);
  held.forEach(value => expect(value).toEqual(new Uint8Array(value.length)));
  await expect(openNotesKeyring(key, "custody-therapist", sealed)).resolves.toEqual(ring);
});
it.each([true, false])("releases host-held decrypted custody serialization on successful decode: %s", async valid => {
  const payload = valid ? { v: 1, active: toBase64(new Uint8Array(32).fill(3)), historical: [] } : { v: 2 };
  const sealed = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(payload)), context("portal-notes-keyring", "custody-therapist", "v1")));
  const rawDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  const held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const result = await rawDecrypt(...args); held.push(new Uint8Array(result)); return result;
  });
  if (valid) await expect(openNotesKeyring(key, "custody-therapist", sealed)).resolves.toMatchObject({ historical: [] });
  else await expect(openNotesKeyring(key, "custody-therapist", sealed)).rejects.toThrow("Unsupported notes custody.");
  expect(held).toHaveLength(1);
  expect(held[0]).toEqual(new Uint8Array(held[0]!.length));
});
it("releases its encrypted identity workspace while leaving the returned DER in the caller's custody", async () => {
  const pair = await generateTherapistKeyPair(key, "custody-therapist");
  const rawDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  const held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (algorithm, cryptoKey, data) => {
    held.push(bytes(data)); return rawDecrypt(algorithm, cryptoKey, data);
  });
  const privateKey = await openSealedPrivateKey(key, pair.wrapKeyBlobB64, "custody-therapist");
  if (!privateKey) throw new Error("Identity did not unlock");
  expect(privateKey.some(value => value !== 0)).toBe(true);
  expect(held).toHaveLength(1);
  expect(held[0]).toEqual(new Uint8Array(held[0]!.length));
  privateKey.fill(0);
  expect(fromBase64(pair.wrapKeyBlobB64).some(value => value !== 0)).toBe(true);
});
it("scrubs decoded secret keys when a later authenticated custody item is rejected", async () => {
  const sealed = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify({ v: 1, active: toBase64(new Uint8Array(32).fill(3)), historical: [{}] })), context("portal-notes-keyring", "custody-therapist", "v1")));
  const NativeBytes = Uint8Array;
  const held: Uint8Array[] = [];
  vi.stubGlobal("Uint8Array", new Proxy(NativeBytes, { construct(target, argumentsList) {
    const value = Reflect.construct(target, argumentsList) as Uint8Array;
    if (value.length === key.length) held.push(value);
    return value;
  } }));
  await expect(openNotesKeyring(key, "custody-therapist", sealed)).rejects.toMatchObject({ message: "Invalid notes custody key." });
  expect(held.length).toBeGreaterThan(0);
  held.forEach(value => expect(value).toEqual(new NativeBytes(value.length)));
});
