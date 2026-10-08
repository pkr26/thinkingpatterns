import { createCipheriv, createDecipheriv } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { decryptEntry, decryptInsights, decryptQuestion, encryptEntry, type EntryPayload } from "../src/crypto/patient";
import * as core from "../src/crypto/core";

const KEY = new Uint8Array(new ArrayBuffer(32)).fill(7), USER = "patient-wire-owner", ID = "journal-one";
const DATE = "2026-10-05T12:00:00Z";
afterEach(() => vi.restoreAllMocks());
function aad(...parts: string[]): Buffer { return Buffer.from(JSON.stringify(parts), "ascii"); }
function wireOpen(encoded: string, associated: Buffer): unknown {
  const blob = Buffer.from(encoded, "base64"), decipher = createDecipheriv("aes-256-gcm", KEY, blob.subarray(0, 12));
  decipher.setAAD(associated); decipher.setAuthTag(blob.subarray(-16));
  return JSON.parse(Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]).toString());
}
function wireSeal(payload: unknown, associated: Buffer): string {
  const nonce = Buffer.alloc(12, 6), cipher = createCipheriv("aes-256-gcm", KEY, nonce); cipher.setAAD(associated);
  return Buffer.concat([nonce, cipher.update(Buffer.from(JSON.stringify(payload))), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

it("writes each optional structured channel and valid generation binding for an independent AES-GCM wire reader", async () => {
  for (const structured of [undefined, {}, { energy: 0 }, { sleep: 0 }, { tags: ["work"] }, { tod: "night" }, { energy: 3, sleep: 4, tags: ["family"], tod: "morning" }]) {
    for (const version of [undefined, 0, -1, 1.5, Number.NaN, Infinity, 1, 2]) {
      const { blobB64 } = await encryptEntry(KEY, USER, ID, "edited", DATE, 0, structured, version);
      const associated = Number.isSafeInteger(version) && version! >= 1 ? aad("entry", USER, ID, String(version)) : aad("entry", USER, ID);
      expect(wireOpen(blobB64, associated)).toEqual({ v: structured && Object.keys(structured).length ? 2 : 1, text: "edited", sentiment: 0, created_at: DATE, ...(structured ?? {}) });
    }
  }
});
it("removes old known optional channels on a typed edit while retaining additive authenticated fields", async () => {
  const original = { v: 3 as const, text: "old", sentiment: -1, created_at: DATE, energy: 4, sleep: 5, tags: ["work"], tod: "night", input_mode: "voice" as const, transcript_lang: "es", english_text: "old translation", future_field: { retained: true } };
  const { blobB64 } = await encryptEntry(KEY, USER, ID, "edited", DATE, null, undefined, undefined, undefined, original);
  expect(wireOpen(blobB64, aad("entry", USER, ID))).toEqual({ v: 1, text: "edited", sentiment: null, created_at: DATE, future_field: { retained: true } });
});
it("clears explicit null and empty optional channels instead of serializing a stale rating", async () => {
  for (const structured of [{ energy: null, sleep: 2 }, { sleep: null, energy: 2 }, { tags: [], energy: 2 }, { tod: null as unknown as string, energy: 2 }]) {
    const { blobB64 } = await encryptEntry(KEY, USER, ID, "edited", DATE, null, structured);
    expect(wireOpen(blobB64, aad("entry", USER, ID))).toEqual({ v: 2, text: "edited", sentiment: null, created_at: DATE, ...(structured.energy != null ? { energy: structured.energy } : {}), ...(structured.sleep != null ? { sleep: structured.sleep } : {}) });
  }
});
it("reports only independently authenticated valid v2 bindings and refuses legacy replay when that binding is already known", async () => {
  const payload = { v: 1, text: "stored", sentiment: null, created_at: DATE };
  for (const version of [1, 2, 8]) {
    const bound = vi.fn(), blob = wireSeal(payload, aad("entry", USER, ID, String(version)));
    expect(await decryptEntry(KEY, USER, ID, blob, version, { onV2Bound: bound })).toEqual(payload); expect(bound).toHaveBeenCalledOnce();
    await expect(decryptEntry(KEY, USER, ID, blob, version + 1, { forbidLegacyAad: true })).rejects.toThrow();
  }
  const legacy = wireSeal(payload, aad("entry", USER, ID));
  for (const version of [undefined, 0, -1, 1.5, Number.NaN, Infinity, 1, 8]) {
    const bound = vi.fn(); expect(await decryptEntry(KEY, USER, ID, legacy, version, { onV2Bound: bound })).toEqual(payload); expect(bound).not.toHaveBeenCalled();
  }
  await expect(decryptEntry(KEY, USER, ID, legacy, 2, { forbidLegacyAad: true })).rejects.toThrow("blob failed authentication");
  for (const invalid of [undefined, 0, -1, 1.5, Number.NaN, Infinity]) {
    const bound = vi.fn(), blob = wireSeal(payload, aad("entry", USER, ID, String(invalid)));
    await expect(decryptEntry(KEY, USER, ID, blob, invalid, { onV2Bound: bound })).rejects.toThrow("blob failed authentication"); expect(bound).not.toHaveBeenCalled();
  }
});
it("erases actual public encryption/decryption plaintext buffers after success and parse failure while retaining the caller's shared key", async () => {
  const nativeEncrypt = core.encrypt, nativeDecrypt = core.decrypt;
  const written: Uint8Array[] = [], opened: Uint8Array[] = [];
  vi.spyOn(core, "encrypt").mockImplementation(async (...args) => { written.push(args[1]); return nativeEncrypt(...args); });
  vi.spyOn(core, "decrypt").mockImplementation(async (...args) => { const result = await nativeDecrypt(...args); opened.push(result); return result; });
  const entry = await encryptEntry(KEY, USER, ID, "private writing", DATE, null);
  expect(await decryptEntry(KEY, USER, ID, entry.blobB64)).toMatchObject({ text: "private writing" });
  expect(await decryptInsights(KEY, USER, wireSeal({ v: 2 }, aad("insights", USER, "patterns")))).toEqual({ v: 2 });
  expect(await decryptQuestion(KEY, USER, "2026-10-05", wireSeal({ for_date: "2026-10-05", question: "A private prompt?" }, aad("question", USER, "2026-10-05")))).toMatchObject({ question: "A private prompt?" });
  await expect(decryptEntry(KEY, USER, ID, wireSeal({ v: 9 } as unknown as EntryPayload, aad("entry", USER, ID)))).rejects.toThrow();
  expect(written.length).toBeGreaterThan(0); expect(opened.length).toBeGreaterThan(0);
  for (const bytes of [...written, ...opened]) expect(bytes.every(b => b === 0)).toBe(true);
  expect(KEY).toEqual(new Uint8Array(32).fill(7));
});
it("rejects authenticated nonfinite numeric fields before returning a journal payload", async () => {
  // JSON's null conversion is avoided to exercise a genuinely nonfinite authenticated number.
  const nonce = Buffer.alloc(12, 6), cipher = createCipheriv("aes-256-gcm", KEY, nonce); cipher.setAAD(aad("entry", USER, ID));
  const blob = Buffer.concat([nonce, cipher.update(Buffer.from('{"v":1,"text":"stored","sentiment":1e400}')), cipher.final(), cipher.getAuthTag()]).toString("base64");
  await expect(decryptEntry(KEY, USER, ID, blob)).rejects.toThrow("Invalid encrypted sentiment.");
});
