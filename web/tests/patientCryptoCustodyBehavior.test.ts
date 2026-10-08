import { afterEach, expect, it, vi } from "vitest";
import { decryptAudio, decryptEntry, encryptAudio, encryptEntry, type EntryStructured } from "../src/crypto/patient";
import { encrypt, fromBase64, TamperError, toBase64 } from "../src/crypto/core";
import { createDecipheriv } from "node:crypto";

afterEach(() => vi.restoreAllMocks());

it.each(["foreign account", "altered ciphertext"])("a refused %s audio envelope erases its owned bytes accepted by real WebCrypto", async refusal => {
  const key = new Uint8Array(new ArrayBuffer(32)).fill(29);
  const audio = new TextEncoder().encode("The caller retains these original recorded audio bytes");
  const originalAudio = audio.slice();
  const { blobB64 } = await encryptAudio(key, "audio-custody-owner", "audio-custody-entry", audio);
  const wire = Buffer.from(blobB64, "base64");
  if (refusal === "altered ciphertext") wire[12] = wire[12]! ^ 1;
  const accepted: Uint8Array[] = [];
  const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const value = args[2];
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    // The public Native provider sees ciphertext, not an invented helper
    // invocation. Retain the actual backing allocation it was given.
    expect(Array.from(bytes)).toEqual(Array.from(wire.subarray(12)));
    accepted.push(new Uint8Array(bytes.buffer));
    return nativeDecrypt(...args);
  });
  await expect(decryptAudio(key, refusal === "foreign account" ? "another-audio-owner" : "audio-custody-owner", "audio-custody-entry", wire.toString("base64"))).rejects.toBeInstanceOf(TamperError);
  expect(accepted.length).toBeGreaterThan(0);
  for (const allocation of accepted) expect(allocation).toEqual(new Uint8Array(allocation.length));
  expect(audio).toEqual(originalAudio);
  expect(key).toEqual(new Uint8Array(32).fill(29));
});

function independentEntry(key: Uint8Array, blobB64: string, user: string, id: string): Record<string, unknown> {
  const wire = Buffer.from(blobB64, "base64"), reader = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  reader.setAAD(Buffer.from(JSON.stringify(["entry", user, id, "1"])));
  reader.setAuthTag(wire.subarray(-16));
  return JSON.parse(Buffer.concat([reader.update(wire.subarray(12, -16)), reader.final()]).toString("utf8"));
}

it("a real authenticated additive empty-name field survives a patient edit with all newly supplied required fields", async () => {
  const key = new Uint8Array(new ArrayBuffer(32)).fill(31), user = "patient-additive-owner", id = "patient-additive-entry", date = "2026-10-07T12:00:00Z";
  const prior = { v: 1, text: "The earlier authenticated writing", sentiment: 1, created_at: date, "": { retained: "A valid opaque additive JSON field" } };
  const sealed = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(prior)), new TextEncoder().encode(JSON.stringify(["entry", user, id, "1"]))));
  const original = await decryptEntry(key, user, id, sealed, 1);
  expect(original).toEqual(prior);
  const { blobB64 } = await encryptEntry(key, user, id, "The newly edited writing", date, null, undefined, 1, undefined, original);
  expect(independentEntry(key, blobB64, user, id)).toEqual({ "": prior[""], v: 1, text: "The newly edited writing", sentiment: null, created_at: date });
});

it("the exported patient encoder keeps an absent typed read-through tags value out of its encrypted payload", async () => {
  const key = new Uint8Array(new ArrayBuffer(32)).fill(37), user = "patient-read-through-owner", id = "patient-read-through-entry", date = "2026-10-07T12:00:00Z";
  // A JavaScript getter is valid EntryStructured input. The oracle is the
  // independent authenticated payload; getter invocations are not counted.
  let supplied = false;
  const structured: EntryStructured = { energy: 0, get tags() { if (!supplied) { supplied = true; return undefined; } return ["A later read-through collection"]; } };
  const { blobB64 } = await encryptEntry(key, user, id, "Read-through typed encoder input", date, null, structured, 1);
  expect(independentEntry(key, blobB64, user, id)).toEqual({ v: 2, text: "Read-through typed encoder input", sentiment: null, created_at: date, energy: 0 });
  expect(fromBase64(blobB64).length).toBeGreaterThan(28);
});
