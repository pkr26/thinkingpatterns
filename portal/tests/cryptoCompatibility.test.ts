import { expect, it } from "vitest";
import { decryptAudio, decryptEntry, decryptNoteAny, encrypt, generateTherapistKeyPair, openSealedPrivateKey, TamperError, toBase64, unlockWrapPrivateKeyWithNotesKey } from "../src/crypto";
const key = new Uint8Array(32).fill(13);
let count = 0;
const context = (...parts: string[]) => new TextEncoder().encode(JSON.stringify(parts));

it("opens kept recording bytes with the published audio binding and rejects relocation", async () => {
  const recording = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 1, 2, 3, 4]);
  const blob = toBase64(await encrypt(key, recording, context("audio", "audio-patient", "audio-entry", "1")));
  await expect(decryptAudio(key, "audio-patient", "audio-entry", blob)).resolves.toEqual(recording);
  await expect(decryptAudio(key, "other-patient", "audio-entry", blob)).rejects.toBeInstanceOf(TamperError);
  await expect(decryptAudio(key, "audio-patient", "other-entry", blob)).rejects.toBeInstanceOf(TamperError);
});

it("reads legacy entries until a version-bound entry authenticates, then refuses an old-ciphertext replay", async () => {
  const id = `downgrade-protection-${++count}`;
  const user = "entry-compatibility-patient";
  const legacy = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify({ v: 1, text: "Historical entry" })), context("entry", user, id)));
  const current = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify({ v: 3, text: "Current entry" })), context("entry", user, id, "2")));
  await expect(decryptEntry(key, user, { client_entry_id: id, content_version: 2, blob: legacy })).resolves.toMatchObject({ text: "Historical entry" });
  await expect(decryptEntry(key, user, { client_entry_id: id, content_version: 2, blob: current })).resolves.toMatchObject({ text: "Current entry" });
  await expect(decryptEntry(key, user, { client_entry_id: id, content_version: 2, blob: legacy })).rejects.toBeInstanceOf(TamperError);
});

it.each([undefined, 0, -1, 1.5, NaN, Infinity, "01", "2"])("uses the documented v1 metadata fallback for unsupported content_version %s", async version => {
  const id = `metadata-fallback-${++count}`;
  const user = "entry-metadata-patient";
  const blob = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify({ v: 1, text: "Version-one entry" })), context("entry", user, id, "1")));
  await expect(decryptEntry(key, user, { client_entry_id: id, content_version: version as number | undefined, blob })).resolves.toMatchObject({ text: "Version-one entry" });
});

it("reports failed entry authentication as tampering before attempting schema decoding", async () => {
  await expect(decryptEntry(key, "failed-entry-patient", { client_entry_id: `failed-${++count}`, blob: toBase64(new Uint8Array(28)) })).rejects.toBeInstanceOf(TamperError);
});

it("reopens an independently sealed historical identity note after password-based key custody unlocks", async () => {
  const pair = await generateTherapistKeyPair(key, "compatibility-therapist");
  const privateBytes = await openSealedPrivateKey(key, pair.wrapKeyBlobB64, "compatibility-therapist");
  if (!privateBytes) throw new Error("Historical identity did not unlock");
  const input = await crypto.subtle.importKey("raw", privateBytes, "HKDF", false, ["deriveBits"]);
  const historicalKey = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("mindpattern/portal-notes/v2") }, input, 256));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", historicalKey, "AES-GCM", false, ["encrypt"]);
  const body = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: context("note", "compatibility-therapist", "note-patient", "historical-note") }, aes, new TextEncoder().encode(JSON.stringify({ v: 1, text: "Historical identity note" })));
  const sealed = new Uint8Array(12 + body.byteLength); sealed.set(nonce); sealed.set(new Uint8Array(body), 12);
  const unlocked = await unlockWrapPrivateKeyWithNotesKey(key, pair.wrapKeyBlobB64, "compatibility-therapist");
  await expect(decryptNoteAny(unlocked.noteKeyV2, new Uint8Array(32), "compatibility-therapist", "note-patient", "historical-note", toBase64(sealed))).resolves.toBe("Historical identity note");
  expect(unlocked.privateKey.extractable).toBe(false);
  await expect(crypto.subtle.exportKey("pkcs8", unlocked.privateKey)).rejects.toThrow();
  privateBytes.fill(0); historicalKey.fill(0); unlocked.noteKeyV2.fill(0);
});
