/** UNEXECUTED review draft. Native fixture construction is independent of production crypto. */
import { createCipheriv, createDecipheriv } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import * as client from "../src/api/client";
import { api, type ListedEntry } from "../src/api/client";
import { decrypt, encryptWithFixedNonce, MIN_BLOB_SIZE, NONCE_SIZE, type Bytes } from "../src/crypto/core";
import { HistoryView } from "../src/views/History";
import { setKvBackendForTests } from "../src/kvstore";
import { vault } from "../src/vault";
import { resetEntryVersionMirrors } from "../src/entryVersions";
import { __setLocaleForTests, t } from "../src/strings";
import { installSession, resetTestState } from "./helpers/api";
import { isDisabled, press, render, textOf } from "./helpers/rtr";

const bytes = (size: number, fill = 0): Bytes => new Uint8Array(new ArrayBuffer(size)).fill(fill);
const plain = bytes(4, 23), nonce = bytes(12, 41), aad = Buffer.from("independent public key-strength contract");
function sealNative(key: Uint8Array, input: Uint8Array, context: Uint8Array): Buffer {
  const algorithm = key.byteLength === 16 ? "aes-128-gcm" : key.byteLength === 24 ? "aes-192-gcm" : "aes-256-gcm";
  const cipher = createCipheriv(algorithm, key, nonce);
  cipher.setAAD(context);
  return Buffer.concat([Buffer.from(nonce), cipher.update(input), cipher.final(), cipher.getAuthTag()]);
}
function openNative(key: Uint8Array, blob: Uint8Array, context: Uint8Array): Buffer {
  const algorithm = key.byteLength === 16 ? "aes-128-gcm" : key.byteLength === 24 ? "aes-192-gcm" : "aes-256-gcm";
  const cipher = createDecipheriv(algorithm, key, blob.subarray(0, 12));
  cipher.setAAD(context); cipher.setAuthTag(blob.subarray(-16));
  return Buffer.concat([cipher.update(blob.subarray(12, -16)), cipher.final()]);
}
function copy(input: Uint8Array): Bytes { const output = bytes(input.byteLength); output.set(input); return output; }
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); setKvBackendForTests(null); __setLocaleForTests("en"); });

it("publishes the AES envelope minimum as twelve nonce bytes plus the sixteen-byte authentication tag", () => {
  expect(NONCE_SIZE).toBe(12);
  expect(MIN_BLOB_SIZE).toBe(28);
});

it("refuses other native AES strengths through both public AES-256 entry points", async () => {
  for (const size of [16, 24]) {
    const key = bytes(size, 19), sealed = sealNative(key, plain, aad);
    expect(openNative(key, sealed, aad)).toEqual(Buffer.from(plain));
    await expect(encryptWithFixedNonce(key, plain, nonce, copy(aad))).rejects.toBeInstanceOf(Error);
    await expect(decrypt(key, copy(sealed), copy(aad))).rejects.toBeInstanceOf(Error);
  }
});

it("refuses a thirteen-byte nonce before granting a fixed-twelve-byte public envelope", async () => {
  await expect(encryptWithFixedNonce(bytes(32, 17), plain, bytes(13, 41), copy(aad))).rejects.toBeInstanceOf(Error);
});

it("renders the authenticated-recording failure category after genuine native authentication refusal", async () => {
  resetTestState(); __setLocaleForTests("en"); resetEntryVersionMirrors();
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  const records = new Map<string, string>();
  setKvBackendForTests({ getItem: async name => records.get(name) ?? null, setItem: async (name, value) => { records.set(name, value); }, removeItem: async name => { records.delete(name); }, keys: async () => [...records.keys()] });
  const owner = "public-crypto-recording-owner", key = bytes(32, 71);
  installSession(owner); vault.unlock({ authKey: copy(key), dataKey: copy(key) }, owner);
  const entryContext = Buffer.from(JSON.stringify(["entry", owner, "recorded", "1"]));
  const entryInput = Buffer.from(JSON.stringify({ v: 1, text: "An actual retained recording", sentiment: 0.8, created_at: "2026-10-05T11:22:33.000Z" }));
  const entryBlob = sealNative(key, entryInput, entryContext);
  expect(openNative(key, entryBlob, entryContext)).toEqual(entryInput);
  const listed: ListedEntry = { id: "server-recorded", client_entry_id: "recorded", blob: entryBlob.toString("base64"), entry_date: "2026-10-05", received_at: "2026-10-05T11:23:00.000Z", content_version: 1, audio: { attachment_id: "audio-recorded", expires_at: "2026-11-01" } };
  vi.spyOn(client, "listEntriesWalk").mockResolvedValue([listed]);
  const audioContext = Buffer.from(JSON.stringify(["audio", owner, "recorded", "1"]));
  const audio = bytes(4, 29), authentic = sealNative(key, audio, audioContext);
  expect(openNative(key, authentic, audioContext)).toEqual(Buffer.from(audio));
  const corrupt = Buffer.from(authentic); corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  expect(() => openNative(key, corrupt, audioContext)).toThrow();
  vi.spyOn(api, "fetchAudioAttachment").mockResolvedValue({ id: "audio-recorded", client_entry_id: "recorded", blob: corrupt.toString("base64"), mime_type: "audio/webm", duration_seconds: 2, size_bytes: corrupt.length, created_at: "2026-10-05", expires_at: "2026-11-01" });
  const root = await render(<HistoryView />);
  await vi.waitFor(() => expect(textOf(root)).toContain("An actual retained recording"));
  await press(root, t("history.playRecording"));
  // Both failure categories finish and restore the public action; the wait does not assert the category.
  await vi.waitFor(() => expect(isDisabled(root, t("history.playRecording"))).toBe(false));
  expect(textOf(root)).toContain(t("history.playbackTampered"));
  expect(root.root.findAllByType("audio")).toHaveLength(0);
});
