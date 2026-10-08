import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "./helpers/expoFsMock";
import * as crypto from "../src/crypto/journalCrypto";
import { playVoiceAttachment } from "../src/audio/playback";
import { scrubAllVoiceScratchFiles } from "../src/audio/voiceScratch";

const key = Buffer.alloc(32, 7), userId = "playback-owner", clientEntryId = "recording-one";
function blob() { return { blob: crypto.encryptAudio({ dataKey: key }, userId, clientEntryId, Buffer.from("native audio bytes")).blobB64, mime_type: "audio/m4a", duration_seconds: 4 }; }
beforeEach(() => fs.__resetFiles());
afterEach(() => vi.restoreAllMocks());

describe("kept recording playback lifecycle", () => {
  it("writes decrypted bytes and repeated release leaves only the newer scratch intact", async () => {
    const playing = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    expect(playing.durationSeconds).toBe(4); expect(fs.__hasFile(playing.uri)).toBe(true);
    expect(fs.writeAsStringAsync).toHaveBeenCalledWith(playing.uri, Buffer.from("native audio bytes").toString("base64"), { encoding: "base64" });
    await playing.release();
    const newer = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    await expect(playing.release()).resolves.toBeUndefined();
    expect(fs.__hasFile(playing.uri)).toBe(false); expect(fs.__hasFile(newer.uri)).toBe(true);
    await newer.release(); expect(fs.__hasFile(newer.uri)).toBe(false);
  });
  it("does not allocate a scratch file after fetch-time cancellation", async () => {
    await expect(playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId, cancelled: () => true })).rejects.toThrow("Playback cancelled");
    expect(fs.writeAsStringAsync).not.toHaveBeenCalled();
  });
  it("releases successfully when cold-start cleanup already removed the plaintext file", async () => {
    const playing = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    await scrubAllVoiceScratchFiles(); expect(fs.__hasFile(playing.uri)).toBe(false);
    await expect(playing.release()).resolves.toBeUndefined();
  });
  it("a released handle remains a successful no-op during a later native provider outage", async () => {
    const playing = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    await playing.release();
    const newer = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    const remove = fs.deleteAsync.getMockImplementation()!;
    fs.deleteAsync.mockImplementation(async () => { throw new Error("Native file provider unavailable"); });
    try {
      await expect(playing.release()).resolves.toBeUndefined();
      expect(fs.__hasFile(playing.uri)).toBe(false); expect(fs.__hasFile(newer.uri)).toBe(true);
    } finally { fs.deleteAsync.mockImplementation(remove); await newer.release(); }
  });
  it("removes written plaintext if cancelled before handing playback to the caller", async () => {
    const cancelled = vi.fn().mockReturnValueOnce(false).mockReturnValue(true);
    await expect(playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId, cancelled })).rejects.toThrow("Playback cancelled");
    const uri = fs.writeAsStringAsync.mock.calls[0]![0]; expect(fs.__hasFile(uri)).toBe(false);
  });
  it("cleans partial scratch writes while preserving the original failure", async () => {
    const original = fs.writeAsStringAsync.getMockImplementation()!, failure = new Error("native writer refused");
    fs.writeAsStringAsync.mockImplementationOnce(async (uri, content) => { await original(uri, content); throw failure; });
    await expect(playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId })).rejects.toBe(failure);
    expect(fs.__hasFile(fs.writeAsStringAsync.mock.calls[0]![0])).toBe(false);
  });
  it("preserves fetch failures even if no plaintext buffer or scratch exists", async () => {
    const failure = new Error("attachment missing");
    await expect(playVoiceAttachment({ fetchBlob: async () => { throw failure; }, keys: { dataKey: key }, userId, clientEntryId })).rejects.toBe(failure);
  });
  it("releases crypto consumer buffers while leaving the caller's live vault key intact", async () => {
    const decrypt = crypto.decryptAudio;
    let consumerKey: Buffer | undefined, consumerPlaintext: Buffer | undefined;
    vi.spyOn(crypto, "decryptAudio").mockImplementation((keys, owner, entry, ciphertext) => {
      consumerKey = keys.dataKey; consumerPlaintext = decrypt(keys, owner, entry, ciphertext); return consumerPlaintext;
    });
    const playing = await playVoiceAttachment({ fetchBlob: async () => blob(), keys: { dataKey: key }, userId, clientEntryId });
    expect(consumerKey).toEqual(Buffer.alloc(32));
    expect(consumerPlaintext).toEqual(Buffer.alloc("native audio bytes".length));
    expect(key).toEqual(Buffer.alloc(32, 7));
    await playing.release();
  });
});
