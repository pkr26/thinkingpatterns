import { beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "./helpers/expoFsMock";
import {
  createPlaybackScratchUri,
  scrubAllVoiceScratchFiles,
  scrubVoiceScratchForOwner,
} from "../src/audio/voiceScratch";

const ownerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ownerB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

beforeEach(() => fs.__resetFiles());

describe("plaintext voice scratch lifecycle", () => {
  it("allocates pseudonymous, unpredictable owner-scoped playback paths", async () => {
    const first = await createPlaybackScratchUri(ownerA, "audio/m4a");
    const second = await createPlaybackScratchUri(ownerA, "audio/m4a; codecs=aac");

    expect(first).toMatch(
      /^\/tmp\/mindpattern-test-cache\/mindpattern-voice-playback\/[a-f0-9]{64}\/voice-[a-f0-9]{32}\.m4a$/,
    );
    expect(first).not.toContain(ownerA);
    expect(second).not.toBe(first);
    expect(fs.makeDirectoryAsync).toHaveBeenCalledWith(
      first.slice(0, first.lastIndexOf("/") + 1),
      { intermediates: true },
    );
    await expect(createPlaybackScratchUri(ownerA, "text/plain")).rejects.toThrow(
      "Unsupported voice playback format",
    );
  });

  it("normalizes parameterized MIME values and preserves the allowlisted extension", async () => {
    const cases = [
      [" audio/mp4 ; codecs=aac", ".m4a"],
      ["AUDIO/X-M4A", ".m4a"],
      ["audio/ogg; codecs=opus", ".ogg"],
    ] as const;
    for (const [mime, extension] of cases) {
      const uri = await createPlaybackScratchUri(ownerA, mime);
      expect(uri.endsWith(extension)).toBe(true);
    }
  });

  it("rejects empty and oversized owner scopes before allocating a directory", async () => {
    await expect(createPlaybackScratchUri("", "audio/m4a")).rejects.toThrow(
      "Voice scratch owner is invalid",
    );
    await expect(createPlaybackScratchUri("x".repeat(129), "audio/m4a")).rejects.toThrow(
      "Voice scratch owner is invalid",
    );
    for (const malformed of [null, undefined, 42]) {
      await expect(createPlaybackScratchUri(malformed as unknown as string, "audio/m4a")).rejects.toThrow("Voice scratch owner is invalid");
    }
    const boundary = await createPlaybackScratchUri("x".repeat(128), "audio/m4a");
    expect(boundary).toMatch(/\/voice-[a-f0-9]{32}\.m4a$/);
  });

  it("erasure removes one owner's playback and all unscoped native recordings", async () => {
    const a = await createPlaybackScratchUri(ownerA, "audio/m4a");
    const b = await createPlaybackScratchUri(ownerB, "audio/webm");
    fs.__seedFile(a);
    fs.__seedFile(b);
    fs.__seedFile(`${fs.cacheDirectory}ExpoAudio/recording-ios.m4a`);
    fs.__seedFile(`${fs.cacheDirectory}Audio/recording-android.m4a`);
    fs.__seedFile(`${fs.cacheDirectory}unrelated/cache.bin`);

    await scrubVoiceScratchForOwner(ownerA);

    expect(fs.__hasFile(a)).toBe(false);
    expect(fs.__hasFile(b)).toBe(true);
    expect(fs.__hasFile(`${fs.cacheDirectory}ExpoAudio/recording-ios.m4a`)).toBe(false);
    expect(fs.__hasFile(`${fs.cacheDirectory}Audio/recording-android.m4a`)).toBe(false);
    expect(fs.__hasFile(`${fs.cacheDirectory}unrelated/cache.bin`)).toBe(true);
  });

  it("cold-start scrub removes every app-owned voice scratch and nothing else", async () => {
    const a = await createPlaybackScratchUri(ownerA, "audio/mpeg");
    const b = await createPlaybackScratchUri(ownerB, "audio/wav");
    fs.__seedFile(a);
    fs.__seedFile(b);
    fs.__seedFile(`${fs.cacheDirectory}ExpoAudio/recording-stale.m4a`);
    fs.__seedFile(`${fs.cacheDirectory}unrelated/cache.bin`);

    await scrubAllVoiceScratchFiles();

    expect(fs.__hasFile(a)).toBe(false);
    expect(fs.__hasFile(b)).toBe(false);
    expect(fs.__hasFile(`${fs.cacheDirectory}ExpoAudio/recording-stale.m4a`)).toBe(false);
    expect(fs.__hasFile(`${fs.cacheDirectory}unrelated/cache.bin`)).toBe(true);
  });

  it("attempts every target after a partial failure and succeeds on retry", async () => {
    const playback = await createPlaybackScratchUri(ownerA, "audio/m4a");
    const iosRecording = `${fs.cacheDirectory}ExpoAudio/recording-stale.m4a`;
    const androidRecording = `${fs.cacheDirectory}Audio/recording-stale.m4a`;
    fs.__seedFile(playback);
    fs.__seedFile(iosRecording);
    fs.__seedFile(androidRecording);
    vi.mocked(fs.deleteAsync).mockRejectedValueOnce(new Error("private native path"));

    await expect(scrubVoiceScratchForOwner(ownerA)).rejects.toThrow(
      "Voice scratch cleanup failed",
    );
    expect(fs.__hasFile(playback)).toBe(true);
    expect(fs.__hasFile(iosRecording)).toBe(false);
    expect(fs.__hasFile(androidRecording)).toBe(false);

    await scrubVoiceScratchForOwner(ownerA);
    expect(fs.__hasFile(playback)).toBe(false);
  });

  it.each([null, ""])("fails closed when the native cache root is unavailable (%s)", async cacheDirectory => {
    vi.resetModules();
    vi.doMock("expo-file-system/legacy", () => ({
      cacheDirectory,
      makeDirectoryAsync: vi.fn(async () => {}),
      deleteAsync: vi.fn(async () => {}),
    }));
    try {
      const isolated = await import("../src/audio/voiceScratch");
      await expect(isolated.createPlaybackScratchUri(ownerA, "audio/m4a")).rejects.toThrow(
        "Voice scratch storage is unavailable",
      );
    } finally {
      vi.doUnmock("expo-file-system/legacy");
      vi.resetModules();
    }
  });

  it("normalizes a cache root supplied without a trailing slash", async () => {
    const makeDirectoryAsync = vi.fn(async () => {});
    vi.resetModules();
    vi.doMock("expo-file-system/legacy", () => ({
      cacheDirectory: "/tmp/no-trailing-slash",
      makeDirectoryAsync,
      deleteAsync: vi.fn(async () => {}),
    }));
    try {
      const isolated = await import("../src/audio/voiceScratch");
      const uri = await isolated.createPlaybackScratchUri(ownerA, "audio/m4a");
      expect(uri).toMatch(/^\/tmp\/no-trailing-slash\/mindpattern-voice-playback\//);
      expect(makeDirectoryAsync).toHaveBeenCalledTimes(1);
    } finally {
      vi.doUnmock("expo-file-system/legacy");
      vi.resetModules();
    }
  });
});
