import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { expect, it, vi } from "vitest";

it("returns an owner-scoped playback URI under an actual trailing-slash native file cache URI", async () => {
  const nativeCache = await mkdtemp(join(tmpdir(), "mindpattern-voice-cache-"));
  const cacheDirectory = pathToFileURL(nativeCache + sep).href;
  const owner = "native-cache-owner";
  vi.resetModules();
  vi.doMock("expo-file-system/legacy", () => ({
    cacheDirectory,
    makeDirectoryAsync: async (uri: string, options?: { intermediates?: boolean }) => {
      await mkdir(fileURLToPath(uri), { recursive: options?.intermediates ?? false });
    },
    deleteAsync: async (uri: string, options?: { idempotent?: boolean }) => {
      await rm(fileURLToPath(uri), { recursive: true, force: options?.idempotent ?? false });
    },
  }));
  try {
    const { createPlaybackScratchUri } = await import("../src/audio/voiceScratch");
    const uri = await createPlaybackScratchUri(owner, "audio/m4a");
    const ownerHash = createHash("sha256").update(owner, "utf8").digest("hex");
    const expectedDirectory = cacheDirectory + "mindpattern-voice-playback/" + ownerHash + "/";
    expect(uri.slice(0, uri.lastIndexOf("/") + 1)).toBe(expectedDirectory);
    expect(uri.slice(uri.lastIndexOf("/") + 1)).toMatch(/^voice-[a-f0-9]{32}\.m4a$/);
    expect((await stat(fileURLToPath(expectedDirectory))).isDirectory()).toBe(true);
  } finally {
    vi.doUnmock("expo-file-system/legacy");
    vi.resetModules();
    await rm(nativeCache, { recursive: true, force: true });
  }
});
