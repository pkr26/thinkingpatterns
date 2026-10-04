/**
 * Plaintext voice scratch lifecycle.
 *
 * Expo Audio necessarily records to a native cache file, and native players
 * need a URI for decrypted playback.  Those files are deliberately confined
 * to cache storage, scrubbed before authentication on every cold start, and
 * scrubbed again for account erasure/server-origin retirement.  We never
 * delete the cache root itself: only the directories owned by MindPattern and
 * the two Expo Audio recording directories used by the pinned native module.
 */
import * as FileSystem from "expo-file-system/legacy";
import { engine } from "../crypto/engine";

const PLAYBACK_ROOT = "mindpattern-voice-playback/";
const NATIVE_RECORDING_ROOTS = ["ExpoAudio/", "Audio/"] as const;

const MIME_EXTENSION: Readonly<Record<string, string>> = Object.freeze({
  "audio/webm": ".webm",
  "audio/mp4": ".m4a",
  "audio/m4a": ".m4a",
  "audio/x-m4a": ".m4a",
  "audio/ogg": ".ogg",
  "audio/mpeg": ".mp3",
  "audio/wav": ".wav",
});

function cacheRoot(): string {
  const root = FileSystem.cacheDirectory;
  if (typeof root !== "string" || root.length === 0) {
    throw new Error("Voice scratch storage is unavailable");
  }
  return root.endsWith("/") ? root : `${root}/`;
}

function ownerScope(owner: string): string {
  if (typeof owner !== "string" || owner.length === 0 || owner.length > 128) {
    throw new Error("Voice scratch owner is invalid");
  }
  return engine.createHash("sha256").update(Buffer.from(owner, "utf8")).digest().toString("hex");
}

function playbackOwnerDirectory(owner: string): string {
  return `${cacheRoot()}${PLAYBACK_ROOT}${ownerScope(owner)}/`;
}

async function removeTargets(targets: readonly string[]): Promise<void> {
  const results = await Promise.allSettled(
    targets.map((target) => FileSystem.deleteAsync(target, { idempotent: true })),
  );
  if (results.some((result) => result.status === "rejected")) {
    // Do not forward native filesystem exception text: paths can contain
    // account-linked metadata and diagnostics outlive the cache itself.
    throw new Error("Voice scratch cleanup failed");
  }
}

/** Allocate a cryptographically unpredictable, pseudonymous playback path. */
export async function createPlaybackScratchUri(owner: string, mimeType: string): Promise<string> {
  const normalizedMime = mimeType.split(";", 1)[0]!.trim().toLowerCase();
  const extension = MIME_EXTENSION[normalizedMime];
  if (!extension) throw new Error("Unsupported voice playback format");
  const directory = playbackOwnerDirectory(owner);
  await FileSystem.makeDirectoryAsync(directory, { intermediates: true });
  const nonce = Buffer.from(engine.randomBytes(16)).toString("hex");
  return `${directory}voice-${nonce}${extension}`;
}

/** Remove one owner's playback files plus unscoped native recorder files. */
export async function scrubVoiceScratchForOwner(owner: string): Promise<void> {
  const root = cacheRoot();
  await removeTargets([
    playbackOwnerDirectory(owner),
    ...NATIVE_RECORDING_ROOTS.map((directory) => `${root}${directory}`),
  ]);
}

/** Cold-start/origin-retirement scrub. Unrelated cache content is untouched. */
export async function scrubAllVoiceScratchFiles(): Promise<void> {
  const root = cacheRoot();
  await removeTargets([
    `${root}${PLAYBACK_ROOT}`,
    ...NATIVE_RECORDING_ROOTS.map((directory) => `${root}${directory}`),
  ]);
}
