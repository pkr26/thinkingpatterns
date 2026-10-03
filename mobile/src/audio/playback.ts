/**
 * Decrypt-and-play for kept recordings (VOICE_PLAN P4, 2026-09-29).
 *
 * Fetch the encrypted attachment → decrypt in memory → write a cache file
 * expo-audio can play → release the plaintext buffer. Nothing decrypted
 * persists beyond the OS cache dir, and `release` deletes the scratch file.
 */
import * as FileSystem from "expo-file-system/legacy";
import { decryptAudio } from "../crypto/MindPatternCrypto";

export interface PlayingVoice {
  uri: string;
  durationSeconds: number;
  release: () => Promise<void>;
}

export async function playVoiceAttachment(options: {
  fetchBlob: () => Promise<{ blob: string; mime_type: string; duration_seconds: number }>;
  keys: { dataKey: Buffer };
  userId: string;
  clientEntryId: string;
  cancelled?: () => boolean;
}): Promise<PlayingVoice> {
  const key = Buffer.from(options.keys.dataKey);
  let plaintext: Buffer | null = null;
  let uri: string | null = null;
  try {
    const fetched = await options.fetchBlob();
    if (options.cancelled?.()) throw new Error("Playback cancelled");
    plaintext = decryptAudio({ dataKey: key }, options.userId, options.clientEntryId, fetched.blob);
    uri = `${FileSystem.cacheDirectory}voice-${Date.now()}-${Math.random().toString(36).slice(2)}.m4a`;
    await FileSystem.writeAsStringAsync(uri, plaintext.toString("base64"), { encoding: FileSystem.EncodingType.Base64 });
    if (options.cancelled?.()) throw new Error("Playback cancelled");
    const scratch = uri;
    let released = false;
    return {
      uri: scratch, durationSeconds: fetched.duration_seconds,
      release: async () => {
        if (released) return;
        await FileSystem.deleteAsync(scratch, { idempotent: true });
        released = true;
      },
    };
  } catch (err) {
    if (uri) await FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => {});
    throw err;
  } finally { key.fill(0); plaintext?.fill(0); }
}
