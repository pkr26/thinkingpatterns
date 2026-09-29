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
}): Promise<PlayingVoice> {
  const fetched = await options.fetchBlob();
  const plaintext = decryptAudio(options.keys, options.userId, options.clientEntryId, fetched.blob);
  const scratchName = `voice-${options.clientEntryId}-${Date.now()}.m4a`;
  const uri = `${FileSystem.cacheDirectory}${scratchName}`;
  await FileSystem.writeAsStringAsync(uri, plaintext.toString("base64"), {
    encoding: FileSystem.EncodingType.Base64,
  });
  let released = false;
  return {
    uri,
    durationSeconds: fetched.duration_seconds,
    release: async (): Promise<void> => {
      if (released) return;
      released = true;
      try {
        await FileSystem.deleteAsync(uri, { idempotent: true });
      } catch {
        // the cache dir is reclaimed by the OS regardless
      }
    },
  };
}
