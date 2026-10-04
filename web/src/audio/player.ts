/**
 * Decrypt-and-play for kept recordings (VOICE_PLAN P3, 2026-09-29).
 *
 * Fetch the encrypted attachment → decrypt with the audio AAD in memory →
 * play through a revocable object URL. Nothing is ever cached at rest
 * (the same rule as every other decrypted surface in this app), and the
 * URL dies on ended/error/unmount so the blob can be collected.
 */
// @ts-nocheck

import type { Bytes } from "../crypto/core";
import { decryptAudio } from "../crypto/patient";

export interface PlayingAudio {
  url: string;
  mime: string;
  durationSeconds: number;
  release: () => void;
}

export async function playAttachment(options: {
  fetchBlob: () => Promise<{ blob: string; mime_type: string; duration_seconds: number }>;
  dataKey: Bytes;
  userId: string;
  clientEntryId: string;
}): Promise<PlayingAudio> {
  const fetched = await options.fetchBlob();
  const plaintext = await decryptAudio(
    options.dataKey,
    options.userId,
    options.clientEntryId,
    fetched.blob,
  );
  let url: string;
  try { url = URL.createObjectURL(new Blob([plaintext], { type: fetched.mime_type })); }
  finally { plaintext.fill(0); }
  const revokeObjectUrl = URL.revokeObjectURL.bind(URL);
  let released = false;
  return {
    url,
    mime: fetched.mime_type,
    durationSeconds: fetched.duration_seconds,
    release: (): void => {
      if (!released) {
        released = true;
        revokeObjectUrl(url);
      }
    },
  };
}
