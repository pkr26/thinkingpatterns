/**
 * Fetch and decrypt kept recordings in memory for playback.
 * Object URLs are revoked on completion, failure, and unmount; decrypted
 * audio is never written to persistent storage.
 */
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
