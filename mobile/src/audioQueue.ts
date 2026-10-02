/**
 * Ciphertext-only offline queue for KEPT VOICE RECORDINGS (wave 2,
 * 2026-09-30). Voice-first users used to lose the recording itself the
 * moment a save queued offline — the transcript survived in the text queue
 * while the primary artifact was destroyed with a transient notice. The
 * audio ciphertext now rides the same discipline as the text queue:
 *
 *  - CIPHERTEXT-ONLY at rest: the take is sealed with the account's data
 *    key at stash time (the vault is unlocked by construction then); the
 *    flush uploads the stored bytes verbatim — a locked vault is fine.
 *  - Scoped per (origin, account): each item is its own AsyncStorage row
 *    keyed by scope — audio blobs are megabyte-scale and Android's
 *    cursor-window limit (~2 MB) applies PER ROW, so one-row-per-take is
 *    the only layout that cannot wedge the store.
 *  - Bounded: MAX_AUDIO_QUEUE_ITEMS takes, oldest dropped first; a single
 *    take above MAX_TAKE_BYTES is refused at stash time (the honest
 *    not-kept notice, never a wedged row).
 *  - Honest flush semantics: success removes the row; 401 parks the row
 *    (session expiry, like the text queue's M-14); permanent rejections
 *    (403 consent gone, 404 entry deleted elsewhere, 409 replaced, 413
 *    too large) drop the row — the server will never accept it; network
 *    and 5xx keep the row for the next reconnect.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api, ApiError, canonicalOrigin, getBaseUrl, OriginPinnedError } from "./api/client";

const KEY_PREFIX = "@mindpattern/audioqueue.v1";
export const MAX_AUDIO_QUEUE_ITEMS = 12;
/** One m4a take at the app's own 5-minute cap is ~1–2 MB of base64;
 * 6 MB refuses pathological inputs long before the row can wedge. */
export const MAX_TAKE_BYTES = 6_000_000;
/** Parked-notBefore after a 401 mid-flush (mirrors the text queue's
 * M-14: a dead session must not be hammered item-by-item from every
 * foreground; the next healthy flush after re-auth recovers it). */
const SESSION_EXPIRED_RETRY_MS = 15 * 60_000;

export interface QueuedAudio {
  /** The client-encrypted audio blob exactly as uploadAudioAttachment
   * expects it — never plaintext, never re-encrypted at flush. */
  blobB64: string;
  mime: string;
  durationSeconds: number;
  queuedAt: number;
  notBefore?: number;
}

export class AudioTooLargeError extends Error {
  constructor() {
    super("kept-recording queue: take exceeds the on-device bound");
    this.name = "AudioTooLargeError";
  }
}

/** Process-wide generation fence: a clear (account deletion) beats every
 *  in-flight stash/flush without holding the mutex across network I/O. */
let audioGeneration = 0;
let audioMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = audioMutex.then(operation, operation);
  audioMutex = run.catch(() => {});
  return run;
}

function itemKey(origin: string, userId: string, clientEntryId: string): string {
  return `${KEY_PREFIX}:${canonicalOrigin(origin)}:${userId}:${clientEntryId}`;
}

async function scopeKeys(origin: string, userId: string): Promise<string[]> {
  const prefix = `${KEY_PREFIX}:${canonicalOrigin(origin)}:${userId}:`;
  const keys = await AsyncStorage.getAllKeys();
  return keys.filter((k) => k.startsWith(prefix)).sort();
}

/** Stash one kept take (replaces any older take for the same entry — the
 *  upload path is one-attachment-per-entry by server contract). Throws
 *  AudioTooLargeError for an oversized take: the caller shows the honest
 *  not-kept notice instead of wedging the store. */
export async function enqueueAudio(params: {
  userId: string;
  clientEntryId: string;
  blobB64: string;
  mime: string;
  durationSeconds: number;
}): Promise<void> {
  if (params.blobB64.length > MAX_TAKE_BYTES) throw new AudioTooLargeError();
  const origin = await getBaseUrl();
  const generation = audioGeneration;
  await serialized(async () => {
    if (generation !== audioGeneration) return; // a clear raced us: drop the stash
    const key = itemKey(origin, params.userId, params.clientEntryId);
    const keys = await scopeKeys(origin, params.userId);
    const others = keys.filter((k) => k !== key);
    // Count cap with drop-oldest (explicit timestamp order — key sort is
    // not a time order): the newest takes win.
    const items = await Promise.all(
      others.map(async (k) => ({ k, item: safeParse(await AsyncStorage.getItem(k)) })),
    );
    items.sort((a, b) => (a.item?.queuedAt ?? 0) - (b.item?.queuedAt ?? 0));
    let excess = items.length + 1 - MAX_AUDIO_QUEUE_ITEMS;
    for (const { k } of items) {
      if (excess <= 0) break;
      await AsyncStorage.removeItem(k);
      excess -= 1;
    }
    await AsyncStorage.setItem(
      key,
      JSON.stringify({
        blobB64: params.blobB64,
        mime: params.mime,
        durationSeconds: params.durationSeconds,
        queuedAt: Date.now(),
      }),
    );
  });
}

function safeParse(raw: string | null): QueuedAudio | null {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as QueuedAudio;
    if (
      typeof parsed.blobB64 !== "string" ||
      typeof parsed.mime !== "string" ||
      typeof parsed.durationSeconds !== "number" ||
      typeof parsed.queuedAt !== "number"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function audioQueueCount(userId?: string): Promise<number> {
  const owner = userId ?? (await api.getUserId());
  if (!owner) return 0;
  return (await scopeKeys(await getBaseUrl(), owner)).length;
}

/** Upload every queued take for the CURRENT account scope. Ciphertext-only
 *  (the stored blob ships verbatim — no key needed); best-effort, one
 *  item's failure never blocks the others. Returns how many uploaded. */
export async function flushAudioQueue(): Promise<number> {
  const userId = await api.getUserId();
  if (!userId) return 0;
  const origin = await getBaseUrl();
  const generation = audioGeneration;
  let uploaded = 0;
  const keys = await scopeKeys(origin, userId);
  for (const key of keys) {
    if (generation !== audioGeneration) break; // deletion raced the flush
    const item = safeParse(await AsyncStorage.getItem(key));
    if (item === null) {
      await AsyncStorage.removeItem(key); // corrupt row: drop, keep walking
      continue;
    }
    if (item.notBefore !== undefined && Date.now() < item.notBefore) continue;
    const entryId = key.slice(key.lastIndexOf(":") + 1);
    try {
      // 2026-10-01 audit H1: re-pin EVERY item to the flush's origin. A
      // server switch mid-flush refuses locally (OriginPinnedError) instead
      // of uploading to the new origin where the entry does not exist —
      // the 404 branch below would have destroyed the only copy.
      await api.uploadAudioAttachment(
        entryId,
        item.blobB64,
        item.mime,
        item.durationSeconds,
        origin,
      );
      await AsyncStorage.removeItem(key);
      uploaded += 1;
    } catch (err) {
      if (err instanceof OriginPinnedError) {
        continue; // the row stays queued under its own origin's scope
      }
      if (err instanceof ApiError && err.status === 401) {
        await AsyncStorage.setItem(key, JSON.stringify({ ...item, notBefore: Date.now() + SESSION_EXPIRED_RETRY_MS }));
        continue;
      }
      if (err instanceof ApiError && [403, 404, 409, 413].includes(err.status)) {
        // The server will never accept this take (consent withdrawn, entry
        // deleted elsewhere, a newer take already stored, or too large):
        // drop it honestly rather than retrying forever.
        await AsyncStorage.removeItem(key);
        continue;
      }
      // Network/5xx: keep the row for the next reconnect.
    }
  }
  return uploaded;
}

/** Delete this account's queued takes (account deletion — the same policy
 *  as the text queue: sign-out KEEPS ciphertext, deletion erases). */
/** 2026-10-01 audit H1: abort an in-flight flush when the API origin
 *  changes (the store's origin-change handler calls this): bumping the
 *  generation stops the loop before its next item — the text queue's
 *  abortInFlightFlush twin. Rows stay queued under their own origin. */
export function abortInFlightAudioFlush(): void {
  audioGeneration += 1;
}

export async function clearAudioQueue(userId?: string): Promise<void> {
  const owner = userId ?? (await api.getUserId());
  if (!owner) return;
  const origin = await getBaseUrl();
  await serialized(async () => {
    audioGeneration += 1;
    const keys = await scopeKeys(origin, owner);
    if (keys.length > 0) await AsyncStorage.multiRemove(keys);
  });
}
