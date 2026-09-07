/**
 * Offline-first sync queue. Entries are encrypted BEFORE queueing (the
 * queue only ever holds ciphertext), survive restarts, and flush on the
 * next Entry screen mount.
 *
 * Concurrency is serialized by a module-level promise chain (the mutex
 * below): the old read-modify-write races silently LOST entries — an
 * enqueue landing mid-flush was overwritten by the flush's write-back of
 * its stale snapshot, and two concurrent enqueues each dropped the other's
 * item. Every mutating/reading operation now runs under the mutex.
 *
 * clearQueue() deliberately stays OUTSIDE the mutex: it must remain
 * callable from inside a flush (sign-out racing an in-flight sync). The
 * generation counter is what neutralizes an in-flight flush's stale
 * write-back; the mutex prevents writer-vs-writer and writer-vs-flush
 * interleaving in the first place.
 *
 * Account isolation is enforced by MECHANISM, not convention:
 *   1. Every queued entry records the userId it was encrypted for; a flush
 *      under a different account skips those items.
 *   2. clearQueue() bumps a generation counter; any in-flight flush detects
 *      the bump and abandons its final write-back, and an enqueue whose read
 *      straddled the wipe abandons its commit instead of resurrecting an
 *      item inside the just-wiped queue.
 *   3. The queue is capacity-bounded with a LOUD failure (QueueFullError).
 *   4. A server 422 does NOT silently destroy the entry: the ciphertext is
 *      moved to a rejected-store for recovery — a hostile server must not
 *      be able to erase a user's only copy with an error code.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api, ApiError } from "./api/client";

const QUEUE_KEY = "@mindpattern/queue";
/** Corrupt queue payloads are moved here instead of destroyed — silent data
 *  loss is exactly what the audit flagged. UI can offer recovery later. */
const QUARANTINE_KEY = "@mindpattern/queue_quarantine";
/** Entries the server permanently rejected (422). Dropped from the retry
 *  loop (it can never succeed) but PRESERVED — not silently destroyed. */
const REJECTED_KEY = "@mindpattern/queue_rejected";
export const MAX_QUEUE_LENGTH = 200;

/** Bumped on every wipe; in-flight flushes compare against it. */
let queueGeneration = 0;

/** Serializes all queue read-modify-write cycles so no operation ever
 *  works from a snapshot another operation is about to overwrite. */
let queueMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = queueMutex.then(operation, operation);
  queueMutex = run.catch(() => {});
  return run;
}

export interface QueuedEntry {
  userId: string;
  clientEntryId: string;
  blobB64: string;
  entryDate: string;
}

export class QueueFullError extends Error {
  constructor() {
    super(`offline queue is full (${MAX_QUEUE_LENGTH} entries) — sync before writing more`);
    this.name = "QueueFullError";
  }
}

async function readQueue(): Promise<QueuedEntry[]> {
  // "" and "[]" both yield an empty queue (the empty string falls into the
  // corrupted-storage recovery below, which returns [] as well).
  const raw = (await AsyncStorage.getItem(QUEUE_KEY)) ?? "[]";
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // Corrupted storage must not brick sync forever — but neither may it
    // destroy the (ciphertext) bytes: quarantine the raw value (appending,
    // so a SECOND corruption never overwrites the first recovery copy),
    // then start a fresh queue.
    const previous = await AsyncStorage.getItem(QUARANTINE_KEY);
    const record = previous === null ? raw : `${previous}\n---corruption---\n${raw}`;
    await AsyncStorage.setItem(QUARANTINE_KEY, record);
    await AsyncStorage.removeItem(QUEUE_KEY);
    return [];
  }
}

/** True when a corrupt queue payload sits in quarantine (for UI recovery). */
export async function quarantinedQueueExists(): Promise<boolean> {
  return (await AsyncStorage.getItem(QUARANTINE_KEY)) !== null;
}

/** Entries permanently rejected by the server (recovery surface for 422s). */
export async function rejectedEntries(): Promise<QueuedEntry[]> {
  const raw = await AsyncStorage.getItem(REJECTED_KEY);
  try {
    const parsed = JSON.parse(raw ?? "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function appendRejected(item: QueuedEntry): Promise<void> {
  const list = await rejectedEntries();
  list.push(item);
  await AsyncStorage.setItem(REJECTED_KEY, JSON.stringify(list));
}

export async function enqueue(item: QueuedEntry): Promise<void> {
  return serialized(async () => {
    const generation = queueGeneration;
    const queue = await readQueue();
    // clearQueue stays outside the mutex on purpose (see its comment), so a
    // wipe can land inside our read-to-write window. If the generation
    // moved, the wipe BEGAN before our commit and this entry must not
    // survive it: re-reading the wiped queue and writing anyway would
    // resurrect an item in a queue the user just wiped (sign-out / account
    // deletion). Abandon the commit — the entry text is still on the Entry
    // screen, and the account context it belonged to is gone.
    if (queueGeneration !== generation) return;
    if (queue.length >= MAX_QUEUE_LENGTH) {
      throw new QueueFullError();
    }
    queue.push(item);
    // There is deliberately no await between the generation check above and
    // this write: a wipe can only begin at an await point, so any clearQueue
    // starting from here on runs AFTER the write and removes the item itself.
    await AsyncStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
  });
}

export async function flushQueue(currentUserId: string): Promise<number> {
  return serialized(async () => {
    const generation = queueGeneration;
    const queue = await readQueue();
    let sent = 0;
    const remaining: QueuedEntry[] = [];
    for (let i = 0; i < queue.length; i++) {
      if (queueGeneration !== generation) {
        // The queue was wiped mid-flush (sign-out / account deletion).
        // Abandon everything: our snapshot is stale, and writing it back
        // would resurrect another account's wiped ciphertext.
        return sent;
      }
      const item = queue[i];
      if (!item) continue;
      if (item.userId !== currentUserId) {
        // Ciphertext owned by a different account: never upload it here.
        // Keep it queued so its owner can still sync it on their next login.
        remaining.push(item);
        continue;
      }
      try {
        await api.createEntry(item.clientEntryId, item.blobB64, item.entryDate);
        sent += 1;
      } catch (err) {
        const status = err instanceof ApiError ? err.status : 0;
        if (status === 409) {
          // The server already has this exact entry (double flush).
          continue;
        }
        if (status === 422) {
          // The server permanently rejects this blob — retrying can never
          // succeed and would poison the queue. But the ciphertext is
          // possibly the user's ONLY copy: quarantine it for recovery
          // instead of destroying it on the server's word.
          await appendRejected(item);
          continue;
        }
        if (status === 401) {
          // The session is dead — every remaining item would fail too.
          // Keep them (they are valid ciphertext) for after re-unlock.
          remaining.push(...queue.slice(i));
          break;
        }
        remaining.push(item); // network / 5xx / 429 — retry on next launch
      }
    }
    if (queueGeneration !== generation) return sent; // wiped mid-flush
    await AsyncStorage.setItem(QUEUE_KEY, JSON.stringify(remaining));
    return sent;
  });
}

export async function clearQueue(): Promise<void> {
  // NOT under the mutex: this must stay callable from inside an in-flight
  // flush's network callback (the generation bump below is what makes the
  // flush abandon its write-back; taking the mutex here would deadlock).
  // Stryker disable AssignmentOperator
  queueGeneration += 1; // kill any in-flight flush and its write-back
  // Stryker restore AssignmentOperator
  await AsyncStorage.removeItem(QUEUE_KEY);
  // A full wipe must cover the recovery stores too — the previous account's
  // quarantined/rejected ciphertext must not outlive sign-out of deletion.
  await AsyncStorage.removeItem(QUARANTINE_KEY);
  await AsyncStorage.removeItem(REJECTED_KEY);
}

export async function queueLength(): Promise<number> {
  return serialized(async () => (await readQueue()).length);
}
