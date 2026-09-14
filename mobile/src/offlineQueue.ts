/**
 * Offline-first sync queue. Entries are encrypted BEFORE queueing (the
 * queue only ever holds ciphertext), survive restarts, and flush on the
 * next Entry screen mount or reconnect foregrounding.
 *
 * Concurrency: a module-level promise chain (the mutex below) serializes
 * every storage read-modify-write — but NEVER network I/O. The flush loop
 * peeks one item under the mutex, uploads it WITHOUT holding the mutex,
 * then commits the outcome under the mutex. An enqueue landing mid-flush
 * resolves immediately instead of queueing behind up to 200 × 15s of
 * blackholed-network timeouts (the old loop held the mutex for the whole
 * flush — a user pressing Save during an outage hung behind it).
 *
 * clearQueue() deliberately stays OUTSIDE the mutex: it must remain
 * callable from inside a flush's network callback (sign-out racing an
 * in-flight sync). The generation counter is what neutralizes an
 * in-flight flush's stale write-back; the mutex prevents
 * writer-vs-writer and writer-vs-flush interleaving in the first place.
 *
 * Account isolation is enforced by MECHANISM, not convention:
 *   1. Every queued entry records the userId it was encrypted for; a flush
 *      under a different account skips those items.
 *   2. clearQueue() bumps a generation counter; any in-flight flush detects
 *      the bump and abandons its write-back, and an enqueue whose read
 *      straddled the wipe abandons its commit instead of resurrecting an
 *      item inside the just-wiped queue — LOUDLY (QueueAbandonedError), so
 *      the UI never reports "Saved offline" for an entry that was not saved.
 *      The same generation check guards the recovery stores: an
 *      appendRejected / quarantine write that straddled the wipe must not
 *      re-create REJECTED_KEY / QUARANTINE_KEY after account deletion.
 *   3. The queue is capacity-bounded with a LOUD failure (QueueFullError).
 *   4. Terminal server rejections do NOT silently destroy the entry: the
 *      ciphertext is moved to a rejected-store for recovery — a hostile
 *      server must not be able to erase a user's only copy with an error
 *      code.
 *   5. A server 401 means the session is dead — UNLESS the flush was
 *      aborted by a local sign-out (abortInFlightFlush), in which case the
 *      401 is self-inflicted (the token was just revoked/cleared) and the
 *      items are REQUEUED, not rejected. A genuine 401 moves every doomed
 *      current-user item to the rejected store (preserved, never
 *      destroyed) and fails LOUDLY with SessionExpiredError; the client
 *      layer has already locked the vault by then (setUnauthorizedHandler).
 *
 * Per-item failure classification (the flush loop below):
 *   2xx           → sent, removed.
 *   409 conflict  → the server already has this exact entry (double
 *                   flush): removed, not counted as sent.
 *   401           → session handling above.
 *   403 / 413 / other 4xx
 *                 → terminal for THIS entry (it can never succeed): moved
 *                   to the rejected store, flush continues. 413 quota also
 *                   STOPS the flush: the cumulative quota dooms every
 *                   later item identically, but those stay queued — the
 *                   user may free space before the next sync.
 *   422 future    → the ONE retryable 422: an entry_date beyond the
 *     date        server's today+1d grace becomes valid as time passes.
 *                   Detected via the v1 code (validation_error) plus the
 *                   "future" detail text (legacy fallback).
 *   429           → retryable; Retry-After (surfaced on ApiError by the
 *                   client) sets the delay; STOPS the flush — the throttle
 *                   is server-wide, so later items would 429 too.
 *   0 (network /  → retryable with exponential backoff; STOPS the flush:
 *   timeout)        an unreachable server fails every later item the same
 *                   way, so pushing on would only burn the 15s timeouts.
 *   5xx           → retryable with backoff, flush continues (a 500 may be
 *                   specific to one blob).
 *
 * Retriable failures carry persisted per-item backoff (attempts +
 * notBefore on the record): exponential with jitter, so a restart does
 * not reset the clock and a recovering fleet does not retry in lockstep.
 *
 * Storage schema: QUEUE_KEY and REJECTED_KEY hold a versioned envelope
 * { v: 1, items: [...] }. The legacy bare-array shape migrates
 * transparently on read (read-through, same idiom as the mood log);
 * unparseable payloads quarantine, and parseable-but-unrecognized shapes
 * are kept untouched for repair.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api, ApiError } from "./api/client";

const QUEUE_KEY = "@mindpattern/queue";
/** Corrupt queue payloads are moved here instead of destroyed — silent data
 *  loss is exactly what the audit flagged. UI can offer recovery later. */
const QUARANTINE_KEY = "@mindpattern/queue_quarantine";
/** Entries the server permanently rejected (4xx). Dropped from the retry
 *  loop (they can never succeed) but PRESERVED — not silently destroyed. */
const REJECTED_KEY = "@mindpattern/queue_rejected";
export const MAX_QUEUE_LENGTH = 200;

/** Persisted backoff: first retry after ~30s, doubling to a 30-minute
 *  ceiling, jittered into [50%, 100%) of the exponential value. */
const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 30 * 60_000;

/** Bumped on every wipe/abort; in-flight flushes compare against it. */
let queueGeneration = 0;

/** Serializes all queue read-modify-write cycles so no operation ever
 *  works from a snapshot another operation is about to overwrite. Network
 *  I/O must NEVER run inside this: the flush holds it only for the
 *  peek/commit storage steps. */
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
  /** Backoff state (absent on legacy records = never failed, due now). */
  attempts?: number;
  notBefore?: number; // epoch ms; the entry is not retried before then
}

export class QueueFullError extends Error {
  constructor() {
    super(`offline queue is full (${MAX_QUEUE_LENGTH} entries) — sync before writing more`);
    this.name = "QueueFullError";
  }
}

/** The queue was wiped (sign-out / account deletion) between the enqueue's
 *  read and its commit, so the entry was NOT saved. Throwing — instead of
 *  returning normally — keeps the UI honest: no "Saved offline", the draft
 *  stays on screen. */
export class QueueAbandonedError extends Error {
  constructor() {
    super("the queue was wiped while saving — the entry was NOT queued");
    this.name = "QueueAbandonedError";
  }
}

/** The session died mid-flush (401 with no local sign-out): the doomed
 *  ciphertext was moved to the rejected store for recovery and the flush
 *  stopped instead of re-queueing it against the dead session forever. */
export class SessionExpiredError extends Error {
  constructor() {
    super("session expired mid-flush — unsent entries were preserved in the rejected store");
    this.name = "SessionExpiredError";
  }
}

/** A wipe that began after `generation` was captured wins: the read's
 *  follow-up writes (and the caller's commit) must be abandoned. */
function wipedSince(generation: number | undefined): boolean {
  return generation !== undefined && queueGeneration !== generation;
}

/** Drop null/tampered slots and normalize the optional backoff fields so
 *  the flush loop never compares against hostile types. Records that are
 *  objects are otherwise preserved verbatim — even a malformed one (it may
 *  still be someone's ciphertext, and the server decides its fate). */
function normalizeEntry(raw: unknown): QueuedEntry | null {
  if (typeof raw !== "object" || raw === null) return null;
  const entry = raw as Record<string, unknown>;
  const normalized: QueuedEntry = {
    userId: entry.userId as string,
    clientEntryId: entry.clientEntryId as string,
    blobB64: entry.blobB64 as string,
    entryDate: entry.entryDate as string,
  };
  if (typeof entry.attempts === "number" && Number.isFinite(entry.attempts)) normalized.attempts = entry.attempts;
  if (typeof entry.notBefore === "number" && Number.isFinite(entry.notBefore)) normalized.notBefore = entry.notBefore;
  return normalized;
}

function normalizeItems(raw: unknown): QueuedEntry[] {
  if (!Array.isArray(raw)) return [];
  const items: QueuedEntry[] = [];
  for (const slot of raw) {
    const entry = normalizeEntry(slot);
    if (entry) items.push(entry);
  }
  return items;
}

function serializeItems(items: QueuedEntry[]): string {
  return JSON.stringify({ v: 1, items });
}

async function writeQueue(items: QueuedEntry[]): Promise<void> {
  await AsyncStorage.setItem(QUEUE_KEY, serializeItems(items));
}

/** Parse a queue/rejected payload: the v1 envelope, the legacy bare array
 *  (migrated by the caller's next write — or immediately by readQueue),
 *  or null for parseable-but-unrecognized shapes (kept for repair). */
function parseItemsEnvelope(raw: string): { items: QueuedEntry[]; legacy: boolean } | null {
  const parsed: unknown = JSON.parse(raw);
  if (Array.isArray(parsed)) return { items: normalizeItems(parsed), legacy: true };
  if (typeof parsed === "object" && parsed !== null && (parsed as { v?: unknown }).v === 1) {
    return { items: normalizeItems((parsed as { items?: unknown }).items), legacy: false };
  }
  return null;
}

async function readQueue(generation?: number): Promise<QueuedEntry[]> {
  const raw = await AsyncStorage.getItem(QUEUE_KEY);
  if (raw === null || raw === "") return [];
  try {
    const parsed = parseItemsEnvelope(raw);
    if (parsed === null) return []; // unrecognized shape: leave the bytes for repair
    if (parsed.legacy && !wipedSince(generation)) {
      // Read-through migration (moodLog idiom): refresh the storage shape
      // now so the legacy window stays bounded. A wipe racing this read
      // wins — re-creating the key would resurrect a wiped queue.
      await AsyncStorage.setItem(QUEUE_KEY, serializeItems(parsed.items));
    }
    return parsed.items;
  } catch {
    // Corrupted storage must not brick sync forever — but neither may it
    // destroy the (ciphertext) bytes: quarantine the raw value (appending,
    // so a SECOND corruption never overwrites the first recovery copy),
    // then start a fresh queue.
    const previous = await AsyncStorage.getItem(QUARANTINE_KEY);
    // A wipe (account deletion) racing this read wins: re-creating the
    // quarantine key now would resurrect ciphertext after the wipe.
    if (wipedSince(generation)) return [];
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

/** Entries permanently rejected by the server (recovery surface for 4xx). */
export async function rejectedEntries(): Promise<QueuedEntry[]> {
  const raw = await AsyncStorage.getItem(REJECTED_KEY);
  if (raw === null || raw === "") return [];
  try {
    return parseItemsEnvelope(raw)?.items ?? [];
  } catch {
    return [];
  }
}

/** How many entries sit in the rejected store (badge for a future
 *  "recovered entries" UI). */
export async function rejectedEntryCount(): Promise<number> {
  return (await rejectedEntries()).length;
}

async function writeRejected(items: QueuedEntry[]): Promise<void> {
  await AsyncStorage.setItem(REJECTED_KEY, serializeItems(items));
}

async function appendRejected(item: QueuedEntry, generation?: number): Promise<void> {
  const list = await rejectedEntries();
  // A wipe (sign-out / account deletion) racing this read-modify-write wins:
  // re-writing REJECTED_KEY now would resurrect ciphertext after the wipe.
  if (wipedSince(generation)) return;
  list.push(item);
  await writeRejected(list);
}

export async function enqueue(item: QueuedEntry): Promise<void> {
  return serialized(async () => {
    const generation = queueGeneration;
    const queue = await readQueue(generation);
    // clearQueue stays outside the mutex on purpose (see its comment), so a
    // wipe can land inside our read-to-write window. If the generation
    // moved, the wipe BEGAN before our commit and this entry must not
    // survive it: re-reading the wiped queue and writing anyway would
    // resurrect an item in a queue the user just wiped (sign-out / account
    // deletion). Abandon the commit LOUDLY — the entry text is still on the
    // Entry screen, and the account context it belonged to is gone.
    if (queueGeneration !== generation) throw new QueueAbandonedError();
    if (queue.length >= MAX_QUEUE_LENGTH) {
      throw new QueueFullError();
    }
    queue.push(item);
    // There is deliberately no await between the generation check above and
    // this write: a wipe can only begin at an await point, so any clearQueue
    // starting from here on runs AFTER the write and removes the item itself.
    await writeQueue(queue);
  });
}

/** The ONE retryable 422: an entry dated beyond the server's today+1d
 *  grace is rejected now but becomes valid as time passes. Detected via
 *  the v1 error code when present (anything but validation_error is not
 *  this case) plus the detail text — the legacy server had no code. */
function isFutureDateRejection(err: ApiError): boolean {
  if (err.code !== undefined && err.code !== "validation_error") return false;
  return /future/i.test(err.message);
}

/** Exponential backoff with jitter in [50%, 100%): a fleet recovering from
 *  the same outage must not retry in lockstep. */
function retryDelayMs(attempts: number): number {
  const exponential = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(attempts, 10));
  return Math.floor(exponential / 2 + Math.random() * (exponential / 2));
}

type FlushOutcome =
  | { kind: "sent" }
  | { kind: "duplicate" } // 409: the server already has this exact entry
  | { kind: "reject" } // terminal per-entry: preserve in the rejected store
  | { kind: "reject-and-stop" } // 413 quota: terminal AND dooms later items
  | { kind: "session-expired" } // 401
  | { kind: "retry"; retryAfterMs?: number; stop: boolean };

function classifyError(err: unknown): FlushOutcome {
  if (!(err instanceof ApiError)) {
    // Non-ApiError (TypeError "fetch failed", etc.): network-class failure —
    // the server is unreachable and every later item would fail the same.
    return { kind: "retry", stop: true };
  }
  if (err.status === 409) return { kind: "duplicate" };
  if (err.status === 401) return { kind: "session-expired" };
  if (err.status === 429) {
    // Server-wide throttle: honor Retry-After when the server sent one, and
    // stop the flush — later items would only burn the same allowance.
    return { kind: "retry", retryAfterMs: err.retryAfterMs, stop: true };
  }
  if (err.status === 422 && isFutureDateRejection(err)) return { kind: "retry", stop: false };
  if (err.status === 413) return { kind: "reject-and-stop" };
  if (err.status >= 400 && err.status < 500) {
    // 403 (verification_failed), 404, a non-future 422, any other 4xx: this
    // entry can NEVER succeed — but the ciphertext may be the user's only
    // copy, so it moves to the rejected store rather than being destroyed.
    return { kind: "reject" };
  }
  // 0 (network/timeout): stop — the server is unreachable. 5xx: per-item
  // retry, keep going (the failure may be specific to this blob).
  return { kind: "retry", stop: err.status === 0 };
}

/**
 * Upload every due queued entry owned by `currentUserId`; returns how many
 * the server accepted. Foreign-account items and items still inside their
 * backoff window stay queued. Safe to call concurrently with itself: both
 * loops race the same items, the server dedupes (409) and the commit step
 * notices an already-resolved item.
 */
export async function flushQueue(currentUserId: string): Promise<number> {
  let sent = 0;
  for (;;) {
    // PEEK — under the mutex, storage only.
    const peek = await serialized(async () => {
      const generation = queueGeneration;
      const queue = await readQueue(generation);
      const now = Date.now();
      const item = queue.find(
        (entry) => entry.userId === currentUserId && (entry.notBefore === undefined || entry.notBefore <= now),
      );
      return { generation, item };
    });
    const item = peek.item;
    if (!item) return sent;

    // UPLOAD — deliberately OUTSIDE the mutex: a blackholed server parks
    // only this await, never an enqueue or another flush.
    let outcome: FlushOutcome;
    try {
      await api.createEntry(item.clientEntryId, item.blobB64, item.entryDate);
      // The entry left the device — count it even if a wipe abandons the
      // commit below (the duplicate will 409-dedupe on the next flush).
      sent += 1;
      outcome = { kind: "sent" };
    } catch (err) {
      outcome = classifyError(err);
    }

    if (outcome.kind === "session-expired") {
      // The session is dead: every remaining upload for THIS account is
      // doomed, and re-queueing the items would loop
      // unlock → flush → 401 → lock forever. Move them ALL to the rejected
      // store (preserved for recovery, never destroyed), keep other
      // accounts' items queued, then fail LOUDLY. (The client layer has
      // already locked the vault via setUnauthorizedHandler.)
      const doomed = await serialized(async () => {
        const queue = await readQueue(peek.generation);
        if (wipedSince(peek.generation)) {
          // Sign-out (abortInFlightFlush) or account deletion won the race:
          // this 401 is SELF-INFLICTED (our own logout/token-clear), so the
          // items must be REQUEUED — i.e. simply left where the wipe logic
          // placed them — never rejected. null = do not reject, do not throw.
          return null;
        }
        const remaining: QueuedEntry[] = [];
        const rejected: QueuedEntry[] = [];
        for (const entry of queue) {
          if (entry.userId === currentUserId) rejected.push(entry);
          else remaining.push(entry);
        }
        for (const entry of rejected) {
          await appendRejected(entry, peek.generation);
          if (wipedSince(peek.generation)) return null; // wiped mid-reject
        }
        await writeQueue(remaining);
        return rejected.length;
      });
      if (doomed === null) return sent;
      throw new SessionExpiredError();
    }

    // COMMIT — under the mutex, storage only.
    const committed = await serialized(async () => {
      const queue = await readQueue(peek.generation);
      if (wipedSince(peek.generation)) return false; // wiped mid-flight: abandon
      const index = queue.findIndex(
        (entry) => entry.userId === item.userId && entry.clientEntryId === item.clientEntryId,
      );
      if (index < 0) return true; // a concurrent flush already resolved it
      switch (outcome.kind) {
        case "sent":
        case "duplicate":
          queue.splice(index, 1);
          await writeQueue(queue);
          break;
        case "reject":
        case "reject-and-stop":
          queue.splice(index, 1);
          // Internally wipe-guarded; re-check before the queue write below.
          await appendRejected(item, peek.generation);
          if (wipedSince(peek.generation)) return false;
          await writeQueue(queue);
          break;
        case "retry": {
          // The delay scales with the failures SO FAR (2^0 for the first
          // retry); the stored counter then records this failure.
          const previousAttempts = item.attempts ?? 0;
          // Retry-After is honored exactly (clamped by the client already);
          // everything else takes the exponential schedule.
          const delay = outcome.retryAfterMs ?? retryDelayMs(previousAttempts);
          queue[index] = {
            ...item,
            attempts: previousAttempts + 1,
            notBefore: Date.now() + Math.min(delay, RETRY_MAX_MS),
          };
          await writeQueue(queue);
          break;
        }
      }
      return true;
    });
    if (!committed) return sent;
    // Fail-fast: an unreachable/throttled server or a full quota fails
    // every later item identically — stop instead of burning timeouts.
    if (outcome.kind === "reject-and-stop") return sent;
    if (outcome.kind === "retry" && outcome.stop) return sent;
  }
}

/** Sign-out coordination (store.signOut calls this BEFORE revoking the
 *  session): bumps the generation so an in-flight flush treats any 401 it
 *  then sees as self-inflicted and REQUEUES the current user's items
 *  instead of rejecting them. Unlike clearQueue() nothing is removed —
 *  sign-out deliberately preserves unsynced ciphertext for the next
 *  login. */
export function abortInFlightFlush(): void {
  // Stryker disable AssignmentOperator
  queueGeneration += 1;
  // Stryker restore AssignmentOperator
}

/** Move rejected entries back into the live queue (a future Settings
 *  "recovered entries" surface calls this after the underlying problem —
 *  expired session, freed quota — is resolved). Returns how many moved;
 *  backoff marks are reset so recovery retries promptly, duplicates of
 *  still-queued items are dropped, and the capacity bound holds (anything
 *  that does not fit stays rejected — recoverable on the next attempt). */
export async function requeueRejected(): Promise<number> {
  return serialized(async () => {
    const generation = queueGeneration;
    const rejected = await rejectedEntries();
    if (rejected.length === 0) return 0;
    const queue = await readQueue(generation);
    if (wipedSince(generation)) return 0;
    const queuedIds = new Set(queue.map((entry) => `${entry.userId} ${entry.clientEntryId}`));
    const stillRejected: QueuedEntry[] = [];
    let moved = 0;
    for (const item of rejected) {
      const id = `${item.userId} ${item.clientEntryId}`;
      if (queuedIds.has(id)) continue; // already live: drop the stale copy
      if (queue.length >= MAX_QUEUE_LENGTH) {
        stillRejected.push(item);
        continue;
      }
      const { attempts: _a, notBefore: _n, ...rest } = item;
      queue.push(rest);
      queuedIds.add(id);
      moved += 1;
    }
    await writeQueue(queue);
    if (wipedSince(generation)) return 0; // a wipe racing us wins both writes
    await writeRejected(stillRejected);
    return moved;
  });
}

/** Foregrounding sync, wired to AppState by the session store: a non-empty
 *  queue plus an authenticated session triggers a flush. Uploads are
 *  ciphertext-only, so this runs even with a LOCKED vault. Throttled so a
 *  foreground/background flap cannot stampede the server; a failed flush
 *  just leaves the queue for the next trigger (Entry mount, next
 *  foregrounding). */
const RECONNECT_FLUSH_MIN_INTERVAL_MS = 10_000;
let lastReconnectFlushAt = 0;

export async function flushQueueOnReconnect(): Promise<void> {
  const now = Date.now();
  if (now - lastReconnectFlushAt < RECONNECT_FLUSH_MIN_INTERVAL_MS) return;
  lastReconnectFlushAt = now;
  const userId = await api.getUserId();
  if (!userId) return; // signed out (or mid-sign-out): nothing to sync
  if ((await queueLength()) === 0) return;
  await flushQueue(userId).catch(() => {
    // Still offline, or the session died: the queue keeps the ciphertext.
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
  return serialized(async () => (await readQueue(queueGeneration)).length);
}
