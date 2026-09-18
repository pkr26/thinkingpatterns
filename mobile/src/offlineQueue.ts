/**
 * Ciphertext-only offline queue.
 *
 * Every queue, rejected-store, and corruption quarantine is physically
 * partitioned by BOTH API origin and account id. Earlier releases had one
 * global AsyncStorage key and filtered it only at flush time; that let an
 * account-deletion wipe another account's pending work and made recovery UI
 * expose another account's metadata. Scope is now a storage mechanism, not
 * a convention.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api, ApiError, getBaseUrl } from "./api/client";

const LEGACY_QUEUE_KEY = "@mindpattern/queue";
const LEGACY_REJECTED_KEY = "@mindpattern/queue_rejected";
const LEGACY_QUARANTINE_KEY = "@mindpattern/queue_quarantine";
/** Opaque preservation for old unscoped data. We never guess which origin it
 * belongs to and therefore never upload it to a potentially different one. */
const LEGACY_RECOVERY_KEY = "@mindpattern/queue.legacy-unscoped.v1";
const STORAGE_PREFIX = "@mindpattern/queue.v2";
export const MAX_QUEUE_LENGTH = 200;

const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 30 * 60_000;

/** A process-wide generation fence makes sign-out/origin switch beat every
 * in-flight storage commit without holding a mutex across network I/O. */
let queueGeneration = 0;
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
  attempts?: number;
  notBefore?: number;
}

export class QueueFullError extends Error {
  constructor() {
    super(`offline queue is full (${MAX_QUEUE_LENGTH} entries) — sync before writing more`);
    this.name = "QueueFullError";
  }
}

export class QueueAbandonedError extends Error {
  constructor() {
    super("the queue was cleared while saving — the entry was NOT queued");
    this.name = "QueueAbandonedError";
  }
}

export class SessionExpiredError extends Error {
  constructor() {
    super("session expired mid-flush — unsent entries were preserved for recovery");
    this.name = "SessionExpiredError";
  }
}

interface QueueScope {
  origin: string;
  userId: string;
  queue: string;
  rejected: string;
  quarantine: string;
}

function scopeId(origin: string, userId: string): string {
  // AsyncStorage keys are observable metadata, so avoid putting a readable
  // username or host in them. This is an identifier, not cryptographic
  // secrecy; ciphertext remains encrypted independently.
  return Buffer.from(`${origin}\u0000${userId}`, "utf8").toString("base64url");
}

async function scopeFor(userId: string): Promise<QueueScope> {
  if (!userId) throw new Error("cannot access an offline queue without an account id");
  // `getBaseUrl` is always present in production. The fallback makes this
  // module usable by old isolated test mocks while retaining a safe concrete
  // local-only origin there.
  const base = typeof getBaseUrl === "function" ? await getBaseUrl() : "http://localhost:8000";
  const origin = new URL(base).origin;
  const id = scopeId(origin, userId);
  return {
    origin,
    userId,
    queue: `${STORAGE_PREFIX}.items.${id}`,
    rejected: `${STORAGE_PREFIX}.rejected.${id}`,
    quarantine: `${STORAGE_PREFIX}.quarantine.${id}`,
  };
}

/** Transitional convenience for callers from pre-v2 queue APIs. Runtime
 * callers without an explicit id are still resolved from the encrypted
 * current session; they never fall back to an arbitrary shared scope. */
async function resolveUserId(userId?: string): Promise<string> {
  if (userId) return userId;
  const current = await api.getUserId();
  if (!current) throw new Error("cannot access an offline queue without an account id");
  return current;
}

let legacyMigration: Promise<void> | null = null;
/**
 * Preserve pre-v2 global bytes without assigning them to the currently
 * selected server. Assigning them would recreate the exact cross-origin
 * upload risk this migration closes. A support/recovery tool can inspect the
 * opaque retained record after the owner identifies the original server.
 */
async function migrateUnscopedLegacyData(): Promise<void> {
  if (legacyMigration) return legacyMigration;
  legacyMigration = (async () => {
    const entries = await Promise.all(
      [LEGACY_QUEUE_KEY, LEGACY_REJECTED_KEY, LEGACY_QUARANTINE_KEY].map(async (key) => [key, await AsyncStorage.getItem(key)] as const),
    );
    const records = entries.filter((entry): entry is readonly [string, string] => entry[1] !== null && entry[1] !== "");
    if (records.length === 0) return;
    const previous = await AsyncStorage.getItem(LEGACY_RECOVERY_KEY);
    const envelope = {
      v: 1,
      records: records.map(([key, raw]) => ({ key, raw })),
      previous: previous ?? undefined,
    };
    await AsyncStorage.setItem(LEGACY_RECOVERY_KEY, JSON.stringify(envelope));
    await AsyncStorage.multiRemove(records.map(([key]) => key));
  })();
  // Always release the single-flight marker. A later app operation may see
  // a restored backup containing old global keys; it must migrate those too,
  // not trust a process-lifetime "already checked" flag.
  void legacyMigration.then(
    () => { legacyMigration = null; },
    () => { legacyMigration = null; },
  );
  return legacyMigration;
}

function wipedSince(generation: number): boolean {
  return queueGeneration !== generation;
}

function normalizeEntry(raw: unknown): QueuedEntry | null {
  if (typeof raw !== "object" || raw === null) return null;
  const item = raw as Record<string, unknown>;
  if (
    typeof item.userId !== "string" ||
    typeof item.clientEntryId !== "string" ||
    typeof item.blobB64 !== "string" ||
    typeof item.entryDate !== "string"
  ) {
    return null;
  }
  const normalized: QueuedEntry = {
    userId: item.userId,
    clientEntryId: item.clientEntryId,
    blobB64: item.blobB64,
    entryDate: item.entryDate,
  };
  if (typeof item.attempts === "number" && Number.isFinite(item.attempts)) normalized.attempts = item.attempts;
  if (typeof item.notBefore === "number" && Number.isFinite(item.notBefore)) normalized.notBefore = item.notBefore;
  return normalized;
}

function parseItems(raw: string): QueuedEntry[] | null {
  const parsed: unknown = JSON.parse(raw);
  const slots = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" && parsed !== null && (parsed as { v?: unknown }).v === 1
      ? (parsed as { items?: unknown }).items
      : null;
  if (!Array.isArray(slots)) return null;
  return slots.map(normalizeEntry).filter((entry): entry is QueuedEntry => entry !== null);
}

function serializeItems(items: QueuedEntry[]): string {
  return JSON.stringify({ v: 1, items });
}

async function appendQuarantine(scope: QueueScope, raw: string, generation: number): Promise<void> {
  if (wipedSince(generation)) return;
  const previous = await AsyncStorage.getItem(scope.quarantine);
  if (wipedSince(generation)) return;
  const records = previous ? (() => {
    try {
      const parsed = JSON.parse(previous) as { v?: unknown; records?: unknown };
      return parsed.v === 1 && Array.isArray(parsed.records) ? parsed.records.filter((x): x is string => typeof x === "string") : [previous];
    } catch {
      return [previous];
    }
  })() : [];
  records.push(raw);
  await AsyncStorage.setItem(scope.quarantine, JSON.stringify({ v: 1, records }));
}

async function readItems(key: string, scope: QueueScope, generation: number): Promise<QueuedEntry[]> {
  const raw = await AsyncStorage.getItem(key);
  if (!raw) return [];
  try {
    const parsed = parseItems(raw);
    // A parseable but unrecognized shape is retained untouched for manual
    // repair; treating it as an empty queue cannot cause cross-account data
    // disclosure.
    if (parsed === null) return [];
    return parsed.filter((item) => item.userId === scope.userId);
  } catch {
    await appendQuarantine(scope, raw, generation);
    if (!wipedSince(generation)) await AsyncStorage.removeItem(key);
    return [];
  }
}

async function writeItems(key: string, items: QueuedEntry[]): Promise<void> {
  if (items.length === 0) {
    await AsyncStorage.removeItem(key);
  } else {
    await AsyncStorage.setItem(key, serializeItems(items));
  }
}

async function rejectedFor(scope: QueueScope, generation = queueGeneration): Promise<QueuedEntry[]> {
  return readItems(scope.rejected, scope, generation);
}

async function appendRejected(scope: QueueScope, items: QueuedEntry[], generation: number): Promise<void> {
  if (items.length === 0 || wipedSince(generation)) return;
  const existing = await rejectedFor(scope, generation);
  if (wipedSince(generation)) return;
  const ids = new Set(existing.map((item) => item.clientEntryId));
  for (const item of items) {
    if (!ids.has(item.clientEntryId)) {
      existing.push(item);
      ids.add(item.clientEntryId);
    }
  }
  if (!wipedSince(generation)) await writeItems(scope.rejected, existing);
}

export async function quarantinedQueueExists(userId?: string): Promise<boolean> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  return (await AsyncStorage.getItem(scope.quarantine)) !== null;
}

export async function rejectedEntries(userId?: string): Promise<QueuedEntry[]> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  return rejectedFor(scope);
}

export async function rejectedEntryCount(userId?: string): Promise<number> {
  return (await rejectedEntries(userId)).length;
}

export async function enqueue(item: QueuedEntry): Promise<void> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(item.userId);
  return serialized(async () => {
    const generation = queueGeneration;
    const queue = await readItems(scope.queue, scope, generation);
    if (wipedSince(generation)) throw new QueueAbandonedError();
    if (queue.length >= MAX_QUEUE_LENGTH) throw new QueueFullError();
    // Scope owns the account id. Normalize it from the caller so a tampered
    // record cannot poison another account's queue key.
    queue.push({ ...item, userId: scope.userId });
    if (wipedSince(generation)) throw new QueueAbandonedError();
    await writeItems(scope.queue, queue);
  });
}

function retryDelayMs(attempts: number): number {
  const exponential = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(attempts, 10));
  return Math.floor(exponential / 2 + Math.random() * (exponential / 2));
}

type FlushOutcome =
  | { kind: "sent" }
  | { kind: "duplicate" }
  | { kind: "reject" }
  | { kind: "reject-and-stop" }
  | { kind: "session-expired" }
  | { kind: "retry"; retryAfterMs?: number; stop: boolean };

function isFutureDateRejection(error: ApiError): boolean {
  return (error.code === undefined || error.code === "validation_error") && /future/i.test(error.message);
}

function classifyError(error: unknown): FlushOutcome {
  if (!(error instanceof ApiError)) return { kind: "retry", stop: true };
  if (error.status === 409) return { kind: "duplicate" };
  if (error.status === 401) return { kind: "session-expired" };
  if (error.status === 429) return { kind: "retry", retryAfterMs: error.retryAfterMs, stop: true };
  if (error.status === 422 && isFutureDateRejection(error)) return { kind: "retry", stop: false };
  if (error.status === 413) return { kind: "reject-and-stop" };
  if (error.status >= 400 && error.status < 500) return { kind: "reject" };
  return { kind: "retry", stop: error.status === 0 };
}

/** Upload due items for exactly one origin/account scope. */
export async function flushQueue(currentUserId: string): Promise<number> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(currentUserId);
  let sent = 0;
  for (;;) {
    const peek = await serialized(async () => {
      const generation = queueGeneration;
      const queue = await readItems(scope.queue, scope, generation);
      const item = queue.find((entry) => entry.notBefore === undefined || entry.notBefore <= Date.now());
      return { generation, item };
    });
    const item = peek.item;
    if (!item) return sent;

    let outcome: FlushOutcome;
    try {
      await api.createEntry(item.clientEntryId, item.blobB64, item.entryDate);
      sent += 1;
      outcome = { kind: "sent" };
    } catch (error) {
      outcome = classifyError(error);
    }

    if (outcome.kind === "session-expired") {
      const rejected = await serialized(async () => {
        const queue = await readItems(scope.queue, scope, peek.generation);
        if (wipedSince(peek.generation)) return false;
        await appendRejected(scope, queue, peek.generation);
        if (wipedSince(peek.generation)) return false;
        await writeItems(scope.queue, []);
        return true;
      });
      if (!rejected) return sent; // local sign-out/origin change won
      throw new SessionExpiredError();
    }

    const committed = await serialized(async () => {
      const queue = await readItems(scope.queue, scope, peek.generation);
      if (wipedSince(peek.generation)) return false;
      const index = queue.findIndex((entry) => entry.clientEntryId === item.clientEntryId);
      if (index < 0) return true; // another flush resolved it
      switch (outcome.kind) {
        case "sent":
        case "duplicate":
          queue.splice(index, 1);
          await writeItems(scope.queue, queue);
          break;
        case "reject":
        case "reject-and-stop":
          queue.splice(index, 1);
          await appendRejected(scope, [item], peek.generation);
          if (wipedSince(peek.generation)) return false;
          await writeItems(scope.queue, queue);
          break;
        case "retry": {
          const attempts = item.attempts ?? 0;
          queue[index] = {
            ...item,
            attempts: attempts + 1,
            notBefore: Date.now() + Math.min(outcome.retryAfterMs ?? retryDelayMs(attempts), RETRY_MAX_MS),
          };
          await writeItems(scope.queue, queue);
          break;
        }
      }
      return true;
    });
    if (!committed) return sent;
    if (outcome.kind === "reject-and-stop" || (outcome.kind === "retry" && outcome.stop)) return sent;
  }
}

/** Sign-out/origin switch fences in-flight writes but keeps ciphertext for
 * the correct account scope. Account deletion calls clearQueue instead. */
export function abortInFlightFlush(): void {
  queueGeneration += 1;
}

export async function requeueRejected(userId?: string): Promise<number> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  return serialized(async () => {
    const generation = queueGeneration;
    const [queue, rejected] = await Promise.all([
      readItems(scope.queue, scope, generation),
      rejectedFor(scope, generation),
    ]);
    if (wipedSince(generation) || rejected.length === 0) return 0;
    const ids = new Set(queue.map((item) => item.clientEntryId));
    const stillRejected: QueuedEntry[] = [];
    let moved = 0;
    for (const item of rejected) {
      if (ids.has(item.clientEntryId)) continue;
      if (queue.length >= MAX_QUEUE_LENGTH) {
        stillRejected.push(item);
        continue;
      }
      const { attempts: _attempts, notBefore: _notBefore, ...fresh } = item;
      queue.push(fresh);
      ids.add(item.clientEntryId);
      moved += 1;
    }
    if (wipedSince(generation)) return 0;
    await writeItems(scope.queue, queue);
    if (wipedSince(generation)) return 0;
    await writeItems(scope.rejected, stillRejected);
    return moved;
  });
}

const RECONNECT_FLUSH_MIN_INTERVAL_MS = 10_000;
let lastReconnectFlushAt = 0;

export async function flushQueueOnReconnect(): Promise<void> {
  const now = Date.now();
  if (now - lastReconnectFlushAt < RECONNECT_FLUSH_MIN_INTERVAL_MS) return;
  lastReconnectFlushAt = now;
  const userId = await api.getUserId();
  if (!userId || (await queueLength(userId)) === 0) return;
  await flushQueue(userId).catch(() => {});
}

/** Delete only this account's data for the currently selected origin. */
export async function clearQueue(userId?: string): Promise<void> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  queueGeneration += 1;
  await AsyncStorage.multiRemove([scope.queue, scope.rejected, scope.quarantine]);
}

export async function queueLength(userId?: string): Promise<number> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  return serialized(async () => (await readItems(scope.queue, scope, queueGeneration)).length);
}

/** A visible, non-uploadable indication for an upgrade that found old global
 * queue bytes. This lets Settings tell the user the bytes were preserved
 * without ever assigning them to the wrong account/server. */
export async function hasLegacyQueueRecovery(): Promise<boolean> {
  await migrateUnscopedLegacyData();
  return (await AsyncStorage.getItem(LEGACY_RECOVERY_KEY)) !== null;
}
