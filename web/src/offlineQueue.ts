/**
 * Ciphertext-only offline queue — ported from mobile's offlineQueue.ts
 * (WEB_PLAN P4.4). Every queue, rejected-store, and corruption quarantine
 * is physically partitioned by BOTH API origin and account id; scope is a
 * storage mechanism, not a convention. Storage runs over the kvstore seam
 * (IndexedDB with an in-memory degradation); uploads run over this app's
 * single fixed origin, so the mobile client's origin-switch pinning
 * collapses to a scope equality check (the origin cannot move — but the
 * check stays, because defense in depth is cheap here).
 *
 * Differences from the mobile original, all deliberate:
 *  - no legacy-key migration (this is a v1 app; no pre-v2 keys exist),
 *  - no OriginPinnedError surface (there is no user-configurable server
 *    URL to move under a flush),
 *  - Buffer.byteLength → TextEncoder length, Buffer base64url → manual.
 */
import { ApiError, api, sessionUserId } from "./api/client";
import { currentOrigin, withLock } from "./platform";
import { kv } from "./kvstore";

const STORAGE_PREFIX = "mindpattern/queue.v1";
export const MAX_QUEUE_LENGTH = 200;
/** Serialized byte ceiling for one scope's queue value (mobile M-13): the
 *  count cap alone let a handful of max-size entries wedge storage. */
export const MAX_QUEUE_BYTES = 1_000_000;

const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 30 * 60_000;
const SERVER_ADVISORY_MAX_MS = 60 * 60_000;
/** Floor for a server Retry-After advisory (audit 2026-09-25): `Retry-After:
 *  0` is valid HTTP, but a hostile or looping server must not be able to
 *  turn it into a zero-pause in-process re-POST storm — the drain loop
 *  would pick the same item again immediately. One second of honest pause
 *  bounds the loop; anything the server genuinely wanted "now" still gets
 *  effectively-now. */
const SERVER_ADVISORY_MIN_MS = 1_000;
/** After a 401 mid-flush the items stay QUEUED (not parked in the rejected
 *  store) with this long notBefore — a dead session cannot be hammered
 *  item-by-item, and the next healthy flush after re-auth recovers it. */
const SESSION_EXPIRED_RETRY_MS = 15 * 60_000;

/** A process-wide generation fence makes sign-out beat every in-flight
 *  storage commit without holding a mutex across network I/O. */
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
  constructor(detail = `${MAX_QUEUE_LENGTH} entries`) {
    super(`offline queue is full (${detail}) — sync before writing more`);
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
  // Storage keys are observable metadata, so avoid a readable username or
  // host in them. An identifier, not cryptographic secrecy; the ciphertext
  // stays encrypted independently. The NUL separator defends against
  // (origin, userId) pairs that concatenate to the same string.
  const bytes = new TextEncoder().encode(`${origin}\u0000${userId}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function scopeFor(userId: string): Promise<QueueScope> {
  if (!userId) throw new Error("cannot access an offline queue without an account id");
  const origin = currentOrigin();
  const id = scopeId(origin, userId);
  return {
    origin,
    userId,
    queue: `${STORAGE_PREFIX}.items.${id}`,
    rejected: `${STORAGE_PREFIX}.rejected.${id}`,
    quarantine: `${STORAGE_PREFIX}.quarantine.${id}`,
  };
}

async function resolveUserId(userId?: string): Promise<string> {
  if (userId) return userId;
  const current = sessionUserId();
  if (!current) throw new Error("cannot access an offline queue without an account id");
  return current;
}

function wipedSince(generation: number): boolean {
  return queueGeneration !== generation;
}

function normalizeEntry(raw: unknown): QueuedEntry | null {
  if (typeof raw !== "object" || raw === null) return null;
  const item = raw as Record<string, unknown>;
  if (
    typeof item.userId !== "string"
    || typeof item.clientEntryId !== "string"
    || typeof item.blobB64 !== "string"
    || typeof item.entryDate !== "string"
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

/** parseItems, but the raw serialization of every slot that failed
 * normalization is kept too — readItems quarantines those verbatim instead
 * of silently dropping ciphertext (audit 2026-09-25: custody is
 * quarantine-first everywhere else in this module). */
function parseItemsWithMalformed(raw: string): { items: QueuedEntry[]; malformedRaw: string[] } | null {
  const parsed: unknown = JSON.parse(raw);
  const slots = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" && parsed !== null && (parsed as { v?: unknown }).v === 1
      ? (parsed as { items?: unknown }).items
      : null;
  if (!Array.isArray(slots)) return null;
  const items: QueuedEntry[] = [];
  const malformedRaw: string[] = [];
  for (const slot of slots) {
    const normalized = normalizeEntry(slot);
    if (normalized === null) malformedRaw.push(JSON.stringify(slot));
    else items.push(normalized);
  }
  return { items, malformedRaw };
}

function serializeItems(items: QueuedEntry[]): string {
  return JSON.stringify({ v: 1, items });
}

function serializedBytes(items: QueuedEntry[]): number {
  return new TextEncoder().encode(serializeItems(items)).length;
}

/** Quarantine keeps at most this many raw records (audit 2026-09-25): it is
 *  an evidence drawer for inspection, not a parallel queue — a hostile or
 *  corrupt store must not be able to grow it without bound. When full, the
 *  NEWEST records win (they are the ones a human will inspect first); the
 *  oldest are dropped. */
const QUARANTINE_MAX_RECORDS = 50;

async function appendQuarantine(scope: QueueScope, raw: string, generation: number): Promise<void> {
  if (wipedSince(generation)) return;
  const previous = await kv.getItem(scope.quarantine);
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
  while (records.length > QUARANTINE_MAX_RECORDS) records.shift();
  await kv.setItem(scope.quarantine, JSON.stringify({ v: 1, records }));
}

async function readItems(key: string, scope: QueueScope, generation: number): Promise<QueuedEntry[]> {
  let raw: string | null = null;
  try {
    raw = await kv.getItem(key);
    if (!raw) return [];
    const parsed = parseItemsWithMalformed(raw);
    if (parsed === null) {
      // A parseable but unrecognized shape gets the SAME custody as
      // unparseable bytes: quarantine it, then clear the key — leaving it
      // in place would only delay the loss to the next overwrite.
      await appendQuarantine(scope, raw, generation);
      if (!wipedSince(generation)) await kv.removeItem(key);
      return [];
    }
    if (parsed.malformedRaw.length > 0) {
      // A well-formed envelope with corrupt member records: those records
      // are ciphertext this account may still own — quarantine them
      // verbatim rather than dropping them on the floor.
      for (const slot of parsed.malformedRaw) {
        await appendQuarantine(scope, slot, generation);
      }
      if (!wipedSince(generation)) await writeItems(key, parsed.items);
    }
    const own = parsed.items.filter((item) => item.userId === scope.userId);
    const foreign = parsed.items.filter((item) => item.userId !== scope.userId);
    if (foreign.length > 0) {
      // A well-formed record carrying a FOREIGN userId inside this scope
      // key must not be silently dropped by the next rewrite — quarantine
      // it verbatim and persist the scope-owned remainder.
      for (const item of foreign) {
        await appendQuarantine(scope, serializeItems([item]), generation);
      }
      if (!wipedSince(generation)) await writeItems(key, own);
    }
    return own;
  } catch {
    await appendQuarantine(scope, raw ?? JSON.stringify({ v: 1, unreadable: true, key }), generation);
    if (!wipedSince(generation)) await kv.removeItem(key);
    return [];
  }
}

async function writeItems(key: string, items: QueuedEntry[]): Promise<void> {
  if (items.length === 0) {
    await kv.removeItem(key);
  } else {
    await kv.setItem(key, serializeItems(items));
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
  const scope = await scopeFor(await resolveUserId(userId));
  return (await kv.getItem(scope.quarantine)) !== null;
}

export async function rejectedEntries(userId?: string): Promise<QueuedEntry[]> {
  const scope = await scopeFor(await resolveUserId(userId));
  return rejectedFor(scope);
}

export async function rejectedEntryCount(userId?: string): Promise<number> {
  return (await rejectedEntries(userId)).length;
}

export async function enqueue(item: QueuedEntry): Promise<void> {
  const scope = await scopeFor(item.userId);
  return serialized(async () => {
    const generation = queueGeneration;
    const queue = await readItems(scope.queue, scope, generation);
    if (wipedSince(generation)) throw new QueueAbandonedError();
    if (queue.length >= MAX_QUEUE_LENGTH) throw new QueueFullError();
    // The client_entry_id IS the dedupe key of the whole sync path (server
    // idempotency): enqueueing the same id twice — a caller retry after a
    // mid-commit failure, or storage tampering — must not fork it.
    if (queue.some((entry) => entry.clientEntryId === item.clientEntryId)) return;
    // Scope owns the account id. Normalize it from the caller so a tampered
    // record cannot poison another account's queue key.
    const candidate = [...queue, { ...item, userId: scope.userId }];
    if (serializedBytes(candidate) > MAX_QUEUE_BYTES) throw new QueueFullError("over 1 MB of pending entries");
    if (wipedSince(generation)) throw new QueueAbandonedError();
    await writeItems(scope.queue, candidate);
    // Write-after-wipe rollback (audit 2026-09-25): a clearQueue that won
    // the race between the last fence check and this commit would find its
    // wipe undone. The storage mutex is still held, so the content below is
    // exactly what this enqueue wrote — remove it and fail honestly. (A
    // NEXT session's enqueue chains on the mutex after this callback and
    // cannot interleave.)
    if (wipedSince(generation)) {
      await kv.removeItem(scope.queue);
      throw new QueueAbandonedError();
    }
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

/** Future-dated entries are the client clock's error, not the entry's:
 *  exported for direct unit tests (the classifier previously had none —
 *  audit 2026-09-25). */
export function isFutureDateRejection(error: ApiError): boolean {
  return (error.code === undefined || error.code === "validation_error") && /future/i.test(error.message);
}

function classifyError(error: unknown): FlushOutcome {
  if (!(error instanceof ApiError)) return { kind: "retry", stop: true };
  if (error.status === 401) return { kind: "session-expired" };
  if (error.status === 429) return { kind: "retry", retryAfterMs: error.retryAfterMs, stop: true };
  if (error.status === 422 && isFutureDateRejection(error)) return { kind: "retry", stop: false };
  if (error.status === 413) return { kind: "reject-and-stop" };
  if (error.status >= 400 && error.status < 500) return { kind: "reject" };
  // 5xx (and status 0): pass any server advisory through; status 0 (local
  // refusal/network) never carries one and stops (no retry storm against a
  // dead network stack).
  return { kind: "retry", retryAfterMs: error.retryAfterMs, stop: error.status === 0 };
}

/** A 409 on a queued upload means "the server already has this entry" ONLY
 *  if the server can PROVE it (mobile audit M-5): every 409 is verified
 *  with the single-entry GET — 200 ⇒ genuine duplicate (safe discard),
 *  404 ⇒ the 409 lied (park in the rejected store), anything else ⇒ retry
 *  later with the item still queued. */
async function verifyDuplicateOutcome(clientEntryId: string): Promise<FlushOutcome> {
  try {
    await api.getEntry(clientEntryId);
    return { kind: "duplicate" };
  } catch (verifyError) {
    if (verifyError instanceof ApiError && verifyError.status === 404) {
      return { kind: "reject" };
    }
    if (verifyError instanceof ApiError && verifyError.status === 401) {
      return { kind: "session-expired" };
    }
    return { kind: "retry", stop: false };
  }
}

/** Upload due items for exactly one origin/account scope. */
export async function flushQueue(currentUserId: string): Promise<number> {
  const scope = await scopeFor(currentUserId);
  let sent = 0;
  for (;;) {
    if (scope.origin !== currentOrigin()) return sent;
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
      // A queue upload is always the first generation of its id.
      await api.createEntry(item.clientEntryId, item.blobB64, item.entryDate, 1);
      outcome = { kind: "sent" };
    } catch (error) {
      outcome =
        error instanceof ApiError && error.status === 409
          ? await verifyDuplicateOutcome(item.clientEntryId)
          : classifyError(error);
    }

    if (outcome.kind === "session-expired") {
      // Keep EVERY item queued: the unattempted ones untouched, the
      // attempted one under a long notBefore so a dead session is not
      // hammered item-by-item.
      const preserved = await serialized(async () => {
        const queue = await readItems(scope.queue, scope, peek.generation);
        if (wipedSince(peek.generation)) return false;
        const index = queue.findIndex((entry) => entry.clientEntryId === item.clientEntryId);
        if (index >= 0) {
          queue[index] = {
            ...item,
            attempts: (item.attempts ?? 0) + 1,
            notBefore: Date.now() + SESSION_EXPIRED_RETRY_MS,
          };
          await writeItems(scope.queue, queue);
          if (wipedSince(peek.generation)) return false;
        }
        return true;
      });
      if (!preserved) return sent;
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
          const delay =
            outcome.retryAfterMs !== undefined
              ? Math.min(Math.max(outcome.retryAfterMs, SERVER_ADVISORY_MIN_MS), SERVER_ADVISORY_MAX_MS)
              : retryDelayMs(attempts);
          queue[index] = {
            ...item,
            attempts: attempts + 1,
            notBefore: Date.now() + delay,
          };
          await writeItems(scope.queue, queue);
          break;
        }
      }
      return true;
    });
    if (!committed) return sent;
    if (outcome.kind === "sent") sent += 1;
    if (outcome.kind === "reject-and-stop" || (outcome.kind === "retry" && outcome.stop)) return sent;
  }
}

/** Sign-out fences in-flight writes but keeps ciphertext for the correct
 *  account scope. Account deletion calls clearQueue instead. */
export function abortInFlightFlush(): void {
  queueGeneration += 1;
}

export async function requeueRejected(userId?: string): Promise<number> {
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
      const { attempts: _attempts, notBefore: _notBefore, ...fresh } = item;
      const candidate = queue.concat(fresh);
      if (queue.length >= MAX_QUEUE_LENGTH || serializedBytes(candidate) > MAX_QUEUE_BYTES) {
        stillRejected.push(item);
        continue;
      }
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
  // Throttle only within a real, forward-looking window: a clock step
  // BACKWARDS (NTP correction, or a faked clock in tests) must not leave
  // the flusher throttled until the wall clock catches up to a stale
  // future timestamp (audit 2026-09-25).
  if (now >= lastReconnectFlushAt && now - lastReconnectFlushAt < RECONNECT_FLUSH_MIN_INTERVAL_MS) return;
  lastReconnectFlushAt = now;
  const userId = sessionUserId();
  if (!userId || (await queueLength(userId)) === 0) return;
  await withLock("queue-flush", () => flushQueue(userId)).catch(() => {});
}

/** Delete only this account's data for this origin. */
export async function clearQueue(userId?: string): Promise<void> {
  const scope = await scopeFor(await resolveUserId(userId));
  queueGeneration += 1;
  await kv.multiRemove([scope.queue, scope.rejected, scope.quarantine]);
}

export async function queueLength(userId?: string): Promise<number> {
  const scope = await scopeFor(await resolveUserId(userId));
  return serialized(async () => (await readItems(scope.queue, scope, queueGeneration)).length);
}

