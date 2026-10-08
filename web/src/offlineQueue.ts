/**
 * Ciphertext-only journal queue with rejected-record and corruption stores.
 *
 * Each store is partitioned by API origin and account id. IndexedDB writes
 * must commit before acknowledgement; storage failures propagate. All queue
 * operations share the same Web Lock and in-tab serialization chain so
 * read-repair, enqueue, and upload cannot overwrite each other.
 */
import { ApiError, api, sessionAbortSignal, sessionUserId } from "./api/client";
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { currentOrigin, withLock } from "./platform";
import { kv,StorageCommitError,StorageReadError,type WritePermit } from "./kvstore";

/** The single Web Lock name for EVERY queue operation (audit 2026-09-26
 *  MEDIUM): the flush path already serialized drains cross-tab; the
 *  mutation paths (enqueue/requeue/clear) now take the SAME lock, so a
 *  read-modify-write in one signed-in tab can never interleave with a
 *  drain or another mutation in another tab — last-write-wins used to
 *  DROP a queued entry. Same name on purpose: a mutation that held a
 *  different lock could still interleave with a flush's read→commit
 *  window. */
const QUEUE_LOCK_NAME = "queue-flush";

const STORAGE_PREFIX = "mindpattern/queue.v1";
export const MAX_QUEUE_LENGTH = 200;
/** Serialized byte ceiling for one scope's queue value (mobile M-13): the
 *  count cap alone let a handful of max-size entries wedge storage. */
export const MAX_QUEUE_BYTES = 1_000_000;
export const MAX_REJECTED_LENGTH = 200;
export const MAX_REJECTED_BYTES = 1_000_000;
export const MAX_QUARANTINE_BYTES = 250_000;
const MAX_QUARANTINE_RECORD_BYTES = 32_000;

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
  evictions: string;
  permit: WritePermit;
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
    evictions: `${STORAGE_PREFIX}.evictions.${id}`,
    permit:await kv.captureWritePermit(userId),
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

export interface QueueEvictionSummary { rejected: number; quarantine: number }

async function recordEvictions(
  scope: QueueScope,
  kind: keyof QueueEvictionSummary,
  count: number,
  generation: number,
): Promise<void> {
  if (count <= 0 || wipedSince(generation)) return;
  let summary: QueueEvictionSummary = { rejected: 0, quarantine: 0 };
  try {
    const parsed = JSON.parse((await kv.getItem(scope.evictions)) ?? "null") as Partial<QueueEvictionSummary> | null;
    if (parsed) summary = {
      rejected: Number.isSafeInteger(parsed.rejected) && (parsed.rejected ?? 0) >= 0 ? parsed.rejected! : 0,
      quarantine: Number.isSafeInteger(parsed.quarantine) && (parsed.quarantine ?? 0) >= 0 ? parsed.quarantine! : 0,
    };
  } catch { /* replace corrupt metadata with the truthful new count */ }
  summary[kind] = Math.min(Number.MAX_SAFE_INTEGER, summary[kind] + count);
  if (!wipedSince(generation)) await kv.setItem(scope.evictions, JSON.stringify(summary), scope.permit);
}

function quarantineBytes(records: string[]): number {
  return new TextEncoder().encode(JSON.stringify({ v: 1, records })).length;
}

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
  const encoded = new TextEncoder().encode(raw);
  let bounded = raw;
  let dropped = 0;
  if (encoded.length > MAX_QUARANTINE_RECORD_BYTES) {
    bounded = JSON.stringify({
      v: 1,
      truncated: true,
      original_bytes: encoded.length,
      preview: new TextDecoder().decode(encoded.slice(0, MAX_QUARANTINE_RECORD_BYTES - 256)),
    });
    dropped += 1;
  }
  records.push(bounded);
  while (records.length > QUARANTINE_MAX_RECORDS || quarantineBytes(records) > MAX_QUARANTINE_BYTES) {
    records.shift();
    dropped += 1;
  }
  await kv.setItem(scope.quarantine, JSON.stringify({ v: 1, records }),scope.permit);
  await recordEvictions(scope, "quarantine", dropped, generation);
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
      if (!wipedSince(generation)) await kv.removeItem(key,scope.permit);
      return [];
    }
    if (parsed.malformedRaw.length > 0) {
      // A well-formed envelope with corrupt member records: those records
      // are ciphertext this account may still own — quarantine them
      // verbatim rather than dropping them on the floor.
      for (const slot of parsed.malformedRaw) {
        await appendQuarantine(scope, slot, generation);
      }
      if (!wipedSince(generation)) await writeItems(key, parsed.items,scope.permit);
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
      if (!wipedSince(generation)) await writeItems(key, own,scope.permit);
    }
    return own;
  } catch (cause) {
    // A failed device read is not evidence that the ciphertext is corrupt.
    // Retain the original slot for a retry; failed repair commits must also
    // propagate instead of being mistaken for malformed queue contents.
    if (cause instanceof StorageReadError || cause instanceof StorageCommitError) throw cause;
    await appendQuarantine(scope, raw ?? JSON.stringify({ v: 1, unreadable: true, key }), generation);
    if (!wipedSince(generation)) await kv.removeItem(key,scope.permit);
    return [];
  }
}

async function writeItems(key: string, items: QueuedEntry[],permit:WritePermit): Promise<void> {
  if (items.length === 0) {
    await kv.removeItem(key,permit);
  } else {
    await kv.setItem(key, serializeItems(items),permit);
  }
}

async function rejectedFor(scope: QueueScope, generation = queueGeneration): Promise<QueuedEntry[]> {
  const items = await readItems(scope.rejected, scope, generation);
  let dropped = 0;
  while (items.length > MAX_REJECTED_LENGTH || serializedBytes(items) > MAX_REJECTED_BYTES) {
    items.shift();
    dropped += 1;
  }
  if (dropped > 0 && !wipedSince(generation)) {
    await writeItems(scope.rejected, items, scope.permit);
    await recordEvictions(scope, "rejected", dropped, generation);
  }
  return items;
}

async function appendRejected(scope: QueueScope, items: QueuedEntry[], generation: number, stillCurrent: () => boolean): Promise<void> {
  if (items.length === 0 || !stillCurrent() || wipedSince(generation)) return;
  const existing = await rejectedFor(scope, generation);
  if (!stillCurrent() || wipedSince(generation)) return;
  const ids = new Set(existing.map((item) => item.clientEntryId));
  for (const item of items) {
    if (!ids.has(item.clientEntryId)) {
      existing.push(item);
      ids.add(item.clientEntryId);
    }
  }
  let dropped = 0;
  while (existing.length > MAX_REJECTED_LENGTH || serializedBytes(existing) > MAX_REJECTED_BYTES) {
    existing.shift();
    dropped += 1;
  }
  await recordEvictions(scope, "rejected", dropped, generation);
  if (stillCurrent() && !wipedSince(generation)) await writeItems(scope.rejected, existing,scope.permit);
}

export async function queueEvictionSummary(userId?: string): Promise<QueueEvictionSummary> {
  const scope = await scopeFor(await resolveUserId(userId));
  return withLock(QUEUE_LOCK_NAME, () => serialized(async () => {
    try {
      const parsed = JSON.parse((await kv.getItem(scope.evictions)) ?? "null") as Partial<QueueEvictionSummary> | null;
      return {
        rejected: Number.isSafeInteger(parsed?.rejected) && (parsed?.rejected ?? 0) >= 0 ? parsed!.rejected! : 0,
        quarantine: Number.isSafeInteger(parsed?.quarantine) && (parsed?.quarantine ?? 0) >= 0 ? parsed!.quarantine! : 0,
      };
    } catch {
      return { rejected: 0, quarantine: 0 };
    }
  }));
}

export async function quarantinedQueueExists(userId?: string): Promise<boolean> {
  const scope = await scopeFor(await resolveUserId(userId));
  return (await kv.getItem(scope.quarantine)) !== null;
}

/** independent audit 2026-09-27 (P2): the read APIs below self-heal —
 *  readItems quarantines corrupt shapes and REWRITES the key — so a bare
 *  unlocked read could interleave with a locked enqueue in another tab and
 *  drop it exactly like the mutation race did. Both now take the SAME
 *  queue-flush Web Lock as every mutation (never a different name: a
 *  differently-named lock could still interleave with a flush's
 *  read→commit window). */
export async function rejectedEntries(userId?: string): Promise<QueuedEntry[]> {
  const scope = await scopeFor(await resolveUserId(userId));
  return withLock(QUEUE_LOCK_NAME, () => serialized(() => rejectedFor(scope)));
}

export async function enqueue(item: QueuedEntry,producerPermit?:WritePermit): Promise<void> {
  const generation = queueGeneration; // capture before storage/lock awaits
  const scope = await scopeFor(item.userId);
  if(producerPermit){
    if(!producerPermit.keyBound || producerPermit.owner!==item.userId)throw new StorageCommitError("A queued entry requires its producer's account-key generation permit.");
    scope.permit=producerPermit;
  }else if(scope.permit.generation!==null)throw new StorageCommitError("An old queued entry cannot be inserted without its encryption generation permit; the ciphertext was retained by its caller.");
  // Cross-tab serialization FIRST (Web Lock), per-process serialization
  // second (the mutex): two signed-in tabs used to interleave their
  // read→write windows — the per-process mutex could not see the other
  // tab — and last-write-wins silently dropped a queued entry (audit
  // 2026-09-26 MEDIUM).
  return withLock(QUEUE_LOCK_NAME, () => serialized(async () => {
    if(wipedSince(generation))throw new QueueAbandonedError();
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
    await writeItems(scope.queue, candidate,scope.permit);
    // Post-commit fence check (audit 2026-09-25 → corrected 2026-09-28,
    // H-3): the generation can only have moved here if abortInFlightFlush()
    // fired during the write — a sign-out/idle/expiry lockDown. Those
    // deliberately KEEP ciphertext ("sign-out keeps ciphertext for the
    // account scope"), so the honest response is to fail THIS enqueue's
    // caller (their session ended) while leaving storage exactly as
    // committed: every parked entry plus this one. The old "rollback"
    // deleted the WHOLE queue key — it was written for a clearQueue race
    // that the shared queue-flush Web Lock has since made unreachable
    // (clearQueue bumps the generation inside the same lock this enqueue
    // holds), which left the destructive path triggering ONLY on the
    // must-not-wipe one.
    if (wipedSince(generation)) throw new QueueAbandonedError();
  }));
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

/** Upload due items for exactly one origin/account scope.
 *
 *  2026-09-26 audit LOW: the drain used to re-read and re-parse the whole
 *  queue for EVERY item — O(n²) in queued entries. It now reads the batch
 *  ONCE, drains it in memory (network I/O outside the storage mutex, so an
 *  enqueue in this tab never blocks on a slow server), and commits every
 *  item's outcome with ONE write-back — still under the per-process mutex
 *  + generation fence, and cross-tab under the queue-flush Web Lock that
 *  flushQueueOnReconnect holds around this call. */
export async function flushQueue(currentUserId: string): Promise<number> {
  // Storage scope identifies the ciphertext owner, not the bearer that a
  // later API call will capture. Retain the starting session across every
  // queue/read/network await, including an explicit old-owner callback.
  const signal = sessionAbortSignal();
  const startingGeneration = queueGeneration;
  const ownsSession = () => !!signal && !signal.aborted && sessionUserId() === currentUserId && !wipedSince(startingGeneration);
  if (!ownsSession()) return 0;
  const scope = await scopeFor(currentUserId);
  if (!ownsSession()) return 0;
  const batch = await serialized(async () => {
    const generation = queueGeneration;
    return { generation, items: await readItems(scope.queue, scope, generation) };
  });
  const { generation } = batch;
  let sent = 0;
  if (!ownsSession() || batch.items.length === 0) return sent;

  const removed = new Set<string>(); // sent / verified duplicate / rejected
  const requeued = new Map<string, QueuedEntry>(); // retry / session-expired
  const rejects: QueuedEntry[] = [];
  let sessionExpired = false;
  let stop = false;

  for (const item of batch.items) {
    if (stop || !ownsSession() || scope.origin !== currentOrigin()) break;
    // In order, skipping items still inside a backoff/advisory window —
    // exactly the "first due item" the per-item drain used to pick.
    if (item.notBefore !== undefined && item.notBefore > Date.now()) continue;
    let outcome: FlushOutcome;
    try {
      // A queue upload is always the first generation of its id.
      await api.createEntry(item.clientEntryId, item.blobB64, item.entryDate, 1);
      outcome = { kind: "sent" };
    } catch (error) {
      if (!ownsSession()) return sent;
      outcome =
        error instanceof ApiError && error.status === 409
          ? await verifyDuplicateOutcome(item.clientEntryId)
          : classifyError(error);
    }
    if (!ownsSession()) return sent;
    switch (outcome.kind) {
      case "sent":
        removed.add(item.clientEntryId);
        sent += 1;
        break;
      case "duplicate":
        removed.add(item.clientEntryId);
        break;
      case "reject":
      case "reject-and-stop":
        removed.add(item.clientEntryId);
        rejects.push(item);
        stop = outcome.kind === "reject-and-stop";
        break;
      case "session-expired":
        // Keep EVERY item queued: the unattempted ones untouched, the
        // attempted one under a long notBefore so a dead session is not
        // hammered item-by-item.
        requeued.set(item.clientEntryId, {
          ...item,
          attempts: (item.attempts ?? 0) + 1,
          notBefore: Date.now() + SESSION_EXPIRED_RETRY_MS,
        });
        sessionExpired = true;
        stop = true;
        break;
      case "retry": {
        const attempts = item.attempts ?? 0;
        const delay =
          outcome.retryAfterMs !== undefined
            ? Math.min(Math.max(outcome.retryAfterMs, SERVER_ADVISORY_MIN_MS), SERVER_ADVISORY_MAX_MS)
            : retryDelayMs(attempts);
        requeued.set(item.clientEntryId, {
          ...item,
          attempts: attempts + 1,
          notBefore: Date.now() + delay,
        });
        stop = outcome.stop;
        break;
      }
    }
  }

  if (removed.size > 0 || requeued.size > 0 || rejects.length > 0) {
    const committed = await serialized(async () => {
      if (!ownsSession() || wipedSince(generation)) return false;
      // Re-read under the mutex and apply by id: entries enqueued in THIS
      // process while the drain was awaiting the network survive untouched
      // (and an item another flush already resolved is simply not found).
      const current = await readItems(scope.queue, scope, generation);
      if (!ownsSession() || wipedSince(generation)) return false;
      if (rejects.length > 0) await appendRejected(scope, rejects, generation, ownsSession);
      if (!ownsSession() || wipedSince(generation)) return false;
      await writeItems(
        scope.queue,
        current
          .filter((entry) => !removed.has(entry.clientEntryId))
          .map((entry) => requeued.get(entry.clientEntryId) ?? entry),
        scope.permit,
      );
      return true;
    });
    if (!committed) return sent;
  }
  if (sessionExpired) throw new SessionExpiredError();
  return sent;
}

/** Sign-out fences in-flight writes but keeps ciphertext for the correct
 *  account scope. Account deletion calls clearQueue instead. */
export function abortInFlightFlush(): void {
  queueGeneration += 1;
}

export async function requeueRejected(userId?: string): Promise<number> {
  const scope = await scopeFor(await resolveUserId(userId));
  // The same cross-tab Web Lock discipline as enqueue (audit 2026-09-26):
  // a rejected-store drain is a read-modify-write over the same keys.
  return withLock(QUEUE_LOCK_NAME, () => serialized(async () => {
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
    await writeItems(scope.queue, queue,scope.permit);
    if (wipedSince(generation)) return 0;
    await writeItems(scope.rejected, stillRejected,scope.permit);
    return moved;
  }));
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
  await withLock(QUEUE_LOCK_NAME, () => flushQueue(userId)).catch(() => {});
}

/** Delete only this account's data for this origin. Cross-tab serialized
 *  with every other queue mutation (audit 2026-09-26). */
export async function clearQueue(userId?: string): Promise<void> {
  const scope = await scopeFor(await resolveUserId(userId));
  await withLock(QUEUE_LOCK_NAME, async () => {
    queueGeneration += 1;
    for(const key of [scope.queue,scope.rejected,scope.quarantine,scope.evictions])await kv.removeItem(key,scope.permit);
  });
}

export async function queueLength(userId?: string): Promise<number> {
  const scope = await scopeFor(await resolveUserId(userId));
  return withLock(QUEUE_LOCK_NAME, () =>
    serialized(async () => (await readItems(scope.queue, scope, queueGeneration)).length));
}

/** independent audit 2026-09-27 (P1): a v1 password rotation rekeys the
 *  SERVER corpus but never touched THIS queue — blobs sealed under the old
 *  data key uploaded after the rekey and became permanently undecryptable
 *  ("N entries hidden"). The two halves below close it: a best-effort
 *  drain BEFORE the rotation's server steps (the user is necessarily
 *  online to rotate), and a rewrap of anything still held locally AFTER
 *  the credential rotation. */

/** Best-effort upload of every due queued item for one account, under the
 *  same cross-tab Web Lock a reconnect flush takes. Returns the number of
 *  entries still held locally after the attempt — 0 means nothing a
 *  rotation can orphan. A drain that errors outright reads as -1 (the
 *  caller treats every non-zero answer as "do not rotate"). */
export async function drainPendingQueueForRotation(userId: string): Promise<number> {
  // The drain holds the lock; the length re-check must run OUTSIDE it —
  // the Web Locks API is not reentrant and queueLength takes this lock.
  await withLock(QUEUE_LOCK_NAME, () => flushQueue(userId)).catch(() => undefined);
  return queueLength(userId);
}

/** Open one queued blob under the rotation's OLD key and re-seal it under
 *  the new key with the SAME AAD it was sealed with (queue uploads are
 *  always the first generation of their id, so the version-bound AAD is
 *  tried first and the legacy three-part binding is the fallback —
 *  decryptEntry's rule). Null when the blob cannot be opened at all. */
async function rewrapEntryBlob(item: QueuedEntry, oldKey: Bytes, newKey: Bytes): Promise<string | null> {
  const blob = fromBase64(item.blobB64);
  const bindings = [
    buildAad("entry", item.userId, item.clientEntryId, "1"),
    buildAad("entry", item.userId, item.clientEntryId),
  ];
  try {
    for (const aad of bindings) {
      let plaintext: Bytes | null = null;
      try {
        plaintext = await decrypt(oldKey, blob, aad);
        return toBase64(await encrypt(newKey, plaintext, aad));
      } catch {
        // Wrong binding for this blob: fall through to the legacy one.
      } finally {
        zeroize(plaintext);
      }
    }
    return null;
  } finally {
    zeroize(...bindings);
  }
}

/** Re-seal every locally held blob — queue items AND rejected entries —
 *  from the rotation's old data key to the new one, under the queue's Web
 *  Lock so the read-modify-write cannot interleave with an enqueue or
 *  drain in another tab. A blob that fails to rewrap is left EXACTLY
 *  as-is (a rejected item then fails visibly on requeue); nothing here
 *  may block or unwind the completed rotation. */
export async function rewrapQueue(owner: string, oldKey: Bytes, newKey: Bytes): Promise<void> {
  const scope = await scopeFor(owner);
  scope.permit=await kv.captureWritePermit(owner,newKey);
  await withLock(QUEUE_LOCK_NAME, () => serialized(async () => {
    const generation = queueGeneration;
    const [queue, rejected] = await Promise.all([
      readItems(scope.queue, scope, generation),
      readItems(scope.rejected, scope, generation),
    ]);
    const rewrap = async (items: QueuedEntry[]): Promise<QueuedEntry[]> => {
      const out: QueuedEntry[] = [];
      for (const item of items) {
        const blobB64 = await rewrapEntryBlob(item, oldKey, newKey);
        out.push(blobB64 === null ? item : { ...item, blobB64 });
      }
      return out;
    };
    const items = await rewrap(queue);
    const rejects = await rewrap(rejected);
    if (wipedSince(generation)) return;
    await writeItems(scope.queue, items,scope.permit);
    if (wipedSince(generation)) return;
    await writeItems(scope.rejected, rejects,scope.permit);
  }));
}
