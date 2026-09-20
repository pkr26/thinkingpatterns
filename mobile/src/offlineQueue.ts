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
import { api, ApiError, canonicalOrigin, getBaseUrl, OriginPinnedError } from "./api/client";

const LEGACY_QUEUE_KEY = "@mindpattern/queue";
const LEGACY_REJECTED_KEY = "@mindpattern/queue_rejected";
const LEGACY_QUARANTINE_KEY = "@mindpattern/queue_quarantine";
/** Opaque preservation for old unscoped data. We never guess which origin it
 * belongs to and therefore never upload it to a potentially different one. */
const LEGACY_RECOVERY_KEY = "@mindpattern/queue.legacy-unscoped.v1";
const STORAGE_PREFIX = "@mindpattern/queue.v2";
export const MAX_QUEUE_LENGTH = 200;
/** M-13: serialized byte ceiling for one scope's queue value. Android's
 *  AsyncStorage cursor window tops out near 2 MB PER ROW — ~15 max-size
 *  entries (100k chars each) already exceed it, and once a row is oversize
 *  getItem throws on every read, wedging the whole scope (the count cap
 *  alone counts rows, never bytes). 1 MB keeps the row comfortably under
 *  the platform limit while still holding hundreds of typical entries. */
export const MAX_QUEUE_BYTES = 1_000_000;

const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 30 * 60_000;
/** L-51: the client's parseRetryAfter already clamps a server advisory to
 *  one hour. This local clamp mirrors it as defense-in-depth for an
 *  ApiError constructed elsewhere — advisories within the upstream ceiling
 *  are honored in full; only values beyond it are cut. */
const SERVER_ADVISORY_MAX_MS = 60 * 60_000;
/** M-14: after a 401 mid-flush the items stay QUEUED (not parked in the
 *  rejected store) with this long notBefore on the attempted row — long
 *  enough that a dead session cannot be hammered item-by-item from every
 *  foreground, short enough that the next healthy flush after re-auth
 *  recovers it automatically. */
const SESSION_EXPIRED_RETRY_MS = 15 * 60_000;

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
  /** The pinned count-cap message stays byte-identical; the byte cap (M-13)
   *  names its own reason through the same error class so every existing
   *  caller branch (EntryScreen's queueFull path) keeps working. */
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
  // AsyncStorage keys are observable metadata, so avoid putting a readable
  // username or host in them. This is an identifier, not cryptographic
  // secrecy; ciphertext remains encrypted independently.
  // Stryker disable next-line StringLiteral: the NUL separator is defense-in-depth against (origin,userId) pairs that CONCATENATE to the same string; no real origin contains NUL, so every mutant only swaps one unambiguous separator for another and stays collision-free for all testable inputs
  return Buffer.from(`${origin}\u0000${userId}`, "utf8").toString("base64url");
}

/** Localhost, 127.0.0.1 and [::1] address the same loopback interface.
 * Unify their spelling for queue scoping only (the saved server URL itself
 * is untouched): switching between aliases must not strand pending
 * ciphertext behind a different storage key with no recovery surface.
 * The helper is SHARED with client.ts's origin pin (H-1) — the queue passes
 * the canonical form as `expectedOrigin`, so the send-point comparison must
 * canonicalize identically or every pinned upload would refuse to leave the
 * device under a differently-spelled stored base URL. */
// (canonicalOrigin now lives in ./api/client — one implementation, both call sites.)

async function currentOrigin(): Promise<string> {
  // `getBaseUrl` is always present in production. The fallback makes this
  // module usable by old isolated test mocks while retaining a safe concrete
  // local-only origin there.
  // Stryker disable next-line ConditionalExpression,StringLiteral: the fallback arm exists only for test mocks that omit getBaseUrl entirely; the production suite always provides it, so mutants of the dead arm are unobservable by construction
  const base = typeof getBaseUrl === "function" ? await getBaseUrl() : "http://localhost:8000";
  return canonicalOrigin(new URL(base).origin);
}

async function scopeFor(userId: string): Promise<QueueScope> {
  if (!userId) throw new Error("cannot access an offline queue without an account id");
  const origin = await currentOrigin();
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
  // Stryker disable next-line ConditionalExpression: while a migration is in flight every caller MUST share it; the mutation (concurrent re-run) is only distinguishable with deliberate interleaving that the public API cannot produce
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

/** M-13: the queue is bounded by SERIALIZED BYTES, not only row count —
 *  this is the measurement the enqueue/requeue caps gate on. */
function serializedBytes(items: QueuedEntry[]): number {
  return Buffer.byteLength(serializeItems(items), "utf8");
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
  // M-13: the getItem lives INSIDE the try. Android refuses to hand an
  // oversize AsyncStorage row through the cursor window — a throw escaping
  // readItems would reject every enqueue/flushQueue/queueLength call on
  // this scope forever (the "wedged scope" failure mode). The bytes are
  // unreadable through this API, so the catch records an honest marker in
  // quarantine and clears the key instead of wedging the scope.
  let raw: string | null = null;
  try {
    raw = await AsyncStorage.getItem(key);
    if (!raw) return [];
    const parsed = parseItems(raw);
    if (parsed === null) {
      // A parseable but unrecognized shape gets the SAME custody as
      // unparseable bytes: quarantine it. Returning [] while leaving the
      // bytes in place would only delay the loss — the next write to this
      // key overwrites them, silently destroying the retained record the
      // old comment promised to keep for manual repair.
      await appendQuarantine(scope, raw, generation);
      if (!wipedSince(generation)) await AsyncStorage.removeItem(key);
      return [];
    }
    const own = parsed.filter((item) => item.userId === scope.userId);
    const foreign = parsed.filter((item) => item.userId !== scope.userId);
    if (foreign.length > 0) {
      // L-52: a well-formed record carrying a FOREIGN userId inside this
      // scope key (tampering or a restored backup) must not be silently
      // dropped by the next rewrite — quarantine it verbatim, exactly like
      // corrupt bytes, and persist the scope-owned remainder. This scope
      // can never upload the foreign record; preservation, not delivery,
      // is the point.
      for (const item of foreign) {
        await appendQuarantine(scope, serializeItems([item]), generation);
      }
      if (!wipedSince(generation)) await writeItems(key, own);
    }
    return own;
  } catch {
    await appendQuarantine(
      scope,
      raw ?? JSON.stringify({ v: 1, unreadable: true, key }),
      generation,
    );
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
  // Stryker disable next-line ConditionalExpression: the empty-list arm is a cheap guard for future callers; every current caller passes a non-empty list, so flipping it changes nothing observable
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
    const candidate = [...queue, { ...item, userId: scope.userId }];
    // M-13: the count cap alone let ~15 max-size entries grow the single
    // AsyncStorage value past Android's per-row cursor-window limit, after
    // which getItem throws and the scope is wedged. Bound the SERIALIZED
    // bytes of the value too.
    if (serializedBytes(candidate) > MAX_QUEUE_BYTES) throw new QueueFullError("over 1 MB of pending entries");
    if (wipedSince(generation)) throw new QueueAbandonedError();
    await writeItems(scope.queue, candidate);
  });
}

function retryDelayMs(attempts: number): number {
  // Stryker disable next-line ArithmeticOperator: the inner Math.min(attempts, 10) cap is redundant with the outer RETRY_MAX_MS clamp for every attempts value (2**10*30s and 2**1000 both clamp to RETRY_MAX_MS); it exists only to avoid computing 2**huge
  const exponential = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(attempts, 10));
  // Stryker disable next-line ArithmeticOperator: floor vs ceil differs by at most 1ms of backoff jitter — indistinguishable from Date.now() scheduling granularity by any assertion that is not inherently flaky
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
  // 5xx (and status 0): pass any server advisory through here too —
  // L-54: client.request parses Retry-After on 503 maintenance responses
  // as well as 429s, and dropping it on this branch made a 503 advisory
  // silently fall back to the 30 s+ local exponential backoff. Status 0
  // (local refusal/network) never carries one, so it is unaffected.
  return { kind: "retry", retryAfterMs: error.retryAfterMs, stop: error.status === 0 };
}

/** Upload due items for exactly one origin/account scope. */
export async function flushQueue(currentUserId: string): Promise<number> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(currentUserId);
  let sent = 0;
  for (;;) {
    // The queue's scope was captured at flush start, but the send path
    // resolves the CURRENT server selection and bearer token. If the user
    // switched origins while this flush was in flight, stop here: the items
    // stay queued (intact) for their own origin and can never be uploaded
    // under a different origin's credentials. The request-level pin below
    // closes the same window between this check and the send itself.
    if (scope.origin !== (await currentOrigin())) return sent;
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
      await api.createQueuedEntry(item.clientEntryId, item.blobB64, item.entryDate, scope.origin);
      outcome = { kind: "sent" };
    } catch (error) {
      // Refused locally: the origin moved under us between the check above
      // and the send. Nothing reached the network; leave the queue untouched.
      if (error instanceof OriginPinnedError) return sent;
      outcome = classifyError(error);
    }

    if (outcome.kind === "session-expired") {
      // M-14: a 401 mid-flush (natural token expiry) must NOT park
      // unattempted entries in the rejected store — after re-login
      // flushQueueOnReconnect would see an empty queue and the only path
      // back was the manual Settings "Recover" button. Keep EVERY item
      // queued: the unattempted ones untouched (they retry on the first
      // healthy flush after re-auth) and the attempted one under a long
      // notBefore so a dead session is not hammered item-by-item.
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
      if (!preserved) return sent; // local sign-out/origin change won
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
          // L-51: a server advisory (429/503 Retry-After, already clamped to
          // one hour in parseRetryAfter) is honored IN FULL — re-clamping it
          // to RETRY_MAX_MS guaranteed one doomed request per item per pass
          // for every advisory above 30 minutes. Only the LOCAL exponential
          // backoff is bounded by RETRY_MAX_MS; the advisory is bounded by
          // the same upstream one-hour ceiling.
          const delay =
            outcome.retryAfterMs !== undefined
              ? Math.min(outcome.retryAfterMs, SERVER_ADVISORY_MAX_MS)
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
    // Count only uploads whose queue removal also committed. A fence-
    // abandoned commit leaves the entry queued, so reporting it as sent
    // would overstate progress to the badge/UI.
    if (outcome.kind === "sent") sent += 1;
    if (outcome.kind === "reject-and-stop" || (outcome.kind === "retry" && outcome.stop)) return sent;
  }
}

/** Sign-out/origin switch fences in-flight writes but keeps ciphertext for
 * the correct account scope. Account deletion calls clearQueue instead. */
export function abortInFlightFlush(): void {
  // Stryker disable next-line AssignmentOperator: the fence only needs generation CHANGES, never their direction; +=1 vs -=1 is indistinguishable through wipedSince's strict inequality
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
    // Stryker disable next-line ConditionalExpression: with an empty rejected list the loop below is a no-op that returns the same 0; the short-circuit is a cheap guard, not observable behavior
    if (wipedSince(generation) || rejected.length === 0) return 0;
    const ids = new Set(queue.map((item) => item.clientEntryId));
    const stillRejected: QueuedEntry[] = [];
    let moved = 0;
    for (const item of rejected) {
      if (ids.has(item.clientEntryId)) continue;
      const { attempts: _attempts, notBefore: _notBefore, ...fresh } = item;
      // M-13: recovery respects BOTH caps — count and serialized bytes —
      // so re-filling the queue can never wedge the scope either.
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
  if (now - lastReconnectFlushAt < RECONNECT_FLUSH_MIN_INTERVAL_MS) return;
  lastReconnectFlushAt = now;
  const userId = await api.getUserId();
  if (!userId || (await queueLength(userId)) === 0) return;
  await flushQueue(userId).catch(() => {});
}

/** Delete only this account's data for the currently selected origin.
 * Account deletion also drops the preserved legacy-unscoped bytes: the
 * deleting account is the device owner in every realistic upgrade path,
 * and right-to-erasure must not leave their pre-upgrade ciphertext on the
 * device indefinitely. */
export async function clearQueue(userId?: string): Promise<void> {
  await migrateUnscopedLegacyData();
  const scope = await scopeFor(await resolveUserId(userId));
  // Stryker disable next-line AssignmentOperator: same rationale as abortInFlightFlush — direction of the generation change is unobservable through the inequality fence
  queueGeneration += 1;
  await AsyncStorage.multiRemove([scope.queue, scope.rejected, scope.quarantine, LEGACY_RECOVERY_KEY]);
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
