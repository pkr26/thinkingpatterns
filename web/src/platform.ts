/**
 * Browser-platform seam. Views and services never touch `window`,
 * `document`, `navigator` or `URL` directly: under the node test runtime
 * there is no DOM, and a private-mode browser can throw on storage or
 * downloads — every capability degrades to an inert default instead of
 * crashing the app (WEB_PLAN P1.3, R-7).
 */

/** Randomness goes through the seam so tests can observe (and a future
 *  non-browser host can override) it. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function currentOrigin(): string {
  try {
    return typeof window !== "undefined" ? window.location.origin : "";
  } catch {
    return "";
  }
}

export const localStore = {
  get(key: string): string | null {
    try {
      return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  set(key: string, value: string): void {
    try {
      if (typeof window !== "undefined") window.localStorage.setItem(key, value);
    } catch {
      // Private mode / storage disabled: non-content preferences are
      // cosmetic (WEB_PLAN D-4 — nothing sensitive is ever stored).
    }
  },
  remove(key: string): void {
    try {
      if (typeof window !== "undefined") window.localStorage.removeItem(key);
    } catch {
      // Storage is optional; never let a cleanup write fail a flow.
    }
  },
  /** Remove only this app's non-content namespace at lock/logout. */
  removePrefix(prefix: string): void {
    try {
      if (typeof window === "undefined") return;
      const keys: string[] = [];
      for (let index = 0; index < window.localStorage.length; index += 1) {
        const key = window.localStorage.key(index);
        if (key?.startsWith(prefix)) keys.push(key);
      }
      keys.forEach((key) => window.localStorage.removeItem(key));
    } catch {
      // Storage is optional; never make sign-out fail on a private-mode DOM.
    }
  },
};

/** Save a text file (the encrypted export bundle — WEB_PLAN P7.5).
 *  Returns true when a download was actually initiated, so callers can
 *  offer a copy-to-clipboard fallback in browsers that block programmatic
 *  downloads. Blob URLs are revoked on the next macrotask; the anchor is
 *  never attached to the DOM. */
export function downloadTextFile(filename: string, contents: string, mime: string): boolean {
  try {
    if (typeof window === "undefined" || typeof window.document === "undefined") return false;
    const urlFactory = (
      globalThis as {
        URL?: {
          createObjectURL?: (blob: Blob) => string;
          revokeObjectURL?: (url: string) => void;
        };
      }
    ).URL;
    if (!urlFactory?.createObjectURL || !urlFactory.revokeObjectURL) return false;
    const blob = new Blob([contents], { type: mime });
    const url = urlFactory.createObjectURL(blob);
    const anchor = window.document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.click();
    setTimeout(() => urlFactory.revokeObjectURL?.(url), 0);
    return true;
  } catch {
    return false;
  }
}

type LocksLike = {
  locks?: {
    request: <T>(name: string, callback: () => Promise<T>) => Promise<T>;
  };
};

// --- L-7 (2026-09-28 audit): the Web Locks fallback ---------------------------
//
// navigator.locks is missing on Safari < 15.2 — a plausible population for
// a patient web client — and the old fallback simply RAN the section, so
// the cross-tab last-write-wins the lock was added to prevent silently
// returned there. The fallback is a Lamport-bakery mutex over
// localStorage: each contender writes its own vote key, everyone reads
// every live vote, and the SMALLEST contender id holds the lock (unique
// per attempt, so there is never a tie). Under localStorage's coherent
// same-origin store the write→read order is a total order, which makes
// "both contenders miss each other's vote" a cyclic impossibility —
// mutual exclusion holds. Crashed holders self-heal: votes older than
// LOCK_STALE_MS are swept by the next contender, so a tab that died
// mid-section cannot deadlock the lock. Browsers whose storage is absent
// (locked-down private modes, T-1 pentest 2026-09-29) fall through to the
// in-memory mutex below — same-tab serialization without any storage.
const LOCK_VOTE_PREFIX = "mindpattern.lockvote.";
const LOCK_STALE_MS = 15_000;
const LOCK_MAX_WAIT_MS = 30_000;

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
  length: number;
}

function lockStorage(): StorageLike | null {
  try {
    const storage = (globalThis as { window?: { localStorage?: StorageLike } }).window
      ?.localStorage;
    return storage ?? null;
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** One live vote: a monotonic Lamport ticket plus a per-attempt suffix.
 *  The id is the zero-padded ticket first, so lexicographic order IS
 *  ticket order — the bakery's "smallest active ticket holds" rule. */
interface Vote {
  id: string;
  voteKey: string;
  ts: number;
}

/** The bakery read: every LIVE vote for this lock, smallest id first.
 *  Expired votes (a crashed holder's) are swept on sight. */
function liveVotes(storage: StorageLike, name: string): Vote[] {
  const now = Date.now();
  const prefix = `${LOCK_VOTE_PREFIX}${name}.`;
  const votes: Vote[] = [];
  const expired: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const voteKey = storage.key(index);
    if (voteKey === null || !voteKey.startsWith(prefix)) continue;
    const id = voteKey.slice(prefix.length);
    try {
      const stamp = JSON.parse(storage.getItem(voteKey) ?? "{}") as { ts?: number };
      if (typeof stamp.ts === "number" && now - stamp.ts < LOCK_STALE_MS) {
        votes.push({ id, voteKey, ts: stamp.ts });
        continue;
      }
    } catch {
      // An unparseable vote is a crashed write: sweep it.
    }
    expired.push(voteKey);
  }
  expired.forEach((voteKey) => {
    try {
      storage.removeItem(voteKey);
    } catch {
      // Sweeping is best-effort.
    }
  });
  return votes.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function nextTicket(votes: Vote[]): number {
  let max = 0;
  for (const vote of votes) {
    const ticket = parseInt(vote.id.split("-", 1)[0] ?? "0", 36);
    if (Number.isFinite(ticket) && ticket > max) max = ticket;
  }
  return max + 1;
}

async function withStorageLock<T>(storage: StorageLike, name: string, run: () => Promise<T>): Promise<T> {
  // Lamport bakery over the coherent same-origin store. The ticket is
  // MONOTONIC (one past every live vote): a later contender can never
  // order before a live holder — the failure mode of the first cut,
  // which ordered by random ids and let a late arrival "win" while the
  // real holder was still running. Contenders that choose simultaneously
  // draw the same ticket; the unique random suffix breaks that tie, and
  // the beat before the first gate read ensures both writes are visible
  // before either decides (write→read is a total order on this store, so
  // "both miss each other" is a cyclic impossibility).
  const suffix = Math.floor(Math.random() * 2 ** 31).toString(36);
  const ticket = nextTicket(liveVotes(storage, name));
  const id = `${ticket.toString(36).padStart(8, "0")}-${suffix}`;
  const voteKey = `${LOCK_VOTE_PREFIX}${name}.${id}`;
  const deadline = Date.now() + LOCK_MAX_WAIT_MS;
  const touch = (): void => {
    storage.setItem(voteKey, JSON.stringify({ ts: Date.now() }));
  };
  touch();
  const beat = (): Promise<void> => sleep(2 + Math.floor(Math.random() * 8));
  try {
    await beat();
    for (;;) {
      const votes = liveVotes(storage, name);
      const mine = votes.find((vote) => vote.id === id);
      if (mine !== undefined && votes[0]!.id === id) break; // we hold it
      if (mine === undefined) touch(); // our vote was swept as stale: re-draw
      if (Date.now() >= deadline) break; // liveness over exclusion past the cap
      // Refresh OUR stamp so a long wait is never mistaken for a crash,
      // then back off a randomized beat before re-reading.
      touch();
      await beat();
    }
    // A section that outlives LOCK_STALE_MS must not read as a crash to
    // the next contender: keep the stamp fresh for the whole run.
    const keepalive = setInterval(() => {
      try {
        touch();
      } catch {
        // Best-effort; staleness recovers the vote either way.
      }
    }, Math.floor(LOCK_STALE_MS / 3));
    try {
      return await run();
    } finally {
      clearInterval(keepalive);
    }
  } finally {
    try {
      storage.removeItem(voteKey);
    } catch {
      // Release is best-effort; staleness recovers the vote anyway.
    }
  }
}

// --- T-1 (pentest 2026-09-29): the storage-free last fallback -----------------
//
// When neither navigator.locks NOR a usable localStorage exists (locked-
// down private modes), the "locked" section used to run UNLOCKED — so two
// same-tab read-modify-writes over the offline queue could interleave and
// last-write-wins would drop a queued entry. This per-name promise chain
// closes the SAME-TAB half of that window: every section on one name runs
// strictly after the previous one settles, in this tab. What it honestly
// does NOT protect: other tabs and other windows (cross-tab serialization
// is physically impossible without Web Locks or shared storage — it never
// existed in this configuration), so cross-tab interleaving remains
// bounded by the server-side idempotency the queue's uploads already
// carry, exactly as before. The chain is unbounded in waiting sections
// but never in memory: one settled-tail reference per live name.
const memoryLockTails = new Map<string, Promise<unknown>>();

function withMemoryLock<T>(name: string, run: () => Promise<T>): Promise<T> {
  const tail = memoryLockTails.get(name) ?? Promise.resolve();
  const result = tail.then(run, run);
  const settled = result.catch(() => undefined);
  memoryLockTails.set(name, settled);
  // When this link is the settled tail, the chain is idle: drop the entry
  // so a process lifetime of distinct lock names cannot grow the map. The
  // identity check makes the sweep safe against a caller that chained a
  // newer section between this link's settlement and this microtask.
  void settled.then(() => {
    if (memoryLockTails.get(name) === settled) memoryLockTails.delete(name);
  });
  return result;
}

/** Serialize an async section across SAME-ORIGIN tabs via the Web Locks
 *  API (WEB_PLAN P4/P5, R-4: two tabs must not double-flush the offline
 *  queue or double-run reconciliation). Fallback ladder (L-7 audit
 *  2026-09-28 + T-1 pentest 2026-09-29): where the API is absent (Safari
 *  < 15.2) a localStorage bakery mutex provides real cross-tab
 *  serialization; where even storage is unusable (locked-down private
 *  modes) a per-name in-memory mutex still serializes same-tab sections —
 *  the unlocked run is gone. Cross-tab exclusion without storage was
 *  never possible and remains delegated to the queue's server-side
 *  idempotency. */
export async function withLock<T>(name: string, run: () => Promise<T>): Promise<T> {
  const locks = (globalThis as { navigator?: LocksLike }).navigator?.locks;
  if (locks?.request) return locks.request(name, run);
  const storage = lockStorage();
  if (storage !== null) return withStorageLock(storage, name, run);
  return withMemoryLock(name, run);
}

/** Connectivity probe. Unknown (node, or a stripped browser) reads as
 *  online: a false "offline" would disable journaling unnecessarily. */
export function isOnline(): boolean {
  try {
    const nav = (globalThis as { navigator?: { onLine?: boolean } }).navigator;
    return nav?.onLine !== false;
  } catch {
    return true;
  }
}

/** Subscribe to a window event through the seam (online / offline /
 *  visibilitychange / pageshow). Returns an unsubscribe function; a
 *  no-op when there is no usable window. */
/** Is the page currently hidden? The browser truth is
 * `document.visibilityState`; the node test runtime has no document, so
 * the seam also accepts the state carried on the synthetic event the
 * test shim dispatches (the same pattern the bfcache guard uses for
 * `persisted`). A missing/unknown state reads as visible — never locks
 * on a guess. */
export function pageHidden(event?: unknown): boolean {
  try {
    const doc = (globalThis as { document?: { visibilityState?: unknown } }).document;
    if (doc && typeof doc.visibilityState === "string") {
      return doc.visibilityState === "hidden";
    }
  } catch {
    // Fall through to the event-borne state.
  }
  return (event as { visibilityState?: unknown } | undefined)?.visibilityState === "hidden";
}

export function onWindowEvent(type: string, listener: (event?: unknown) => void): () => void {
  try {
    if (typeof window === "undefined" || typeof window.addEventListener !== "function") {
      return () => undefined;
    }
    window.addEventListener(type, listener);
    return () => window.removeEventListener(type, listener);
  } catch {
    return () => undefined;
  }
}
