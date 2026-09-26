/**
 * Async key-value storage seam (AsyncStorage's contract over IndexedDB).
 * Everything the app persists locally — the offline queue, encrypted
 * version marks, the encrypted mood log — goes through here. Keys are
 * observable metadata: never a username, never plaintext content
 * (WEB_PLAN D-4/R-7).
 *
 * Degradation: where IndexedDB is unavailable or hostile (private modes,
 * node test runtime), the seam falls back to a per-process in-memory map —
 * journaling still works online; the offline queue simply does not survive
 * a reload, which is disclosed rather than crashed on.
 */

export interface KvBackend {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  /** 2026-09-26 audit LOW d: enumerate the backend's keys. Optional so
   *  injected test backends stay two-method compatible; a backend without
   *  it enumerates as empty. The VALUES stay behind getItem — enumeration
   *  is for diagnostics and the storage-scrape red-team sweep, which used
   *  to carry a dead no-op where this call now stands. */
  keys?(): Promise<string[]>;
}

const DB_NAME = "mindpattern";
const STORE = "kv";

let dbPromise: Promise<IDBDatabase | null> | null = null;

function openDb(): Promise<IDBDatabase | null> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      const factory = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
      if (!factory) {
        resolve(null);
        return;
      }
      const request = factory.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
      request.onblocked = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  // A connection that later closes (user clears site data) must not wedge
  // the seam forever: allow one re-open.
  void dbPromise.then((db) => {
    if (db) db.onclose = () => { dbPromise = null; };
  });
  return dbPromise;
}

const memoryBackend: KvBackend = (() => {
  const map = new Map<string, string>();
  return {
    async getItem(key) {
      return map.get(key) ?? null;
    },
    async setItem(key, value) {
      map.set(key, value);
    },
    async removeItem(key) {
      map.delete(key);
    },
    async keys() {
      return [...map.keys()];
    },
  };
})();

let overrideBackend: KvBackend | null = null;

/** Tests inject an isolated backend here; the app never calls it. */
export function setKvBackendForTests(backend: KvBackend | null): void {
  overrideBackend = backend;
}

/** Test hook: drop the memoized IndexedDB connection so a new fake factory
 *  takes effect (the app never needs this — its connection is for life). */
export function resetKvConnectionForTests(): void {
  dbPromise = null;
}

async function backend(): Promise<KvBackend> {
  if (overrideBackend) return overrideBackend;
  const db = await openDb();
  if (!db) return memoryBackend;
  return {
    async getItem(key) {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const request = tx.objectStore(STORE).get(key);
        request.onsuccess = () => resolve(request.result === undefined ? null : (request.result as string));
        request.onerror = () => reject(request.error);
      });
    },
    async setItem(key, value) {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    },
    async removeItem(key) {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    },
    async keys() {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const request = tx.objectStore(STORE).getAllKeys();
        request.onsuccess = () => resolve(request.result.map((k) => String(k)));
        request.onerror = () => reject(request.error);
      });
    },
  };
}

export const kv = {
  async getItem(key: string): Promise<string | null> {
    try {
      return await (await backend()).getItem(key);
    } catch {
      return null;
    }
  },
  async setItem(key: string, value: string): Promise<void> {
    try {
      await (await backend()).setItem(key, value);
    } catch {
      // Private mode / quota: fail closed, never crash the journal flow.
    }
  },
  async removeItem(key: string): Promise<void> {
    try {
      await (await backend()).removeItem(key);
    } catch {
      // Removal is idempotent from the caller's perspective.
    }
  },
  async multiRemove(keys: string[]): Promise<void> {
    for (const key of keys) await kv.removeItem(key);
  },
  /** Enumerate every key in the active backend ([] when the backend cannot
   *  or does not support it — see KvBackend.keys). */
  async keys(): Promise<string[]> {
    try {
      const active = await backend();
      return active.keys ? await active.keys() : [];
    } catch {
      return [];
    }
  },
};
