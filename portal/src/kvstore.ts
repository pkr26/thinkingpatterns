/**
 * IndexedDB storage for encrypted clinician drafts and pending note requests.
 * Keys are observable metadata and must not contain usernames or plaintext
 * content. Writes resolve only after commit; unavailable storage and failed
 * transactions throw instead of reporting volatile data as saved.
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
const DB_NAME = "mindpattern-portal";
const STORE = "kv";
let dbPromise: Promise<IDBDatabase | null> | null = null;

function openDb(): Promise<IDBDatabase | null> {
  if (dbPromise)
    return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      const factory = (globalThis as {
        indexedDB?: IDBFactory;
      }).indexedDB;
      if (!factory) {
        resolve(null);
        return;
      }
      const request = factory.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE))
          db.createObjectStore(STORE);
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
    if (db)
      db.onclose = () => { dbPromise = null; };
    else
      dbPromise = null;
  });
  return dbPromise;
}
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
  if (overrideBackend)
    return overrideBackend;
  const db = await openDb();
  if (!db)
    throw new StorageCommitError("Durable storage is unavailable — keep this writing open and retry when storage is available.");
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

export class StorageCommitError extends Error {
  constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = "StorageCommitError"; }
}

export class StorageReadError extends Error {
  constructor(message: string, options?: ErrorOptions) { super(message, options); this.name = "StorageReadError"; }
}
export const kv = {
  async getItem(key: string): Promise<string | null> {
    try {
      return await (await backend()).getItem(key);
    } catch (cause) {
      throw new StorageReadError("Local encrypted records could not be read. Keep this view open and retry before changing stored data.", { cause });
    }
  },
  async setItem(key: string, value: string): Promise<void> {
    try {
      await (await backend()).setItem(key, value);
    } catch (cause) {
      throw new StorageCommitError("Writing was not saved on this device — storage is full or unavailable. Keep it open and retry.", { cause });
    }
  },
  async removeItem(key: string): Promise<void> {
    try {
      await (await backend()).removeItem(key);
    } catch (cause) {
      throw new StorageCommitError("Local deletion did not finish — retry before leaving this device.", { cause });
    }
  },
  async multiRemove(keys: string[]): Promise<void> {
    for (const key of keys)
      await kv.removeItem(key);
  },
  /** Enumerate every key in the active backend ([] when the backend cannot
   *  or does not support it — see KvBackend.keys). */
  async keys(): Promise<string[]> {
    try {
      const active = await backend();
      return active.keys ? await active.keys() : [];
    } catch (cause) {
      throw new StorageReadError("Local encrypted records could not be enumerated. Retry before replacing or deleting stored records.", { cause });
    }
  },
};
