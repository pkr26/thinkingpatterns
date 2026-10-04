/**
 * IndexedDB storage for encrypted local records and non-content preferences.
 * Keys are observable metadata and must not contain usernames or plaintext
 * content. Writes resolve only after commit; unavailable storage and failed
 * transactions throw instead of reporting volatile data as saved.
 */
import { hkdfSha256, toBase64, zeroize, type Bytes } from "./crypto/core";
import { accountKeyPolicy } from "./ownerStorage";

export interface WritePermit {
  owner: string;
  generation: string | null;
  keyBound: boolean;
}
export const writeGenerationKey = (owner: string): string => `mindpattern.writeGeneration.${owner}`;

interface WriteGeneration {
  v: 1;
  nonce: string;
  deleted: boolean;
  keyTag?: string;
}

function generationRecord(raw: string): WriteGeneration {
  const row = JSON.parse(raw) as WriteGeneration;
  if (row.v !== 1 || !/^[a-f0-9]{32}$/.test(row.nonce) || typeof row.deleted !== "boolean" || (!row.deleted && (typeof row.keyTag !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(row.keyTag))))
    throw new Error("The local writing generation is unreadable; records were retained.");
  return row;
}

async function keyTag(owner: string, dataKey: Bytes): Promise<string> {
  const copy = new Uint8Array(dataKey);
  let tag: Bytes | null = null;
  try {
    tag = await hkdfSha256(copy, new Uint8Array(32), new TextEncoder().encode(`mindpattern/local-write-generation/v1/${owner}`), 32);
    return toBase64(tag);
  } finally {
    zeroize(copy, tag);
  }
}

function nonce(): string { return [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, "0")).join(""); }

export async function newWriteGeneration(owner: string, dataKey: Bytes): Promise<string> {
  return JSON.stringify({ v: 1, nonce: nonce(), deleted: false, keyTag: await keyTag(owner, dataKey) });
}

function permitAllowed(owner: string, raw: string | null, keyBound: boolean, permit?: WritePermit): boolean {
  if (permit && (permit.owner !== owner || permit.generation !== raw))
    return false;
  if (raw === null)
    return true; // legacy install before its first rotation/deletion fence
  const generation = generationRecord(raw);
  if (generation.deleted)
    return false;
  return !keyBound || !!permit;
}

export interface KvBackend {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string, permit?: WritePermit): Promise<void>;
  removeItem(key: string, permit?: WritePermit): Promise<void>;
  /** Must compare and commit in one transaction; never emulate with get/set. */
  compareAndSet?(key: string, expected: string | null, value: string, permit?: WritePermit, stillCurrent?: () => boolean): Promise<boolean>;
  /** 2026-09-26 audit LOW d: enumerate the backend's keys. Optional so
   *  injected test backends stay two-method compatible; a backend without
   *  it enumerates as empty. The VALUES stay behind getItem — enumeration
   *  is for diagnostics and the storage-scrape red-team sweep, which used
   *  to carry a dead no-op where this call now stands. */
  keys?(): Promise<string[]>;
}
const DB_NAME = "mindpattern";
const STORE = "kv";

/** Exhaustive ownership policy for account-scoped IndexedDB keys.
 *
 * Ciphertext producers must present the generation they captured before
 * their async work. Metadata/rotation producers predate that permit seam,
 * but still read the durable fence in the commit transaction: a deleted
 * generation therefore rejects every late write after the erasure
 * tombstone itself has gone. Supplying a metadata permit strengthens the
 * rule and rejects a superseded generation too (queue eviction counters do
 * this). The canonical prefix/queue registry lives in ownerStorage.ts and
 * is shared with local erasure. */

function mutate(db: IDBDatabase, key: string, value: string | null, expected?: string | null, permit?: WritePermit, stillCurrent?: () => boolean): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite"), store = tx.objectStore(STORE);
    let changed = false;
    let failure: unknown;
    tx.oncomplete = () => resolve(changed);
    tx.onerror = () => reject(failure ?? tx.error);
    tx.onabort = () => reject(failure ?? tx.error);
    const apply = () => {
      try {
        if (stillCurrent && !stillCurrent())
          throw new Error("The authenticated unlock changed before storage committed.");
        if (value === null)
          store.delete(key);
        else
          store.put(value, key);
        changed = true;
      } catch (error) {
        failure = error;
        tx.abort();
      }
    };
    const compare = () => {
      if (expected === undefined) {
        apply();
        return;
      }
      const request = store.get(key);
      request.onsuccess = () => {
        if ((request.result === undefined ? null : request.result) === expected)
          apply();
      };
      request.onerror = () => { failure = request.error; };
    };
    const policy = accountKeyPolicy(key);
    if (!policy) {
      compare();
      return;
    }
    const { owner, keyBound } = policy;
    const refuse = (reason: string) => {
      if (value !== null) {
        failure = new Error(reason);
        tx.abort();
        return;
      }
      const erasure = store.get(`mindpattern.erase.${owner}`);
      erasure.onerror = () => { failure = erasure.error; };
      erasure.onsuccess = () => {
        try {
          const row = JSON.parse(erasure.result);
          if (row.v === 1 && row.owner === owner && row.remoteConfirmed === true) {
            apply();
            return;
          }
        } catch { /* retain records */ }
        failure = new Error(reason);
        tx.abort();
      };
    };
    const generation = store.get(writeGenerationKey(owner));
    generation.onerror = () => { failure = generation.error; };
    generation.onsuccess = () => {
      try {
        if (!permitAllowed(owner, generation.result === undefined ? null : generation.result, keyBound, permit)) {
          refuse("This writing belongs to an earlier account-key generation; the current record was retained.");
          return;
        }
      } catch (error) {
        failure = error;
        tx.abort();
        return;
      }
      if (expected !== undefined) {
        compare();
        return;
      } // migration CAS still proves its generation
      // The checkpoint blocks content writes while a rekey is pending.
      // Rotation journals/salts and non-content account metadata must remain
      // writable/removable so the rotation can itself reach a terminal state.
      if (!keyBound) {
        compare();
        return;
      }
      const checkpoint = store.get(`mindpattern.localRotation.${owner}`);
      checkpoint.onerror = () => { failure = checkpoint.error; };
      checkpoint.onsuccess = () => {
        if (checkpoint.result === undefined) {
          compare();
          return;
        }
        refuse("A key migration is pending; keep this writing open and finish recovery before saving.");
      };
    };
  });
}
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
      dbPromise = null; // a Retry must reopen after a transient failure
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
    async setItem(key, value, permit) {
      await mutate(db, key, value, undefined, permit);
    },
    async removeItem(key, permit) {
      await mutate(db, key, null, undefined, permit);
    },
    compareAndSet: (key, expected, value, permit, stillCurrent) => mutate(db, key, value, expected, permit, stillCurrent),
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
  /** Key-bound producers capture this before crypto/network awaits. Queue
   * metadata movers may omit the key but retain the same durable token. */
  async captureWritePermit(owner: string, dataKey?: Bytes): Promise<WritePermit> {
    const tag = dataKey ? await keyTag(owner, dataKey) : null;
    const generation = await kv.getItem(writeGenerationKey(owner));
    if (generation !== null) {
      const row = generationRecord(generation);
      if (row.deleted || (tag !== null && row.keyTag !== tag))
        throw new StorageCommitError("This old account key cannot save writing after migration or deletion; current records were retained.");
    }
    return { owner, generation, keyBound: dataKey !== undefined };
  },
  /** Called only after an authenticated fresh unlock. A rotation on another
   * device may change the valid key; adopt its generation without touching
   * any existing ciphertext or guessing whether an unreadable draft is empty. */
  async adoptVerifiedWriteGeneration(owner: string, dataKey: Bytes, stillCurrent: () => boolean = () => true): Promise<void> {
    let tag: string | null = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      if (!stillCurrent())
        return;
      const before = await kv.getItem(writeGenerationKey(owner));
      if (before === null)
        return; // legacy devices acquire their first marker at rotation
      tag ??= await keyTag(owner, dataKey);
      const row = generationRecord(before);
      if (row.deleted)
        throw new StorageCommitError("This account's local records were erased; old callbacks remain disabled.");
      if (row.keyTag === tag)
        return;
      const after = JSON.stringify({ v: 1, nonce: nonce(), deleted: false, keyTag: tag });
      if (await kv.compareAndSetForMigration(writeGenerationKey(owner), before, after, undefined, stillCurrent))
        return;
    }
    throw new StorageCommitError("The account writing generation changed during unlock; keep local records and retry.");
  },
  async getItem(key: string): Promise<string | null> {
    try {
      return await (await backend()).getItem(key);
    } catch (cause) {
      throw new StorageReadError("Local encrypted records could not be read. Keep this view open and retry before changing stored data.", { cause });
    }
  },
  async setItem(key: string, value: string, permit?: WritePermit): Promise<void> {
    try {
      await (await backend()).setItem(key, value, permit);
    } catch (cause) {
      throw new StorageCommitError("Writing was not saved on this device — storage is full or unavailable. Keep it open and retry.", { cause });
    }
  },
  async removeItem(key: string, permit?: WritePermit): Promise<void> {
    try {
      await (await backend()).removeItem(key, permit);
    } catch (cause) {
      throw new StorageCommitError("Local deletion did not finish — retry before leaving this device.", { cause });
    }
  },
  async compareAndSetForMigration(key: string, expected: string | null, value: string, permit?: WritePermit, stillCurrent?: () => boolean): Promise<boolean> {
    try {
      const active = await backend();
      if (!active.compareAndSet)
        throw new Error("Atomic storage comparison is unavailable; the migration checkpoint was retained.");
      return await active.compareAndSet(key, expected, value, permit, stillCurrent);
    } catch (cause) {
      throw new StorageCommitError("Migration was not saved atomically — keep the encrypted checkpoint and retry.", { cause });
    }
  },
  async markOwnerErased(owner: string): Promise<void> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const before = await kv.getItem(writeGenerationKey(owner));
      if (before !== null && generationRecord(before).deleted)
        return;
      const after = JSON.stringify({ v: 1, nonce: nonce(), deleted: true });
      if (await kv.compareAndSetForMigration(writeGenerationKey(owner), before, after))
        return;
    }
    throw new StorageCommitError("Account deletion could not fence pending writing; retry cleanup.");
  },
  async multiRemove(keys: string[]): Promise<void> {
    for (const key of keys)
      await kv.removeItem(key);
  },
  /** Enumeration errors must not look like an empty device. */
  async keys(): Promise<string[]> {
    try {
      const active = await backend();
      return active.keys ? await active.keys() : [];
    } catch (cause) {
      throw new StorageReadError("Local encrypted records could not be enumerated. Retry before replacing or deleting stored records.", { cause });
    }
  },
};
