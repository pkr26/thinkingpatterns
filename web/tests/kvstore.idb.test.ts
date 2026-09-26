/** The kvstore's IndexedDB path, driven by a minimal fake IDB factory (the
 *  node runtime has none). The in-memory degradation path is exercised by
 *  every other suite implicitly; this pins the real storage adapter. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { kv, resetKvConnectionForTests, setKvBackendForTests } from "../src/kvstore";

/** A tiny synchronous IndexedDB: one database, one object store, promise-
 *  wrapped in the kvstore's own style (request success/error events). */
function installFakeIdb(): { dump: () => Map<string, string>; failNext: () => void } {
  const store = new Map<string, string>();
  let fail = false;
  const request = (result: unknown): IDBRequest => {
    const req = { result, onsuccess: null, onerror: null } as unknown as IDBRequest;
    if (fail) {
      queueMicrotask(() => req.onerror?.(new Event("error")));
    } else {
      queueMicrotask(() => req.onsuccess?.(new Event("success")));
    }
    return req;
  };
  const fire = (tx: { oncomplete: ((e: Event) => void) | null; onerror: ((e: Event) => void) | null }): void => {
    queueMicrotask(() => tx.oncomplete?.(new Event("complete")));
  };
  const db = {
    objectStoreNames: { contains: () => true },
    transaction: () => {
      const tx = {
        objectStore: () => ({
          get: (key: string) => request(store.has(key) ? store.get(key) : undefined),
          put: (value: string, key: string) => {
            store.set(key, value);
            return request(undefined);
          },
          delete: (key: string) => {
            store.delete(key);
            return request(undefined);
          },
        }),
        oncomplete: null,
        onerror: null,
        onabort: null,
      } as unknown as { oncomplete: ((e: Event) => void) | null };
      queueMicrotask(() => fire(tx as unknown as { oncomplete: ((e: Event) => void) | null; onerror: ((e: Event) => void) | null }));
      return tx;
    },
    onclose: null,
    close: () => undefined,
  };
  const openRequest = {
    result: db,
    onupgradeneeded: null,
    onsuccess: null,
    onerror: null,
    onblocked: null,
  } as unknown as IDBOpenDBRequest;
  queueMicrotask(() => openRequest.onsuccess?.(new Event("success")));
  vi.stubGlobal("indexedDB", {
    open: () => openRequest,
  });
  return { dump: () => store, failNext: () => { fail = true; } };
}

beforeEach(() => {
  setKvBackendForTests(null); // force the real backend selection path
  resetKvConnectionForTests(); // a fresh fake factory per test
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("kvstore over IndexedDB", () => {
  it("round-trips values through the object store", async () => {
    const fake = installFakeIdb();
    await kv.setItem("mindpattern.test", "value-1");
    expect(await kv.getItem("mindpattern.test")).toBe("value-1");
    expect(fake.dump().get("mindpattern.test")).toBe("value-1");
    await kv.removeItem("mindpattern.test");
    expect(await kv.getItem("mindpattern.test")).toBeNull();
    expect(fake.dump().has("mindpattern.test")).toBe(false);
  });

  it("multiRemove clears each key", async () => {
    installFakeIdb();
    await kv.setItem("a", "1");
    await kv.setItem("b", "2");
    await kv.multiRemove(["a", "b"]);
    expect(await kv.getItem("a")).toBeNull();
    expect(await kv.getItem("b")).toBeNull();
  });

  it("a failing request degrades to null / silent no-throw, never crashes", async () => {
    const fake = installFakeIdb();
    await kv.setItem("k", "v");
    fake.failNext();
    expect(await kv.getItem("k")).toBeNull(); // read failure → null
    fake.failNext();
    await kv.setItem("k", "v2"); // write failure → silent
    fake.failNext();
    await kv.removeItem("k"); // remove failure → silent
  });
});
