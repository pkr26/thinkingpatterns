import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { kv, resetKvConnectionForTests, setKvBackendForTests, StorageCommitError, StorageReadError } from "../src/kvstore";

beforeEach(() => { setKvBackendForTests(null); resetKvConnectionForTests(); vi.stubGlobal("indexedDB", new IDBFactory()); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); resetKvConnectionForTests(); });

describe("portal durable IndexedDB records", () => {
  it("retains an acknowledged encrypted record through reconnection and removes it durably", async () => {
    await kv.setItem("portal.draft.owner.patient", "encrypted-content");
    resetKvConnectionForTests();
    expect(await kv.getItem("portal.draft.owner.patient")).toBe("encrypted-content");
    expect(await kv.getItem("absent")).toBeNull();
    expect(await kv.keys()).toEqual(["portal.draft.owner.patient"]);
    await kv.multiRemove(["portal.draft.owner.patient"]);
    resetKvConnectionForTests();
    expect(await kv.getItem("portal.draft.owner.patient")).toBeNull();
  });

  it("distinguishes unreadable storage from absence, refuses writes, and allows retry without losing the existing record", async () => {
    const factory = globalThis.indexedDB;
    await kv.setItem("saved", "original-ciphertext");
    resetKvConnectionForTests(); vi.stubGlobal("indexedDB", undefined);
    await expect(kv.getItem("saved")).rejects.toBeInstanceOf(StorageReadError);
    await expect(kv.keys()).rejects.toBeInstanceOf(StorageReadError);
    await expect(kv.setItem("saved", "replacement")).rejects.toBeInstanceOf(StorageCommitError);
    await expect(kv.removeItem("saved")).rejects.toBeInstanceOf(StorageCommitError);
    vi.stubGlobal("indexedDB", factory);
    expect(await kv.getItem("saved")).toBe("original-ciphertext");
  });

  it("does not acknowledge a real aborted transaction or delete an existing ciphertext", async () => {
    await kv.setItem("saved", "original-ciphertext");
    const request = indexedDB.open("mindpattern-portal", 1);
    const db = await new Promise<IDBDatabase>((resolve, reject) => {request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});
    const prototype = Object.getPrototypeOf(db) as IDBDatabase;
    const original = prototype.transaction;
    const abort = vi.spyOn(prototype,"transaction").mockImplementation(function (this:IDBDatabase, ...args:Parameters<IDBDatabase["transaction"]>) {
      const transaction = original.apply(this,args); if(args[1]==="readwrite")transaction.abort(); return transaction;
    });
    await expect(kv.setItem("saved","replacement")).rejects.toBeInstanceOf(StorageCommitError);
    await expect(kv.removeItem("saved")).rejects.toBeInstanceOf(StorageCommitError);
    abort.mockRestore(); db.close(); resetKvConnectionForTests();
    expect(await kv.getItem("saved")).toBe("original-ciphertext");
  });
});
