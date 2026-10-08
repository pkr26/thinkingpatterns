import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { kv, resetKvConnectionForTests, setKvBackendForTests, StorageCommitError, StorageReadError } from "../src/kvstore";

beforeEach(() => { runTestControl(setKvBackendForTests, null); runTestControl(resetKvConnectionForTests); vi.stubGlobal("indexedDB", new IDBFactory()); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); runTestControl(resetKvConnectionForTests); });

it("reads records persisted by the installed portal database format", async () => {
  // This fixture models an earlier browser session, before the current
  // module opens storage; acknowledgement must survive application reloads.
  const request = indexedDB.open("mindpattern-portal", 1);
  request.onupgradeneeded = () => request.result.createObjectStore("kv");
  const db = await new Promise<IDBDatabase>((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").put("earlier encrypted draft", "portal.draft.owner.patient");
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
  db.close();
  expect(await kv.getItem("portal.draft.owner.patient")).toBe("earlier encrypted draft");
  expect(await kv.keys()).toEqual(["portal.draft.owner.patient"]);
});

it("reports denied database opening promptly and recovers when the host permits a retry", async () => {
  const usable = indexedDB;
  vi.stubGlobal("indexedDB", { open() { throw new DOMException("denied", "SecurityError"); } });
  let outcome: unknown;
  const read = kv.getItem("saved").catch(error => { outcome = error; });
  for (let step = 0; step < 20; step++) await Promise.resolve();
  expect(outcome).toBeInstanceOf(StorageReadError);
  await read;
  vi.stubGlobal("indexedDB", usable);
  await expect(kv.setItem("saved", "ciphertext after retry")).resolves.toBeUndefined();
  await expect(kv.getItem("saved")).resolves.toBe("ciphertext after retry");
});

it.each(["error", "blocked"] as const)("reports a database-open %s before exposing a saved-data state", async event => {
  const request = { result: { onclose: null }, onsuccess: null, onerror: null, onblocked: null } as unknown as IDBOpenDBRequest;
  vi.stubGlobal("indexedDB", { open: () => request });
  let settled = false;
  let failure: unknown;
  const read = kv.getItem("saved").then(() => { settled = true; }, error => { settled = true; failure = error; });
  try {
    if (event === "error") request.onerror?.call(request, new Event("error"));
    else request.onblocked?.call(request, new IDBVersionChangeEvent("blocked", {oldVersion:1,newVersion:2}));
    for (let step = 0; step < 20; step++) await Promise.resolve();
    expect(settled).toBe(true);
    expect(failure).toBeInstanceOf(StorageReadError);
  } finally {
    // A mutant that omits the failure listener still gets a completion
    // event after the assertion, so the test has a behavioral failure.
    request.onsuccess?.call(request, new Event("success"));
    await read;
  }
});

it.each([
  ["read", "error"], ["keys", "error"], ["write", "error"],
  ["write", "abort"], ["delete", "error"], ["delete", "abort"],
] as const)("settles a host %s transaction %s as an actionable failure", async (operation, event) => {
  const cause = new DOMException("device rejected operation", "AbortError");
  const request = { result: operation === "keys" ? [] : undefined, error: cause, onsuccess: null, onerror: null } as unknown as IDBRequest;
  const tx = { error: cause, oncomplete: null, onerror: null, onabort: null, objectStore: () => ({ get: () => request, getAllKeys: () => request, put: () => request, delete: () => request }) } as unknown as IDBTransaction;
  const db = { onclose: null, transaction: () => tx };
  const open = { result: db, onsuccess: null } as unknown as IDBOpenDBRequest;
  vi.stubGlobal("indexedDB", { open: () => { queueMicrotask(() => open.onsuccess?.call(open, new Event("success"))); return open; } });
  let settled = false;
  let failure: unknown;
  const promise = (operation === "read" ? kv.getItem("saved") : operation === "keys" ? kv.keys() : operation === "write" ? kv.setItem("saved", "ciphertext") : kv.removeItem("saved"))
    .then(() => { settled = true; }, error => { settled = true; failure = error; });
  try {
    for (let step = 0; step < 20; step++) await Promise.resolve();
    if (operation === "read" || operation === "keys") request.onerror?.call(request, new Event("error"));
    else tx[event === "error" ? "onerror" : "onabort"]?.call(tx, new Event(event));
    for (let step = 0; step < 20; step++) await Promise.resolve();
    expect(settled).toBe(true);
    expect(failure).toBeInstanceOf(operation === "read" || operation === "keys" ? StorageReadError : StorageCommitError);
    expect((failure as Error).cause).toBe(cause);
  } finally {
    request.onsuccess?.call(request, new Event("success"));
    tx.oncomplete?.call(tx, new Event("complete"));
    await promise;
  }
});

it.each(["read","keys","write","delete"] as const)("acknowledges a completed host %s event before displaying a durable result",async operation=>{
  const request={result:operation==="keys"?["saved"]:"ciphertext",onsuccess:null,onerror:null} as unknown as IDBRequest;
  const transaction={oncomplete:null,onerror:null,onabort:null,objectStore:()=>({get:()=>request,getAllKeys:()=>request,put:()=>request,delete:()=>request})} as unknown as IDBTransaction;
  const db={onclose:null,transaction:()=>transaction};
  const open={result:db,onsuccess:null} as unknown as IDBOpenDBRequest;
  vi.stubGlobal("indexedDB",{open:()=>open});
  const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};
  const promise=operation==="read"?kv.getItem("saved"):operation==="keys"?kv.keys():operation==="write"?kv.setItem("saved","ciphertext"):kv.removeItem("saved");
  void promise.then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
  open.onsuccess?.call(open,new Event("success"));
  for(let step=0;step<20;step++)await Promise.resolve();
  request.onsuccess?.call(request,new Event("success"));transaction.oncomplete?.call(transaction,new Event("complete"));
  for(let step=0;step<20;step++)await Promise.resolve();
  expect(outcome.settled).toBe(true);expect(outcome.error).toBeUndefined();
  expect(outcome.value).toEqual(operation==="read"?"ciphertext":operation==="keys"?["saved"]:undefined);
});

describe("portal durable IndexedDB records", () => {
  it("retains an acknowledged encrypted record through reconnection and removes it durably", async () => {
    await kv.setItem("portal.draft.owner.patient", "encrypted-content");
    runTestControl(resetKvConnectionForTests);
    expect(await kv.getItem("portal.draft.owner.patient")).toBe("encrypted-content");
    expect(await kv.getItem("absent")).toBeNull();
    expect(await kv.keys()).toEqual(["portal.draft.owner.patient"]);
    await kv.multiRemove(["portal.draft.owner.patient"]);
    runTestControl(resetKvConnectionForTests);
    expect(await kv.getItem("portal.draft.owner.patient")).toBeNull();
  });

  it("distinguishes unreadable storage from absence, refuses writes, and allows retry without losing the existing record", async () => {
    const factory = globalThis.indexedDB;
    await kv.setItem("saved", "original-ciphertext");
    runTestControl(resetKvConnectionForTests); vi.stubGlobal("indexedDB", undefined);
    await expect(kv.getItem("saved")).rejects.toBeInstanceOf(StorageReadError);
    await expect(kv.getItem("saved")).rejects.toMatchObject({cause:{name:"StorageCommitError",message:"Durable storage is unavailable — keep this writing open and retry when storage is available."}});
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
    abort.mockRestore(); db.close(); runTestControl(resetKvConnectionForTests);
    expect(await kv.getItem("saved")).toBe("original-ciphertext");
  });
});

it("retains empty ciphertext strings distinctly from missing keys", async () => {
  await kv.setItem("empty", "");
  expect(await kv.getItem("empty")).toBe("");
  expect(await kv.getItem("missing")).toBeNull();
  await kv.setItem("other", "other-ciphertext");
  await kv.multiRemove(["empty", "other"]);
  expect(await kv.keys()).toEqual([]);
});

it("wraps backend failures with actionable text and retains their cause", async () => {
  const cause = new Error("quota denied");
  runTestControl(setKvBackendForTests, {
    getItem: async () => { throw cause; },
    setItem: async () => { throw cause; },
    removeItem: async () => { throw cause; },
    keys: async () => { throw cause; },
  });
  await expect(kv.getItem("saved")).rejects.toMatchObject({ name: "StorageReadError", cause, message: "Local encrypted records could not be read. Keep this view open and retry before changing stored data." });
  await expect(kv.setItem("saved", "encrypted")).rejects.toMatchObject({ name: "StorageCommitError", cause, message: "Writing was not saved on this device — storage is full or unavailable. Keep it open and retry." });
  await expect(kv.removeItem("saved")).rejects.toMatchObject({ name: "StorageCommitError", cause, message: "Local deletion did not finish — retry before leaving this device." });
  await expect(kv.keys()).rejects.toMatchObject({ name: "StorageReadError", cause, message: "Local encrypted records could not be enumerated. Retry before replacing or deleting stored records." });
});

it("supports an injected backend without enumeration and deletes requested keys in order", async () => {
  const removed: string[] = [];
  runTestControl(setKvBackendForTests, {
    getItem: async () => null,
    setItem: async () => {},
    removeItem: async key => { removed.push(key); },
  });
  await expect(kv.keys()).resolves.toEqual([]);
  await kv.multiRemove(["first", "second"]);
  expect(removed).toEqual(["first", "second"]);
});

it("reopens storage after the browser reports a closed connection", async () => {
  const original = indexedDB.open.bind(indexedDB);
  const requests: IDBOpenDBRequest[] = [];
  vi.spyOn(indexedDB, "open").mockImplementation((...args) => {
    const request = original(...args);
    requests.push(request);
    return request;
  });
  await kv.setItem("saved", "ciphertext");
  expect(requests).toHaveLength(1);
  // IDB's forced-close notification is a host event; dispatch it through
  // the registered browser callback, then verify an ordinary read recovers.
  requests[0]!.result.close();
  requests[0]!.result.onclose?.call(requests[0]!.result, new Event("close"));
  await expect(kv.getItem("saved")).resolves.toBe("ciphertext");
  expect(requests).toHaveLength(2);
});

it("retains acknowledged encrypted records through a transient denial of new host connections",async()=>{
 await kv.setItem("portal.draft.owner.patient","acknowledged encrypted draft");
 const opening=vi.spyOn(indexedDB,"open").mockImplementation(()=>{throw new DOMException("new connections temporarily denied","SecurityError");});
 try{await expect(kv.getItem("portal.draft.owner.patient")).resolves.toBe("acknowledged encrypted draft");await expect(kv.keys()).resolves.toEqual(["portal.draft.owner.patient"]);await expect(kv.setItem("portal.draft.owner.patient","new committed encrypted draft")).resolves.toBeUndefined();await expect(kv.getItem("portal.draft.owner.patient")).resolves.toBe("new committed encrypted draft");}finally{opening.mockRestore();}
});
