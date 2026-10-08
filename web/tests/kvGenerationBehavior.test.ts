import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { forceCloseDatabase, IDBFactory, IDBObjectStore } from "fake-indexeddb";
import { hkdfSync } from "node:crypto";
import { kv, newWriteGeneration, resetKvConnectionForTests, setKvBackendForTests, StorageCommitError, StorageReadError, writeGenerationKey } from "../src/kvstore";
import { toBase64 } from "../src/crypto/core";
import { displayError } from "../src/errors";
import { enqueue } from "../src/offlineQueue";

const owner = "generation-consumer", other = "generation-other";
const content = `mindpattern.draft.active.${owner}`, metadata = `mindpattern.measureCadence.${owner}`;
const key = new Uint8Array(new ArrayBuffer(32)).fill(29), incoming = new Uint8Array(new ArrayBuffer(32)).fill(31);
beforeEach(() => { setKvBackendForTests(null); resetKvConnectionForTests(); vi.stubGlobal("indexedDB", new IDBFactory()); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); setKvBackendForTests(null); resetKvConnectionForTests(); });
const tag = (secret: Uint8Array, user = owner) => toBase64(new Uint8Array(hkdfSync("sha256", secret, new Uint8Array(32), new TextEncoder().encode(`mindpattern/local-write-generation/v1/${user}`), 32)));
async function initialize() { const generation = await newWriteGeneration(owner, key); await kv.setItem(writeGenerationKey(owner), generation); return generation; }

it("uses an independent HKDF key proof to accept the correct encryption generation and refuse a different key", async () => {
  const before = key.slice(), raw = await initialize();
  expect(JSON.parse(raw)).toMatchObject({ v: 1, deleted: false, keyTag: tag(key) });
  expect(JSON.parse(raw).nonce).toMatch(/^[a-f0-9]{32}$/); expect(key).toEqual(before);
  const permit = await kv.captureWritePermit(owner, key); await kv.setItem(content, "encrypted writing", permit);
  await expect(kv.captureWritePermit(owner, incoming)).rejects.toBeInstanceOf(StorageCommitError);
  expect(await kv.getItem(content)).toBe("encrypted writing");
});
it.each([false, true])("erases actual WebCrypto-observed key proof inputs and outputs after generation creation: failure=%s", async fail => {
  const realImport = crypto.subtle.importKey.bind(crypto.subtle), realDerive = crypto.subtle.deriveBits.bind(crypto.subtle);
  const inputs: Uint8Array[] = [], outputs: Uint8Array[] = [], failure = new Error("HKDF device failure"), original = key.slice();
  vi.spyOn(crypto.subtle, "importKey").mockImplementation(async (...args) => {
    if (args[0] === "raw" && args[2] === "HKDF") { const value = args[1] as Uint8Array; inputs.push(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)); }
    return realImport(...args);
  });
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { if (fail) throw failure; const output = await realDerive(...args); outputs.push(new Uint8Array(output)); return output; });
  const operation = newWriteGeneration(owner, key);
  if (fail) await expect(operation).rejects.toBe(failure); else expect(JSON.parse(await operation).keyTag).toBe(tag(key));
  expect(inputs.length).toBeGreaterThan(0); for (const secret of [...inputs, ...outputs]) expect(secret).toEqual(new Uint8Array(secret.length)); expect(key).toEqual(original);
});
it("does not create a marker on a legacy installation or rewrite an already verified generation", async () => {
  await kv.adoptVerifiedWriteGeneration(owner, key); expect(await kv.getItem(writeGenerationKey(owner))).toBeNull();
  const generation = await initialize(); await kv.adoptVerifiedWriteGeneration(owner, key);
  expect(await kv.getItem(writeGenerationKey(owner))).toBe(generation);
});
it("adopts a fresh authenticated account key without changing writing, and fences the old producer", async () => {
  await initialize(); const oldPermit = await kv.captureWritePermit(owner, key); await kv.setItem(content, "recoverable ciphertext", oldPermit);
  await kv.adoptVerifiedWriteGeneration(owner, incoming); const current = JSON.parse((await kv.getItem(writeGenerationKey(owner)))!);
  expect(current.keyTag).toBe(tag(incoming)); expect(current.deleted).toBe(false); expect(await kv.getItem(content)).toBe("recoverable ciphertext");
  await expect(kv.setItem(content, "retired callback", oldPermit)).rejects.toBeInstanceOf(StorageCommitError);
  await kv.setItem(content, "fresh ciphertext", await kv.captureWritePermit(owner, incoming)); expect(await kv.getItem(content)).toBe("fresh ciphertext");
});
it("refuses account changes both before work and inside the atomic commit", async () => {
  const generation = await initialize(); await kv.adoptVerifiedWriteGeneration(owner, incoming, () => false);
  expect(await kv.getItem(writeGenerationKey(owner))).toBe(generation);
  let current = true;
  const original = kv.compareAndSetForMigration.bind(kv);
  vi.spyOn(kv, "compareAndSetForMigration").mockImplementation(async (...args) => { current = false; return original(...args); });
  await expect(kv.adoptVerifiedWriteGeneration(owner, incoming, () => current)).rejects.toBeInstanceOf(StorageCommitError);
  expect(await kv.getItem(writeGenerationKey(owner))).toBe(generation);
});
it("exposes the authenticated-owner refusal through the public migration error cause", async () => {
  await kv.setItem("unscoped", "before");
  try { await kv.compareAndSetForMigration("unscoped", "before", "wrong", undefined, () => false); throw new Error("expected owner refusal"); }
  catch (error) { expect(error).toBeInstanceOf(StorageCommitError); expect((error as Error).cause).toMatchObject({ name: "Error", message: "The authenticated unlock changed before storage committed." }); }
  expect(await kv.getItem("unscoped")).toBe("before");
});
it("reports a superseded producer and a pending key migration through actual public storage error causes", async () => {
  await initialize(); const permit = await kv.captureWritePermit(owner, key);
  try { await kv.setItem(content, "wrong", { ...permit, generation: null }); throw new Error("expected retired producer refusal"); }
  catch (error) { expect((error as Error).cause).toMatchObject({ message: "This writing belongs to an earlier account-key generation; the current record was retained." }); }
  await kv.setItem(`mindpattern.localRotation.${owner}`, "retained opaque migration checkpoint");
  try { await kv.setItem(content, "wrong", permit); throw new Error("expected migration refusal"); }
  catch (error) { expect((error as Error).cause).toMatchObject({ message: "A key migration is pending; keep this writing open and finish recovery before saving." }); }
  expect(await kv.getItem(content)).toBeNull();
});
it("refuses a metadata-only generation permit when its consumer requires proof of encrypted writing", async () => {
  const permit = await kv.captureWritePermit(owner);
  await expect(enqueue({ userId: owner, clientEntryId: "metadata-is-not-encryption-proof", blobB64: "retained caller ciphertext", entryDate: "2026-10-05" }, permit)).rejects.toBeInstanceOf(StorageCommitError);
});
it("keeps the original generation when concurrent changes prevent bounded adoption or erasure", async () => {
  const generation = await initialize(); vi.spyOn(kv, "compareAndSetForMigration").mockResolvedValue(false);
  await expect(kv.adoptVerifiedWriteGeneration(owner, incoming)).rejects.toThrow("changed during unlock");
  await expect(kv.markOwnerErased(owner)).rejects.toThrow("could not fence");
  expect(await kv.getItem(writeGenerationKey(owner))).toBe(generation);
});
it.each(["adoption", "erasure"])("retains records and asks the caller to retry after five failed atomic %s attempts", async operation => {
  const generation = await initialize();
  const realCompare = kv.compareAndSetForMigration.bind(kv); let contentionRemaining = 5;
  vi.spyOn(kv, "compareAndSetForMigration").mockImplementation(async (...args) => {
    if (contentionRemaining-- > 0) return false;
    return realCompare(...args);
  });
  const promise = operation === "adoption" ? kv.adoptVerifiedWriteGeneration(owner, incoming) : kv.markOwnerErased(owner);
  await expect(promise).rejects.toBeInstanceOf(StorageCommitError);
  expect(await kv.getItem(writeGenerationKey(owner))).toBe(generation);
});
it.each([
  "{", "null", "[]", JSON.stringify({}),
  { v: 2 }, { nonce: "A".repeat(32) }, { nonce: "a".repeat(31) }, { nonce: "x" + "a".repeat(32) }, { nonce: "a".repeat(32) + "x" },
  { deleted: "false" }, { deleted: null }, { keyTag: 1 }, { keyTag: "a".repeat(42) + "=" }, { keyTag: "a".repeat(43) },
  { keyTag: "a".repeat(43) + "=extra" }, { keyTag: "!" + "a".repeat(42) + "=" }, { keyTag: "prefix" + "a".repeat(43) + "=" }, { keyTag: [tag(key)] },
])("retains malformed generation metadata and rejects writing instead of guessing ownership: %#", async fields => {
  const raw = typeof fields === "string" ? fields : JSON.stringify({ v: 1, nonce: "a".repeat(32), deleted: false, keyTag: tag(key), ...fields });
  await kv.setItem(writeGenerationKey(owner), raw);
  await expect(kv.captureWritePermit(owner, key)).rejects.toBeDefined();
  await expect(kv.captureWritePermit(owner)).rejects.toBeDefined();
  await expect(kv.setItem(content, "unverified ciphertext")).rejects.toBeInstanceOf(StorageCommitError);
  expect(await kv.getItem(content)).toBeNull(); expect(await kv.getItem(writeGenerationKey(owner))).toBe(raw);
});
it("presents a local generation corruption explanation to a caller instead of an empty error", async () => {
  await kv.setItem(writeGenerationKey(owner), "{}");
  try { await kv.captureWritePermit(owner); throw new Error("expected refusal"); }
  catch (error) { expect(displayError(error, "Retry")).toBe("The local writing generation is unreadable; records were retained."); }
});
it("reopens the actual database after the browser forcibly closes a connection", async () => {
  const factory = new IDBFactory(), original = factory.open.bind(factory); let opened: IDBDatabase | undefined;
  vi.spyOn(factory, "open").mockImplementation((...args) => { const request = original(...args); request.addEventListener("success", () => { opened = request.result; }); return request; });
  vi.stubGlobal("indexedDB", factory); await kv.setItem("reopen", "recoverable");
  // fake-indexeddb's declaration uses the constructor type for this
  // instance-taking helper; its implementation closes the supplied DB.
  forceCloseDatabase(opened! as unknown as Parameters<typeof forceCloseDatabase>[0]); await new Promise(resolve => setTimeout(resolve, 10));
  expect(await kv.getItem("reopen")).toBe("recoverable"); await kv.setItem("reopen", "resumed"); expect(await kv.getItem("reopen")).toBe("resumed");
});
it.each(["throw", "error", "blocked"])("does not acknowledge unavailable IndexedDB after an open %s and retries a healthy backend", async fault => {
  const request = { onerror: null, onblocked: null } as unknown as IDBOpenDBRequest;
  vi.stubGlobal("indexedDB", { open: () => { if (fault === "throw") throw new Error("browser denied storage"); queueMicrotask(() => { if (fault === "error") request.onerror?.(new Event("error")); else request.onblocked?.(Object.assign(new Event("blocked"), { oldVersion: 0, newVersion: 1 })); }); return request; } });
  await expect(kv.setItem("x", "value")).rejects.toBeInstanceOf(StorageCommitError);
  vi.stubGlobal("indexedDB", new IDBFactory()); await kv.setItem("x", "value"); expect(await kv.getItem("x")).toBe("value");
});
it("returns an empty key list only when an otherwise usable injected backend has no enumeration surface", async () => {
  setKvBackendForTests({ getItem: async () => null, setItem: async () => {}, removeItem: async () => {} }); expect(await kv.keys()).toEqual([]);
});
it.each(["read", "compare", "generation", "checkpoint", "erasure"])("preserves the actual browser request error when a %s transaction aborts", async fault => {
  await kv.setItem(content, "retained writing"); const permit = await kv.captureWritePermit(owner, key);
  if (fault === "erasure") await kv.markOwnerErased(owner);
  const target = fault === "read" || fault === "compare" ? (fault === "compare" ? "unscoped" : content)
    : fault === "generation" ? writeGenerationKey(owner) : fault === "checkpoint" ? `mindpattern.localRotation.${owner}` : `mindpattern.erase.${owner}`;
  const original = IDBObjectStore.prototype.get; let browserError: unknown;
  vi.spyOn(IDBObjectStore.prototype, "get").mockImplementation(function (this: IDBObjectStore, query) {
    const request = original.call(this, query);
    if (query === target) { request.addEventListener("error", () => { browserError = request.error; }); queueMicrotask(() => this.transaction.abort()); }
    return request;
  });
  const operation = fault === "read" ? kv.getItem(content) : fault === "compare" ? kv.compareAndSetForMigration("unscoped", null, "candidate")
    : fault === "erasure" ? kv.removeItem(content) : kv.setItem(content, "wrong replacement", permit);
  try { await operation; throw new Error("expected aborted browser operation"); }
  catch (error) { expect(error).toBeInstanceOf(fault === "read" ? StorageReadError : StorageCommitError); expect(browserError).toMatchObject({ name: "AbortError" }); expect((error as Error).cause).toBe(browserError); }
  vi.restoreAllMocks(); expect(await kv.getItem(content)).toBe("retained writing");
});
it("preserves a browser enumeration failure instead of reporting an empty device", async () => {
  await kv.setItem("retained", "writing"); const original = IDBObjectStore.prototype.getAllKeys; let browserError: unknown;
  vi.spyOn(IDBObjectStore.prototype, "getAllKeys").mockImplementation(function (this: IDBObjectStore, ...args) {
    const request = original.apply(this, args); request.addEventListener("error", () => { browserError = request.error; }); queueMicrotask(() => this.transaction.abort()); return request;
  });
  try { await kv.keys(); throw new Error("expected failed enumeration"); }
  catch (error) { expect(error).toBeInstanceOf(StorageReadError); expect(browserError).toMatchObject({ name: "AbortError" }); expect((error as Error).cause).toBe(browserError); }
  vi.restoreAllMocks(); expect(await kv.keys()).toEqual(["retained"]);
});
it("keeps a deleted account fenced after checkpoint cleanup and never revives its generation", async () => {
  await initialize(); await kv.setItem(content, "retained ciphertext", await kv.captureWritePermit(owner, key)); await kv.markOwnerErased(owner);
  const marker = (await kv.getItem(writeGenerationKey(owner)))!; expect(JSON.parse(marker)).toMatchObject({ v: 1, deleted: true });
  await kv.markOwnerErased(owner); expect(await kv.getItem(writeGenerationKey(owner))).toBe(marker);
  await expect(kv.adoptVerifiedWriteGeneration(owner, incoming)).rejects.toThrow("were erased");
  await expect(kv.captureWritePermit(owner)).rejects.toBeInstanceOf(StorageCommitError);
  await expect(kv.setItem(metadata, "new metadata")).rejects.toBeInstanceOf(StorageCommitError);
  await expect(kv.removeItem(content)).rejects.toBeInstanceOf(StorageCommitError); expect(await kv.getItem(content)).toBe("retained ciphertext");
  await kv.setItem(`mindpattern.draft.active.${other}`, "other owner"); expect(await kv.getItem(`mindpattern.draft.active.${other}`)).toBe("other owner");
});
it.each([{ v: 2, owner, remoteConfirmed: true }, { v: 1, owner: other, remoteConfirmed: true }, { v: 1, owner, remoteConfirmed: false }, { v: 1, owner, remoteConfirmed: "true" }])
  ("does not delete fenced writing under a malformed or unconfirmed erasure checkpoint: %j", async row => {
    await kv.setItem(content, "retained ciphertext"); await kv.markOwnerErased(owner); await kv.setItem(`mindpattern.erase.${owner}`, JSON.stringify(row));
    await expect(kv.removeItem(content)).rejects.toBeInstanceOf(StorageCommitError); expect(await kv.getItem(content)).toBe("retained ciphertext");
  });
it("permits confirmed erasure to remove writing while retaining the minimal deleted fence", async () => {
  await kv.setItem(content, "confirmed ciphertext"); await kv.markOwnerErased(owner);
  await kv.setItem(`mindpattern.erase.${owner}`, JSON.stringify({ v: 1, owner, remoteConfirmed: true }));
  await kv.removeItem(content); expect(await kv.getItem(content)).toBeNull(); expect(JSON.parse((await kv.getItem(writeGenerationKey(owner)))!).deleted).toBe(true);
  await expect(kv.setItem(content, "revived writing")).rejects.toBeInstanceOf(StorageCommitError); expect(await kv.getItem(content)).toBeNull();
});
it("deletes every requested key on the actual backend without deleting unrelated writing", async () => {
  await kv.setItem("first", "one"); await kv.setItem("retained", "two"); await kv.setItem("last", "three");
  await kv.multiRemove(["first", "last"]); expect(await kv.keys()).toEqual(["retained"]); expect(await kv.getItem("retained")).toBe("two");
});
it("exposes missing durability and missing atomic comparison as actionable public error causes", async () => {
  vi.stubGlobal("indexedDB", undefined);
  try { await kv.setItem("x", "writing"); throw new Error("expected durability refusal"); }
  catch (error) { expect((error as Error).cause).toMatchObject({ name: "StorageCommitError", message: "Durable storage is unavailable — keep this writing open and retry when storage is available." }); }
  setKvBackendForTests({ getItem: async () => "before", setItem: async () => {}, removeItem: async () => {} });
  try { await kv.compareAndSetForMigration("x", "before", "after"); throw new Error("expected atomicity refusal"); }
  catch (error) { expect((error as Error).cause).toMatchObject({ name: "Error", message: "Atomic storage comparison is unavailable; the migration checkpoint was retained." }); }
});
it("compares absent and present records in an actual atomic transaction and returns commit truth", async () => {
  expect(await kv.compareAndSetForMigration("unscoped", "wrong", "after")).toBe(false);
  expect(await kv.compareAndSetForMigration("unscoped", null, "initial")).toBe(true);
  expect(await kv.compareAndSetForMigration("unscoped", null, "wrong")).toBe(false);
  expect(await kv.compareAndSetForMigration("unscoped", "initial", "after")).toBe(true); expect(await kv.getItem("unscoped")).toBe("after");
  await expect(kv.compareAndSetForMigration("unscoped", "after", "retired", undefined, () => false)).rejects.toBeInstanceOf(StorageCommitError);
  expect(await kv.getItem("unscoped")).toBe("after");
});
it("refuses wrong-owner and superseded generation permits on both writes and atomic migrations", async () => {
  await initialize(); const permit = await kv.captureWritePermit(owner, key); await kv.setItem(content, "before", permit);
  for (const stale of [{ ...permit, owner: other }, { ...permit, generation: null }]) {
    await expect(kv.setItem(content, "wrong", stale)).rejects.toBeInstanceOf(StorageCommitError);
    await expect(kv.compareAndSetForMigration(content, "before", "wrong", stale)).rejects.toBeInstanceOf(StorageCommitError);
  }
  expect(await kv.getItem(content)).toBe("before");
});
it("preserves typed error causes for each failed storage surface and retries after unavailable storage", async () => {
  const failure = new Error("device failed"); setKvBackendForTests({ getItem: async () => { throw failure; }, setItem: async () => { throw failure; }, removeItem: async () => { throw failure; }, keys: async () => { throw failure; }, compareAndSet: async () => { throw failure; } });
  for (const run of [() => kv.getItem("x"), () => kv.keys()]) { try { await run(); throw new Error("expected rejection"); } catch (error) { expect(error).toBeInstanceOf(StorageReadError); expect((error as Error).name).toBe("StorageReadError"); expect((error as Error).cause).toBe(failure); expect(displayError(error, "Retry")).not.toBe(""); } }
  for (const run of [() => kv.setItem("x", "value"), () => kv.removeItem("x"), () => kv.compareAndSetForMigration("x", null, "value")]) {
    try { await run(); throw new Error("expected rejection"); } catch (error) { expect(error).toBeInstanceOf(StorageCommitError); expect((error as Error).name).toBe("StorageCommitError"); expect((error as Error).cause).toBe(failure); expect(displayError(error, "Retry")).not.toBe(""); }
  }
  setKvBackendForTests(null); vi.stubGlobal("indexedDB", undefined); await expect(kv.setItem("x", "value")).rejects.toBeInstanceOf(StorageCommitError);
  vi.stubGlobal("indexedDB", new IDBFactory()); await kv.setItem("x", "value"); expect(await kv.getItem("x")).toBe("value"); expect(await kv.keys()).toEqual(["x"]);
});
