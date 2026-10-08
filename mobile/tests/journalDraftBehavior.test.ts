import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv } from "node:crypto";
import storage from "./helpers/storageMock";
import { engine } from "./helpers/nodeEngine";
import { runTestControl } from "./helpers/testControl";
import { setSecureStoreBackend } from "../src/secureStore";
import { accountStorageKey } from "../src/accountStorage";
import { setBaseUrl } from "../src/api/client";
import { __resetLocalKeyLifecycleForTests, changeLocalSessionOwner } from "../src/localWriteGuard";
import { __resetJournalDraftRuntimeForTests, acknowledgeJournalDraft, journalDraftScope, loadJournalDraft, newJournalDraft, saveJournalDraft, waitJournalDraftWrites, type JournalDraft, type JournalDraftScope } from "../src/journalDraft";

const owner = "11111111111111111111111111111111", key = Buffer.alloc(32, 19);
let scope: JournalDraftScope;
function deferred() { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; }
async function turn() { await new Promise<void>(resolve => setImmediate(resolve)); }
const draft = (): JournalDraft => ({ v: 1, editorId: "0123456789abcdef0123456789abcdef", revision: 1, text: "Held native journal plaintext", mood: 0, energy: 3, sleep: 4, tags: ["work"] });
function sealed(value: unknown): string {
  const nonce = Buffer.alloc(12, 5), cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["journal-draft", owner, scope.origin])));
  return Buffer.concat([nonce, cipher.update(JSON.stringify(value)), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
beforeEach(async () => {
  vi.restoreAllMocks(); await waitJournalDraftWrites(); runTestControl(__resetJournalDraftRuntimeForTests); runTestControl(__resetLocalKeyLifecycleForTests);
  storage.__reset(); runTestControl(setSecureStoreBackend, null); await setBaseUrl("http://localhost:8000"); scope = await journalDraftScope(owner);
});
afterEach(async () => { vi.restoreAllMocks(); await waitJournalDraftWrites(); });

it("creates a new empty editor with a fresh usable identifier and neutral metadata", () => {
  const first = newJournalDraft(), second = newJournalDraft();
  expect(first).toMatchObject({ v: 1, revision: 0, text: "", mood: null, energy: null, sleep: null, tags: [] });
  expect(first.editorId).toMatch(/^[a-f0-9]{32}$/); expect(second.editorId).toMatch(/^[a-f0-9]{32}$/); expect(second.editorId).not.toBe(first.editorId);
});

it("accepts each inclusive metadata boundary through save and independently sealed restore", async () => {
  const cases: JournalDraft[] = [
    { ...draft(), text: "x".repeat(100_000), mood: -1, energy: -1, sleep: 1, tags: Array(200).fill("t".repeat(200)) },
    { ...draft(), mood: 1, energy: 5, sleep: 5, revision: Number.MAX_SAFE_INTEGER },
    { ...draft(), mood: null, energy: null, sleep: null, revision: 0, tags: [] },
  ];
  for (const value of cases) {
    await storage.removeItem(scope.slot); await saveJournalDraft(key, scope, value);
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(value);
    await storage.setItem(scope.slot, sealed(value)); expect((await loadJournalDraft(key, scope))?.draft).toEqual(value);
  }
});

it.each([
  { editorId: "x0123456789abcdef0123456789abcdef" }, { editorId: "0123456789abcdef0123456789abcdefx" },
  { text: 42 }, { text: { length: 1 } }, { tags: [42] }, { tags: [{ length: 1 }] }, { tags: ["t".repeat(201)] }, { tags: Array(201).fill("t") },
  { revision: 0.5 }, { revision: Number.MAX_SAFE_INTEGER + 1 }, { mood: -1.01 }, { mood: 1.01 },
  { energy: -1.01 }, { energy: 5.01 }, { sleep: 0.99 }, { sleep: 5.01 }, { mood: false }, { energy: "3" }, { sleep: "4" },
])("retains authenticated malformed metadata %j and refuses its publication", async patch => {
  const value = { ...draft(), ...patch } as JournalDraft, raw = sealed(value);
  await storage.setItem(scope.slot, raw);
  await expect(loadJournalDraft(key, scope)).rejects.toThrow("ciphertext was retained");
  await expect(saveJournalDraft(key, scope, value)).rejects.toThrow("Invalid journal draft");
  expect(await storage.getItem(scope.slot)).toBe(raw);
});

it.each([null, false, 42, "text", [], {}])("retains authenticated non-draft JSON %j", async value => {
  const raw = sealed(value); await storage.setItem(scope.slot, raw);
  await expect(loadJournalDraft(key, scope)).rejects.toThrow("ciphertext was retained"); expect(await storage.getItem(scope.slot)).toBe(raw);
});

it.each([null, false, 42, "text", [], {}])("rejects a non-draft publication %j with the promised validation error", async value => {
  await expect((async () => saveJournalDraft(key, scope, value as JournalDraft))()).rejects.toThrow("Invalid journal draft");
  expect(await loadJournalDraft(key, scope)).toBeNull();
});

it("does not accept a callable object as a typed editor draft", async () => {
  const callable = Object.assign(() => undefined, draft());
  await expect(saveJournalDraft(key, scope, callable)).rejects.toThrow("Invalid journal draft");
  expect(await loadJournalDraft(key, scope)).toBeNull();
});

it("rejects absent ownership and URL path scopes even when their storage slot is self-consistent", async () => {
  for (const invalid of [
    { userId: "", origin: scope.origin, slot: accountStorageKey.journalDraft(scope.origin, "") },
    { userId: owner, origin: `${scope.origin}/private`, slot: accountStorageKey.journalDraft(`${scope.origin}/private`, owner) },
  ]) await expect(loadJournalDraft(key, invalid)).rejects.toThrow("Invalid draft account/server scope");
  expect(await loadJournalDraft(key, scope)).toBeNull();
});

it("validates an acknowledgement scope before touching an unrelated native slot", () => {
  const value = draft();
  expect(() => acknowledgeJournalDraft(key, { ...scope, slot: "another native account slot" }, value.editorId, value.revision)).toThrow("Invalid draft account/server scope");
});

it.each([false, true])("scrubs the key and plaintext seen by native encryption after commit failure=%s", async failure => {
  const keys: Buffer[] = [], plaintexts: Buffer[] = [], create = engine.createCipheriv.bind(engine);
  vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, received, nonce) => {
    keys.push(received as Buffer); const cipher = create(algorithm, received, nonce), update = cipher.update.bind(cipher);
    vi.spyOn(cipher, "update").mockImplementation((value: Buffer) => { plaintexts.push(value); return update(value); }); return cipher;
  });
  if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("native draft commit failed"));
  const operation = saveJournalDraft(key, scope, draft());
  if (failure) await expect(operation).rejects.toThrow("native draft commit failed"); else await expect(operation).resolves.toBe("saved");
  expect(keys.length).toBeGreaterThan(0); expect(plaintexts.length).toBeGreaterThan(0);
  for (const allocation of [...keys, ...plaintexts]) { expect(allocation).not.toBe(key); expect(allocation.every(byte => byte === 0)).toBe(true); }
  expect(key).toEqual(Buffer.alloc(32, 19));
});

it.each(["load", "acknowledge", "save-conflict"])("scrubs native decryption key and the parsed plaintext after %s", async action => {
  const value = draft(), raw = sealed(value); await storage.setItem(scope.slot, raw);
  const keys: Buffer[] = [], parsed: Buffer[] = [], create = engine.createDecipheriv.bind(engine), stringify = Buffer.prototype.toString;
  vi.spyOn(engine, "createDecipheriv").mockImplementation((algorithm, received, nonce) => { keys.push(received as Buffer); return create(algorithm, received, nonce); });
  vi.spyOn(Buffer.prototype, "toString").mockImplementation(function(this: Buffer, ...args: any[]) {
    const result = stringify.apply(this, args as [BufferEncoding?, number?, number?]); if (result === JSON.stringify(value)) parsed.push(this); return result;
  });
  if (action === "load") expect((await loadJournalDraft(key, scope))?.draft).toEqual(value);
  else if (action === "acknowledge") await expect(acknowledgeJournalDraft(key, scope, value.editorId, value.revision)).resolves.toBe(true);
  else await expect(saveJournalDraft(key, scope, { ...value, text: "Changed equal revision" })).rejects.toThrow("Another editor changed this draft");
  expect(keys.length).toBeGreaterThan(0); expect(parsed.length).toBeGreaterThan(0);
  for (const allocation of [...keys, ...parsed]) { expect(allocation).not.toBe(key); expect(allocation.every(byte => byte === 0)).toBe(true); }
  expect(key).toEqual(Buffer.alloc(32, 19));
});

it("keeps every queued save and restore behind submitted native commits", async () => {
  const first = deferred(), second = deferred(), entered = [deferred(), deferred()], original = storage.setItem;
  let count = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, raw) => {
    if (slot === scope.slot && count < 2) { const index = count++; entered[index]!.resolve(); await (index === 0 ? first : second).promise; } return original(slot, raw);
  });
  const base = draft(), firstWrite = saveJournalDraft(key, scope, base);
  await Promise.race([entered[0]!.promise, firstWrite.then(() => { throw new Error("First save skipped its native commit"); })]);
  const next = { ...base, revision: 2, text: "second queued write" }, secondWrite = saveJournalDraft(key, scope, next);
  let drained = false; const drain = waitJournalDraftWrites().then(() => { drained = true; });
  let restored = false; const restore = loadJournalDraft(key, scope).then(value => { restored = true; return value; });
  await turn(); expect(drained).toBe(false); expect(restored).toBe(false);
  first.resolve(); await firstWrite;
  await Promise.race([entered[1]!.promise, secondWrite.then(() => { throw new Error("Second save skipped its native commit"); })]);
  const latest = { ...base, revision: 3, text: "third queued write" }, thirdWrite = saveJournalDraft(key, scope, latest);
  await turn(); expect(drained).toBe(false); expect(restored).toBe(false);
  second.resolve(); await secondWrite; await thirdWrite; await drain; await restore;
  expect((await loadJournalDraft(key, scope))?.draft).toEqual(latest);
});

it("uses the caller's immutable content snapshot while a save waits in the native queue", async () => {
  const gate = deferred(), entered = deferred(), original = storage.getItem; let once = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === scope.slot && once) { once = false; entered.resolve(); await gate.promise; } return original(slot); });
  const value = draft(), operation = saveJournalDraft(key, scope, value);
  await Promise.race([entered.promise, operation.then(() => { throw new Error("Save skipped its queued native read"); })]);
  value.text = "later caller edit"; value.tags.push("later-tag"); gate.resolve(); await operation;
  expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft());
});

it("refuses acknowledgement admitted before its account scope was replaced", async () => {
  const value = draft(); await saveJournalDraft(key, scope, value);
  const pending = acknowledgeJournalDraft(key, scope, value.editorId, value.revision).catch(error => error);
  changeLocalSessionOwner(owner); expect(await pending).toBeInstanceOf(Error); expect((await loadJournalDraft(key, scope))?.draft).toEqual(value);
});

it("supersedes revision zero after an acknowledgement and keeps a later acknowledgement high-water mark", async () => {
  const base = { ...draft(), revision: 0 };
  await acknowledgeJournalDraft(key, scope, base.editorId, 0); expect(await saveJournalDraft(key, scope, base)).toBe("superseded");
  await acknowledgeJournalDraft(key, scope, base.editorId, 8); await acknowledgeJournalDraft(key, scope, base.editorId, 3);
  expect(await saveJournalDraft(key, scope, { ...base, revision: 5 })).toBe("superseded"); expect(await loadJournalDraft(key, scope)).toBeNull();
});

it("does not need a native read to reject an already acknowledged callback", async () => {
  const value = draft(); await acknowledgeJournalDraft(key, scope, value.editorId, value.revision);
  vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native storage is unavailable"));
  await expect(saveJournalDraft(key, scope, value)).resolves.toBe("superseded");
});

it.each([0, 5])("supersedes revision %s whose durable acknowledgement arrives during its native read", async revision => {
  const gate = deferred(), entered = deferred(), original = storage.getItem; let once = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot === scope.slot && once) { once = false; entered.resolve(); await gate.promise; } return original(slot);
  });
  const value = { ...draft(), revision }, save = saveJournalDraft(key, scope, value);
  await Promise.race([entered.promise, save.then(() => { throw new Error("Save skipped its native read"); })]);
  const ack = acknowledgeJournalDraft(key, scope, value.editorId, value.revision);
  gate.resolve(); await expect(save).resolves.toBe("superseded"); await expect(ack).resolves.toBe(true); expect(await loadJournalDraft(key, scope)).toBeNull();
});

it("does not let a revision-zero acknowledgement suppress a later revision", async () => {
  const value = draft(); await acknowledgeJournalDraft(key, scope, value.editorId, 0);
  await expect(saveJournalDraft(key, scope, value)).resolves.toBe("saved"); expect((await loadJournalDraft(key, scope))?.draft).toEqual(value);
});

it("allows an exact-ciphertext replacement by a new editor regardless of the former editor's revision", async () => {
  const previous = { ...draft(), revision: 9 }, replacement = { ...draft(), editorId: "fedcba9876543210fedcba9876543210", text: "Explicit editor replacement" };
  await saveJournalDraft(key, scope, previous); const loaded = (await loadJournalDraft(key, scope))!;
  await expect(saveJournalDraft(key, scope, replacement, loaded.ciphertext)).resolves.toBe("saved"); expect((await loadJournalDraft(key, scope))?.draft).toEqual(replacement);
});

it.each(["save", "acknowledge"])("refuses a queued %s from a retired account before reading native storage", async action => {
  const value = draft(); vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native draft read unavailable"));
  const operation = action === "save" ? saveJournalDraft(key, scope, value) : acknowledgeJournalDraft(key, scope, value.editorId, value.revision);
  const completion = operation.catch(error => error); changeLocalSessionOwner(owner);
  expect(await completion).toMatchObject({ message: "The local write belongs to a retired account or key generation" });
});

it("reports a retired save even when an acknowledgement also arrives during its native read", async () => {
  const gate = deferred(), entered = deferred(), original = storage.getItem; let once = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot === scope.slot && once) { once = false; entered.resolve(); await gate.promise; } return original(slot);
  });
  const value = draft(), save = saveJournalDraft(key, scope, value), completion = save.catch(error => error);
  await Promise.race([entered.promise, completion.then(() => { throw new Error("Save skipped its native read"); })]);
  const ack = acknowledgeJournalDraft(key, scope, value.editorId, value.revision).catch(error => error);
  changeLocalSessionOwner(owner); gate.resolve();
  expect(await completion).toMatchObject({ message: "The local write belongs to a retired account or key generation" });
  expect(await ack).toBeInstanceOf(Error);
});
