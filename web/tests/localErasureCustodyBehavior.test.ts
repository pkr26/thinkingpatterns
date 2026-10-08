/** Exported erasure/KvBackend/browser-preference contracts; no rendered App
 * or real IndexedDB engine claim. Crypto and public version mirrors are real. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { kv, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { stageLocalErasure, confirmLocalErasure, confirmRemoteLocalErasure, pendingLocalErasures, resumeConfirmedErasures } from "../src/localErasure";
import { knownEntryVersion, observeEntryVersions, resetEntryVersionMirrors } from "../src/entryVersions";
import { withLock } from "../src/platform";
const owner = "erasure-custody", other = "unrelated-custody", id = `mindpattern.erase.${owner}`, plan = `mindpattern.safetyPlan.${owner}`;
let physical: Map<string, string>;
const row = () => ({ v: 1, owner, remoteConfirmed: false, keys: [plan] });
beforeEach(() => {
  physical = new Map(); resetEntryVersionMirrors();
  setKvBackendForTests({
    async getItem(key) { return physical.get(key) ?? null; },
    async setItem(key, value) { physical.set(key, value); },
    async removeItem(key) { physical.delete(key); },
    async keys() { return [...physical.keys()]; },
    async compareAndSet(key, expected, value) { if ((physical.get(key) ?? null) !== expected) return false; physical.set(key, value); return true; },
  });
  window.localStorage.clear(); window.sessionStorage.clear();
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); setKvBackendForTests(null); resetEntryVersionMirrors(); window.localStorage.clear(); window.sessionStorage.clear(); });
const malformed = [
  { v: 2 }, { owner: "" }, { owner: other },
  { remoteConfirmed: null }, { remoteConfirmed: "yes" }, { remoteConfirmed: 1 },
  { keys: null }, { keys: {} }, { keys: "not an array" },
  { keys: [0] }, { keys: [null] },
  { keys: [plan, `mindpattern.safetyPlan.${other}`] },
  { owner: other, keys: [] },
];
it.each(malformed)("refuses a malformed durable erasure checkpoint without consuming its ciphertext: %j", async fields => {
  physical.set(plan, "retained encrypted plan");
  const raw = JSON.stringify({ ...row(), ...fields }); physical.set(id, raw);
  const before = [...physical];
  await expect(pendingLocalErasures()).rejects.toThrow("unreadable");
  expect([...physical]).toEqual(before);
});
it("accepts a valid empty checkpoint and preserves every unconfirmed deletion", async () => {
  physical.set(id, JSON.stringify({ ...row(), keys: [] }));
  expect(await pendingLocalErasures()).toEqual([{ ...row(), keys: [] }]);
  expect(await resumeConfirmedErasures()).toEqual([{ ...row(), keys: [] }]);
});
it("validates an existing checkpoint before returning from stage", async () => {
  const raw = JSON.stringify({ ...row(), remoteConfirmed: "invalid" }); physical.set(id, raw);
  await expect(stageLocalErasure(owner)).rejects.toThrow("unreadable"); expect(physical.get(id)).toBe(raw);
});
it("resumes only the confirmed member of a mixed checkpoint batch", async () => {
  physical.set(plan, "deleted owner encrypted plan"); physical.set(id, JSON.stringify({ ...row(), remoteConfirmed: true }));
  const otherId = `mindpattern.erase.${other}`, otherPlan = `mindpattern.safetyPlan.${other}`;
  const retained = { v: 1, owner: other, remoteConfirmed: false, keys: [otherPlan] };
  physical.set(otherPlan, "unconfirmed encrypted plan"); physical.set(otherId, JSON.stringify(retained));
  expect(await resumeConfirmedErasures()).toEqual([retained]); expect(physical.has(plan)).toBe(false); expect(physical.get(otherPlan)).toBe("unconfirmed encrypted plan");
});
it("an already staged checkpoint preserves the original captured deletion registry", async () => {
  const original = { ...row(), keys: [] }; physical.set(id, JSON.stringify(original)); physical.set(plan, "a later encrypted plan");
  await stageLocalErasure(owner); expect(JSON.parse(physical.get(id)!)).toEqual(original);
});
it("a newly staged checkpoint captures every owner key and no unrelated ciphertext", async () => {
  const foreign = `mindpattern.safetyPlan.${other}`;
  physical.set(plan, "our encrypted plan"); physical.set(foreign, "unrelated encrypted plan");
  await stageLocalErasure(owner);
  expect(JSON.parse(physical.get(id)!)).toEqual(row());
  expect(physical.get(foreign)).toBe("unrelated encrypted plan");
});
it("a remote confirmation creates an owner-only checkpoint before a failed physical removal", async () => {
  const foreign = `mindpattern.safetyPlan.${other}`; physical.set(plan, "retained encrypted plan"); physical.set(foreign, "unrelated ciphertext");
  const remove = kv.removeItem.bind(kv);
  vi.spyOn(kv, "removeItem").mockImplementation(async key => { if (key === plan) throw new Error("physical removal failed"); return remove(key); });
  await expect(confirmRemoteLocalErasure(owner)).rejects.toThrow("physical removal failed");
  expect(JSON.parse(physical.get(id)!)).toEqual({ ...row(), remoteConfirmed: true }); expect(physical.get(foreign)).toBe("unrelated ciphertext");
});
it("erases late owner ciphertext and only the app-owned browser preferences in both stores", async () => {
  physical.set(id, JSON.stringify({ ...row(), keys: [] })); physical.set(plan, "late encrypted plan");
  const deletedFence = JSON.stringify({ v: 1, nonce: "a".repeat(32), deleted: true }); physical.set(writeGenerationKey(owner), deletedFence);
  const ours = `mindpattern.setting.${owner}`, unrelated = `another-app.setting.${owner}`, foreign = `mindpattern.setting.${other}`;
  for (const storage of [window.localStorage, window.sessionStorage]) { storage.setItem(ours, "our non-content preference"); storage.setItem(unrelated, "unrelated app preference"); storage.setItem(foreign, "other account preference"); }
  await confirmLocalErasure(owner);
  expect(physical.has(plan)).toBe(false); expect(physical.get(writeGenerationKey(owner))).toBe(deletedFence);
  for (const storage of [window.localStorage, window.sessionStorage]) { expect(storage.getItem(ours)).toBeNull(); expect(storage.getItem(unrelated)).toBe("unrelated app preference"); expect(storage.getItem(foreign)).toBe("other account preference"); }
});
it("confirmed erasure removes the public process version memory after deleting its durable ciphertext", async () => {
  const key = new Uint8Array(32).fill(71), entry = "erased-entry";
  await observeEntryVersions(owner, key, [{ clientEntryId: entry, contentVersion: 7 }]);
  expect(await knownEntryVersion(owner, key, entry)).toBe(7);
  await stageLocalErasure(owner); await confirmLocalErasure(owner);
  expect(await knownEntryVersion(owner, key, entry)).toBeNull();
});
it("a remote confirmation preserves a previously captured empty registry before a failed late removal", async () => {
  physical.set(id, JSON.stringify({ ...row(), keys: [] })); physical.set(plan, "late encrypted plan");
  const remove = kv.removeItem.bind(kv);
  vi.spyOn(kv, "removeItem").mockImplementation(async key => { if (key === plan) throw new Error("physical removal failed"); return remove(key); });
  await expect(confirmRemoteLocalErasure(owner)).rejects.toThrow("physical removal failed");
  expect(JSON.parse(physical.get(id)!)).toEqual({ ...row(), remoteConfirmed: true, keys: [] });
});
it("confirmation without a staged checkpoint completes without creating an erasure", async () => {
  await expect(confirmLocalErasure(owner)).resolves.toBeUndefined(); expect([...physical]).toEqual([]);
});
it("a checkpoint removed physically after enumeration is absent from the pending receipt", async () => {
  physical.set(id, JSON.stringify(row()));
  setKvBackendForTests({
    async getItem(key) { return physical.get(key) ?? null; }, async setItem(key, value) { physical.set(key, value); }, async removeItem(key) { physical.delete(key); },
    async keys() { const captured = [...physical.keys()]; physical.delete(id); return captured; },
  });
  expect(await pendingLocalErasures()).toEqual([]);
});
it("retains a foreign browser preference even when its name is a mutation marker", async () => {
  physical.set(id, JSON.stringify(row()));
  for (const storage of [window.localStorage, window.sessionStorage]) storage.setItem("Stryker was here", "unrelated application preference");
  await confirmLocalErasure(owner);
  for (const storage of [window.localStorage, window.sessionStorage]) expect(storage.getItem("Stryker was here")).toBe("unrelated application preference");
});
it.each(["remove", "append"] as const)("handles an independent browser agent's %s between the public storage length and key receipts", async event => {
  // Multi-agent Web Storage boundary. The HTML standard does not grant a
  // lock across agent clusters: https://html.spec.whatwg.org/multipage/webstorage.html#the-localstorage-attribute
  // Forward real DOM Storage values, WebIDL key conversion and writes.
  // One already-pending external physical update is delivered after a
  // length read captured its value, before that synchronous reply. This
  // is an exported provider contract fixture, not a real-browser timing claim.
  const local = window.localStorage, session = window.sessionStorage, preference = `mindpattern.setting.${owner}`;
  physical.set(id, JSON.stringify(row()));
  if (event === "remove") local.setItem(preference, "external agent removes this");
  let externalUpdate: (() => void) | undefined = event === "remove" ? () => local.removeItem(preference) : () => local.setItem(preference, "external agent's later preference");
  const provider: Storage = {
    get length() { const captured = local.length, deliver = externalUpdate; externalUpdate = undefined; deliver?.(); return captured; },
    key: index => local.key(index), getItem: key => local.getItem(key), setItem: (key,value) => local.setItem(key,value), removeItem: key => local.removeItem(key), clear: () => local.clear(),
  };
  vi.stubGlobal("window", { localStorage: provider, sessionStorage: session });
  await expect(confirmLocalErasure(owner)).resolves.toBeUndefined();
  expect(physical.has(id)).toBe(false);
  expect(local.getItem(preference)).toBe(event === "append" ? "external agent's later preference" : null);
});
it("finishes durable erasure in a DOM-free caller", async () => {
  physical.set(id, JSON.stringify(row())); physical.set(plan, "encrypted plan"); vi.stubGlobal("window", undefined);
  await confirmLocalErasure(owner); expect(physical.has(plan)).toBe(false); expect(physical.has(id)).toBe(false);
});

it.each(["stage", "remote", "confirm", "resume"])("the exported %s operation waits for the shared account-erasure browser lock", async operation => {
  // A generic exclusive LockManager provider serializes every name. It has
  // no special erasure branch, quota, cache or callback-count condition.
  const tails = new Map<string, Promise<unknown>>();
  vi.stubGlobal("navigator", { locks: { request<T>(name: string, callback: () => Promise<T>): Promise<T> {
    const run = (tails.get(name) ?? Promise.resolve()).then(callback, callback); tails.set(name, run.catch(() => {})); return run;
  } } });
  if (operation !== "stage") physical.set(id, JSON.stringify({ ...row(), remoteConfirmed: operation === "resume" }));
  physical.set(plan, "retained encrypted plan"); const before = [...physical];
  let entered!: () => void, release!: () => void;
  const admitted = new Promise<void>(resolve => { entered = resolve; }), receipt = new Promise<void>(resolve => { release = resolve; });
  const held = withLock("account-erasure", async () => { entered(); await receipt; }); await admitted;
  const work = operation === "stage" ? stageLocalErasure(owner) : operation === "remote" ? confirmRemoteLocalErasure(owner) : operation === "confirm" ? confirmLocalErasure(owner) : resumeConfirmedErasures();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    expect(await Promise.race([work.then(() => "settled", () => "settled"), new Promise<string>(resolve => { timer = setTimeout(() => resolve("held behind shared lock"), 100); })])).toBe("held behind shared lock");
    expect([...physical]).toEqual(before);
  } finally { if (timer !== undefined) clearTimeout(timer); release(); await held; await work; }
});
it("an unconfirmed pending checkpoint returns without acquiring a competing erasure lock", async () => {
  const tails = new Map<string, Promise<unknown>>();
  vi.stubGlobal("navigator", { locks: { request<T>(name: string, callback: () => Promise<T>): Promise<T> {
    const run = (tails.get(name) ?? Promise.resolve()).then(callback, callback); tails.set(name, run.catch(() => {})); return run;
  } } });
  physical.set(id, JSON.stringify(row()));
  let entered!: () => void, release!: () => void;
  const admitted = new Promise<void>(resolve => { entered = resolve; }), receipt = new Promise<void>(resolve => { release = resolve; });
  const held = withLock("account-erasure", async () => { entered(); await receipt; }); await admitted;
  const work = resumeConfirmedErasures(); let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    expect(await Promise.race([work.then(rows => rows), new Promise<string>(resolve => { timer = setTimeout(() => resolve("unfinished competing lock"), 100); })])).toEqual([row()]);
    expect(physical.get(id)).toBe(JSON.stringify(row()));
  } finally { if (timer !== undefined) clearTimeout(timer); release(); await held; await work; }
});
