/** Native encrypted records: independent AES fixtures, actual disk bytes
 * and custody of plaintext/key buffers consumed by the crypto provider. */
import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { engine } from "./helpers/nodeEngine";
import { runTestControl } from "./helpers/testControl";
import { __resetLocalKeyLifecycleForTests, changeLocalSessionOwner, installLocalDataKey } from "../src/localWriteGuard";
import { accountStorageKey } from "../src/accountStorage";
import { captureLocalWritePermit } from "../src/localRekey";
import { observeEntryVersions, knownEntryVersion, noteV2Bound, isV2Bound, forgetEntryVersion, forgetAllEntryVersions, rebindEntryVersions, resetEntryVersionMirrors } from "../src/entryVersions";
import { recordMood, recentMoods, removeMoodDay, localStreak } from "../src/moodLog";
import { saveSafetyPlan, loadSafetyPlan, saveSafetyPlanDraft, loadSafetyPlanDraft, clearSafetyPlanDraft, SafetyPlanReadError, emptySafetyPlan } from "../src/safetyPlan";
const USER = "a".repeat(32), KEY = Buffer.alloc(32, 11), NEXT = Buffer.alloc(32, 12);
function seal(context: string, value: unknown): string {
  return sealRaw(context, JSON.stringify(value));
}
function sealRaw(context: string, plaintext: string): string {
  const nonce = Buffer.alloc(12, 9), cipher = crypto.createCipheriv("aes-256-gcm", KEY, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify([context, USER])));
  return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
function allocations(expectedReads: string[] = []) {
  const written: Buffer[] = [], read: Buffer[] = [], keys: Buffer[] = [], create = engine.createCipheriv.bind(engine), decipher = engine.createDecipheriv.bind(engine), stringify = Buffer.prototype.toString;
  vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, key, nonce) => {
    keys.push(key as Buffer); const cipher = create(algorithm, key, nonce), update = cipher.update.bind(cipher);
    cipher.update = ((value: Buffer) => { written.push(value); return update(value); }) as typeof cipher.update; return cipher;
  });
  vi.spyOn(engine, "createDecipheriv").mockImplementation((algorithm, key, nonce) => { keys.push(key as Buffer); return decipher(algorithm, key, nonce); });
  vi.spyOn(Buffer.prototype, "toString").mockImplementation(function(this: Buffer, ...args: any[]) {
    const value = stringify.apply(this, args as [BufferEncoding?, number?, number?]); if (expectedReads.includes(value)) read.push(this); return value;
  });
  return { written, read, keys };
}
function erased(values: Buffer[]) { expect(values.length).toBeGreaterThan(0); for (const value of values) expect(value.every(byte => byte === 0)).toBe(true); }
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); resetEntryVersionMirrors(); runTestControl(__resetLocalKeyLifecycleForTests); changeLocalSessionOwner(USER); installLocalDataKey(USER, KEY); });
afterEach(() => { vi.restoreAllMocks(); resetEntryVersionMirrors(); });
it.each([false, true])("version-map native write failure=%s erases its owned serialization and key", async failure => {
  const held = allocations(); if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native version-map unavailable"));
  expect(await observeEntryVersions(USER, KEY, [{ clientEntryId: "private-native-entry", contentVersion: 5 }])).toEqual({ rolledBack: [], advanced: true });
  erased(held.written); erased(held.keys); expect(KEY).toEqual(Buffer.alloc(32, 11)); expect(await knownEntryVersion(USER, KEY, "private-native-entry")).toBe(5);
});
it.each(["valid", "malformed"] as const)("authenticated %s version-map plaintext is erased after native parsing", async kind => {
  const value = kind === "valid" ? { "private-native-entry": 5 } : ["malformed-version-record"];
  await storage.setItem(accountStorageKey.entryVersions(USER), seal("entry-versions", value)); const held = allocations([JSON.stringify(value)]);
  expect(await observeEntryVersions(USER, KEY, [])).toEqual({ rolledBack: [], advanced: false }); erased(held.read); erased(held.keys);
});
it("the native v2-bound note erases its key and serialized id payload", async () => {
  const held = allocations(); await noteV2Bound(USER, KEY, "native-bound"); erased(held.written); erased(held.keys); expect(await isV2Bound(USER, KEY, "native-bound")).toBe(true);
});
it("authenticated native v2-bound plaintext is erased after parsing", async () => {
  const value = ["native-bound", 17, null]; await storage.setItem(accountStorageKey.entryV2Bound(USER), seal("entry-v2-bound", value));
  const held = allocations([JSON.stringify(value)]); expect(await isV2Bound(USER, KEY, "native-bound")).toBe(true); erased(held.read); expect(KEY).toEqual(Buffer.alloc(32, 11));
});
it.each([false, true])("mood native write failure=%s erases its owned serialization and key", async failure => {
  const held = allocations(); if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native mood unavailable"));
  const operation = recordMood(KEY, USER, "2026-10-07", 0.5, -0.25);
  if (failure) await expect(operation).rejects.toThrow("Native mood unavailable"); else await operation;
  erased(held.written); erased(held.keys); expect(KEY).toEqual(Buffer.alloc(32, 11));
});
it.each(["valid", "malformed"] as const)("authenticated %s native mood plaintext is erased after parsing", async kind => {
  const value = kind === "valid" ? [{ date: "2026-10-07", value: 0.5, energy: -0.25 }] : { "private-native-mood": 5 };
  await storage.setItem(accountStorageKey.moodLog(USER), seal("moodlog", value)); const held = allocations([JSON.stringify(value)]);
  expect(await recentMoods(KEY, USER)).toEqual(kind === "valid" ? value : []); erased(held.read); erased(held.keys);
});
it.each(["saved", "draft"] as const)("the Native %s safety-plan write erases its copied key and actual AES input", async kind => {
  const plan = { ...emptySafetyPlan(), warningSigns: "Native private warning signs" }, held = allocations();
  await (kind === "saved" ? saveSafetyPlan(KEY, USER, plan) : saveSafetyPlanDraft(KEY, USER, plan)); erased(held.written); erased(held.keys); expect(KEY).toEqual(Buffer.alloc(32, 11));
});
it.each(["saved", "draft"] as const)("the Native %s safety-plan restoration erases parsed plaintext and copied key", async kind => {
  const plan = { ...emptySafetyPlan(), warningSigns: "Native private warning signs" };
  await storage.setItem(kind === "saved" ? accountStorageKey.safetyPlan(USER) : accountStorageKey.safetyPlanDraft(USER), seal(kind === "saved" ? "safety-plan" : "safety-plan-draft", plan));
  const held = allocations([JSON.stringify(plan)]); expect(await (kind === "saved" ? loadSafetyPlan(KEY, USER) : loadSafetyPlanDraft(KEY, USER))).toEqual(plan); erased(held.read); erased(held.keys);
});
it("Native persisted versions admit only positive safe integers, including version one", async () => {
  const record = { first: 1, current: 8, zero: 0, negative: -1, fractional: 1.5, huge: 1e99, text: "4", nil: null, truthy: true, object: {}, array: [] };
  await storage.setItem(accountStorageKey.entryVersions(USER), seal("entry-versions", record));
  for (const [id, value] of Object.entries(record)) expect(await knownEntryVersion(USER, KEY, id)).toBe(id === "first" || id === "current" ? value : null);
  expect(await observeEntryVersions(USER, KEY, [{ clientEntryId: "current", contentVersion: 7 }])).toEqual({ rolledBack: ["current"], advanced: false });
});
it("both Native rollback mirrors retain their observations when storage disappears or refuses reads", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "native-entry", contentVersion: 8 }]); await noteV2Bound(USER, KEY, "native-entry");
  storage.__reset(); expect(await knownEntryVersion(USER, KEY, "native-entry")).toBe(8); expect(await isV2Bound(USER, KEY, "native-entry")).toBe(true);
  vi.spyOn(storage, "getItem").mockRejectedValue(new Error("Native storage unavailable"));
  expect(await knownEntryVersion(USER, KEY, "native-entry")).toBe(8); expect(await isV2Bound(USER, KEY, "native-entry")).toBe(true);
});
it("Native entry deletion persists removal of its version and required-AAD binding", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "deleted-native-entry", contentVersion: 8 }]); await noteV2Bound(USER, KEY, "deleted-native-entry");
  const held = allocations(); await forgetEntryVersion(USER, KEY, "deleted-native-entry"); erased(held.keys); expect(await storage.getItem(accountStorageKey.entryVersions(USER))).toBeNull(); resetEntryVersionMirrors();
  expect(await knownEntryVersion(USER, KEY, "deleted-native-entry")).toBeNull(); expect(await isV2Bound(USER, KEY, "deleted-native-entry")).toBe(false);
  expect(await observeEntryVersions(USER, KEY, [{ clientEntryId: "deleted-native-entry", contentVersion: 1 }])).toEqual({ rolledBack: [], advanced: true });
});
it("forgetting an absent Native entry remains a resolved no-op during write-provider failure", async () => {
  vi.spyOn(storage, "setItem").mockRejectedValue(new Error("Native writes unavailable"));
  await expect(forgetEntryVersion(USER, KEY, "never-recorded")).resolves.toBeUndefined();
});
it("Native whole-account forgetting clears persisted and process-only observations", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "native-entry", contentVersion: 8 }]); await noteV2Bound(USER, KEY, "native-entry");
  await forgetAllEntryVersions(USER); expect(await knownEntryVersion(USER, KEY, "native-entry")).toBeNull(); expect(await isV2Bound(USER, KEY, "native-entry")).toBe(false);
  expect(await storage.getItem(accountStorageKey.entryVersions(USER))).toBeNull(); expect(await storage.getItem(accountStorageKey.entryV2Bound(USER))).toBeNull();
});
it("Native version rebinding survives a restart under the installed replacement key", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "native-entry", contentVersion: 8 }]); await noteV2Bound(USER, KEY, "native-entry");
  installLocalDataKey(USER, NEXT); await rebindEntryVersions(USER, KEY, NEXT); resetEntryVersionMirrors();
  expect(await knownEntryVersion(USER, NEXT, "native-entry")).toBe(8); expect(await isV2Bound(USER, NEXT, "native-entry")).toBe(true);
});
it("Native mood parsing keeps valid days and clamps both mood and energy while dropping hostile rows", async () => {
  const value = [null, false, "bad", 17, {}, { date: "bad", value: 0 }, { date: "2026-10-04", value: "0" }, { date: "2026-10-03", value: 0.2, energy: "unknown" }, { date: "2026-10-02", value: 3, energy: -3 }, { date: "2026-10-01", value: -3, energy: 3 }];
  await storage.setItem(accountStorageKey.moodLog(USER), seal("moodlog", value));
  expect(await recentMoods(KEY, USER)).toEqual([{ date: "2026-10-01", value: -1, energy: 1 }, { date: "2026-10-02", value: 1, energy: -1 }, { date: "2026-10-03", value: 0.2 }]);
});
it("Native mood edits preserve an omitted energy and clear only an explicit null", async () => {
  await recordMood(KEY, USER, "2026-10-01", 0.2, 0.75); await recordMood(KEY, USER, "2026-10-02", 0.4, -0.75);
  await recordMood(KEY, USER, "2026-10-01", -0.2); await recordMood(KEY, USER, "2026-10-02", -0.4, null);
  expect(await recentMoods(KEY, USER)).toEqual([{ date: "2026-10-01", value: -0.2, energy: 0.75 }, { date: "2026-10-02", value: -0.4 }]);
  await recordMood(KEY, USER, "2026-10-03", 0, 99); await recordMood(KEY, USER, "2026-10-04", 0, -99);
  expect((await recentMoods(KEY, USER)).slice(-2)).toEqual([{ date: "2026-10-03", value: 0, energy: 1 }, { date: "2026-10-04", value: 0, energy: -1 }]);
});
it.each([null, {}, "bad", 7])("Native authenticated top-level mood value %j is disposable and reads empty", async value => {
  await storage.setItem(accountStorageKey.moodLog(USER), seal("moodlog", value)); expect(await recentMoods(KEY, USER)).toEqual([]); expect(await localStreak(KEY, USER, "2026-10-07")).toBe(0);
});
it("Native removal drops a real mood day and an already absent day remains a resolved no-op", async () => {
  await recordMood(KEY, USER, "2026-10-06", 0.2, 0.4); await recordMood(KEY, USER, "2026-10-07", 0.4, -0.4);
  const held = allocations(); await removeMoodDay(KEY, USER, "2026-10-06"); erased(held.written); erased(held.keys);
  expect(await recentMoods(KEY, USER)).toEqual([{ date: "2026-10-07", value: 0.4, energy: -0.4 }]);
  vi.spyOn(storage, "setItem").mockRejectedValue(new Error("Native writes unavailable")); await expect(removeMoodDay(KEY, USER, "already-absent")).resolves.toBeUndefined();
});
it("Native legacy mood migration failure reads empty instead of reporting undurable mood data", async () => {
  await storage.setItem(accountStorageKey.moodLog(USER), JSON.stringify([{ date: "2026-10-07", value: 0.4 }]));
  vi.spyOn(storage, "setItem").mockRejectedValue(new Error("Native migration write unavailable")); expect(await recentMoods(KEY, USER)).toEqual([]);
});
it.each([4000, 4001])("Native safety-plan saving respects the exact %i character write boundary", async length => {
  const plan = { ...emptySafetyPlan(), warningSigns: "é".repeat(length) };
  if (length === 4000) { await saveSafetyPlan(KEY, USER, plan); expect(await loadSafetyPlan(KEY, USER)).toEqual(plan); }
  else { await expect(saveSafetyPlan(KEY, USER, plan)).rejects.toThrow("at most 4000"); expect(await storage.getItem(accountStorageKey.safetyPlan(USER))).toBeNull(); }
});
it.each([100000, 100001])("Native safety-plan legacy restoration respects the exact %i character read boundary", async length => {
  const plan = { ...emptySafetyPlan(), warningSigns: "é".repeat(length) }; await storage.setItem(accountStorageKey.safetyPlan(USER), seal("safety-plan", plan));
  if (length === 100000) expect(await loadSafetyPlan(KEY, USER)).toEqual(plan); else await expect(loadSafetyPlan(KEY, USER)).rejects.toBeInstanceOf(SafetyPlanReadError);
});
it.each([null, false, 7, "bad", [], {}])("Native saved/draft safety-plan shape %j fails closed and preserves the saved bytes", async value => {
  const saved = seal("safety-plan", value), draft = seal("safety-plan-draft", value);
  await storage.setItem(accountStorageKey.safetyPlan(USER), saved); await storage.setItem(accountStorageKey.safetyPlanDraft(USER), draft);
  await expect(loadSafetyPlan(KEY, USER)).rejects.toBeInstanceOf(SafetyPlanReadError); expect(await loadSafetyPlanDraft(KEY, USER)).toBeNull();
  expect(await storage.getItem(accountStorageKey.safetyPlan(USER))).toBe(saved);
});
it("a malformed Native draft input cannot create ciphertext that masquerades as a valid plan", async () => {
  await expect(saveSafetyPlanDraft(KEY, USER, { ...emptySafetyPlan(), warningSigns: null } as never)).rejects.toThrow("Invalid safety-plan draft"); expect(await storage.getItem(accountStorageKey.safetyPlanDraft(USER))).toBeNull();
});
it.each(["saved", "draft"] as const)("Native %s safety-plan write failure erases every owned key/plaintext buffer", async kind => {
  const held = allocations(); vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native plan writes unavailable"));
  await expect(kind === "saved" ? saveSafetyPlan(KEY, USER, emptySafetyPlan()) : saveSafetyPlanDraft(KEY, USER, emptySafetyPlan())).rejects.toThrow("Native plan writes unavailable"); erased(held.written); erased(held.keys);
});
it("an equal Native observed version is neither a rollback nor an advancement", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "same-native-entry", contentVersion: 8 }]);
  expect(await observeEntryVersions(USER, KEY, [{ clientEntryId: "same-native-entry", contentVersion: 8 }])).toEqual({ rolledBack: [], advanced: false });
  await storage.setItem(accountStorageKey.entryVersions(USER), seal("entry-versions", { "same-native-entry": 7 }));
  expect(await knownEntryVersion(USER, KEY, "same-native-entry")).toBe(8);
});
it("an authenticated Native string cannot masquerade as a v2-bound id list", async () => {
  await storage.setItem(accountStorageKey.entryV2Bound(USER), seal("entry-v2-bound", "x")); expect(await isV2Bound(USER, KEY, "x")).toBe(false);
});
it("a tampered Native v2-bound record cannot reject an already observed binding", async () => {
  await noteV2Bound(USER, KEY, "native-bound"); await storage.setItem(accountStorageKey.entryV2Bound(USER), "broken authenticated ciphertext");
  await expect(isV2Bound(USER, KEY, "native-bound")).resolves.toBe(true);
});
it("Native persisted observation bytes live in their registered account slots", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "native-entry", contentVersion: 8 }]); await noteV2Bound(USER, KEY, "native-entry");
  expect(await storage.getItem(accountStorageKey.entryVersions(USER))).not.toBeNull(); expect(await storage.getItem(accountStorageKey.entryV2Bound(USER))).not.toBeNull();
});
it.each([NaN, Infinity, -Infinity, "unknown", false])("Native mood edit energy %j preserves the prior valid answer", async energy => {
  await recordMood(KEY, USER, "2026-10-07", 0.2, 0.75); await recordMood(KEY, USER, "2026-10-07", -0.2, energy as never);
  expect(await recentMoods(KEY, USER)).toEqual([{ date: "2026-10-07", value: -0.2, energy: 0.75 }]);
});
it("Native mood dates cannot be coerced from hostile arrays into valid calendar strings", async () => {
  await storage.setItem(accountStorageKey.moodLog(USER), seal("moodlog", [{ date: ["2026-10-06"], value: 0.4 }, { date: "2026-10-07", value: 0.5 }]));
  expect(await recentMoods(KEY, USER)).toEqual([{ date: "2026-10-07", value: 0.5 }]);
});
it("Native streak reading erases its copied key after a real nonempty corpus", async () => {
  await recordMood(KEY, USER, "2026-10-06", 0.4); await recordMood(KEY, USER, "2026-10-07", 0.5);
  const held = allocations(); expect(await localStreak(KEY, USER, "2026-10-07")).toBe(2); erased(held.keys);
});
it("tampered Native safety-plan draft bytes remain a resolved unreadable draft", async () => {
  await storage.setItem(accountStorageKey.safetyPlanDraft(USER), "broken authenticated ciphertext"); await expect(loadSafetyPlanDraft(KEY, USER)).resolves.toBeNull();
});
it.each(["read", "streak", "remove", "record"] as const)("a retired queued Native mood %s fails promptly while its next provider is unavailable", async kind => {
  let releaseFirst!: () => void, releaseNext!: () => void, entered = false, first = true;
  const initial = new Promise<void>(resolve => { releaseFirst = resolve; }), unavailable = new Promise<void>(resolve => { releaseNext = resolve; }), read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (key === accountStorageKey.moodLog(USER)) { if (first) { first = false; entered = true; await initial; } else await unavailable; } return value; });
  const prior = recordMood(KEY, USER, "2026-10-06", 0.4).catch(error => error);
  await vi.waitFor(() => expect(entered).toBe(true));
  let result: unknown;
  const operation = kind === "read" ? recentMoods(KEY, USER) : kind === "streak" ? localStreak(KEY, USER, "2026-10-07") : kind === "remove" ? removeMoodDay(KEY, USER, "2026-10-06") : recordMood(KEY, USER, "2026-10-07", 0.5);
  const observed = operation.catch(error => { result = error; }); installLocalDataKey(USER, NEXT); releaseFirst();
  try { await vi.waitFor(() => expect(result).toBeInstanceOf(Error), { timeout: 1000 }); }
  finally { releaseNext(); await Promise.all([prior, observed]); }
});
it("an existing Native v2 binding remains an acknowledged no-op when later writes are unavailable", async () => {
  await noteV2Bound(USER, KEY, "native-existing-bound"); vi.spyOn(storage, "setItem").mockRejectedValue(new Error("Native writes unavailable"));
  await expect(noteV2Bound(USER, KEY, "native-existing-bound")).resolves.toBeUndefined(); expect(await isV2Bound(USER, KEY, "native-existing-bound")).toBe(true);
});
it("Native mood parsing rejects nonfinite JSON numbers without losing adjacent valid days", async () => {
  await storage.setItem(accountStorageKey.moodLog(USER), sealRaw("moodlog", '[{"date":"2026-10-04","value":1e999},{"date":"2026-10-05","value":0.25,"energy":-1e999},{"date":"2026-10-06","value":0.5,"energy":1e999},{"date":"2026-10-07","value":0.75,"energy":0.5}]'));
  expect(await recentMoods(KEY, USER)).toEqual([{date:"2026-10-05",value:0.25},{date:"2026-10-06",value:0.5},{date:"2026-10-07",value:0.75,energy:0.5}]);
});
it("Native streak defaults to the actual device calendar day", async () => {
  vi.useFakeTimers({toFake:["Date"]}); vi.setSystemTime(new Date(2026,9,7,12));
  try { await recordMood(KEY, USER, "2026-10-06", 0.4); await recordMood(KEY, USER, "2026-10-07", 0.5); expect(await localStreak(KEY, USER)).toBe(2); }
  finally { vi.useRealTimers(); }
});
it("clearing the actual Native unsaved draft removes only its registered account slot", async () => {
  const saved={...emptySafetyPlan(),warningSigns:"Native saved plan"}, draft={...emptySafetyPlan(),warningSigns:"Native unsaved changes"};
  await saveSafetyPlan(KEY,USER,saved); await saveSafetyPlanDraft(KEY,USER,draft); await clearSafetyPlanDraft(USER,captureLocalWritePermit(USER,KEY));
  expect(await storage.getItem(accountStorageKey.safetyPlanDraft(USER))).toBeNull(); expect(await loadSafetyPlan(KEY,USER)).toEqual(saved);
});
it.each(["note", "forget-version", "forget-binding"] as const)("retired Native entry %s cannot change a replacement generation's process observations", async kind => {
  await observeEntryVersions(USER,KEY,[{clientEntryId:"native-existing",contentVersion:8}]); await noteV2Bound(USER,KEY,"native-existing");
  const target=kind==="forget-binding"?accountStorageKey.entryV2Bound(USER):kind==="note"?accountStorageKey.entryV2Bound(USER):accountStorageKey.entryVersions(USER);
  let release!:()=>void, entered=false;const gate=new Promise<void>(resolve=>{release=resolve;}),read=storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const bytes=await read(key);if(key===target){entered=true;await gate;}return bytes;});
  const operation=(kind==="note"?noteV2Bound(USER,KEY,"native-retired"):forgetEntryVersion(USER,KEY,"native-existing")).catch(error=>error);
  await vi.waitFor(()=>expect(entered).toBe(true)); installLocalDataKey(USER,NEXT);release();expect(await operation).toBeInstanceOf(Error);
  if(kind==="note")expect(await isV2Bound(USER,NEXT,"native-retired")).toBe(false);
  else if(kind==="forget-version")expect(await knownEntryVersion(USER,NEXT,"native-existing")).toBe(8);
  else expect(await isV2Bound(USER,NEXT,"native-existing")).toBe(true);
});
it("retired Native rollback rebinding rejects before its next unavailable storage provider",async()=>{
  await observeEntryVersions(USER,KEY,[{clientEntryId:"native-existing",contentVersion:8}]);installLocalDataKey(USER,NEXT);
  let release!:()=>void,releaseNext!:()=>void,entered=false;const gate=new Promise<void>(resolve=>{release=resolve;}),next=new Promise<void>(resolve=>{releaseNext=resolve;}),read=storage.getItem.bind(storage);
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const bytes=await read(key);if(key===accountStorageKey.entryVersions(USER)){entered=true;await gate;}if(key===accountStorageKey.entryV2Bound(USER))await next;return bytes;});
  let result:unknown;const operation=rebindEntryVersions(USER,KEY,NEXT).catch(error=>{result=error;});await vi.waitFor(()=>expect(entered).toBe(true));installLocalDataKey(USER,Buffer.alloc(32,13));release();
  try{await vi.waitFor(()=>expect(result).toBeInstanceOf(Error),{timeout:1000});}finally{releaseNext();await operation;}
});
it("a Native draft writer produces a plan that its account can authenticate on restart",async()=>{
 const plan={...emptySafetyPlan(),warningSigns:"Unshared Native draft"};await saveSafetyPlanDraft(KEY,USER,plan);
 expect(await loadSafetyPlanDraft(KEY,USER)).toEqual(plan);expect(await loadSafetyPlan(KEY,USER)).toBeNull();
});
it("the Native saved-plan writer refuses a nonstring field without creating an unreadable slot",async()=>{
 await expect(saveSafetyPlan(KEY,USER,{...emptySafetyPlan(),warningSigns:17} as never)).rejects.toThrow("at most 4000");expect(await storage.getItem(accountStorageKey.safetyPlan(USER))).toBeNull();
});
it("a Native version observation with no advancement does not depend on a later unavailable AES writer",async()=>{
 await observeEntryVersions(USER,KEY,[{clientEntryId:"native-existing",contentVersion:8}]);vi.spyOn(engine,"createCipheriv").mockImplementation(()=>{throw new Error("Native AES writer unavailable");});
 await expect(observeEntryVersions(USER,KEY,[{clientEntryId:"native-existing",contentVersion:8}])).resolves.toEqual({rolledBack:[],advanced:false});expect(await knownEntryVersion(USER,KEY,"native-existing")).toBe(8);
});
it("nonstring authenticated Native binding baggage cannot exhaust the write budget for a valid new binding",async()=>{
 await storage.setItem(accountStorageKey.entryV2Bound(USER),seal("entry-v2-bound",["native-existing",{padding:"x".repeat(4096)},null,17,true]));
 const write=storage.setItem.bind(storage);vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{if(slot===accountStorageKey.entryV2Bound(USER)&&Buffer.byteLength(value,"utf8")>512)throw new Error("Native storage byte budget exhausted");return write(slot,value);});
 await expect(noteV2Bound(USER,KEY,"native-new-binding")).resolves.toBeUndefined();resetEntryVersionMirrors();expect(await isV2Bound(USER,KEY,"native-new-binding")).toBe(true);expect(await isV2Bound(USER,KEY,"native-existing")).toBe(true);
});
it("a refused Native legacy migration cannot reinterpret a JSON carrier as authenticated mood ciphertext",async()=>{
 const raw=JSON.stringify([seal("moodlog",[{date:"2026-10-07",value:0.75,energy:0.5}])]);await storage.setItem(accountStorageKey.moodLog(USER),raw);vi.spyOn(storage,"setItem").mockRejectedValue(new Error("Native migration write refused"));
 expect(await recentMoods(KEY,USER)).toEqual([]);expect(await storage.getItem(accountStorageKey.moodLog(USER))).toBe(raw);
});
