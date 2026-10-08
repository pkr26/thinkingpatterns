import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { setSecureStoreBackend, secureStore } from "../src/secureStore";
import { prepareLocalRekey, resumeLocalRekey, markLocalRekeyPhase, pendingLocalRekey,
  captureLocalWritePermit, assertLocalWritePermit, storeLocalRekeyTokens, storeLocalRekeyRequest, localRekeyRequest, clearLocalRekey, __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { markAccountDeleted, changeLocalSessionOwner, localWriteScopeEpoch } from "../src/localWriteGuard";
import { recordMood } from "../src/moodLog";
import { recordFeedbackTap } from "../src/questionFeedback";
import { observeEntryVersions, noteV2Bound, resetEntryVersionMirrors } from "../src/entryVersions";
import { emptySafetyPlan, saveSafetyPlan, loadSafetyPlan } from "../src/safetyPlan";
import { savePendingMeasure, clearPendingMeasure, loadPendingMeasure } from "../src/pendingMeasure";
import { newJournalDraft, journalDraftScope, saveJournalDraft, __resetJournalDraftRuntimeForTests } from "../src/journalDraft";
import { enqueue } from "../src/offlineQueue";
import { enqueueAudio } from "../src/audioQueue";
import { eraseDeletedAccountLocals } from "../src/accountErasure";
import * as nativeFeatures from "../src/nativeFeatures";
import { api, setBaseUrl, getBaseUrl, setUnauthorizedHandler, setOriginChangeHandler } from "../src/api/client";
import { buildAad, decrypt } from "../src/crypto/envelope";
const USER = "11111111111111111111111111111111", OTHER = "22222222222222222222222222222222";
const OLD = Buffer.alloc(32, 5), NEXT = Buffer.alloc(32, 9);
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
function open(key: Buffer, slot: string, purpose: string, raw: string): unknown { return JSON.parse(decrypt(key, Buffer.from(raw, "base64"), buildAad(purpose, slot)).toString()); }
async function rotate() { await prepareLocalRekey(USER, OLD, NEXT); await markLocalRekeyPhase(USER, "credential"); await resumeLocalRekey(USER, NEXT); }
function holdRead(slot: string) {
  const original = storage.getItem, gate = deferred(), started = deferred(); let once = true;
  const spy = vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const snapshot = await original(key);
    if (key === slot && once) { once = false; started.resolve(); await gate.promise; }
    return snapshot;
  }); return { original, gate, started, spy };
}
beforeEach(() => {
  vi.restoreAllMocks(); vi.unstubAllGlobals(); storage.__reset(); runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests); resetEntryVersionMirrors(); runTestControl(__resetJournalDraftRuntimeForTests);
  setUnauthorizedHandler(null); setOriginChangeHandler(null);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); setUnauthorizedHandler(null); });

describe("local key-generation ownership", () => {
  it("rejects an old mood callback after complete rotation and permits a new-key write", async () => {
    const slot = `mindpattern.moodlog.${USER}`;
    await recordMood(OLD, USER, "2026-10-01", 0.2);
    const held = holdRead(slot), callerKey = Buffer.from(OLD);
    const oldWrite = recordMood(callerKey, USER, "2026-10-02", 0.7).catch(e => e); callerKey.fill(0);
    await held.started.promise; await rotate();
    expect(await pendingLocalRekey(USER)).toBe(false);
    const migrated = (await held.original(slot))!;
    held.gate.resolve(); expect(await oldWrite).toBeInstanceOf(Error);
    expect(await held.original(slot)).toBe(migrated);
    expect(open(NEXT, USER, "moodlog", migrated)).toEqual([{ date: "2026-10-01", value: 0.2 }]);
    await expect(recordMood(OLD, USER, "2026-10-03", 0.5)).rejects.toThrow("generation");
    await recordMood(NEXT, USER, "2026-10-03", 0.5);
    expect(open(NEXT, USER, "moodlog", (await held.original(slot))!)).toEqual([{ date: "2026-10-01", value: 0.2 }, { date: "2026-10-03", value: 0.5 }]);
  });
  it("keeps queued old-key callbacks retired even with FIFO native-storage ordering", async () => {
    const slot = `mindpattern.moodlog.${USER}`;
    await recordMood(OLD, USER, "2026-10-01", 0.2);
    let nativeQueue: Promise<unknown> = Promise.resolve();
    const ordered = <T>(task: () => Promise<T>): Promise<T> => {
      const run = nativeQueue.then(async () => { await new Promise<void>(r => setImmediate(r)); return task(); });
      nativeQueue = run.catch(() => {}); return run;
    };
    for (const method of ["getItem", "setItem", "getAllKeys", "multiRemove"] as const) {
      const original = storage[method].bind(storage) as (...args: any[]) => Promise<any>;
      vi.spyOn(storage, method).mockImplementation((...args: any[]) => ordered(() => original(...args)) as any);
    }
    const pending = Array.from({ length: 200 }, (_, i) => recordMood(OLD, USER, "2026-10-02", i / 200).catch(e => e));
    await new Promise<void>(r => setImmediate(r)); await rotate();
    expect((await Promise.all(pending)).some(e => e instanceof Error)).toBe(true);
    const raw = (await storage.getItem(slot))!;
    expect(() => open(NEXT, USER, "moodlog", raw)).not.toThrow();
    expect(() => open(OLD, USER, "moodlog", raw)).toThrow();
  });
  it.each([
    ["feedback", `@mindpattern/question_feedback.${USER}`, "feedback-local"],
    ["entry versions", `mindpattern.entryVersions.${USER}`, "entry-versions"],
    ["v2 binding", `mindpattern.entryV2Bound.${USER}`, "entry-v2-bound"],
  ])("preserves migrated %s when an admitted read returns after resume", async (kind, slot, purpose) => {
    const write = (key: Buffer, late: boolean) => kind === "feedback" ? recordFeedbackTap(key, USER, late ? "late" : "original", true)
      : kind === "entry versions" ? observeEntryVersions(USER, key, [{ clientEntryId: late ? "late" : "original", contentVersion: 3 }])
      : noteV2Bound(USER, key, late ? "late" : "original");
    await write(OLD, false);
    const held = holdRead(slot), oldWrite = write(OLD, true).catch(e => e);
    await held.started.promise; await rotate(); const migrated = (await held.original(slot))!;
    held.gate.resolve(); expect(await oldWrite).toBeInstanceOf(Error);
    expect(await held.original(slot)).toBe(migrated);
    expect(() => open(NEXT, USER, purpose, migrated)).not.toThrow();
  });
  it("drains a submitted native safety-plan commit before taking the rotation snapshot", async () => {
    const slot = `@mindpattern/safety_plan_${USER}`, started = deferred(), release = deferred();
    const original = storage.setItem; let once = true;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === slot && once) { once = false; started.resolve(); await release.promise; }
      return original(key, value);
    });
    const plan = { ...emptySafetyPlan(), warningSigns: "acknowledged native write" };
    const write = saveSafetyPlan(OLD, USER, plan); await started.promise;
    let prepared = false; const preparation = prepareLocalRekey(USER, OLD, NEXT).then(() => { prepared = true; });
    await new Promise<void>(r => setImmediate(r)); expect(prepared).toBe(false);
    release.resolve(); await write; await preparation;
    await markLocalRekeyPhase(USER, "credential"); await resumeLocalRekey(USER, NEXT);
    expect(await loadSafetyPlan(NEXT, USER)).toEqual(plan);
  });
  it("drains submitted writes before account erasure and rejects retained deleted-account keys", async () => {
    vi.spyOn(nativeFeatures, "cancelDailyReminder").mockResolvedValue(true);
    vi.spyOn(nativeFeatures, "cancelMeasureReminder").mockResolvedValue(true);
    const slot = `@mindpattern/safety_plan_${USER}`, started = deferred(), release = deferred();
    const original = storage.setItem;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === slot) { started.resolve(); await release.promise; } return original(key, value);
    });
    const write = saveSafetyPlan(OLD, USER, emptySafetyPlan()); await started.promise;
    const erase = eraseDeletedAccountLocals(USER, null); await new Promise<void>(r => setImmediate(r));
    release.resolve(); await write; expect(await erase).toEqual([]); expect(await storage.getItem(slot)).toBeNull();
    await expect(saveSafetyPlan(OLD, USER, emptySafetyPlan())).rejects.toThrow("deleted");
  });
  it("retires pending measures and first-invoked opaque old-key producers after unfreeze", async () => {
    const oldPermit = captureLocalWritePermit(USER, OLD); await rotate();
    await expect(savePendingMeasure(OLD, USER, { kind: "phq9", clientMeasureId: "late", picks: Array(9).fill(0), date: "2026-10-03" })).rejects.toThrow("generation");
    await expect(enqueue({ userId: USER, clientEntryId: "late", blobB64: "old", entryDate: "2026-10-03" }, oldPermit)).rejects.toThrow("retired");
    await expect(enqueueAudio({ userId: USER, clientEntryId: "late", blobB64: "old", mime: "audio/m4a", durationSeconds: 1 }, oldPermit)).rejects.toThrow("retired");
    await expect(enqueue({ userId: USER, clientEntryId: "unknown-source", blobB64: "old", entryDate: "2026-10-03" })).rejects.toThrow("producer permit");
    await enqueue({ userId: USER, clientEntryId: "new", blobB64: "new", entryDate: "2026-10-03" }, captureLocalWritePermit(USER, NEXT));
  });
  it("invalidates a queued journal-draft write when its same-account session is replaced", async () => {
    const scope = await journalDraftScope(USER), draft = { ...newJournalDraft(), text: "old callback" };
    const held = holdRead(scope.slot), pending = saveJournalDraft(OLD, scope, draft).catch(e => e);
    await held.started.promise; changeLocalSessionOwner(USER); held.gate.resolve();
    expect(await pending).toBeInstanceOf(Error); expect(await held.original(scope.slot)).toBeNull();
  });
  it("invalidates retained permits and key bindings across actual origin retirement", async () => {
    await resumeLocalRekey(USER, OLD); const permit = captureLocalWritePermit(USER, OLD);
    await setBaseUrl("https://other.synthetic.invalid");
    expect(() => assertLocalWritePermit(permit)).toThrow();
    await api.setSession("new-origin-session", USER, "synthetic");
    expect(() => captureLocalWritePermit(USER, OLD)).toThrow("generation");
    await resumeLocalRekey(USER, NEXT); await saveSafetyPlan(NEXT, USER, emptySafetyPlan());
    expect(await loadSafetyPlan(NEXT, USER)).toEqual(emptySafetyPlan());
  });
  it("account erasure invalidates already captured permits synchronously", () => {
    const permit = captureLocalWritePermit(USER, OLD); markAccountDeleted(USER);
    expect(() => assertLocalWritePermit(permit)).toThrow("deleted");
  });
});

describe("transport ownership across mutable authentication waits", () => {
  it("refuses old ciphertext if a token lookup spans rotation and would attach the new bearer", async () => {
    await api.setSession("old-token", USER, "synthetic"); await resumeLocalRekey(USER, OLD);
    const permit = captureLocalWritePermit(USER, OLD), started = deferred(), gate = deferred(), original = secureStore.getItem;
    let once = true;
    vi.spyOn(secureStore, "getItem").mockImplementation(async key => {
      if (key === "@mindpattern/token" && once) { once = false; started.resolve(); await gate.promise; }
      return original(key);
    });
    const fetchSpy = vi.fn(); vi.stubGlobal("fetch", fetchSpy);
    const pending = api.createEntry("late", "old ciphertext", "2026-10-03", 1, permit).catch(e => e);
    await started.promise; await rotate(); await api.setSession("new-token", USER, "synthetic"); gate.resolve();
    expect(await pending).toMatchObject({ status: 0, code: "stale_operation" }); expect(fetchSpy).not.toHaveBeenCalled();
  });
  it.each([401, 410, 204])("ignores a previous account's delayed %s response without locking the new session", async status => {
    await api.setSession("old-token", USER, "synthetic");
    const started = deferred(), reply = deferred<Response>(), unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized);
    vi.stubGlobal("fetch", vi.fn(async () => { started.resolve(); return reply.promise; }));
    const pending = api.createEntry("late", "old ciphertext", "2026-10-03", 1).catch(e => e);
    await started.promise; await api.setSession("fresh-token", OTHER, "other");
    reply.resolve(new Response(status === 204 ? null : JSON.stringify({ code: "account_deleted" }), { status }));
    expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
    expect(unauthorized).not.toHaveBeenCalled(); expect(await api.getUserId()).toBe(OTHER);
  });
  it("checks ownership after a delayed error body, before the unauthorized hook", async () => {
    await api.setSession("old-token", USER, "synthetic");
    const started = deferred(), body = deferred<unknown>(), unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized);
    const response = new Response("{}", { status: 401 });
    vi.spyOn(response, "json").mockImplementation(async () => { started.resolve(); return body.promise; });
    vi.stubGlobal("fetch", vi.fn(async () => response));
    const pending = api.createEntry("late", "old ciphertext", "2026-10-03", 1).catch(e => e);
    await started.promise; await api.setSession("fresh-token", OTHER, "other"); body.resolve({ code: "unauthorized" });
    expect(await pending).toMatchObject({ status: 0, code: "stale_operation" }); expect(unauthorized).not.toHaveBeenCalled();
  });
});


describe("physical checkpoint and acknowledgement transitions", () => {
  it("serializes checkpoint request/token updates without losing either exact retry field", async () => {
    await prepareLocalRekey(USER, OLD, NEXT);
    const { operationId } = await localRekeyRequest(USER, NEXT);
    const body = { operation_id: operationId, new_salt: "same saved salt", new_verifier: "same saved verifier", consent_wraps: [] };
    const tokens = { old: "owned-old-processing-token", next: "owned-next-processing-token" };
    await Promise.all([storeLocalRekeyRequest(USER, NEXT, body), storeLocalRekeyTokens(USER, NEXT, tokens)]);
    expect(await localRekeyRequest(USER, NEXT)).toEqual({ operationId, body, tokens });
  });
  it("drains a submitted processing-token checkpoint before erasure so it cannot resurrect", async () => {
    await prepareLocalRekey(USER, OLD, NEXT);
    const started = deferred(), release = deferred(), original = storage.setItem;
    let once = true;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key.includes("local-rekey.") && key.includes(".chunk.") && once) { once = false; started.resolve(); await release.promise; }
      return original(key, value);
    });
    const tokens = storeLocalRekeyTokens(USER, NEXT, { old: "old-owned-token", next: "next-owned-token" });
    await started.promise; markAccountDeleted(USER);
    let cleared = false; const cleanup = clearLocalRekey(USER).then(() => { cleared = true; });
    await new Promise<void>(r => setImmediate(r)); expect(cleared).toBe(false);
    release.resolve(); await tokens; await cleanup;
    expect((await storage.getAllKeys()).some(key => key.includes("local-rekey."))).toBe(false);
    await expect(storeLocalRekeyTokens(USER, NEXT, { old: "retired", next: "retired" })).rejects.toThrow("deleted");
  });
  it("drains an acknowledged measure delete before rotation and refuses a late old-generation ACK", async () => {
    const measure = { kind: "phq9" as const, clientMeasureId: "original", picks: Array(9).fill(0), date: "2026-10-03" };
    await savePendingMeasure(OLD, USER, measure); const source = captureLocalWritePermit(USER, OLD);
    const started = deferred(), release = deferred(), original = storage.removeItem;
    let once = true;
    vi.spyOn(storage, "removeItem").mockImplementation(async key => {
      if (key === `@mindpattern/pending_measure_${USER}` && once) { once = false; started.resolve(); await release.promise; }
      return original(key);
    });
    const ack = clearPendingMeasure(USER, source); await started.promise;
    let prepared = false; const preparation = prepareLocalRekey(USER, OLD, NEXT).then(() => { prepared = true; });
    await new Promise<void>(r => setImmediate(r)); expect(prepared).toBe(false);
    release.resolve(); await ack; await preparation; await markLocalRekeyPhase(USER, "credential"); await resumeLocalRekey(USER, NEXT);
    const next = { ...measure, clientMeasureId: "new-generation" }; await savePendingMeasure(NEXT, USER, next);
    await expect(clearPendingMeasure(USER, source)).rejects.toThrow("retired");
    expect(await loadPendingMeasure(NEXT, USER)).toEqual(next);
  });
  it("does not activate a no-journal key for a different session owner", async () => {
    await api.setSession("other-token", OTHER, "other");
    await expect(resumeLocalRekey(USER, OLD)).rejects.toThrow("account/server");
    expect(() => captureLocalWritePermit(USER, OLD)).toThrow("account/session");
  });
});

describe("serialized credential and origin changes", () => {
  it("cannot publish an old-origin token after a submitted local commit delays authentication", async () => {
    const started = deferred(), release = deferred(), original = storage.setItem;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === `@mindpattern/safety_plan_${USER}`) { started.resolve(); await release.promise; }
      return original(key, value);
    });
    const write = saveSafetyPlan(OLD, USER, emptySafetyPlan()); await started.promise;
    const oldLogin = api.setSession("old-origin-token", USER, "synthetic").catch(e => e);
    const switchOrigin = setBaseUrl("https://new.synthetic.invalid");
    release.resolve(); await write;
    expect(await oldLogin).toMatchObject({ code: "stale_operation" }); await switchOrigin;
    expect(await getBaseUrl()).toBe("https://new.synthetic.invalid");
    expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
    expect(await api.getUserId()).toBeNull();
  });
  it("an already-submitted old session clear cannot erase the replacement session", async () => {
    await api.setSession("old-token", USER, "old");
    const started = deferred(), release = deferred(), original = secureStore.removeItem;
    let once = true;
    vi.spyOn(secureStore, "removeItem").mockImplementation(async key => {
      if (key === "@mindpattern/token" && once) { once = false; started.resolve(); await release.promise; }
      return original(key);
    });
    const oldClear = api.clearSession().catch(e => e); await started.promise;
    const replacement = api.setSession("replacement-token", OTHER, "replacement");
    release.resolve(); expect(await oldClear).toMatchObject({ code: "stale_operation" }); await replacement;
    expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement-token");
    expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("replacement");
  });
});


describe("credential cache ownership", () => {
  it("does not publish a salt whose origin lookup spans a server switch", async () => {
    await api.setSession("old-token", USER, "same-name");
    const held = holdRead("@mindpattern/base_url");
    const oldCache = api.cacheSalt("same-name", "old-salt").catch(e => e);
    await held.started.promise;
    const change = setBaseUrl("https://replacement.synthetic.invalid");
    held.gate.resolve(); expect(await oldCache).toMatchObject({ code: "stale_operation" }); await change;
    expect(await api.getCachedSalt("same-name")).toBeNull();
  });
  it("finishes an admitted old cache deletion before the replacement can publish its cache", async () => {
    await api.setSession("old-token", USER, "same-name"); await api.cacheSalt("same-name", "old-salt");
    const started = deferred(), release = deferred(), original = storage.removeItem; let once = true;
    vi.spyOn(storage, "removeItem").mockImplementation(async key => {
      if (key.includes("salt_") && once) { once = false; started.resolve(); await release.promise; }
      return original(key);
    });
    const oldClear = api.clearCachedSalt("same-name").catch(e => e); await started.promise;
    const replacement = api.setSession("replacement", OTHER, "same-name");
    const replacementCache = api.cacheSalt("same-name", "new-salt");
    release.resolve(); expect(await oldClear).toMatchObject({ code: "stale_operation" });
    await replacement; await replacementCache;
    expect(await api.getCachedSalt("same-name")).toBe("new-salt");
  });
  it("refuses an already retired authentication caller before changing the active scope", async () => {
    await api.setSession("replacement-token", OTHER, "replacement"); const epoch = localWriteScopeEpoch();
    await expect(api.setSession("abandoned-token", USER, "abandoned", { stillCurrent: () => false })).rejects.toMatchObject({ code: "stale_operation" });
    expect(localWriteScopeEpoch()).toBe(epoch); expect(await api.getUserId()).toBe(OTHER);
    expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement-token");
  });
  it("stops native session publication when the caller unmounts during the first admitted write", async () => {
    const started = deferred(), release = deferred(), original = secureStore.setItem; let alive = true;
    vi.spyOn(secureStore, "setItem").mockImplementation(async (key, value) => {
      if (key === "@mindpattern/token") { started.resolve(); await release.promise; } return original(key, value);
    });
    const retired = api.setSession("abandoned-token", USER, "abandoned", { stillCurrent: () => alive }).catch(e => e);
    await started.promise; alive = false; release.resolve();
    expect(await retired).toMatchObject({ code: "stale_operation" });
    expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
    expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  });
});

describe("erasure cleanup ownership", () => {
  it("retires the original-origin cleanup job when an owner lookup spans an exhaustive server change", async () => {
    await api.setSession("deleted-token", USER, "deleted");
    const origin = await getBaseUrl(), started = deferred(), owner = deferred<string | null>();
    vi.spyOn(api, "getUserId").mockImplementation(async () => { started.resolve(); return owner.promise; });
    const erase = eraseDeletedAccountLocals(USER, null, { origin, preserveSession: true }); await started.promise;
    await setBaseUrl("https://replacement.synthetic.invalid");
    const replacementSlot = `@mindpattern/safety_plan_${OTHER}`;
    await storage.setItem(replacementSlot, "replacement-origin-record"); owner.resolve(USER);
    expect(await erase).toEqual(["account scope changed"]);
    expect(await storage.getItem(replacementSlot)).toBe("replacement-origin-record");
    expect((await storage.getAllKeys()).some(k => k.startsWith("@mindpattern/erasure.v1."))).toBe(false);
  });
  it("retires deleted credentials immediately even when a legacy caller requests session preservation", async () => {
    vi.spyOn(nativeFeatures, "cancelDailyReminder").mockResolvedValue(true);
    vi.spyOn(nativeFeatures, "cancelMeasureReminder").mockResolvedValue(true);
    await api.setSession("deleted-token", USER, "deleted"); const origin = await getBaseUrl();
    expect(await eraseDeletedAccountLocals(USER, null, { origin, preserveSession: true })).toEqual([]);
    expect(await api.getUserId()).toBeNull(); expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
    expect((await storage.getAllKeys()).some(k => k.startsWith("@mindpattern/erasure.v1."))).toBe(false);
  });
  it("defaults to clearing only its own deleted session after completing the cleanup", async () => {
    vi.spyOn(nativeFeatures, "cancelDailyReminder").mockResolvedValue(true);
    vi.spyOn(nativeFeatures, "cancelMeasureReminder").mockResolvedValue(true);
    await api.setSession("deleted-token", USER, "deleted");
    expect(await eraseDeletedAccountLocals(USER, null)).toEqual([]);
    expect(await api.getUserId()).toBeNull(); expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  });
});
