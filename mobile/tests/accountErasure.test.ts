import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { eraseDeletedAccountLocals, retryPendingAccountErasures } from "../src/accountErasure";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { emptySafetyPlan, saveSafetyPlan } from "../src/safetyPlan";
import { savePendingMeasure } from "../src/pendingMeasure";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { accountStorageKey } from "../src/accountStorage";
import { journalDraftScope, newJournalDraft, saveJournalDraft } from "../src/journalDraft";
import { api, canonicalOrigin, getBaseUrl } from "../src/api/client";
import * as fs from "./helpers/expoFsMock";
import { createPlaybackScratchUri } from "../src/audio/voiceScratch";
vi.mock("../src/nativeFeatures", () => ({ cancelDailyReminder: vi.fn(async () => true), cancelMeasureReminder: vi.fn(async () => true) }));
const user = "dddddddddddddddddddddddddddddddd";
beforeEach(() => { runTestControl(__resetLocalKeyLifecycleForTests); storage.__reset(); fs.__resetFiles(); runTestControl(setSecureStoreBackend, null); });
afterEach(() => vi.restoreAllMocks());
it("attempts every cleanup after one fails, retains an encrypted job, and retries on restart", async () => {
  await api.setSession("deleted-account-token", user, "private-account-name");
  const key = Buffer.alloc(32, 5);
  await saveSafetyPlan(key, user, { ...emptySafetyPlan(), warningSigns: "Private warning" });
  await savePendingMeasure(key, user, { kind: "phq9", clientMeasureId: "one", picks: Array(9).fill(0), date: "2026-10-03" });
  const draftScope = await journalDraftScope(user);
  await saveJournalDraft(key, draftScope, { ...newJournalDraft(), revision: 1, text: "Private journal draft" });
  const playbackScratch = await createPlaybackScratchUri(user, "audio/m4a");
  const nativeScratch = `${fs.cacheDirectory}ExpoAudio/recording-interrupted.m4a`;
  const unrelatedCache = `${fs.cacheDirectory}unrelated/keep.bin`;
  fs.__seedFile(playbackScratch, "plaintext playback");
  fs.__seedFile(nativeScratch, "plaintext recording");
  fs.__seedFile(unrelatedCache, "unrelated");
  const original = storage.multiRemove;
  const fail = vi.spyOn(storage, "multiRemove").mockImplementation(async slots => {
    if (slots.includes(`@mindpattern/safety_plan_${user}`)) throw new Error("transient disk error");
    return original(slots);
  });
  const failures = await eraseDeletedAccountLocals(user, "private-account-name");
  expect(failures).toContain("safety plan");
  // Authentication dies independently of the failed feature cleanup.
  expect(await api.isLoggedIn()).toBe(false);
  expect(await api.getUserId()).toBeNull();
  expect(await api.getUsername()).toBeNull();
  expect(await storage.getItem(`@mindpattern/pending_measure_${user}`)).toBeNull();
  expect(await storage.getItem(draftScope.slot)).toBeNull();
  expect(fs.__hasFile(playbackScratch)).toBe(false);
  expect(fs.__hasFile(nativeScratch)).toBe(false);
  expect(fs.__hasFile(unrelatedCache)).toBe(true);
  const jobs = (await storage.getAllKeys()).filter(k => k.startsWith("@mindpattern/erasure.v1."));
  expect(jobs).toHaveLength(1);
  expect(await storage.getItem(jobs[0]!)).not.toContain("private-account-name");
  // A process restart loses the in-memory deleted fence, but the opaque job
  // remains sufficient to retry without resurrecting credentials.
  fail.mockRestore(); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(setSecureStoreBackend, null);
  await retryPendingAccountErasures();
  expect(await storage.getItem(`@mindpattern/safety_plan_${user}`)).toBeNull();
  expect((await storage.getAllKeys()).some(k => k.startsWith("@mindpattern/erasure.v1."))).toBe(false);
});

it("counts only durable erasure checkpoints when retrying incomplete cleanup", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  const marker = accountStorageKey.erasure(origin, user);
  await secureStore.setItem(marker, JSON.stringify({ userId: user, username: "alice", origin }));
  await storage.setItem("unrelated", "keep");
  await storage.setItem("unrelated@mindpattern/erasure.v1.", "keep");
  const original = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(async key => { if (key === marker) throw new Error("checkpoint deletion blocked"); return original(key); });
  expect(await retryPendingAccountErasures()).toBe(1);
  expect(await storage.getItem("unrelated")).toBe("keep");
});

it("retains a cleanup checkpoint if physical guard deletion fails", async () => {
  const original = storage.multiRemove;
  vi.spyOn(storage, "multiRemove").mockImplementation(async keys => { if (keys.includes(accountStorageKey.stateSequence(user))) throw new Error("guard storage blocked"); return original(keys); });
  expect(await eraseDeletedAccountLocals(user, null)).toContain("persisted guards");
  expect((await storage.getAllKeys()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
});

it("never retires an account for a malformed stored cleanup job", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  await api.setSession("active-token", user, "alice");
  const slot = accountStorageKey.moodLog(user);
  await storage.setItem(slot, "journal-owner-data");
  const marker = accountStorageKey.erasure(origin, user);
  for (const invalid of [null, false, {}, { userId: user, origin, username: 42 }, { userId: user, origin }, { userId: user, origin: 42, username: null }, { userId: 42, origin, username: null }]) {
    await secureStore.setItem(marker, JSON.stringify(invalid));
    expect(await retryPendingAccountErasures()).toBe(1);
    expect(await api.getUserId()).toBe(user); expect(await storage.getItem(slot)).toBe("journal-owner-data");
  }
});

it("never applies a valid cleanup body stored under another account's checkpoint key", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  await api.setSession("active-token", user, "alice");
  await storage.setItem(accountStorageKey.moodLog(user), "journal-owner-data");
  await secureStore.setItem(accountStorageKey.erasure(origin, "other-owner"), JSON.stringify({ userId: user, origin, username: "alice" }));
  expect(await retryPendingAccountErasures()).toBe(1);
  expect(await api.getUserId()).toBe(user); expect(await storage.getItem(accountStorageKey.moodLog(user))).toBe("journal-owner-data");
});

it("a numeric owner in a sealed checkpoint cannot erase the similarly spelled legacy account", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  await api.setSession("active-token", user, "alice");
  const legacyOwner = "42";
  const slot = accountStorageKey.moodLog(legacyOwner);
  await storage.setItem(slot, "legacy owner's recoverable journal");
  const marker = accountStorageKey.erasure(origin, legacyOwner);
  await secureStore.setItem(marker, JSON.stringify({ userId: 42, origin, username: null }));
  expect(await retryPendingAccountErasures()).toBe(1);
  expect(await storage.getItem(slot)).toBe("legacy owner's recoverable journal");
  expect(await api.getUserId()).toBe(user);
});

it("pending erasure makes progress while an unrelated Native storage receipt is withheld", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  const unrelated = "unrelated-sealed-device-preference";
  await secureStore.setItem(unrelated, "unrelated recoverable setting");
  const marker = accountStorageKey.erasure(origin, user);
  await secureStore.setItem(marker, JSON.stringify({ userId: user, origin, username: null }));
  let release!: () => void;
  const gate = new Promise<void>(done => { release = done; });
  const read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    if (key === unrelated) await gate;
    return value;
  });
  const retry = retryPendingAccountErasures();
  try {
    await vi.waitFor(async () => { expect(await read(marker)).toBeNull(); }, { timeout: 1000 });
  } finally { release(); await retry; }
  expect(await secureStore.getItem(unrelated)).toBe("unrelated recoverable setting");
});

it("a malformed origin checkpoint settles without reserving a Native server-preference read", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  const marker = accountStorageKey.erasure(origin, user);
  // Its string coercion matches the physical checkpoint key. It still has
  // no valid origin and must be refused before entering cleanup's IO.
  await secureStore.setItem(marker, JSON.stringify({ userId: user, username: null, origin: [origin] }));
  const read = storage.getItem.bind(storage);
  let release!: () => void;
  const receipt = new Promise<void>(done => { release = done; });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    if (key === "@mindpattern/base_url") await receipt;
    return value;
  });
  let remaining: number | undefined;
  const retry = retryPendingAccountErasures().then(count => { remaining = count; });
  try {
    await vi.waitFor(() => expect(remaining).toBe(1), { timeout: 1000 });
    expect(await read(marker)).not.toBeNull();
  } finally { release(); await retry; }
});
