import { beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { eraseDeletedAccountLocals, retryPendingAccountErasures } from "../src/accountErasure";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { emptySafetyPlan, saveSafetyPlan } from "../src/safetyPlan";
import { savePendingMeasure } from "../src/pendingMeasure";
import { setSecureStoreBackend } from "../src/secureStore";
import { journalDraftScope, newJournalDraft, saveJournalDraft } from "../src/journalDraft";
import { api } from "../src/api/client";
import * as fs from "./helpers/expoFsMock";
import { createPlaybackScratchUri } from "../src/audio/voiceScratch";
vi.mock("../src/nativeFeatures", () => ({ cancelDailyReminder: vi.fn(async () => true), cancelMeasureReminder: vi.fn(async () => true) }));
const user = "dddddddddddddddddddddddddddddddd";
beforeEach(() => { __resetLocalKeyLifecycleForTests(); storage.__reset(); fs.__resetFiles(); setSecureStoreBackend(null); });
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
  fail.mockRestore(); __resetLocalKeyLifecycleForTests(); setSecureStoreBackend(null);
  await retryPendingAccountErasures();
  expect(await storage.getItem(`@mindpattern/safety_plan_${user}`)).toBeNull();
  expect((await storage.getAllKeys()).some(k => k.startsWith("@mindpattern/erasure.v1."))).toBe(false);
});
