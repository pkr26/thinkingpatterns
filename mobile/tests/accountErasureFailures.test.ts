import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api } from "../src/api/client";
import { eraseDeletedAccountLocals } from "../src/accountErasure";
import { accountStorageKey } from "../src/accountStorage";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { setSecureStoreBackend } from "../src/secureStore";
import * as audio from "../src/audioQueue";
import * as entries from "../src/offlineQueue";
import * as draft from "../src/journalDraft";
import * as plan from "../src/safetyPlan";
import * as pending from "../src/pendingMeasure";
import * as mood from "../src/moodLog";
import * as feedback from "../src/questionFeedback";
import * as brain from "../src/brainSync";
import * as unlock from "../src/unlockProof";
import * as consent from "../src/components/keyConsent";
import * as onboarding from "../src/onboarding";
import * as crisis from "../src/crisisDialog";
import * as threshold from "../src/thresholdNotice";
import * as reminders from "../src/reminders";
import * as measures from "../src/measureReminders";
import * as health from "../src/healthkit";
import * as biometric from "../src/biometricUnlock";
import * as versions from "../src/entryVersions";
import * as analysis from "../src/stateSeqGuard";
import * as scratch from "../src/audio/voiceScratch";
import * as backoff from "../src/unlockBackoff";
import * as rekey from "../src/localRekey";
import * as native from "../src/nativeFeatures";

vi.mock("../src/nativeFeatures", () => ({ cancelDailyReminder: vi.fn(async () => true), cancelMeasureReminder: vi.fn(async () => true) }));
const USER = "dddddddddddddddddddddddddddddddd";
const faultCases: [string, object, string][] = [
  ["recordings", audio, "clearAudioQueue"], ["entries", entries, "clearQueue"],
  ["journal draft", draft, "clearJournalDraft"], ["safety plan", plan, "clearSafetyPlan"],
  ["completed check-in", pending, "erasePendingMeasure"], ["mood log", mood, "clearMoodLog"],
  ["feedback", feedback, "eraseFeedback"], ["recompute stamp", brain, "clearRecomputeStamp"],
  ["unlock proof", unlock, "clearUnlockProof"], ["key sharing consent", consent, "clearKeyShipConsent"],
  ["onboarding", onboarding, "clearOnboardingSeen"], ["crisis dialog stamp", crisis, "clearCrisisDialogStamp"],
  ["threshold notice", threshold, "clearThresholdNotice"], ["reminder preferences", reminders, "clearReminderPrefs"],
  ["check-in preferences", measures, "clearMeasureReminderPrefs"], ["check-in cadence", measures, "clearLastMeasureDate"],
  ["health preference", health, "clearMoodMirrorPref"], ["biometric key", biometric, "eraseBiometricUnlock"],
  ["entry guards", versions, "forgetAllEntryVersions"], ["analysis guard", analysis, "forgetAnalysisGeneration"],
  ["voice scratch", scratch, "scrubVoiceScratchForOwner"], ["salt cache", api, "clearCachedSalt"],
  ["key-envelope cache", api, "clearCachedKeyEnvelope"], ["unlock failures", backoff, "eraseUnlockFailures"],
  ["deleted-account session", api, "retireDeletedSession"], ["key rotation checkpoint", rekey, "clearLocalRekey"],
];

beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(setSecureStoreBackend, null);
  vi.mocked(native.cancelDailyReminder).mockResolvedValue(true);
  vi.mocked(native.cancelMeasureReminder).mockResolvedValue(true);
  await api.setSession("deleted-token", USER, "alice");
});
afterEach(() => vi.restoreAllMocks());

it.each(faultCases)("retains a durable checkpoint and reports %s when that consumer fails", async (label, module, method) => {
  vi.spyOn(module as Record<string, (...args: unknown[]) => Promise<unknown>>, method).mockRejectedValue(new Error("native/storage operation failed"));
  const failures = await eraseDeletedAccountLocals(USER, "alice");
  expect(failures).toContain(label);
  expect((await storage.getAllKeys()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
  if (label !== "deleted-account session") expect(await api.isLoggedIn()).toBe(false);
});

it.each(["daily", "check-in"])("reports an unverified %s notification cancellation", async kind => {
  vi.mocked(kind === "daily" ? native.cancelDailyReminder : native.cancelMeasureReminder).mockResolvedValue(false);
  expect(await eraseDeletedAccountLocals(USER, null)).toContain(`${kind} notification`);
});

it("keeps a different active account's scheduled notifications", async () => {
  await api.setSession("other-token", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "bob");
  vi.mocked(native.cancelDailyReminder).mockClear(); vi.mocked(native.cancelMeasureReminder).mockClear();
  expect(await eraseDeletedAccountLocals(USER, null)).toContain("deleted-account session");
  expect(native.cancelDailyReminder).not.toHaveBeenCalled(); expect(native.cancelMeasureReminder).not.toHaveBeenCalled();
  expect(await api.getUserId()).toBe("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
});

it("sweeps registered storage left by a helper that tolerates its own deletion error", async () => {
  const slot = accountStorageKey.onboardingPanel(USER);
  await storage.setItem(slot, "1");
  expect(await eraseDeletedAccountLocals(USER, null)).toEqual([]);
  expect(await storage.getItem(slot)).toBeNull();
});

it("reports a failed checkpoint write while still retiring the deleted session", async () => {
  const { secureStore } = await import("../src/secureStore");
  vi.spyOn(secureStore, "setItem").mockRejectedValue(new Error("checkpoint disk failure"));
  const failures = await eraseDeletedAccountLocals(USER, null);
  expect(failures).toContain("cleanup checkpoint");
  expect(await api.isLoggedIn()).toBe(false);
});

it("stops before checkpoint creation when the server scope changes during origin lookup", async () => {
  const client = await import("../src/api/client");
  const { advanceLocalWriteScope } = await import("../src/localWriteGuard");
  const origin = await client.getBaseUrl();
  vi.spyOn(client, "getBaseUrl").mockImplementationOnce(async () => { advanceLocalWriteScope(); return origin; });
  expect(await eraseDeletedAccountLocals(USER, null)).toEqual(["server scope changed"]);
  expect((await storage.getAllKeys()).some(key => key.startsWith("@mindpattern/erasure.v1."))).toBe(false);
});

it("retains the checkpoint without touching credentials for a different origin", async () => {
  expect(await eraseDeletedAccountLocals(USER, null, { origin: "https://other.example" })).toEqual(["server scope changed"]);
  expect(await api.isLoggedIn()).toBe(true);
  expect((await storage.getAllKeys()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
});

it("reports account scope changes during the post-retirement owner lookup", async () => {
  const { advanceLocalWriteScope } = await import("../src/localWriteGuard");
  const original = api.getUserId;
  let afterRetirement = false;
  const retire = api.retireDeletedSession;
  vi.spyOn(api, "retireDeletedSession").mockImplementation(async user => { await retire(user); afterRetirement = true; });
  vi.spyOn(api, "getUserId").mockImplementation(async () => {
    const owner = await original();
    if (afterRetirement) advanceLocalWriteScope();
    return owner;
  });
  expect(await eraseDeletedAccountLocals(USER, null)).toEqual(["account scope changed"]);
  expect((await storage.getAllKeys()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
});

it("reports scope retirement while a rotation checkpoint is being removed", async () => {
  const { advanceLocalWriteScope } = await import("../src/localWriteGuard");
  vi.spyOn(rekey, "clearLocalRekey").mockImplementation(async () => { advanceLocalWriteScope(); });
  expect(await eraseDeletedAccountLocals(USER, null)).toContain("key rotation checkpoint");
});

it("reports a registry inventory failure after attempting feature cleanup", async () => {
  vi.spyOn(storage, "getAllKeys").mockRejectedValue(new Error("inventory unavailable"));
  expect(await eraseDeletedAccountLocals(USER, null)).toContain("account storage inventory");
});

it("fences metadata writes immediately while deleted-account origin lookup is pending", async () => {
  const client = await import("../src/api/client");
  const origin = await client.getBaseUrl();
  let release!: (origin: string) => void;
  const held = new Promise<string>(done => { release = done; });
  vi.spyOn(client, "getBaseUrl").mockImplementationOnce(() => held);
  const erasing = eraseDeletedAccountLocals(USER, null);
  try {
    await expect(onboarding.recordOnboardingSeen(USER)).rejects.toThrow("deleted");
    expect(await storage.getItem(accountStorageKey.onboardingSeen(USER))).toBeNull();
  } finally { release(origin); }
  await erasing;
});

it("fences metadata writes while retrying a durable cleanup before native session retirement settles", async () => {
  const { secureStore } = await import("../src/secureStore");
  const { canonicalOrigin, getBaseUrl } = await import("../src/api/client");
  const { retryPendingAccountErasures } = await import("../src/accountErasure");
  const origin = canonicalOrigin(await getBaseUrl());
  await secureStore.setItem(accountStorageKey.erasure(origin, USER), JSON.stringify({ userId: USER, username: null, origin }));
  let start!: () => void, release!: () => void;
  const started = new Promise<void>(done => { start = done; });
  const held = new Promise<void>(done => { release = done; });
  const original = api.retireDeletedSession;
  vi.spyOn(api, "retireDeletedSession").mockImplementation(async user => { start(); await held; await original(user); });
  const retrying = retryPendingAccountErasures();
  try {
    await Promise.race([started, retrying.then(() => { throw new Error("Durable cleanup skipped native session retirement"); })]);
    await expect(onboarding.recordOnboardingSeen(USER)).rejects.toThrow("deleted");
  } finally { release(); }
  expect(await retrying).toBe(0);
});

it("preserves the original erasure scope while the durable checkpoint is being written", async () => {
  const { secureStore } = await import("../src/secureStore");
  const { advanceLocalWriteScope } = await import("../src/localWriteGuard");
  const original = secureStore.setItem;
  vi.spyOn(secureStore, "setItem").mockImplementationOnce(async (key, value) => { await original(key, value); advanceLocalWriteScope(); });
  expect(await eraseDeletedAccountLocals(USER, null)).toEqual(["server scope changed"]);
  expect(await api.getUserId()).toBe(USER);
});

it("reports a failed final cleanup checkpoint removal after all feature retirement succeeds", async () => {
  const original = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(async key => {
    if (key.startsWith("@mindpattern/erasure.v1.")) throw new Error("checkpoint deletion failed");
    return original(key);
  });
  expect(await eraseDeletedAccountLocals(USER, null)).toEqual(["cleanup checkpoint"]);
  expect(await api.isLoggedIn()).toBe(false);
  expect((await storage.getAllKeys()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
});

it("retires a registered password-rotation slot through the final account inventory sweep", async () => {
  const slot = accountStorageKey.pendingRotationSalt(USER);
  await storage.setItem(slot, "previous-rotation-salt");
  const failures = await eraseDeletedAccountLocals(USER, null);
  expect(failures).toEqual([]);
  expect(await storage.getItem(slot)).toBeNull();
});

it("reports scope retirement after inventory lookup without removing the checkpoint", async () => {
  const { advanceLocalWriteScope } = await import("../src/localWriteGuard");
  const original = storage.getAllKeys;
  vi.spyOn(storage, "getAllKeys").mockImplementationOnce(async () => { const keys = await original(); advanceLocalWriteScope(); return keys; });
  expect(await eraseDeletedAccountLocals(USER, null)).toContain("account storage inventory");
  expect((await original()).filter(key => key.startsWith("@mindpattern/erasure.v1."))).toHaveLength(1);
});
