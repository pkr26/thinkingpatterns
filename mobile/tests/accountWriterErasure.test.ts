import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { eraseDeletedAccountLocals } from "../src/accountErasure";
import { accountStorageKey } from "../src/accountStorage";
import { saveOnboardingPanel, recordOnboardingSeen } from "../src/onboarding";
import { recordKeyShipConsent } from "../src/components/keyConsent";
import { setReminderEnabled } from "../src/reminders";
import { setMeasureReminderEnabled, recordMeasureCompleted } from "../src/measureReminders";
import { recordCrisisDialogShown } from "../src/crisisDialog";
import { recordThresholdNotice } from "../src/thresholdNotice";
import { setMoodMirrorPref } from "../src/healthkit";
import { storeUnlockProof } from "../src/unlockProof";
import { recordUnlockFailure } from "../src/unlockBackoff";

vi.mock("../src/nativeFeatures", () => ({
  cancelDailyReminder: vi.fn(async () => true),
  cancelMeasureReminder: vi.fn(async () => true),
}));

const USER = "11111111111111111111111111111111";
const KEY = Buffer.alloc(32, 7);

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

const cases: Array<[string, string, () => Promise<unknown>]> = [
  ["onboarding panel", accountStorageKey.onboardingPanel(USER), () => saveOnboardingPanel(1, USER)],
  ["onboarding completion", accountStorageKey.onboardingSeen(USER), () => recordOnboardingSeen(USER)],
  ["key-shipment consent", accountStorageKey.keyShipmentConsent(USER), () => recordKeyShipConsent(USER)],
  ["daily reminder preference", accountStorageKey.reminders(USER), () => setReminderEnabled(USER, true)],
  ["measure reminder preference", accountStorageKey.measureReminders(USER), () => setMeasureReminderEnabled(USER, true)],
  ["last measure cadence", accountStorageKey.lastMeasure(USER), () => recordMeasureCompleted(USER, "2026-10-04")],
  ["journal crisis stamp", accountStorageKey.crisisJournal(USER), () => recordCrisisDialogShown(USER, "2026-10-04")],
  ["item-9 crisis stamp", accountStorageKey.crisisItem9(USER), () => recordCrisisDialogShown(USER, "2026-10-04", "phq9-item9")],
  ["threshold stamp", accountStorageKey.thresholdNotice(USER), () => recordThresholdNotice(USER)],
  ["Health mirror preference", accountStorageKey.healthMirror(USER), () => setMoodMirrorPref(USER, true)],
  ["offline unlock proof", accountStorageKey.unlockProof(USER), () => storeUnlockProof(KEY, USER)],
  ["offline unlock backoff", accountStorageKey.unlockFailure("alice"), () => recordUnlockFailure("alice", USER)],
];

beforeEach(async () => {
  vi.restoreAllMocks();
  storage.__reset();
  __resetLocalKeyLifecycleForTests();
  setSecureStoreBackend(null);
  await api.setSession("owner-token", USER, "alice");
});

describe("tracked account metadata commits", () => {
  it.each(cases)("drains a delayed %s write before erasure and leaves no resurrection", async (_name, slot, write) => {
    const started = deferred();
    const release = deferred();
    const original = storage.setItem;
    let held = false;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === slot && !held) {
        held = true;
        started.resolve();
        await release.promise;
      }
      return original(key, value);
    });

    const pendingWrite = write();
    await started.promise;
    let erased = false;
    const cleanup = eraseDeletedAccountLocals(USER, "alice").then(result => { erased = true; return result; });
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(erased).toBe(false);
    release.resolve();
    // Preference setters now report a retired completion to their caller
    // as well as joining the erasure drain. The already-dispatched physical
    // write must still be deleted before cleanup reports success.
    if (slot === accountStorageKey.reminders(USER) || slot === accountStorageKey.measureReminders(USER)) {
      await expect(pendingWrite).rejects.toThrow("deleted");
    } else {
      await pendingWrite;
    }
    expect(await cleanup).toEqual([]);
    expect(await storage.getItem(slot)).toBeNull();
  });
});
