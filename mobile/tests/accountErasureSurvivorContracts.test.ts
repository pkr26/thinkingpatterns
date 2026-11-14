import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { eraseDeletedAccountLocals, retryPendingAccountErasures } from "../src/accountErasure";
import { accountStorageKey } from "../src/accountStorage";
import { api, canonicalOrigin, getBaseUrl } from "../src/api/client";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import * as native from "../src/nativeFeatures";
import { emptySafetyPlan, loadSafetyPlan, saveSafetyPlan } from "../src/safetyPlan";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";

vi.mock("../src/nativeFeatures", () => ({
  cancelDailyReminder: vi.fn(async () => true),
  cancelMeasureReminder: vi.fn(async () => true),
}));

const USER = "dddddddddddddddddddddddddddddddd";

beforeEach(async () => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(setSecureStoreBackend, null);
  vi.mocked(native.cancelDailyReminder).mockResolvedValue(true);
  vi.mocked(native.cancelMeasureReminder).mockResolvedValue(true);
  await api.setSession("active-account-token", USER, "alice");
  vi.mocked(native.cancelDailyReminder).mockClear();
  vi.mocked(native.cancelMeasureReminder).mockClear();
});
afterEach(() => vi.restoreAllMocks());

it("reports both unverified notification cancellations when deleted-session retirement fails", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  const marker = accountStorageKey.erasure(origin, USER);
  vi.spyOn(api, "retireDeletedSession").mockRejectedValue(new Error("credential storage unavailable"));
  vi.mocked(native.cancelDailyReminder).mockResolvedValue(false);
  vi.mocked(native.cancelMeasureReminder).mockResolvedValue(false);

  const failures = await eraseDeletedAccountLocals(USER, "alice", { origin });

  expect(failures).toEqual(expect.arrayContaining([
    "daily notification", "check-in notification", "deleted-account session",
  ]));
  expect(native.cancelDailyReminder).toHaveBeenCalledTimes(1);
  expect(native.cancelMeasureReminder).toHaveBeenCalledTimes(1);
  expect(await api.getUserId()).toBe(USER);
  expect(JSON.parse((await secureStore.getItem(marker))!)).toEqual({ userId: USER, username: "alice", origin });
});

it("rejects array owners in sealed cleanup checkpoints without erasing the matching active account", async () => {
  const origin = canonicalOrigin(await getBaseUrl());
  const marker = accountStorageKey.erasure(origin, USER);
  const moodSlot = accountStorageKey.moodLog(USER);
  const key = Buffer.alloc(32, 17);
  const plan = { ...emptySafetyPlan(), warningSigns: "My current plan remains available" };
  await storage.setItem(moodSlot, "recoverable current-account journal");
  try {
    await saveSafetyPlan(key, USER, plan);
    for (const invalidOwner of [[USER], [[USER]]]) {
      // Both JSON arrays stringify to the same owner inside a storage key.
      // A matching physical key must not turn a malformed owner into authority.
      const checkpoint = JSON.stringify({ userId: invalidOwner, username: null, origin });
      await secureStore.setItem(marker, checkpoint);

      expect(await retryPendingAccountErasures()).toBe(1);
      expect(await secureStore.getItem(marker)).toBe(checkpoint);
      expect(await api.isLoggedIn()).toBe(true);
      expect(await api.getUserId()).toBe(USER);
      expect(await api.getUsername()).toBe("alice");
      expect(await storage.getItem(moodSlot)).toBe("recoverable current-account journal");
      expect(await loadSafetyPlan(key, USER)).toEqual(plan);
      await expect(saveSafetyPlan(key, USER, plan)).resolves.toBeUndefined();
      await storage.removeItem(marker);
    }
  } finally {
    key.fill(0);
  }
});
