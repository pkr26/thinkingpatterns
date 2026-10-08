/** Public notification migration/API credential handoff. Installed providers
 * are substituted only at physical storage/notification IO; JS replies settle real API/helpers.
 * This boundary does not claim a Root screen produces the credential lookup. */
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import { api, getBaseUrl, DEFAULT_BASE_URL } from "../src/api/client";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
const live = new Set<string>();
let triggerReceipt: (() => void) | undefined;
let notificationReply: (() => void) | undefined;
vi.mock("@notifee/react-native", async () => {
  const { installedNotifee } = await import("./helpers/nativeNotifee");
  return installedNotifee({
    addListener: () => {}, removeListeners: () => {},
    requestPermission: async () => ({ authorizationStatus: 1 }),
    createTriggerNotification: (notification: { id: string }) => {
      live.add(notification.id);
      return new Promise<void>(resolve => { notificationReply = resolve; triggerReceipt?.(); });
    },
    cancelAllNotifications: async () => { live.clear(); },
    cancelAllNotificationsWithIds: async (ids: string[]) => { for (const id of ids) live.delete(id); },
    createChannel: async () => {},
  });
});
import { setMeasureReminderEnabled, recordMeasureCompleted } from "../src/measureReminders";
import { migrateOrphanedReminderNotifications } from "../src/nativeFeatures";
const USER = "a".repeat(32), marker = "@mindpattern/reminder.migration.v2.done";
let releaseIdentity: (() => void) | undefined;
beforeEach(async () => { vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); await api.setSession("initial Native migration bearer", USER, "alice"); live.clear(); triggerReceipt = undefined; notificationReply = undefined; });
afterEach(async () => { releaseIdentity?.(); notificationReply?.(); releaseIdentity = undefined; vi.restoreAllMocks(); await api.clearSession(); });
it("a physical credential reply beside the final Native notification receipt cannot mark a retired migration complete", async () => {
  await setMeasureReminderEnabled(USER, true); await recordMeasureCompleted(USER, new Date().toISOString().slice(0, 10));
  const read = storage.getItem.bind(storage); let identityEntered = false, paired = false, firstIdentity = true;
  const identity = new Promise<void>(resolve => { releaseIdentity = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (slot === "@mindpattern/base_url" && firstIdentity) { firstIdentity = false; identityEntered = true; await identity; }
    return value;
  });
  triggerReceipt = () => { paired = true; };
  const renewal = getBaseUrl().catch(() => null).then(origin => {
    if (origin === null) return;
    if (origin !== DEFAULT_BASE_URL) throw new Error("Native server origin was not verified");
    return api.setSession("renewed Native migration bearer", USER, "alice");
  });
  await vi.waitFor(() => expect(identityEntered).toBe(true));
  const migration = migrateOrphanedReminderNotifications(USER);
  await vi.waitFor(() => expect(paired).toBe(true));
  releaseIdentity!(); notificationReply!();
  await migration; await renewal;
  expect(paired).toBe(true);
  expect(live.has("mindpattern-measure-reminder")).toBe(true);
  expect(await secureStore.getItem("@mindpattern/token")).toBe("renewed Native migration bearer");
  expect(await storage.getItem(marker)).toBeNull();
});


it("a Native migration marker receipt followed by credential renewal keeps its completed marker and void result", async () => {
  await setMeasureReminderEnabled(USER, true); await recordMeasureCompleted(USER, new Date().toISOString().slice(0, 10));
  const write = storage.setItem.bind(storage); let physicalReceipt = false, renewal: Promise<void> | undefined;
  triggerReceipt = () => { notificationReply!(); };
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    await write(slot, value);
    if (slot === marker) {
      physicalReceipt = true;
      // Actual public API actor retires the old credential epoch before the
      // completed Native write's JS receipt resumes its old migration.
      renewal = api.setSession("renewed Native completed-migration bearer", USER, "alice");
    }
  });
  const result = await migrateOrphanedReminderNotifications(USER); await renewal;
  expect(physicalReceipt).toBe(true); expect(result).toBeUndefined();
  expect(live.has("mindpattern-measure-reminder")).toBe(true);
  expect(await storage.getItem(marker)).toBe("1");
  expect(await secureStore.getItem("@mindpattern/token")).toBe("renewed Native completed-migration bearer");
});
