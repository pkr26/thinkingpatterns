/** MOB-02: real reconciliation/native adapter with controlled native completion order. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import {
  __resetLocalKeyLifecycleForTests, changeLocalSessionOwner, markAccountDeleted,
  freezeLocalKeyWrites, installLocalDataKey, waitLocalWriteCommits, localWriteScopeEpoch,
} from "../src/localWriteGuard";
import { beginNotificationUpdate } from "../src/notificationOwnership";

const live = new Set<string>();
const events: string[] = [];
const requestPermission = vi.fn(async () => ({ authorizationStatus: 1 }));
const createChannel = vi.fn(async () => "channel");
const createTriggerNotification = vi.fn(async (notification: { id: string }, _trigger: unknown) => {
  live.add(notification.id); events.push(`create:${notification.id}`); return notification.id;
});
const cancelNotification = vi.fn(async (id: string) => { live.delete(id); events.push(`cancel:${id}`); });
const cancelAllNotifications = vi.fn(async () => { live.clear(); events.push("cancel:all"); });
vi.mock("@notifee/react-native", () => ({
  default: { requestPermission, createChannel, createTriggerNotification, cancelNotification, cancelAllNotifications },
  TriggerType: { TIMESTAMP: 0 }, RepeatFrequency: { DAILY: 1 },
}));
const native = await import("../src/nativeFeatures");
const { syncReminderSchedule, syncMeasureReminderSchedule } = await import("../src/reminderSync");
const { setReminderEnabled, setReminderTime, getReminderPrefs } = await import("../src/reminders");
const { setMeasureReminderEnabled, recordMeasureCompleted, getMeasureReminderPrefs } = await import("../src/measureReminders");
const migrationKey = "@mindpattern/reminder.migration.v2.done";
const dailyId = "mindpattern-daily-reminder";
const measureId = "mindpattern-measure-reminder";
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
async function seed(user = "a") {
  await setReminderEnabled(user, true);
  await setMeasureReminderEnabled(user, true);
  await recordMeasureCompleted(user, new Date().toISOString().slice(0, 10));
}
const tick = () => new Promise<void>(resolve => setTimeout(resolve, 0));
beforeEach(async () => {
  __resetLocalKeyLifecycleForTests(); changeLocalSessionOwner("a"); storage.__reset();
  await storage.setItem(migrationKey, "1");
  live.clear(); events.length = 0;
  requestPermission.mockReset().mockResolvedValue({ authorizationStatus: 1 });
  createChannel.mockReset().mockResolvedValue("channel");
  createTriggerNotification.mockReset().mockImplementation(async notification => { live.add(notification.id); events.push(`create:${notification.id}`); return notification.id; });
  cancelNotification.mockReset().mockImplementation(async id => { live.delete(id); events.push(`cancel:${id}`); });
  cancelAllNotifications.mockReset().mockImplementation(async () => { live.clear(); events.push("cancel:all"); });
});
afterEach(() => { vi.restoreAllMocks(); });

for (const kind of ["daily", "measure"] as const) {
  const slot = kind === "daily" ? "@mindpattern/reminders_a" : "@mindpattern/measure_reminders_a";
  const setEnabled = kind === "daily" ? setReminderEnabled : setMeasureReminderEnabled;
  const getPrefs = kind === "daily" ? getReminderPrefs : getMeasureReminderPrefs;
  const sync = kind === "daily" ? syncReminderSchedule : syncMeasureReminderSchedule;

  it(`${kind}: overlapping preference writes cannot let an older enable override the newest disable`, async () => {
    await recordMeasureCompleted("a", new Date().toISOString().slice(0, 10));
    const wait = deferred<void>();
    const originalRead = storage.getItem.bind(storage);
    let held = false;
    vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const value = await originalRead(key);
      if (key === slot && !held) { held = true; await wait.promise; }
      return value;
    });
    const oldEnable = setEnabled("a", true).then(() => sync("a"));
    await vi.waitFor(() => expect(held).toBe(true));
    const latestDisable = setEnabled("a", false).then(() => sync("a"));
    await tick();
    wait.resolve();
    await Promise.all([oldEnable, latestDisable]);
    expect((await getPrefs("a")).enabled).toBe(false);
    expect(live.size).toBe(0);
  });

  for (const retirement of ["session", "key"] as const) {
    it(`${kind}: a preference read admitted before ${retirement} retirement cannot write into its replacement`, async () => {
      const wait = deferred<void>();
      const originalRead = storage.getItem.bind(storage);
      let held = false;
      vi.spyOn(storage, "getItem").mockImplementation(async key => {
        const value = await originalRead(key);
        if (key === slot && !held) { held = true; await wait.promise; }
        return value;
      });
      const update = setEnabled("a", true);
      // Observe rejection immediately to keep delayed ownership failure handled.
      const outcome = update.then(() => "written", () => "retired");
      await vi.waitFor(() => expect(held).toBe(true));
      if (retirement === "session") { changeLocalSessionOwner(null); changeLocalSessionOwner("a"); }
      else { freezeLocalKeyWrites("a"); installLocalDataKey("a", Buffer.alloc(32, 9)); }
      wait.resolve();
      expect(await outcome).toBe("retired");
      expect(await storage.getItem(slot)).toBeNull();
    });
  }
}

for (const kind of ["daily", "measure"] as const) {
  for (const boundary of ["permission", "channel", "cancel"] as const) {
    it(`${kind}: retirement during ${boundary} drains before final cancellation and never dispatches a late create`, async () => {
      await seed();
      const wait = deferred<void>();
      const seam = boundary === "permission" ? requestPermission : boundary === "channel" ? createChannel : cancelNotification;
      if (boundary === "permission") requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
      if (boundary === "channel") createChannel.mockImplementationOnce(async () => { await wait.promise; return "channel"; });
      if (boundary === "cancel") cancelNotification.mockImplementationOnce(async () => { await wait.promise; });
      const work = kind === "daily" ? syncReminderSchedule("a") : syncMeasureReminderSchedule("a");
      await vi.waitFor(() => expect(seam).toHaveBeenCalledTimes(1));
      markAccountDeleted("a"); changeLocalSessionOwner(null);
      let drained = false;
      const drain = waitLocalWriteCommits("a").then(() => { drained = true; });
      const cancel = native.cancelOriginNotifications();
      await tick();
      expect(drained).toBe(false);
      expect(cancelAllNotifications).not.toHaveBeenCalled();
      wait.resolve();
      await expect(work).resolves.toBe(false);
      await drain; await expect(cancel).resolves.toBe(true);
      expect(createTriggerNotification).not.toHaveBeenCalled();
      expect(live.size).toBe(0);
      expect(events.at(-1)).toBe("cancel:all");
    });
  }
}

describe("native work already dispatched", () => {
  it("deletion waits for a pending native create, then removes the late result", async () => {
    await seed();
    const wait = deferred<void>();
    createTriggerNotification.mockImplementationOnce(async notification => {
      await wait.promise; live.add(notification.id); events.push(`create:${notification.id}`); return notification.id;
    });
    const work = syncReminderSchedule("a");
    await vi.waitFor(() => expect(createTriggerNotification).toHaveBeenCalledTimes(1));
    markAccountDeleted("a"); changeLocalSessionOwner(null);
    let done = false;
    const cleanup = (async () => {
      await waitLocalWriteCommits("a");
      await Promise.all([native.cancelDailyReminder(), native.cancelMeasureReminder()]);
      done = true;
    })();
    await tick(); expect(done).toBe(false);
    wait.resolve();
    await expect(work).resolves.toBe(false); await cleanup;
    expect(live.size).toBe(0);
    expect(events.indexOf(`create:${dailyId}`)).toBeLessThan(events.lastIndexOf(`cancel:${dailyId}`));
  });

  it("the full account-erasure pipeline drains pending work and leaves neither reminder nor a cleanup retry", async () => {
    const { api } = await import("../src/api/client");
    const { eraseDeletedAccountLocals } = await import("../src/accountErasure");
    const user = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    await api.setSession("synthetic-local-test-session", user, "synthetic-test-account");
    await seed(user);
    const wait = deferred<void>();
    requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
    const work = syncReminderSchedule(user);
    await vi.waitFor(() => expect(requestPermission).toHaveBeenCalled());
    const epoch = localWriteScopeEpoch();
    let completed = false;
    const erasure = eraseDeletedAccountLocals(user, "synthetic-test-account").then(result => { completed = true; return result; });
    try {
      await vi.waitFor(() => expect(localWriteScopeEpoch()).toBeGreaterThan(epoch));
      expect(completed).toBe(false);
    } finally { wait.resolve(); }
    await expect(work).resolves.toBe(false);
    await expect(erasure).resolves.toEqual([]);
    expect(await api.getUserId()).toBeNull();
    expect(live.size).toBe(0);
    expect(createTriggerNotification).not.toHaveBeenCalled();
    expect((await storage.getAllKeys()).some(key => key.startsWith("@mindpattern/erasure.v1."))).toBe(false);
  });

  it("a new account owns the final schedule, even when old permission and a queued old cancellation finish later", async () => {
    await seed();
    const wait = deferred<void>();
    requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
    const oldWork = syncReminderSchedule("a");
    await vi.waitFor(() => expect(requestPermission).toHaveBeenCalled());
    changeLocalSessionOwner(null);
    const oldCancel = native.cancelOriginNotifications();
    changeLocalSessionOwner("b");
    await setReminderEnabled("b", true); await setReminderTime("b", 7, 45);
    const newWork = syncReminderSchedule("b");
    wait.resolve();
    await expect(oldWork).resolves.toBe(false);
    await expect(oldCancel).resolves.toBe(false);
    await expect(newWork).resolves.toBe(true);
    expect(cancelAllNotifications).not.toHaveBeenCalled();
    expect(createTriggerNotification).toHaveBeenCalledTimes(1);
    const trigger = createTriggerNotification.mock.calls[0]![1] as { timestamp: number };
    expect(new Date(trigger.timestamp).getHours()).toBe(7);
    expect(new Date(trigger.timestamp).getMinutes()).toBe(45);
    expect(live).toEqual(new Set([dailyId]));
  });

  it("the latest disabled preference supersedes an earlier pending enable", async () => {
    await seed();
    const wait = deferred<void>();
    requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
    const enabled = syncReminderSchedule("a");
    await vi.waitFor(() => expect(requestPermission).toHaveBeenCalled());
    await setReminderEnabled("a", false);
    const disabled = syncReminderSchedule("a");
    wait.resolve();
    await expect(enabled).resolves.toBe(false); await expect(disabled).resolves.toBe(true);
    expect(createTriggerNotification).not.toHaveBeenCalled(); expect(live.size).toBe(0);
    expect(events.at(-1)).toBe(`cancel:${dailyId}`);
  });

  it("unfreezing after rekey cannot revive a permit captured before the key generation changed", async () => {
    await seed();
    const wait = deferred<void>();
    requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
    const oldWork = syncMeasureReminderSchedule("a");
    await vi.waitFor(() => expect(requestPermission).toHaveBeenCalled());
    freezeLocalKeyWrites("a"); installLocalDataKey("a", Buffer.alloc(32, 7));
    wait.resolve(); await expect(oldWork).resolves.toBe(false);
    expect(createTriggerNotification).not.toHaveBeenCalled();
    await expect(syncMeasureReminderSchedule("a")).resolves.toBe(true);
    expect(live).toEqual(new Set([measureId]));
  });
});

describe("migration and sibling restoration", () => {
  it("migration cannot restore siblings or commit its flag after retirement during its cancel-all", async () => {
    await seed(); await storage.removeItem(migrationKey);
    const wait = deferred<void>();
    cancelAllNotifications.mockImplementationOnce(async () => { await wait.promise; live.clear(); });
    const work = native.migrateOrphanedReminderNotifications("a");
    await vi.waitFor(() => expect(cancelAllNotifications).toHaveBeenCalled());
    changeLocalSessionOwner(null);
    const cleanup = native.cancelOriginNotifications();
    wait.resolve(); await work; await cleanup;
    expect(createTriggerNotification).not.toHaveBeenCalled();
    expect(await storage.getItem(migrationKey)).toBeNull();
  });

  it("a fallback sibling restore stops at a late permission result after account retirement", async () => {
    await seed();
    const mod = await import("@notifee/react-native") as unknown as { default: Record<string, unknown> };
    const perId = mod.default.cancelNotification;
    delete mod.default.cancelNotification;
    try {
      const wait = deferred<void>();
      requestPermission.mockImplementationOnce(async () => { await wait.promise; return { authorizationStatus: 1 }; });
      const work = native.cancelDailyReminder("a");
      await vi.waitFor(() => expect(requestPermission).toHaveBeenCalled());
      changeLocalSessionOwner(null);
      const cleanup = native.cancelOriginNotifications();
      wait.resolve(); await expect(work).resolves.toBe(false); await cleanup;
      expect(createTriggerNotification).not.toHaveBeenCalled(); expect(live.size).toBe(0);
    } finally { mod.default.cancelNotification = perId; }
  });

  it("concurrent current-owner daily and measure syncs, including migration, retain both schedules", async () => {
    await seed(); await storage.removeItem(migrationKey);
    await expect(Promise.all([syncReminderSchedule("a"), syncMeasureReminderSchedule("a")])).resolves.toEqual([true, true]);
    expect(live).toEqual(new Set([dailyId, measureId]));
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    expect(await storage.getItem(migrationKey)).toBe("1");
  });

  it("a caller cannot reuse an earlier daily intent after a new daily reconciliation", async () => {
    const stale = beginNotificationUpdate("a", "daily");
    const current = beginNotificationUpdate("a", "daily");
    await expect(native.scheduleDailyReminder(8, 0, stale)).resolves.toBe(false);
    expect(requestPermission).not.toHaveBeenCalled();
    await expect(native.scheduleDailyReminder(9, 0, current)).resolves.toBe(true);
    expect(createTriggerNotification).toHaveBeenCalledTimes(1);
  });
});
