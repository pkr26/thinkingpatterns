/**
 * syncReminderSchedule (src/reminderSync.ts): the preference is the
 * direction of truth — enabled schedules at the stored local time,
 * anything else cancels — and every failure path answers false without
 * throwing. nativeFeatures is mocked here; its own seam is covered in
 * tests/nativeFeatures.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

const scheduleDailyReminder = vi.fn(async () => true);
const cancelDailyReminder = vi.fn(async () => true);

vi.mock("../src/nativeFeatures", () => ({
  scheduleDailyReminder: (...args: unknown[]) => scheduleDailyReminder(...(args as [number, number])),
  cancelDailyReminder: (...args: unknown[]) => cancelDailyReminder(...(args as [])),
}));

const { syncReminderSchedule } = await import("../src/reminderSync");
const { setReminderEnabled, setReminderTime } = await import("../src/reminders");

beforeEach(() => {
  storage.__reset();
  scheduleDailyReminder.mockReset();
  scheduleDailyReminder.mockResolvedValue(true);
  cancelDailyReminder.mockReset();
  cancelDailyReminder.mockResolvedValue(true);
});

describe("syncReminderSchedule", () => {
  it("an enabled preference schedules at the stored local time and returns the capability result", async () => {
    await setReminderTime("user-1", 9, 30);
    await setReminderEnabled("user-1", true);
    await expect(syncReminderSchedule("user-1")).resolves.toBe(true);
    expect(scheduleDailyReminder).toHaveBeenCalledWith(9, 30);
    expect(cancelDailyReminder).not.toHaveBeenCalled();
  });

  it("a disabled preference cancels any stale schedule", async () => {
    await expect(syncReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
  });

  it("a corrupt record is the disabled default — cancel, never a guess", async () => {
    await storage.setItem("@mindpattern/reminders_user-1", "{\"enabled\":true,\"hour\":99}");
    await expect(syncReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
  });

  it("a scheduling that cannot land (permission denied / module absent) answers false", async () => {
    await setReminderEnabled("user-1", true);
    scheduleDailyReminder.mockResolvedValue(false);
    await expect(syncReminderSchedule("user-1")).resolves.toBe(false);
    // The preference itself still reads back honestly — the UI says "not
    // scheduled in this build", not "you never opted in".
    const { getReminderPrefs } = await import("../src/reminders");
    expect((await getReminderPrefs("user-1")).enabled).toBe(true);
  });

  it("a thrown storage read fails toward the disabled default — cancel, nothing scheduled, no throw", async () => {
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      await expect(syncReminderSchedule("user-1")).resolves.toBe(true);
    } finally {
      storage.getItem = original;
    }
    // getReminderPrefs failed toward {enabled:false}; the sync cancelled
    // rather than guessing a time or leaving a stale schedule untouched.
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
  });
});
