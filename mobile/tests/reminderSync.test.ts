/**
 * syncReminderSchedule + syncMeasureReminderSchedule (src/reminderSync.ts):
 * the preference is the direction of truth — for the daily reminder,
 * enabled schedules at the stored local time, anything else cancels; for
 * the check-in nudge, the preference is JOINED BY THE CADENCE (only a due
 * interval schedules). Every failure path answers false without throwing.
 * nativeFeatures is mocked here; its own seam is covered in
 * tests/nativeFeatures.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

const scheduleDailyReminder = vi.fn(async () => true);
const cancelDailyReminder = vi.fn(async () => true);
const scheduleMeasureReminder = vi.fn(async () => true);
const cancelMeasureReminder = vi.fn(async () => true);
// L-9 (2026-09-28): the one-time orphan sweep runs inside every
// syncReminderSchedule; the sync suite stubs it to a no-op (its own seam is
// covered in tests/nativeFeatures.test.ts against the real module).
const migrateOrphanedReminderNotifications = vi.fn(async () => {});

vi.mock("../src/nativeFeatures", () => ({
  scheduleDailyReminder: (...args: unknown[]) => scheduleDailyReminder(...(args as [number, number])),
  cancelDailyReminder: (...args: unknown[]) => cancelDailyReminder(...(args as [])),
  scheduleMeasureReminder: (...args: unknown[]) => scheduleMeasureReminder(...(args as [Date])),
  cancelMeasureReminder: (...args: unknown[]) => cancelMeasureReminder(...(args as [])),
  migrateOrphanedReminderNotifications: (...args: unknown[]) =>
    migrateOrphanedReminderNotifications(...(args as [string])),
}));

const { syncReminderSchedule, syncMeasureReminderSchedule } = await import("../src/reminderSync");
const { setReminderEnabled, setReminderTime } = await import("../src/reminders");
const {
  setMeasureReminderEnabled,
  setMeasureReminderInterval,
  recordMeasureCompleted,
  clearMeasureReminderPrefs,
  clearLastMeasureDate,
} = await import("../src/measureReminders");

beforeEach(async () => {
  storage.__reset();
  scheduleDailyReminder.mockReset();
  scheduleDailyReminder.mockResolvedValue(true);
  cancelDailyReminder.mockReset();
  cancelDailyReminder.mockResolvedValue(true);
  scheduleMeasureReminder.mockReset();
  scheduleMeasureReminder.mockResolvedValue(true);
  cancelMeasureReminder.mockReset();
  cancelMeasureReminder.mockResolvedValue(true);
  migrateOrphanedReminderNotifications.mockReset();
  migrateOrphanedReminderNotifications.mockResolvedValue(undefined);
  // The cadence stamp is secureStore-backed (device-key ciphertext in
  // AsyncStorage): clear it so one test's completion never leaks into the
  // next test's cadence.
  await clearLastMeasureDate("user-1");
});

describe("syncReminderSchedule", () => {
  it("an enabled preference schedules at the stored local time and returns the capability result", async () => {
    await setReminderTime("user-1", 9, 30);
    await setReminderEnabled("user-1", true);
    await expect(syncReminderSchedule("user-1")).resolves.toBe(true);
    expect(scheduleDailyReminder).toHaveBeenCalledWith(9, 30, expect.objectContaining({ permit: expect.objectContaining({ userId: "user-1" }) }));
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

describe("syncMeasureReminderSchedule (2026-09-27: opt-in AND cadence)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("a disabled preference cancels — never a nudge the user never asked for", async () => {
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelMeasureReminder).toHaveBeenCalledTimes(1);
    expect(scheduleMeasureReminder).not.toHaveBeenCalled();
  });

  it("opt-in with NO completed measure schedules nothing (no baseline, no cadence)", async () => {
    await setMeasureReminderEnabled("user-1", true);
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelMeasureReminder).toHaveBeenCalledTimes(1);
    expect(scheduleMeasureReminder).not.toHaveBeenCalled();
  });

  it("opt-in + last measure OLDER than the interval schedules ONE one-shot nudge at the next calm 20:00", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 27, 11, 0, 0)); // 2026-09-27, before 20:00
    await setMeasureReminderEnabled("user-1", true); // default interval: 4 weeks
    await recordMeasureCompleted("user-1", "2026-08-20"); // 38 days old
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(scheduleMeasureReminder).toHaveBeenCalledTimes(1);
    const fireAt = scheduleMeasureReminder.mock.calls[0][0] as Date;
    expect(fireAt).toEqual(new Date(2026, 8, 27, 20, 0, 0, 0));
    expect(cancelMeasureReminder).not.toHaveBeenCalled();
  });

  it("a fresh completion schedules the next cadence even if the app stays closed", async () => {
    await setMeasureReminderEnabled("user-1", true);
    await recordMeasureCompleted("user-1", "2026-09-26");
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelMeasureReminder).not.toHaveBeenCalled();
    expect(scheduleMeasureReminder).toHaveBeenCalledWith(new Date(2026, 9, 24, 20, 0, 0, 0), expect.objectContaining({ permit: expect.objectContaining({ userId: "user-1" }) }));
  });

  it("the interval choice moves the due boundary (2 weeks due, 4 not yet)", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 27, 10, 0, 0));
    await recordMeasureCompleted("user-1", "2026-09-13"); // 14 days old
    await setMeasureReminderEnabled("user-1", true);
    await setMeasureReminderInterval("user-1", 2);
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(scheduleMeasureReminder).toHaveBeenCalledTimes(1);

    scheduleMeasureReminder.mockClear();
    cancelMeasureReminder.mockClear();
    await clearMeasureReminderPrefs("user-1");
    await setMeasureReminderEnabled("user-1", true); // back to the 4-week default
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(scheduleMeasureReminder).toHaveBeenCalledWith(new Date(2026, 9, 11, 20, 0, 0, 0), expect.objectContaining({ permit: expect.objectContaining({ userId: "user-1" }) }));
    expect(cancelMeasureReminder).not.toHaveBeenCalled();
  });

  it("a corrupt preference fails toward the disabled default — cancel, never a guess", async () => {
    await storage.setItem("@mindpattern/measure_reminders_user-1", "{\"enabled\":true,\"intervalWeeks\":99}");
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(true);
    expect(cancelMeasureReminder).toHaveBeenCalledTimes(1);
    expect(scheduleMeasureReminder).not.toHaveBeenCalled();
  });

  it("a scheduling that cannot land answers false without throwing", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 27, 10, 0, 0));
    await setMeasureReminderEnabled("user-1", true);
    await recordMeasureCompleted("user-1", "2026-08-01");
    scheduleMeasureReminder.mockResolvedValue(false);
    await expect(syncMeasureReminderSchedule("user-1")).resolves.toBe(false);
  });
});
