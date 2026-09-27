/**
 * The MBC check-in reminder modules (2026-09-27):
 *  - src/measureReminders.ts: the per-account preference record, the
 *    hostile-input guards, the cadence stamp (forward-only), and the PURE
 *    due / fire-time predicates across calendar boundaries;
 *  - src/notificationRoute.ts: the notification-id → screen mapping and
 *    the one-shot queue the navigator consumes at main-flow entry.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

const {
  clearLastMeasureDate,
  clearMeasureReminderPrefs,
  DEFAULT_MEASURE_REMINDER_PREFS,
  getMeasureReminderPrefs,
  lastMeasureCompletedOn,
  MEASURE_INTERVAL_WEEKS,
  measureReminderDue,
  nextMeasureReminderFireTime,
  recordMeasureCompleted,
  setMeasureReminderEnabled,
  setMeasureReminderInterval,
} = await import("../src/measureReminders");

const KEY_USER1 = "@mindpattern/measure_reminders_user-1";
const KEY_USER2 = "@mindpattern/measure_reminders_user-2";

beforeEach(() => {
  storage.__reset();
  vi.useRealTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("check-in preference round-trip", () => {
  it("reads the disabled 4-week default when nothing was ever stored", async () => {
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: false, intervalWeeks: 4 });
    expect(DEFAULT_MEASURE_REMINDER_PREFS).toEqual({ enabled: false, intervalWeeks: 4 });
    expect(MEASURE_INTERVAL_WEEKS).toEqual([2, 4, 8]);
  });

  it("enabling persists per account and reads back exactly", async () => {
    await setMeasureReminderEnabled("user-1", true);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: true, intervalWeeks: 4 });
    expect(JSON.parse((await storage.getItem(KEY_USER1)) as string)).toEqual({
      enabled: true,
      intervalWeeks: 4,
    });
  });

  it("choosing an interval persists it and enabling preserves it (and vice versa)", async () => {
    await setMeasureReminderInterval("user-1", 8);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: false, intervalWeeks: 8 });
    await setMeasureReminderEnabled("user-1", true);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: true, intervalWeeks: 8 });
    await setMeasureReminderInterval("user-1", 2);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: true, intervalWeeks: 2 });
  });

  it("intervals outside the offer are refused defensively (never week 99)", async () => {
    await setMeasureReminderInterval("user-1", 3);
    await setMeasureReminderInterval("user-1", 0);
    await setMeasureReminderInterval("user-1", -4);
    await setMeasureReminderInterval("user-1", 99);
    await setMeasureReminderInterval("user-1", 2.5 as never);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: false, intervalWeeks: 4 });
  });

  it("records are per account — one account's cadence is not another's", async () => {
    await setMeasureReminderEnabled("user-1", true);
    await setMeasureReminderInterval("user-2", 2);
    expect((await getMeasureReminderPrefs("user-1")).intervalWeeks).toBe(4);
    expect(await getMeasureReminderPrefs("user-2")).toEqual({ enabled: false, intervalWeeks: 2 });
    expect(await storage.getItem(KEY_USER2)).toContain("\"intervalWeeks\":2");
  });
});

describe("hostile or corrupt preference reads fail toward the disabled default", () => {
  it.each([
    ["not json at all", "garbage{"],
    ["non-object json", "\"a string\""],
    ["wrong-typed fields", JSON.stringify({ enabled: "yes", intervalWeeks: 4 })],
    ["hostile interval", JSON.stringify({ enabled: true, intervalWeeks: 99 })],
    ["fractional interval", JSON.stringify({ enabled: true, intervalWeeks: 4.5 })],
    ["missing fields", JSON.stringify({ enabled: true })],
  ])("%s reads as the default", async (_label, raw) => {
    await storage.setItem(KEY_USER1, raw);
    expect(await getMeasureReminderPrefs("user-1")).toEqual({ enabled: false, intervalWeeks: 4 });
  });

  it("a throwing storage read still answers the default instead of crashing Settings", async () => {
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      await expect(getMeasureReminderPrefs("user-1")).resolves.toEqual({ enabled: false, intervalWeeks: 4 });
    } finally {
      storage.getItem = original;
    }
  });
});

describe("account-deletion hygiene (preferences)", () => {
  it("clearMeasureReminderPrefs removes the record (and only that account's)", async () => {
    await setMeasureReminderEnabled("user-1", true);
    await setMeasureReminderEnabled("user-2", true);
    await clearMeasureReminderPrefs("user-1");
    expect(await storage.getItem(KEY_USER1)).toBeNull();
    expect(await storage.getItem(KEY_USER2)).not.toBeNull();
  });
});

describe("the cadence stamp (last completed measure day)", () => {
  it("round-trips and reads as null when absent", async () => {
    expect(await lastMeasureCompletedOn("user-1")).toBeNull();
    await recordMeasureCompleted("user-1", "2026-09-27");
    expect(await lastMeasureCompletedOn("user-1")).toBe("2026-09-27");
  });

  it("is FORWARD-ONLY: an older retry never rewinds the clock", async () => {
    await recordMeasureCompleted("user-1", "2026-09-20");
    await recordMeasureCompleted("user-1", "2026-09-10"); // a stale pending retry
    expect(await lastMeasureCompletedOn("user-1")).toBe("2026-09-20");
    await recordMeasureCompleted("user-1", "2026-09-26");
    expect(await lastMeasureCompletedOn("user-1")).toBe("2026-09-26");
  });

  it("refuses malformed dates and reads hostile stamps as absent", async () => {
    await recordMeasureCompleted("user-1", "09/27/2026");
    await recordMeasureCompleted("user-1", "not-a-date");
    expect(await lastMeasureCompletedOn("user-1")).toBeNull();
    // A hostile stamp planted at the raw slot (behind the secureStore
    // envelope, so planted as ciphertext is unnecessary — the VALUE check
    // guards it) reads as absent, never as a fabricated date.
    const { secureStore } = await import("../src/secureStore");
    await secureStore.setItem("@mindpattern/last_measure_user-1", "9999-99-99");
    expect(await lastMeasureCompletedOn("user-1")).toBeNull();
  });

  it("clearLastMeasureDate removes the stamp (deletion hygiene)", async () => {
    await recordMeasureCompleted("user-1", "2026-09-27");
    await clearLastMeasureDate("user-1");
    expect(await lastMeasureCompletedOn("user-1")).toBeNull();
  });
});

describe("measureReminderDue (PURE, local calendar semantics)", () => {
  it("never due without a baseline — no completed measure, no cadence to nudge", () => {
    expect(measureReminderDue(null, 4, new Date(2026, 8, 27))).toBe(false);
  });

  it("the 4-week boundary: 27 days not due, 28 days due", () => {
    const now = new Date(2026, 8, 27, 15, 0, 0);
    expect(measureReminderDue("2026-08-31", 4, now)).toBe(false); // 27 days
    expect(measureReminderDue("2026-08-30", 4, now)).toBe(true); // 28 days
  });

  it("each offered interval moves the boundary exactly", () => {
    const now = new Date(2026, 8, 27, 8, 0, 0);
    expect(measureReminderDue("2026-09-14", 2, now)).toBe(false); // 13 days
    expect(measureReminderDue("2026-09-13", 2, now)).toBe(true); // 14 days
    expect(measureReminderDue("2026-08-03", 8, now)).toBe(false); // 55 days
    expect(measureReminderDue("2026-08-02", 8, now)).toBe(true); // 56 days
  });

  it("counts CALENDAR days: the same wall date at any hour is the same day", () => {
    // Completed 2026-08-30; 2026-09-27 is day 28 — due at midnight and at
    // 23:59 alike (local midnight-to-midnight, never a UTC guess).
    expect(measureReminderDue("2026-08-30", 4, new Date(2026, 8, 27, 0, 0, 0))).toBe(true);
    expect(measureReminderDue("2026-08-30", 4, new Date(2026, 8, 27, 23, 59, 59))).toBe(true);
    // Yesterday-relative: 27 days at 23:59 is still not due.
    expect(measureReminderDue("2026-08-31", 4, new Date(2026, 8, 27, 23, 59, 59))).toBe(false);
  });

  it("crosses month boundaries correctly (2026-09-27 minus 4 weeks)", () => {
    expect(measureReminderDue("2026-08-30", 4, new Date(2026, 8, 27, 12))).toBe(true);
    expect(measureReminderDue("2026-08-31", 4, new Date(2026, 8, 27, 12))).toBe(false);
  });

  it("hostile input is never due", () => {
    const now = new Date(2026, 8, 27);
    expect(measureReminderDue("garbage", 4, now)).toBe(false);
    expect(measureReminderDue("2026-13-45", 4, now)).toBe(false);
    expect(measureReminderDue("2030-01-01", 4, now)).toBe(false); // future stamp: corrupt, not due
    expect(measureReminderDue("2026-08-01", 0, now)).toBe(false);
    expect(measureReminderDue("2026-08-01", -4, now)).toBe(false);
    expect(measureReminderDue("2026-08-01", 2.5, now)).toBe(false);
  });
});

describe("nextMeasureReminderFireTime (PURE: the calm evening slot)", () => {
  it("today's 20:00 when it is still ahead of now", () => {
    expect(nextMeasureReminderFireTime(new Date(2026, 8, 27, 11, 0, 0))).toEqual(
      new Date(2026, 8, 27, 20, 0, 0, 0),
    );
  });

  it("a slot already past rolls to TOMORROW 20:00 (never a morning alarm, never immediate)", () => {
    expect(nextMeasureReminderFireTime(new Date(2026, 8, 27, 21, 30, 0))).toEqual(
      new Date(2026, 8, 28, 20, 0, 0, 0),
    );
    expect(nextMeasureReminderFireTime(new Date(2026, 8, 27, 20, 0, 0))).toEqual(
      new Date(2026, 8, 28, 20, 0, 0, 0),
    );
  });

  it("crosses the month boundary", () => {
    expect(nextMeasureReminderFireTime(new Date(2026, 8, 30, 21, 0, 0))).toEqual(
      new Date(2026, 9, 1, 20, 0, 0, 0),
    );
  });
});

describe("notificationRoute (notification id → screen, one-shot queue)", () => {
  it("maps the measure reminder id to Measures and nothing else", async () => {
    const { screenForNotificationId } = await import("../src/notificationRoute");
    expect(screenForNotificationId("mindpattern-measure-reminder")).toBe("Measures");
    expect(screenForNotificationId("mindpattern-daily-reminder")).toBeNull();
    expect(screenForNotificationId(undefined)).toBeNull();
    expect(screenForNotificationId(42)).toBeNull();
    expect(screenForNotificationId(null)).toBeNull();
  });

  it("queues and consumes exactly once; unknown ids never route", async () => {
    const {
      hasPendingNotificationRoute,
      queueNotificationRoute,
      takePendingNotificationRoute,
    } = await import("../src/notificationRoute");
    expect(takePendingNotificationRoute()).toBeNull(); // drain leftovers
    expect(hasPendingNotificationRoute()).toBe(false);

    queueNotificationRoute("mindpattern-measure-reminder");
    expect(hasPendingNotificationRoute()).toBe(true);
    expect(takePendingNotificationRoute()).toBe("Measures");
    // One-shot: consumed, not sticky — the next main-flow entry is ordinary.
    expect(takePendingNotificationRoute()).toBeNull();

    queueNotificationRoute("some-other-notification");
    expect(hasPendingNotificationRoute()).toBe(false);
    expect(takePendingNotificationRoute()).toBeNull();
  });

  it("a second tap before the app opens REPLACES the first (latest intent wins)", async () => {
    const { queueNotificationRoute, takePendingNotificationRoute } = await import("../src/notificationRoute");
    queueNotificationRoute("mindpattern-measure-reminder");
    queueNotificationRoute("mindpattern-measure-reminder");
    expect(takePendingNotificationRoute()).toBe("Measures");
    expect(takePendingNotificationRoute()).toBeNull();
  });
});
