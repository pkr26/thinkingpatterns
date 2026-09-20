/**
 * Reminder preferences (src/reminders.ts): the per-account record, the
 * hostile-input guards on everything read back from storage, clear
 * hygiene, and the PURE nextReminderFireTime across day/month boundaries.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import {
  clearReminderPrefs,
  DEFAULT_REMINDER_PREFS,
  DEFAULT_REMINDER_TIME,
  getReminderPrefs,
  nextReminderFireTime,
  setReminderEnabled,
  setReminderTime,
} from "../src/reminders";

const KEY_USER1 = "@mindpattern/reminders_user-1";
const KEY_USER2 = "@mindpattern/reminders_user-2";

beforeEach(() => {
  storage.__reset();
});

describe("reminder preference round-trip", () => {
  it("reads the disabled 20:00 default when nothing was ever stored", async () => {
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 20, minute: 0 });
    expect(DEFAULT_REMINDER_PREFS.enabled).toBe(false);
    expect(DEFAULT_REMINDER_TIME).toEqual({ hour: 20, minute: 0 });
  });

  it("enabling persists per account and reads back exactly", async () => {
    await setReminderEnabled("user-1", true);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: true, hour: 20, minute: 0 });
    expect(JSON.parse((await storage.getItem(KEY_USER1)) as string)).toEqual({
      enabled: true,
      hour: 20,
      minute: 0,
    });
  });

  it("choosing a time persists it and enabling preserves the chosen time", async () => {
    await setReminderTime("user-1", 9, 30);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 9, minute: 30 });
    await setReminderEnabled("user-1", true);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: true, hour: 9, minute: 30 });
    // Toggling later never disturbs the time.
    await setReminderEnabled("user-1", false);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 9, minute: 30 });
  });

  it("out-of-range times are refused defensively (never written as hour 99)", async () => {
    await setReminderTime("user-1", 24, 0);
    await setReminderTime("user-1", -1, 0);
    await setReminderTime("user-1", 9, 60);
    await setReminderTime("user-1", 10.5, 0 as never);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 20, minute: 0 });
  });

  it("records are per account — one account's reminder is not another's", async () => {
    await setReminderEnabled("user-1", true);
    await setReminderTime("user-2", 7, 15);
    expect((await getReminderPrefs("user-1")).enabled).toBe(true);
    expect(await getReminderPrefs("user-2")).toEqual({ enabled: false, hour: 7, minute: 15 });
    expect(await storage.getItem(KEY_USER2)).toContain("\"hour\":7");
  });
});

describe("hostile or corrupt storage reads fail toward the disabled default", () => {
  it.each([
    ["not json at all", "garbage{"],
    ["non-object json", "\"just a string\""],
    ["wrong-typed fields", JSON.stringify({ enabled: "yes", hour: 20, minute: 0 })],
    ["hostile hour", JSON.stringify({ enabled: true, hour: 99, minute: 0 })],
    ["hostile negative minute", JSON.stringify({ enabled: true, hour: 8, minute: -5 })],
    ["fractional hour", JSON.stringify({ enabled: true, hour: 8.5, minute: 0 })],
    ["missing fields", JSON.stringify({ enabled: true })],
  ])("%s reads as the default", async (_label, raw) => {
    await storage.setItem(KEY_USER1, raw);
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 20, minute: 0 });
  });

  it("a throwing storage read still answers the default instead of crashing Settings", async () => {
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      await expect(getReminderPrefs("user-1")).resolves.toEqual({ enabled: false, hour: 20, minute: 0 });
    } finally {
      storage.getItem = original;
    }
  });
});

describe("account-deletion hygiene", () => {
  it("clearReminderPrefs removes the record (and only that account's)", async () => {
    await setReminderEnabled("user-1", true);
    await setReminderEnabled("user-2", true);
    await clearReminderPrefs("user-1");
    expect(await storage.getItem(KEY_USER1)).toBeNull();
    expect(await storage.getItem(KEY_USER2)).not.toBeNull();
    expect(await getReminderPrefs("user-1")).toEqual({ enabled: false, hour: 20, minute: 0 });
  });
});

describe("nextReminderFireTime (PURE, local-time semantics)", () => {
  it("today's slot when it is still ahead of now", () => {
    const now = new Date(2026, 8, 19, 10, 0, 0);
    const fire = nextReminderFireTime(now, 20, 0);
    expect(fire).toEqual(new Date(2026, 8, 19, 20, 0, 0, 0));
  });

  it("a slot already past rolls to TOMORROW at the same local time", () => {
    const now = new Date(2026, 8, 19, 21, 30, 0);
    const fire = nextReminderFireTime(now, 20, 0);
    expect(fire).toEqual(new Date(2026, 8, 20, 20, 0, 0, 0));
  });

  it("a slot exactly now has already missed its moment — tomorrow", () => {
    const now = new Date(2026, 8, 19, 20, 0, 0, 0);
    expect(nextReminderFireTime(now, 20, 0)).toEqual(new Date(2026, 8, 20, 20, 0, 0, 0));
  });

  it("crosses the day boundary into the next month (2026-09-30 23:59 → 10-01)", () => {
    const now = new Date(2026, 8, 30, 23, 59, 30);
    expect(nextReminderFireTime(now, 23, 59)).toEqual(new Date(2026, 9, 1, 23, 59, 0, 0));
  });

  it("crosses the year boundary (Dec 31 after the slot → Jan 1)", () => {
    const now = new Date(2026, 11, 31, 23, 45, 0);
    expect(nextReminderFireTime(now, 23, 30)).toEqual(new Date(2027, 0, 1, 23, 30, 0, 0));
  });

  it("midnight slot after midnight is today; before midnight is tomorrow", () => {
    expect(nextReminderFireTime(new Date(2026, 8, 19, 0, 0, 1), 0, 0)).toEqual(
      new Date(2026, 8, 20, 0, 0, 0, 0),
    );
    expect(nextReminderFireTime(new Date(2026, 8, 18, 23, 59, 59), 0, 0)).toEqual(
      new Date(2026, 8, 19, 0, 0, 0, 0),
    );
  });
});
