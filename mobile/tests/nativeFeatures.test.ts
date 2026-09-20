/**
 * The notifee action seam in src/nativeFeatures.ts (2026-09-19): a missing
 * module is a quiet false, permission denial is a false with no
 * notification created, and a present module (injected via vi.mock on the
 * seam's dynamic import) produces exactly one repeating DAILY trigger at
 * the next local fire time.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// The seam resolves the module through a dynamic import (require fails in
// a node build), which vi.mock intercepts — see probeAsync in nativeFeatures.
const requestPermission = vi.fn(async () => ({ authorizationStatus: 1 }));
const createTriggerNotification = vi.fn(async () => "notif-1");
const cancelAllNotifications = vi.fn(async () => undefined);
const createChannel = vi.fn(async () => "mindpattern-reminders");

vi.mock("@notifee/react-native", () => ({
  default: { requestPermission, createTriggerNotification, cancelAllNotifications, createChannel },
  TriggerType: { TIMESTAMP: 0 },
  RepeatFrequency: { HOURLY: 0, DAILY: 1, WEEKLY: 2 },
}));

const { scheduleDailyReminder, cancelDailyReminder } = await import("../src/nativeFeatures");
const { nextReminderFireTime } = await import("../src/reminders");

beforeEach(() => {
  requestPermission.mockReset();
  requestPermission.mockResolvedValue({ authorizationStatus: 1 });
  createTriggerNotification.mockReset();
  createTriggerNotification.mockResolvedValue("notif-1");
  cancelAllNotifications.mockReset();
  cancelAllNotifications.mockResolvedValue(undefined);
  createChannel.mockReset();
  createChannel.mockResolvedValue("mindpattern-reminders");
});

describe("scheduleDailyReminder", () => {
  it("asks permission first, then creates ONE repeating daily trigger at the next local fire time", async () => {
    const before = Date.now();
    expect(await scheduleDailyReminder(20, 0)).toBe(true);
    expect(requestPermission).toHaveBeenCalledTimes(1);
    expect(createTriggerNotification).toHaveBeenCalledTimes(1);
    const [notification, trigger] = createTriggerNotification.mock.calls[0] as [
      { title: string; body: string; android: { channelId: string } },
      { type: number; timestamp: number; repeatFrequency: number },
    ];
    // Calm copy, no streak-shaming, and the app's own channel.
    expect(notification).toEqual({
      title: "MindPattern",
      body: "A quiet moment to write, whenever it suits you.",
      android: { channelId: "mindpattern-reminders" },
    });
    expect(trigger.type).toBe(0); // TriggerType.TIMESTAMP (from the module's enums)
    expect(trigger.repeatFrequency).toBe(1); // RepeatFrequency.DAILY
    const expectedMin = nextReminderFireTime(new Date(before), 20, 0).getTime();
    const expectedMax = nextReminderFireTime(new Date(Date.now()), 20, 0).getTime();
    expect(trigger.timestamp).toBeGreaterThanOrEqual(expectedMin);
    expect(trigger.timestamp).toBeLessThanOrEqual(expectedMax);
    // The Android channel was ensured before scheduling.
    expect(createChannel).toHaveBeenCalledWith({ id: "mindpattern-reminders", name: "Journal reminders" });
  });

  it("a denied permission schedules NOTHING and reports false", async () => {
    requestPermission.mockResolvedValue({ authorizationStatus: 0 }); // DENIED
    expect(await scheduleDailyReminder(9, 0)).toBe(false);
    expect(createTriggerNotification).not.toHaveBeenCalled();
    expect(createChannel).not.toHaveBeenCalled();
  });

  it("a bare AuthorizationStatus number is honored too (Android contract)", async () => {
    requestPermission.mockResolvedValue(1);
    expect(await scheduleDailyReminder(9, 0)).toBe(true);
  });

  it("provisional authorization does not count as granted for a daily nudge", async () => {
    requestPermission.mockResolvedValue({ authorizationStatus: 2 });
    expect(await scheduleDailyReminder(9, 0)).toBe(false);
    expect(createTriggerNotification).not.toHaveBeenCalled();
  });

  it("a native failure mid-schedule is a false, never a throw", async () => {
    createTriggerNotification.mockRejectedValue(new Error("native exploded"));
    expect(await scheduleDailyReminder(20, 0)).toBe(false);
  });

  it("a permission call failure is a false, never a throw", async () => {
    requestPermission.mockRejectedValue(new Error("no activity"));
    expect(await scheduleDailyReminder(20, 0)).toBe(false);
    expect(createTriggerNotification).not.toHaveBeenCalled();
  });
});

describe("cancelDailyReminder", () => {
  it("cancels the app's (only) notifications and reports true", async () => {
    expect(await cancelDailyReminder()).toBe(true);
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    expect(requestPermission).not.toHaveBeenCalled(); // cancel needs no permission
  });

  it("a native failure is a false, never a throw", async () => {
    cancelAllNotifications.mockRejectedValue(new Error("native exploded"));
    expect(await cancelDailyReminder()).toBe(false);
  });
});

describe("module ABSENT (this build)", () => {
  it("both actions are quiet no-ops returning false", async () => {
    // Simulate the unlinked build: the dynamic import resolves to nothing
    // by making the probed API unusable for this one call.
    const notifee = (await import("@notifee/react-native")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = notifee.default.requestPermission;
    delete notifee.default.requestPermission;
    try {
      expect(await scheduleDailyReminder(20, 0)).toBe(false);
      expect(await cancelDailyReminder()).toBe(false);
    } finally {
      notifee.default.requestPermission = original;
    }
  });
});
