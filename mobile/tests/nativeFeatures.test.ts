/**
 * The notifee action seam in src/nativeFeatures.ts (2026-09-19): a missing
 * module is a quiet false, permission denial is a false with no
 * notification created, and a present module (injected via vi.mock on the
 * seam's dynamic import) produces exactly one repeating DAILY trigger at
 * the next local fire time.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { __resetLocalKeyLifecycleForTests, changeLocalSessionOwner } from "../src/localWriteGuard";

// The seam resolves the module through a dynamic import (require fails in
// a node build), which vi.mock intercepts — see probeAsync in nativeFeatures.
const requestPermission = vi.fn(async () => ({ authorizationStatus: 1 }));
const createTriggerNotification = vi.fn(async () => "notif-1");
const cancelAllNotifications = vi.fn(async () => undefined);
const cancelNotification = vi.fn(async () => undefined);
const createChannel = vi.fn(async () => "mindpattern-reminders");

vi.mock("@notifee/react-native", () => ({
  default: { requestPermission, createTriggerNotification, cancelAllNotifications, cancelNotification, createChannel },
  TriggerType: { TIMESTAMP: 0 },
  RepeatFrequency: { HOURLY: 0, DAILY: 1, WEEKLY: 2 },
}));

const { scheduleDailyReminder, cancelDailyReminder, cancelOriginNotifications } = await import("../src/nativeFeatures");
const { nextReminderFireTime } = await import("../src/reminders");

beforeEach(() => {
  __resetLocalKeyLifecycleForTests();
  changeLocalSessionOwner("user-1");
  requestPermission.mockReset();
  requestPermission.mockResolvedValue({ authorizationStatus: 1 });
  createTriggerNotification.mockReset();
  createTriggerNotification.mockResolvedValue("notif-1");
  cancelAllNotifications.mockReset();
  cancelAllNotifications.mockResolvedValue(undefined);
  cancelNotification.mockReset();
  cancelNotification.mockResolvedValue(undefined);
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
      { id: string; title: string; body: string; android: { channelId: string } },
      { type: number; timestamp: number; repeatFrequency: number },
    ];
    // Calm copy, no streak-shaming, the app's own channel — and the STABLE
    // notification id (2026-09-26 audit MEDIUM): notifee mints a random id
    // when none is passed, and each reschedule stacked a fresh daily
    // trigger; a stable id replaces the previous schedule instead.
    expect(notification).toEqual({
      id: "mindpattern-daily-reminder",
      title: "Fathom",
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

describe("reschedule idempotency (2026-09-26 audit MEDIUM)", () => {
  it("N session-start syncs converge to ONE schedule: every create rides the SAME stable id, each preceded by a cancel of that id", async () => {
    // reminderSync.ts reconciles on EVERY session start; before the fix,
    // each schedule call minted a random notifee id and stacked a new
    // daily trigger (N restarts = N notifications a day). The contract
    // now: the stable id replaces the previous schedule AND the previous
    // id is cancelled explicitly before the create (belt-and-braces for
    // platform builds that lag on same-id replacement).
    const syncs = 5; // five app restarts for an enabled user
    for (let i = 0; i < syncs; i++) {
      expect(await scheduleDailyReminder(20, 0)).toBe(true);
    }
    expect(createTriggerNotification).toHaveBeenCalledTimes(syncs);
    expect(cancelNotification).toHaveBeenCalledTimes(syncs);
    expect(cancelNotification).toHaveBeenNthCalledWith(1, "mindpattern-daily-reminder");
    const ids = (createTriggerNotification.mock.calls as unknown as [
      { id: string },
      unknown,
    ][]).map((call) => call[0].id);
    expect(new Set(ids)).toEqual(new Set(["mindpattern-daily-reminder"]));
    // ORDER: each cancel lands before its create, so no window exists
    // where two schedules for the reminder are live at once.
    for (let i = 0; i < syncs; i++) {
      expect(cancelNotification.mock.invocationCallOrder[i]).toBeLessThan(
        createTriggerNotification.mock.invocationCallOrder[i],
      );
    }
    // The cancel is scoped to the reminder id — never the app's whole
    // notification set (that is cancelDailyReminder's job, deliberately
    // a user action).
    expect(cancelAllNotifications).not.toHaveBeenCalled();
  });

  it("a failed pre-create cancel never blocks the schedule (the stable id is the primary guarantee)", async () => {
    cancelNotification.mockRejectedValue(new Error("nothing scheduled"));
    expect(await scheduleDailyReminder(20, 0)).toBe(true);
    expect(createTriggerNotification).toHaveBeenCalledTimes(1);
  });

  it("an ancient notifee build without cancelNotification still schedules under the stable id", async () => {
    const notifee = (await import("@notifee/react-native")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = notifee.default.cancelNotification;
    delete notifee.default.cancelNotification;
    try {
      expect(await scheduleDailyReminder(20, 0)).toBe(true);
      const [notification] = createTriggerNotification.mock.calls[0] as [
        { id: string },
        unknown,
      ];
      expect(notification.id).toBe("mindpattern-daily-reminder");
    } finally {
      notifee.default.cancelNotification = original;
    }
  });
});

describe("cancelDailyReminder", () => {
  it("cancels by the STABLE reminder id (scoped, never the app's whole set)", async () => {
    expect(await cancelDailyReminder()).toBe(true);
    expect(cancelNotification).toHaveBeenCalledWith("mindpattern-daily-reminder");
    expect(cancelAllNotifications).not.toHaveBeenCalled();
    expect(requestPermission).not.toHaveBeenCalled(); // cancel needs no permission
  });

  it("an ancient notifee build without cancelNotification falls back to cancelAllNotifications", async () => {
    const notifee = (await import("@notifee/react-native")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = notifee.default.cancelNotification;
    delete notifee.default.cancelNotification;
    try {
      expect(await cancelDailyReminder()).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    } finally {
      notifee.default.cancelNotification = original;
    }
  });

  it("a native failure is a false, never a throw", async () => {
    cancelNotification.mockRejectedValue(new Error("native exploded"));
    expect(await cancelDailyReminder()).toBe(false);
  });
});

describe("cancelOriginNotifications", () => {
  it("retires the complete app-owned notification set", async () => {
    expect(await cancelOriginNotifications()).toBe(true);
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    expect(cancelNotification).not.toHaveBeenCalled();
  });

  it("reports a present native scheduler failure", async () => {
    cancelAllNotifications.mockRejectedValueOnce(new Error("native exploded"));
    expect(await cancelOriginNotifications()).toBe(false);
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
      expect(await cancelOriginNotifications()).toBe(true);
    } finally {
      notifee.default.requestPermission = original;
    }
  });
});

describe("notification copy resolves through the catalog (audit fix 22, 2026-09-21)", () => {
  it("the reminder body and Android channel name follow the app locale (catalog parity in both)", async () => {
    const { __setLocaleForTests, enCatalog, esCatalog } = await import("../src/strings");
    // Catalog parity: both locales carry the two keys with distinct copy.
    for (const key of ["notify.reminderBody", "notify.channelName"]) {
      expect(typeof enCatalog[key]).toBe("string");
      expect(enCatalog[key]!.length).toBeGreaterThan(2);
      expect(typeof esCatalog[key]).toBe("string");
      expect(esCatalog[key]!.length).toBeGreaterThan(2);
      expect(esCatalog[key]).not.toBe(enCatalog[key]);
    }

    __setLocaleForTests("es");
    try {
      expect(await scheduleDailyReminder(20, 0)).toBe(true);
      const [notification] = createTriggerNotification.mock.calls[0] as [
        { title: string; body: string },
        unknown,
      ];
      // Spanish nudge, Spanish channel name…
      expect(notification.body).toBe("Un momento tranquilo para escribir, cuando le venga bien.");
      expect(createChannel).toHaveBeenCalledWith({
        id: "mindpattern-reminders",
        name: "Recordatorios del diario",
      });
      // …but the app-name title is the brand and never translates.
      expect(notification.title).toBe("Fathom");
    } finally {
      __setLocaleForTests("en");
    }

    // English still resolves through the catalog (not a hardcoded literal).
    expect(await scheduleDailyReminder(20, 0)).toBe(true);
    const calls = createTriggerNotification.mock.calls as unknown as [
      { title: string; body: string },
      unknown,
    ][];
    const english = calls[calls.length - 1]![0];
    expect(english.body).toBe("A quiet moment to write, whenever it suits you.");
  });
});

// --- independent audit 2026-09-27 (P3): the cancel-all fallback must not
// kill the sibling reminder. Builds without per-id cancel used to wipe BOTH
// schedules; with a userId the survivor is re-created from its stored
// preference through the same schedule function and stable id.
const storageForSiblings = (await import("./helpers/storageMock")).default;
const { cancelMeasureReminder } = await import("../src/nativeFeatures");
const { setReminderEnabled, setReminderTime } = await import("../src/reminders");
const { setMeasureReminderEnabled, recordMeasureCompleted } = await import("../src/measureReminders");

describe("fallback cancel-all restores the SIBLING reminder (P3, 2026-09-27)", () => {
  const storage = storageForSiblings;

  /** Simulate the ancient notifee build for one test body. */
  const withoutPerIdCancel = async (): Promise<() => void> => {
    const notifee = (await import("@notifee/react-native")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = notifee.default.cancelNotification;
    delete notifee.default.cancelNotification;
    return () => {
      notifee.default.cancelNotification = original;
    };
  };

  beforeEach(() => {
    storage.__reset();
  });

  it("cancelDailyReminder(userId) re-creates the measure nudge when its preference + cadence say one exists", async () => {
    const restore = await withoutPerIdCancel();
    try {
      // Enabled AND the cadence is due: the last completion is 5 weeks old
      // (the stamp is forward-only, so the encrypted slot is seeded
      // directly — the same lane recordMeasureCompleted writes).
      await setMeasureReminderEnabled("user-1", true);
      const { secureStore } = await import("../src/secureStore");
      const fiveWeeksAgo = new Date(Date.now() - 35 * 86_400_000).toISOString().slice(0, 10);
      await secureStore.setItem("@mindpattern/last_measure_user-1", fiveWeeksAgo);
      createTriggerNotification.mockClear();
      cancelAllNotifications.mockClear();

      expect(await cancelDailyReminder("user-1")).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1); // the fallback ran
      // …and the sibling came back under its OWN stable id.
      expect(createTriggerNotification).toHaveBeenCalledTimes(1);
      const [notification] = createTriggerNotification.mock.calls[0] as [
        { id: string },
        unknown,
      ];
      expect(notification.id).toBe("mindpattern-measure-reminder");
    } finally {
      restore();
    }
  });

  it("cancelDailyReminder(userId) skips the restore when the measure nudge is opted out", async () => {
    const restore = await withoutPerIdCancel();
    try {
      createTriggerNotification.mockClear();
      expect(await cancelDailyReminder("user-1")).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
      expect(createTriggerNotification).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("cancelDailyReminder(userId) restores the next future cadence after a fresh completion", async () => {
    const restore = await withoutPerIdCancel();
    try {
      await setMeasureReminderEnabled("user-1", true);
      await recordMeasureCompleted("user-1", new Date().toISOString().slice(0, 10));
      createTriggerNotification.mockClear();
      expect(await cancelDailyReminder("user-1")).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
      expect(createTriggerNotification).toHaveBeenCalledTimes(1);
      const trigger = createTriggerNotification.mock.calls[0]![1] as { timestamp: number };
      expect(trigger.timestamp).toBeGreaterThan(Date.now() + 27 * 86_400_000);
    } finally {
      restore();
    }
  });

  it("cancelMeasureReminder(userId) re-creates the DAILY reminder at the preference's own time", async () => {
    const restore = await withoutPerIdCancel();
    try {
      await setReminderEnabled("user-1", true);
      await setReminderTime("user-1", 20, 30);
      createTriggerNotification.mockClear();
      const before = Date.now();
      expect(await cancelMeasureReminder("user-1")).toBe(true);
      const after = Date.now();

      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
      expect(createTriggerNotification).toHaveBeenCalledTimes(1);
      const [notification, trigger] = createTriggerNotification.mock.calls[0] as [
        { id: string },
        { timestamp: number },
      ];
      expect(notification.id).toBe("mindpattern-daily-reminder");
      expect(trigger.timestamp).toBeGreaterThanOrEqual(nextReminderFireTime(new Date(before), 20, 30).getTime());
      expect(trigger.timestamp).toBeLessThanOrEqual(nextReminderFireTime(new Date(after), 20, 30).getTime());
    } finally {
      restore();
    }
  });

  it("WITHOUT a userId (sign-out / account deletion) the fallback stays a plain cancel-all", async () => {
    const restore = await withoutPerIdCancel();
    try {
      await setMeasureReminderEnabled("user-1", true);
      createTriggerNotification.mockClear();
      expect(await cancelDailyReminder()).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
      expect(createTriggerNotification).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("a failing sibling restore never fails the cancel itself (self-heals at next sync)", async () => {
    const restore = await withoutPerIdCancel();
    try {
      await setMeasureReminderEnabled("user-1", true);
      createTriggerNotification.mockRejectedValueOnce(new Error("native exploded"));
      expect(await cancelDailyReminder("user-1")).toBe(true);
      expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    } finally {
      restore();
    }
  });
});

// --- L-9 (2026-09-28): the ONE-TIME orphaned random-id sweep -----------------
// A device upgraded from the pre-stable-id build carries random-id daily
// notifications that no stable-id cancel can ever reach; the FIRST resync on
// this version clears EVERYTHING once (the cancel-all fallback) and rebuilds
// both reminders from stored prefs under their stable ids. The whole resync
// path runs here (real reminderSync + real nativeFeatures seam + the
// notifee/storage stubs above) — exactly the boot of an upgraded device.
const { syncReminderSchedule } = await import("../src/reminderSync");

describe("one-time orphan-id migration (L-9, 2026-09-28)", () => {
  beforeEach(() => {
    storageForSiblings.__reset();
  });

  it("first resync on an upgraded device clears ALL notifications once and reschedules BOTH reminders from prefs", async () => {
    await setReminderEnabled("user-1", true);
    await setReminderTime("user-1", 20, 30);
    await setMeasureReminderEnabled("user-1", true);
    // The measure cadence is DUE: the last completion is 5 weeks old (the
    // stamp is forward-only, so the encrypted slot is seeded directly —
    // the same lane recordMeasureCompleted writes).
    const { secureStore } = await import("../src/secureStore");
    const fiveWeeksAgo = new Date(Date.now() - 35 * 86_400_000).toISOString().slice(0, 10);
    await secureStore.setItem("@mindpattern/last_measure_user-1", fiveWeeksAgo);
    createTriggerNotification.mockClear();
    cancelAllNotifications.mockClear();

    expect(await syncReminderSchedule("user-1")).toBe(true);
    // The sweep ran EXACTLY once and cleared the app's WHOLE notification
    // set — the orphaned random ids from the pre-fix build included.
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1);
    // …and rebuilt BOTH reminders under their STABLE ids from stored prefs
    // (the migration's own reschedule, then the sync's daily reconcile).
    const ids = (createTriggerNotification.mock.calls as unknown as [{ id: string }, unknown][])
      .map((call) => call[0].id);
    expect(new Set(ids)).toEqual(new Set(["mindpattern-daily-reminder", "mindpattern-measure-reminder"]));
    // The flag is committed only AFTER the reschedule completed.
    expect(await storageForSiblings.getItem("@mindpattern/reminder.migration.v2.done")).toBe("1");
  });

  it("the SECOND boot does not sweep again — the reconcile is the plain stable-id path", async () => {
    await setReminderEnabled("user-1", true);
    await setReminderTime("user-1", 9, 15);
    createTriggerNotification.mockClear();
    cancelAllNotifications.mockClear();

    expect(await syncReminderSchedule("user-1")).toBe(true);
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1); // first boot swept
    cancelAllNotifications.mockClear();
    createTriggerNotification.mockClear();

    expect(await syncReminderSchedule("user-1")).toBe(true);
    expect(cancelAllNotifications).not.toHaveBeenCalled(); // idempotent: skipped
    expect(createTriggerNotification).toHaveBeenCalledTimes(1); // just the reconcile
    const [notification] = createTriggerNotification.mock.calls[0] as [{ id: string }, unknown];
    expect(notification.id).toBe("mindpattern-daily-reminder");
  });

  it("DISABLED prefs still sweep the orphans once — and schedule NOTHING afterwards", async () => {
    createTriggerNotification.mockClear();
    cancelAllNotifications.mockClear();

    expect(await syncReminderSchedule("user-1")).toBe(true);
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1); // orphans die too
    expect(createTriggerNotification).not.toHaveBeenCalled();
    expect(await storageForSiblings.getItem("@mindpattern/reminder.migration.v2.done")).toBe("1");
  });

  it("a build without the notification module commits the flag — nothing to sweep, never re-probed", async () => {
    const notifee = (await import("@notifee/react-native")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = notifee.default.requestPermission;
    delete notifee.default.requestPermission;
    try {
      await syncReminderSchedule("user-1");
      expect(cancelAllNotifications).not.toHaveBeenCalled();
      expect(await storageForSiblings.getItem("@mindpattern/reminder.migration.v2.done")).toBe("1");
    } finally {
      notifee.default.requestPermission = original;
    }
  });

  it("a sweep that fails mid-way leaves the flag UNSET — the next resync retries it", async () => {
    cancelAllNotifications.mockRejectedValueOnce(new Error("native exploded"));
    await syncReminderSchedule("user-1");
    expect(await storageForSiblings.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();

    cancelAllNotifications.mockClear();
    await syncReminderSchedule("user-1");
    expect(cancelAllNotifications).toHaveBeenCalledTimes(1); // retried, and…
    expect(await storageForSiblings.getItem("@mindpattern/reminder.migration.v2.done")).toBe("1");
  });
});
