/**
 * Capability checks and scheduling for local notifications.
 * The committed native projects link Notifee; missing native support reports
 * unavailable instead of crashing. Permissions are requested only when the
 * user enables a reminder.
 *
 * reminders.ts and measureReminders.ts own the per-account preferences;
 * reminderSync.ts reconciles them with native schedules. Daily and measure
 * reminders have distinct stable IDs so rescheduling replaces each reminder
 * without affecting the other. Biometric unlock lives in biometricUnlock.ts.
 */

import AsyncStorage from "@react-native-async-storage/async-storage";
import { getReminderPrefs, nextReminderFireTime } from "./reminders";
import {
  getMeasureReminderPrefs,
  lastMeasureCompletedOn,
  nextMeasureReminderFireTime,
} from "./measureReminders";
import { t } from "./strings";
import { assertNotificationOwner, beginNotificationUpdate, runOwnedNotification, runNotificationCancellation, type NotificationOwner, type ReminderKind } from "./notificationOwnership";

export interface NativeCapability {
  available: boolean;
  /** Catalog key explaining an unavailable capability; Settings localizes it. */
  reason?: string;
}

function probe(moduleName: string): unknown | null {
  try {
    // Metro resolves only string-literal require() specifiers — a variable
    // argument fails the entire bundle ("Invalid call at line N:
    // require(moduleName)"), so this seam's optional module is enumerated
    // as a literal rather than required through the parameter. In vitest's
    // ESM runner `require` is not defined, so the ReferenceError reads as
    // "absent" and probeAsync falls through to the mock-interceptable
    // import() below.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod =
      moduleName === "@notifee/react-native" ? require("@notifee/react-native") : null;
    return mod ?? null;
  } catch {
    return null;
  }
}

/** Async resolution for the ACTION seams: the synchronous require first
 * (the RN bundler path — a linked module resolves statically), then a
 * dynamic import so test builds can inject the module through the module
 * runner (vi.mock intercepts `import()`, not `require()`). Both failures
 * read as "absent" — never a throw. The import specifier is a literal for
 * the same Metro reason as the require above. */
async function probeAsync(moduleName: string): Promise<unknown | null> {
  const mod = probe(moduleName);
  if (mod !== null) return mod;
  try {
    return moduleName === "@notifee/react-native"
      ? await import("@notifee/react-native")
      : null;
  } catch {
    return null;
  }
}

export function reminderCapability(): NativeCapability {
  const mod = probe("@notifee/react-native");
  if (mod === null) {
    return {
      available: false,
      reason: "settings.reasonNotifModule",
    };
  }
  return { available: true };
}

/** The notifee API surface this module touches (the real module exports
 *  far more; this keeps the seam typed without importing it). */
interface NotifeeModule {
  requestPermission(): Promise<unknown>;
  createTriggerNotification(notification: unknown, trigger: unknown): Promise<unknown>;
  cancelAllNotifications(): Promise<unknown>;
  /** Cancel ONE scheduled/delivered notification by id. Present in every
   *  notifee build this app can link (9.x); optional only so a hostile or
   *  ancient mock degrades to the id-replacement guarantee alone. */
  cancelNotification?(notificationId: string): Promise<unknown>;
  createChannel?(channel: unknown): Promise<unknown>;
}

/** notifee.AuthorizationStatus.AUTHORIZED — the only answer that counts as
 *  permission granted (provisional stays "not granted" for a daily nudge:
 *  quiet delivery is not what the user agreed to). */
const AUTHORIZATION_STATUS_AUTHORIZED = 1;
/** notifee TriggerType.TIMESTAMP / RepeatFrequency.DAILY fallbacks for a
 *  module build that does not export its enums; the module's own values
 *  are preferred whenever present so the real runtime never guesses. */
const FALLBACK_TRIGGER_TYPE_TIMESTAMP = 0;
const FALLBACK_REPEAT_FREQUENCY_DAILY = 1;

/** Reminders (the daily nudge and the measure check-in nudge) are the ONLY
 *  notifications this app schedules, so one stable channel id is safe and
 *  lets the OS surface "Journal reminders" in system settings honestly. */
const REMINDER_CHANNEL_ID = "mindpattern-reminders";

/** Stable ID makes rescheduling replace the previous daily notification. */
const REMINDER_NOTIFICATION_ID = "mindpattern-daily-reminder";

/** Use a distinct stable ID so check-in and daily reminders cannot replace
 * each other. */
export const MEASURE_REMINDER_NOTIFICATION_ID = "mindpattern-measure-reminder";

/** Resolve notification copy at scheduling time using the active locale. */
function reminderNotification(): {
  id: string;
  title: string;
  body: string;
  android: { channelId: string };
} {
  return {
    id: REMINDER_NOTIFICATION_ID,
    title: "Fathom",
    body: t("notify.reminderBody"),
    android: { channelId: REMINDER_CHANNEL_ID },
  };
}

/** The measure check-in nudge: same brand title, same channel (one honest
 *  "Fathom reminders" surface in system settings), its own stable id
 *  and its own calm body — an invitation to re-run a questionnaire, never
 *  a debt (no "overdue", no streak, nothing to feel bad about). */
function measureReminderNotification(): {
  id: string;
  title: string;
  body: string;
  android: { channelId: string };
} {
  return {
    id: MEASURE_REMINDER_NOTIFICATION_ID,
    title: "Fathom",
    body: t("notify.measureReminderBody"),
    android: { channelId: REMINDER_CHANNEL_ID },
  };
}

function notifeeFrom(mod: unknown): NotifeeModule | null {
  if (mod === null || typeof mod !== "object") return null;
  // The package's default export carries the API; tolerate a bare object.
  const candidate = (mod as { default?: unknown }).default ?? mod;
  if (typeof candidate !== "object" || candidate === null) return null;
  const api = candidate as Partial<NotifeeModule>;
  if (typeof api.requestPermission !== "function") return null;
  if (typeof api.createTriggerNotification !== "function") return null;
  if (typeof api.cancelAllNotifications !== "function") return null;
  return api as NotifeeModule;
}

function authorizationGranted(result: unknown): boolean {
  // requestPermission answers either a bare AuthorizationStatus number or a
  // permission-status record; only an explicit AUTHORIZED counts.
  const status = typeof result === "number" ? result : (result as { authorizationStatus?: unknown } | null)?.authorizationStatus;
  return status === AUTHORIZATION_STATUS_AUTHORIZED;
}

/** Native primitives below run only inside the shared, tracked notification
 * lane. Sibling restoration must use these primitives rather than enqueueing
 * another operation and waiting on itself. */
async function scheduleNative(
  mod: unknown, api: NotifeeModule, owner: NotificationOwner,
  kind: ReminderKind, fireAt: () => Date,
): Promise<boolean> {
  const check = () => assertNotificationOwner(owner, kind);
  check();
  const permission = await api.requestPermission();
  check();
  if (!authorizationGranted(permission)) return false;
  const id = kind === "daily" ? REMINDER_NOTIFICATION_ID : MEASURE_REMINDER_NOTIFICATION_ID;
  if (typeof api.cancelNotification === "function") {
    await api.cancelNotification(id).catch(() => {});
    check();
  }
  if (typeof api.createChannel === "function") {
    await api.createChannel({ id: REMINDER_CHANNEL_ID, name: t("notify.channelName") });
    check();
  }
  const enums = mod as { TriggerType?: { TIMESTAMP?: number }; RepeatFrequency?: { DAILY?: number } };
  check();
  await api.createTriggerNotification(kind === "daily" ? reminderNotification() : measureReminderNotification(), {
    type: enums.TriggerType?.TIMESTAMP ?? FALLBACK_TRIGGER_TYPE_TIMESTAMP,
    timestamp: fireAt().getTime(),
    ...(kind === "daily" ? { repeatFrequency: enums.RepeatFrequency?.DAILY ?? FALLBACK_REPEAT_FREQUENCY_DAILY } : {}),
  });
  check();
  return true;
}

/** The owner is captured by reconciliation before reading preferences. */
export async function scheduleDailyReminder(hour: number, minute: number, owner: NotificationOwner): Promise<boolean> {
  try {
    return await runOwnedNotification(owner, async () => {
      assertNotificationOwner(owner, "daily");
      const mod = await probeAsync("@notifee/react-native");
      assertNotificationOwner(owner, "daily");
      const api = notifeeFrom(mod);
      return api === null ? false : await scheduleNative(mod, api, owner, "daily", () => nextReminderFireTime(new Date(), hour, minute));
    });
  } catch { return false; }
}

export async function scheduleMeasureReminder(fireAt: Date, owner: NotificationOwner): Promise<boolean> {
  try {
    return await runOwnedNotification(owner, async () => {
      assertNotificationOwner(owner, "measure");
      const mod = await probeAsync("@notifee/react-native");
      assertNotificationOwner(owner, "measure");
      const api = notifeeFrom(mod);
      return api === null ? false : await scheduleNative(mod, api, owner, "measure", () => fireAt);
    });
  } catch { return false; }
}

async function restoreSibling(mod: unknown, api: NotifeeModule, owner: NotificationOwner, kind: ReminderKind): Promise<boolean> {
  // A newer reconciliation is queued behind this native operation. Let it
  // restore its own current preference rather than replaying this snapshot.
  try { assertNotificationOwner(owner, kind); }
  catch { assertNotificationOwner(owner); return true; }
  const userId = owner.permit.userId;
  if (kind === "daily") {
    const prefs = await getReminderPrefs(userId);
    assertNotificationOwner(owner, kind);
    return !prefs.enabled || await scheduleNative(mod, api, owner, kind, () => nextReminderFireTime(new Date(), prefs.hour, prefs.minute));
  }
  const prefs = await getMeasureReminderPrefs(userId);
  assertNotificationOwner(owner, kind);
  if (!prefs.enabled) return true;
  const last = await lastMeasureCompletedOn(userId);
  assertNotificationOwner(owner, kind);
  return last === null || await scheduleNative(mod, api, owner, kind, () => nextMeasureReminderFireTime(new Date(), last, prefs.intervalWeeks));
}

async function cancelReminder(kind: ReminderKind, userId?: string, suppliedOwner?: NotificationOwner): Promise<boolean> {
  const id = kind === "daily" ? REMINDER_NOTIFICATION_ID : MEASURE_REMINDER_NOTIFICATION_ID;
  try {
    if (userId !== undefined) {
      const owner = suppliedOwner ?? beginNotificationUpdate(userId, kind);
      if (owner.permit.userId !== userId) return false;
      return await runOwnedNotification(owner, async () => {
        const check = () => assertNotificationOwner(owner, kind);
        check();
        const mod = await probeAsync("@notifee/react-native");
        check();
        const api = notifeeFrom(mod);
        if (api === null) return false;
        if (typeof api.cancelNotification === "function") {
          await api.cancelNotification(id);
        } else {
          await api.cancelAllNotifications();
          check();
          // The cancellation succeeded even if native delivery of the
          // sibling is temporarily unavailable. Ownership errors still
          // prevent any following native dispatch or success claim.
          await restoreSibling(mod, api, owner, kind === "daily" ? "measure" : "daily").catch(() => {});
        }
        check();
        return true;
      });
    }
    return await runNotificationCancellation([kind], async check => {
      const api = notifeeFrom(await probeAsync("@notifee/react-native"));
      check();
      if (api === null) return false;
      if (typeof api.cancelNotification === "function") await api.cancelNotification(id);
      else await api.cancelAllNotifications();
      check();
      return true;
    });
  } catch { return false; }
}

/** Feature cancellation retains the other reminder; administrative removal
 * omits userId and never recreates a sibling. */
export async function cancelDailyReminder(userId?: string, owner?: NotificationOwner): Promise<boolean> {
  return cancelReminder("daily", userId, owner);
}
export async function cancelMeasureReminder(userId?: string, owner?: NotificationOwner): Promise<boolean> {
  return cancelReminder("measure", userId, owner);
}

/** Origin retirement invalidates both producers before waiting for already
 * dispatched native work. No old completion can follow the final cancel. */
export async function cancelOriginNotifications(): Promise<boolean> {
  try {
    return await runNotificationCancellation(["daily", "measure"], async check => {
      const api = notifeeFrom(await probeAsync("@notifee/react-native"));
      check();
      if (api === null) return true;
      await api.cancelAllNotifications();
      check();
      return true;
    });
  } catch { return false; }
}

const REMINDER_MIGRATION_V2_KEY = "@mindpattern/reminder.migration.v2.done";

/** One-time removal of old random IDs, followed by restoration from current
 * preferences. The entire migration is one tracked native transaction. */
export async function migrateOrphanedReminderNotifications(userId: string, suppliedOwner?: NotificationOwner): Promise<void> {
  try {
    const owner = suppliedOwner ?? beginNotificationUpdate(userId, "daily");
    if (owner.permit.userId !== userId) return;
    await runOwnedNotification(owner, async () => {
      const migrated = await AsyncStorage.getItem(REMINDER_MIGRATION_V2_KEY);
      assertNotificationOwner(owner);
      if (migrated !== null) return;
      const mod = await probeAsync("@notifee/react-native");
      assertNotificationOwner(owner);
      const api = notifeeFrom(mod);
      if (api !== null) {
        await api.cancelAllNotifications();
        assertNotificationOwner(owner);
        if (!await restoreSibling(mod, api, owner, "daily")) return;
        if (!await restoreSibling(mod, api, owner, "measure")) return;
      }
      assertNotificationOwner(owner);
      await AsyncStorage.setItem(REMINDER_MIGRATION_V2_KEY, "1");
      assertNotificationOwner(owner);
    });
  } catch { /* Keep migration pending for a later valid reconciliation. */ }
}

// ---------------------------------------------------------------------------
// Notification-tap routing (2026-09-27)
// ---------------------------------------------------------------------------

/** The notifee event surface this module touches (see notifeeFrom for the
 *  scheduling half — the event API is a DIFFERENT, smaller surface). */
interface NotifeeEventModule {
  onForegroundEvent(handler: (event: { type: number; detail?: { notification?: { id?: unknown } } }) => void): () => void;
  getInitialNotification(): Promise<{ notification?: { id?: unknown } } | null>;
}

/** notifee.EventType.PRESS — the fallback for a build that stopped
 *  exporting its enums (the module's own value is preferred). */
const FALLBACK_EVENT_TYPE_PRESS = 1;

/**
 * Route notification TAPS to screens (the measure nudge's promise: tapping
 * opens the Measures screen). Called ONCE from App mount; wires both tap
 * moments — a cold start from a notification (getInitialNotification) and
 * a tap while the app is foregrounded (onForegroundEvent PRESS) — into the
 * pure queue in notificationRoute.ts, which the navigator consumes when
 * the main flow is entered. Returns false — never throws — when the module
 * is absent or either registration fails: without routing, a tap just
 * opens the app on the journal (the daily reminder's behavior all along),
 * which is a degraded nudge, never a broken one.
 */
export async function startNotificationPressRouting(): Promise<(() => void) | null> {
  const { queueNotificationRoute } = await import("./notificationRoute");
  const mod = await probeAsync("@notifee/react-native");
  if (mod === null || typeof mod !== "object") return null;
  const candidate = (mod as { default?: unknown }).default ?? mod;
  if (typeof candidate !== "object" || candidate === null) return null;
  const api = candidate as Partial<NotifeeEventModule>;
  if (typeof api.onForegroundEvent !== "function") return null;
  if (typeof api.getInitialNotification !== "function") return null;
  let disposed = false;
  try {
    const enums = mod as { EventType?: { PRESS?: number } };
    const pressType = enums.EventType?.PRESS ?? FALLBACK_EVENT_TYPE_PRESS;
    // Cold start: the notification that launched the app (never awaited —
    // it resolves after the navigator has mounted, and the QUEUE is what
    // hands it across, not this promise).
    void api.getInitialNotification().then((initial) => {
      if (!disposed) queueNotificationRoute(initial?.notification?.id);
    }).catch(() => {});
    const unsubscribe = api.onForegroundEvent((event) => {
      if (!disposed && event.type === pressType) queueNotificationRoute(event.detail?.notification?.id);
    });
    return () => { disposed = true; unsubscribe(); };
  } catch {
    // A failed subscription is inactive, including its pending cold-start
    // callback: the caller has no disposer to revoke that callback later.
    disposed = true;
    return null;
  }
}
