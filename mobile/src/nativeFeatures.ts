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

/** Schedule the daily reminder at a local clock time. A stable ID and scoped
 * cancel-before-create keep rescheduling idempotent. Missing modules, denied
 * permission, and native failures return false. */
export async function scheduleDailyReminder(hour: number, minute: number): Promise<boolean> {
  const mod = await probeAsync("@notifee/react-native");
  const api = notifeeFrom(mod);
  if (api === null) return false;
  try {
    if (!authorizationGranted(await api.requestPermission())) return false;
    // Cancel-before-create, scoped to the ONE reminder id (never the app's
    // whole notification set): the belt-and-braces half of idempotency. A
    // failure here must not block the create — the stable id is the primary
    // guarantee, and there may be nothing scheduled to cancel yet.
    if (typeof api.cancelNotification === "function") {
      await api.cancelNotification(REMINDER_NOTIFICATION_ID).catch(() => {});
    }
    // Prefer the module's own enum values (named exports
    // TriggerType.TIMESTAMP / RepeatFrequency.DAILY); the constants above
    // are only a fallback for builds that stopped exporting them.
    const enums = mod as {
      TriggerType?: { TIMESTAMP?: number };
      RepeatFrequency?: { DAILY?: number };
    };
    const triggerType = enums.TriggerType?.TIMESTAMP ?? FALLBACK_TRIGGER_TYPE_TIMESTAMP;
    const repeatFrequency = enums.RepeatFrequency?.DAILY ?? FALLBACK_REPEAT_FREQUENCY_DAILY;
    // Android delivers through a channel; creating it again is an idempotent
    // update. A channel-less Android notification never shows. The channel
    // NAME is user-visible in system settings, so it localizes too (fix 22).
    if (typeof api.createChannel === "function") {
      await api.createChannel({ id: REMINDER_CHANNEL_ID, name: t("notify.channelName") });
    }
    await api.createTriggerNotification(reminderNotification(), {
      type: triggerType,
      // The first fire is the next H:M still ahead of now; the daily repeat
      // keeps that time-of-day (reminders.ts computes it in LOCAL time).
      timestamp: nextReminderFireTime(new Date(), hour, minute).getTime(),
      repeatFrequency,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Schedule (or reschedule) the ONE-SHOT measure check-in nudge at an exact
 * moment (`fireAt` — reminderSync.ts computes it: only when the cadence is
 * due, at the next calm 20:00 local). No repeatFrequency: the nudge is
 * re-evaluated against the cadence at every sync, never left to a blind OS
 * repeat that would nag daily about a fortnightly check-in. Same
 * idempotency contract as the daily reminder (stable id + scoped
 * cancel-before-create), and the same quiet false on absent module /
 * denied permission / native failure.
 */
export async function scheduleMeasureReminder(fireAt: Date): Promise<boolean> {
  const mod = await probeAsync("@notifee/react-native");
  const api = notifeeFrom(mod);
  if (api === null) return false;
  try {
    if (!authorizationGranted(await api.requestPermission())) return false;
    if (typeof api.cancelNotification === "function") {
      await api.cancelNotification(MEASURE_REMINDER_NOTIFICATION_ID).catch(() => {});
    }
    const enums = mod as { TriggerType?: { TIMESTAMP?: number } };
    const triggerType = enums.TriggerType?.TIMESTAMP ?? FALLBACK_TRIGGER_TYPE_TIMESTAMP;
    if (typeof api.createChannel === "function") {
      await api.createChannel({ id: REMINDER_CHANNEL_ID, name: t("notify.channelName") });
    }
    await api.createTriggerNotification(measureReminderNotification(), {
      type: triggerType,
      timestamp: fireAt.getTime(),
    });
    return true;
  } catch {
    return false;
  }
}

/** Cancel only the check-in reminder when per-ID cancellation is available.
 * A cancel-all fallback restores the daily sibling when userId is supplied.
 * Sign-out and erasure omit userId to remove every schedule. */
export async function cancelMeasureReminder(userId?: string): Promise<boolean> {
  const api = notifeeFrom(await probeAsync("@notifee/react-native"));
  if (api === null) return false;
  try {
    if (typeof api.cancelNotification === "function") {
      await api.cancelNotification(MEASURE_REMINDER_NOTIFICATION_ID);
      return true;
    }
    // Ancient builds without per-id cancel: cancel-all is the only tool.
    // The measure nudge (and any reschedule) self-heals at the next sync.
    await api.cancelAllNotifications();
    if (userId !== undefined) {
      await rescheduleDailyReminderSibling(userId).catch(() => {});
    }
    return true;
  } catch {
    return false;
  }
}

/** Restore an enabled daily reminder after a cancel-all fallback. A failed
 * restore is retried at the next schedule sync. */
async function rescheduleDailyReminderSibling(userId: string): Promise<void> {
  const prefs = await getReminderPrefs(userId);
  if (!prefs.enabled) return;
  await scheduleDailyReminder(prefs.hour, prefs.minute);
}

/** Restore an enabled check-in reminder after a cancel-all fallback, using
 * the stored completion date and cadence. */
async function rescheduleMeasureReminderSibling(userId: string): Promise<void> {
  const prefs = await getMeasureReminderPrefs(userId);
  if (!prefs.enabled) return;
  const last = await lastMeasureCompletedOn(userId);
  if (last === null) return;
  await scheduleMeasureReminder(nextMeasureReminderFireTime(new Date(), last, prefs.intervalWeeks));
}

/** Cancel the daily reminder. A cancel-all fallback restores the check-in
 * sibling when userId is supplied. Return false on missing native support
 * or cancellation failure. */
export async function cancelDailyReminder(userId?: string): Promise<boolean> {
  const api = notifeeFrom(await probeAsync("@notifee/react-native"));
  if (api === null) return false;
  try {
    if (typeof api.cancelNotification === "function") {
      await api.cancelNotification(REMINDER_NOTIFICATION_ID);
      return true;
    }
    await api.cancelAllNotifications();
    if (userId !== undefined) {
      await rescheduleMeasureReminderSibling(userId).catch(() => {});
    }
    return true;
  } catch {
    return false;
  }
}

/** Administrative origin retirement. Unlike the preference-level helpers,
 * this deliberately cancels the complete app-owned notification set so
 * pre-stable-id schedules cannot remain associated with the old server.
 * A build without the native module has no reachable native scheduler and
 * is already clean; a present module that rejects is a retryable failure. */
export async function cancelOriginNotifications(): Promise<boolean> {
  const api = notifeeFrom(await probeAsync("@notifee/react-native"));
  if (api === null) return true;
  try {
    await api.cancelAllNotifications();
    return true;
  } catch {
    return false;
  }
}

/** L-9 (2026-09-28): the persisted "orphaned random-id notifications were
 *  cleared" mark. Notifications are device-local (not per-account), so the
 *  flag is device-wide in this module's prefs namespace — it says THIS
 *  build's one-time sweep ran, and nothing else. */
const REMINDER_MIGRATION_V2_KEY = "@mindpattern/reminder.migration.v2.done";

/**
 * L-9 (2026-09-28): ONE-TIME sweep of the pre-stable-id era's orphaned
 * notifications. Before the stable-id fix (2026-09-26 audit MEDIUM) notifee
 * minted a RANDOM id per create and every reschedule stacked a new daily
 * trigger; the fix made NEW schedules replace-by-id, but a device upgraded
 * from a pre-fix build keeps every orphaned random-id notification firing
 * forever — no stable id exists to cancel them by. The only tool that
 * reaches them is the cancel-all fallback, so the FIRST reminder resync on
 * this version:
 *
 *   1. cancelAllNotifications() — clears EVERY scheduled notification,
 *      orphaned random ids included (reminders are the only notifications
 *      this app schedules, and disabled prefs lose nothing by the sweep —
 *      orphans SHOULD be cleared even then);
 *   2. immediately reschedules BOTH reminders from stored prefs via the
 *      existing stable-id resync paths (daily reminder; measure-cadence
 *      nudge when its preference AND cadence say one should exist);
 *   3. only then sets the flag, so the sweep is idempotent — every later
 *      boot skips it. A mid-migration failure leaves the flag unset and the
 *      next resync retries the whole sweep (harmless: the reschedule is the
 *      same reconciliation the sync performs anyway).
 *
 * Called from reminderSync.syncReminderSchedule (the resync every session
 * start runs). Never throws; a build without the notification module has
 * nothing to sweep and simply marks the migration done.
 */
export async function migrateOrphanedReminderNotifications(userId: string): Promise<void> {
  try {
    if ((await AsyncStorage.getItem(REMINDER_MIGRATION_V2_KEY)) !== null) return; // already swept
    const api = notifeeFrom(await probeAsync("@notifee/react-native"));
    if (api !== null) {
      await api.cancelAllNotifications();
      await rescheduleDailyReminderSibling(userId);
      await rescheduleMeasureReminderSibling(userId);
    }
    await AsyncStorage.setItem(REMINDER_MIGRATION_V2_KEY, "1");
  } catch {
    // Nothing committed: the flag stays unset and the next resync retries.
  }
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
    return null;
  }
}
