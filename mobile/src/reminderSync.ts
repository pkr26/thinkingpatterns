/**
 * Reconcile the stored reminder preference with the actual native
 * schedule (2026-09-19). syncReminderSchedule is called from exactly two
 * places:
 *  - after every preference change (Settings toggle, Settings time chip,
 *    the onboarding opt-in row), and
 *  - once on app start while a session exists (store.tsx mount) so a
 *    reinstall, OS upgrade, or anything else that wiped the native
 *    schedule converges back to what the user chose.
 *
 * Direction of truth is the PREFERENCE: enabled=true schedules, anything
 * else cancels — a preference the native layer cannot honor (module not
 * linked, permission denied) still reads back honestly from storage while
 * the return value tells the UI the schedule did not land. The return is
 * the capability result: true = the schedule now matches the preference,
 * false = not scheduled in this build / right now. Never throws.
 *
 * syncMeasureReminderSchedule (2026-09-27) is the same reconciliation for
 * the MBC check-in nudge, where the PREFERENCE is joined by the CADENCE
 * (see its own header below).
 */
import { getReminderPrefs } from "./reminders";
import { assertAccountActive } from "./localRekey";
import {
  getMeasureReminderPrefs,
  lastMeasureCompletedOn,
  nextMeasureReminderFireTime,
} from "./measureReminders";
import {
  cancelDailyReminder,
  cancelMeasureReminder,
  migrateOrphanedReminderNotifications,
  scheduleDailyReminder,
  scheduleMeasureReminder,
} from "./nativeFeatures";

export async function syncReminderSchedule(userId: string): Promise<boolean> {
  try {
    // L-9 (2026-09-28): the first resync on this version sweeps the
    // pre-stable-id era's orphaned random-id notifications (cancel-all +
    // reschedule from prefs), guarded by a persisted device flag so later
    // boots skip it. Idempotent, never throws, runs before the reconcile
    // below re-establishes the preference's own schedule.
    await migrateOrphanedReminderNotifications(userId);
    const prefs = await getReminderPrefs(userId);
    assertAccountActive(userId);
    // independent audit 2026-09-27 (P3): the userId rides the cancel so a
    // fallback cancel-all can re-schedule the surviving measure nudge.
    if (!prefs.enabled) return await cancelDailyReminder(userId);
    return await scheduleDailyReminder(prefs.hour, prefs.minute);
  } catch {
    // A storage or native hiccup must never take a screen down; the next
    // sync point (next app start / next toggle) retries.
    return false;
  }
}

/**
 * Reconcile the measure check-in nudge (2026-09-27): opt-in AND cadence
 * decide. The last completion plus the chosen interval determines the
 * next local-evening nudge; a fresh completion replaces an older schedule
 * with its new future date. Disabled or unknown cadence is cancelled.
 * Same call points as the daily sync: preference changes (Settings) and
 * once on session start (store.tsx), plus the Measures screen's success
 * path. The return reports whether a nudge is SCHEDULED right now (false
 * also covers "not available in this build"); never throws.
 */
export async function syncMeasureReminderSchedule(userId: string): Promise<boolean> {
  try {
    const prefs = await getMeasureReminderPrefs(userId);
    assertAccountActive(userId);
    // independent audit 2026-09-27 (P3): the userId rides the cancels so a
    // fallback cancel-all can re-schedule the surviving daily reminder.
    if (!prefs.enabled) return await cancelMeasureReminder(userId);
    const last = await lastMeasureCompletedOn(userId);
    assertAccountActive(userId);
    if (last === null) {
      return await cancelMeasureReminder(userId);
    }
    return await scheduleMeasureReminder(nextMeasureReminderFireTime(new Date(), last, prefs.intervalWeeks));
  } catch {
    return false;
  }
}
