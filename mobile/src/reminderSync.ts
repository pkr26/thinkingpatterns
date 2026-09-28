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
import {
  getMeasureReminderPrefs,
  lastMeasureCompletedOn,
  measureReminderDue,
  nextMeasureReminderFireTime,
} from "./measureReminders";
import {
  cancelDailyReminder,
  cancelMeasureReminder,
  scheduleDailyReminder,
  scheduleMeasureReminder,
} from "./nativeFeatures";

export async function syncReminderSchedule(userId: string): Promise<boolean> {
  try {
    const prefs = await getReminderPrefs(userId);
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
 * decide. Scheduled only when the last completed measure is older than
 * the chosen interval (2/4/8 weeks, from the local cadence stamp);
 * cancelled whenever the opt-in is off OR the cadence is not yet due —
 * a fresh completion must kill any nudge scheduled before it landed.
 * Same call points as the daily sync: preference changes (Settings) and
 * once on session start (store.tsx), plus the Measures screen's success
 * path. The return reports whether a nudge is SCHEDULED right now (false
 * also covers "not available in this build"); never throws.
 */
export async function syncMeasureReminderSchedule(userId: string): Promise<boolean> {
  try {
    const prefs = await getMeasureReminderPrefs(userId);
    // independent audit 2026-09-27 (P3): the userId rides the cancels so a
    // fallback cancel-all can re-schedule the surviving daily reminder.
    if (!prefs.enabled) return await cancelMeasureReminder(userId);
    const last = await lastMeasureCompletedOn(userId);
    if (!measureReminderDue(last, prefs.intervalWeeks, new Date())) {
      return await cancelMeasureReminder(userId);
    }
    return await scheduleMeasureReminder(nextMeasureReminderFireTime(new Date()));
  } catch {
    return false;
  }
}
