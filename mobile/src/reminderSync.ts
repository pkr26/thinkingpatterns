/**
 * Reconcile the stored reminder preference with the actual native
 * schedule (2026-09-19). One function, called from exactly two places:
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
 */
import { getReminderPrefs } from "./reminders";
import { cancelDailyReminder, scheduleDailyReminder } from "./nativeFeatures";

export async function syncReminderSchedule(userId: string): Promise<boolean> {
  try {
    const prefs = await getReminderPrefs(userId);
    if (!prefs.enabled) return await cancelDailyReminder();
    return await scheduleDailyReminder(prefs.hour, prefs.minute);
  } catch {
    // A storage or native hiccup must never take a screen down; the next
    // sync point (next app start / next toggle) retries.
    return false;
  }
}
