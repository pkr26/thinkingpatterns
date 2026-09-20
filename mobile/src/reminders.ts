/**
 * Local journaling reminders — the PREFERENCE side (2026-09-19).
 *
 * Design contract (nativeFeatures.ts header): LOCAL notifications only, at
 * most one per day, opt-in (onboarding or Settings), no streak-shaming copy.
 * This module owns the per-account preference record; the native seam in
 * nativeFeatures.ts turns it into (or removes) an actual scheduled
 * notification, and reminderSync.ts reconciles the two.
 *
 * Storage: a plain AsyncStorage record — a non-sensitive preference (the
 * onboarding.ts / components/keyConsent.ts idiom). It holds an opt-in flag
 * and a clock time, never journal content, so it does not need the
 * encrypted store. Key: @mindpattern/reminders_<userId>; account deletion
 * must wipe it (clearReminderPrefs rides the SettingsScreen deletion flow).
 *
 * Failure direction is toward SILENCE: an unreadable or corrupt record
 * reads as the disabled default. A reminder is a nudge — losing it to a
 * storage fault costs nothing, while a phantom "enabled" that cannot be
 * read back honestly would be worse. Values coming back from storage are
 * validated in full (a hostile or half-written record must never produce
 * hour 99 or a notification at 3:47 the user never chose).
 */
import AsyncStorage from "@react-native-async-storage/async-storage";

export interface ReminderPrefs {
  enabled: boolean;
  /** Local clock hour 0..23. */
  hour: number;
  /** Local clock minute 0..59. */
  minute: number;
}

/** The calm default: 20:00 local — an evening write, never a morning alarm. */
export const DEFAULT_REMINDER_TIME: Readonly<Pick<ReminderPrefs, "hour" | "minute">> = {
  hour: 20,
  minute: 0,
};

/** Disabled until the user opts in — the app never installs a notification
 *  unasked, and onboarding's opt-in row defaults to off. */
export const DEFAULT_REMINDER_PREFS: Readonly<ReminderPrefs> = {
  enabled: false,
  ...DEFAULT_REMINDER_TIME,
};

const key = (userId: string): string => `@mindpattern/reminders_${userId}`;

/** Full validation of anything read back from storage. null = not a usable
 *  record (absent, unparsable, or hostile). */
function parsePrefs(raw: string | null): ReminderPrefs | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const { enabled, hour, minute } = parsed as Record<string, unknown>;
    if (typeof enabled !== "boolean") return null;
    if (typeof hour !== "number" || !Number.isInteger(hour) || hour < 0 || hour > 23) return null;
    if (typeof minute !== "number" || !Number.isInteger(minute) || minute < 0 || minute > 59) return null;
    return { enabled, hour, minute };
  } catch {
    return null;
  }
}

/** The stored preference, or the disabled default when absent/corrupt.
 *  Never throws — Settings and the onboarding row read this on mount. */
export async function getReminderPrefs(userId: string): Promise<ReminderPrefs> {
  try {
    return parsePrefs(await AsyncStorage.getItem(key(userId))) ?? { ...DEFAULT_REMINDER_PREFS };
  } catch {
    return { ...DEFAULT_REMINDER_PREFS };
  }
}

async function writePrefs(userId: string, prefs: ReminderPrefs): Promise<void> {
  await AsyncStorage.setItem(key(userId), JSON.stringify(prefs));
}

/** Flip the opt-in, preserving the stored time (or the default when none
 *  was ever chosen). Throwing surfaces to the caller as an honest failure —
 *  the UI never pretends a preference was saved when it was not. */
export async function setReminderEnabled(userId: string, enabled: boolean): Promise<void> {
  const prefs = await getReminderPrefs(userId);
  await writePrefs(userId, { ...prefs, enabled });
}

/** Choose the reminder time (local clock). The caller validates intent;
 *  this validates range defensively for its own writes. */
export async function setReminderTime(userId: string, hour: number, minute: number): Promise<void> {
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) return;
  if (!Number.isInteger(minute) || minute < 0 || minute > 59) return;
  const prefs = await getReminderPrefs(userId);
  await writePrefs(userId, { ...prefs, hour, minute });
}

/** Account-deletion hygiene: the preference must not outlive its account. */
export async function clearReminderPrefs(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}

/**
 * PURE: the next LOCAL fire time for a daily H:M reminder — today at H:M
 * when that moment is still (strictly) ahead of `now`, otherwise tomorrow.
 * Exactly-now rolls to tomorrow: a reminder scheduled for the current
 * second has already missed its moment. Local-time semantics throughout —
 * new Date(y, m, d+1, …) crosses month/year boundaries (and DST) the way
 * the user's clock does, never via a UTC 24h offset that lands an hour off.
 */
export function nextReminderFireTime(now: Date, hour: number, minute: number): Date {
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate(), hour, minute, 0, 0);
  if (today.getTime() > now.getTime()) return today;
  return new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, hour, minute, 0, 0);
}
