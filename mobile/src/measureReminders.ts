/**
 * Measure check-in reminders — the MBC cadence preference (2026-09-27).
 *
 * Design contract (rides the 2026-09-19 reminders discipline): LOCAL
 * notifications only, strictly opt-in (Settings), calm non-shaming copy —
 * an invitation to re-run a wellbeing questionnaire, never a debt. This
 * module owns two per-account records:
 *
 *  - The PREFERENCE (plain AsyncStorage, the reminders.ts idiom — an
 *    opt-in flag and an interval choice carry nothing sensitive):
 *    {enabled, intervalWeeks} at @mindpattern/measure_reminders_<userId>.
 *
 *  - The LAST COMPLETED measure date (secureStore, the crisisDialog.ts
 *    idiom — encrypted at rest under the per-install device key, because
 *    unlike an hour-of-day preference a "when did you last complete a
 *    mental-health questionnaire" stamp is health-adjacent metadata a
 *    backup reader must not see): an ISO local date at
 *    @mindpattern/last_measure_<userId>.
 *
 * Failure direction is toward SILENCE: an unreadable or corrupt record
 * reads as the disabled default / no date, and the pure predicates below
 * never fire on hostile input. The nudge itself lives in nativeFeatures.ts
 * under its own STABLE notification id ("mindpattern-measure-reminder" —
 * distinct from the daily reminder's, so the two schedules can never
 * replace or orphan each other); reminderSync.ts reconciles preference,
 * cadence and native schedule.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { secureStore } from "./secureStore";
import { accountStorageKey } from "./accountStorage";
import { commitReminderPreferenceWrite } from "./reminderPreferences";

export interface MeasureReminderPrefs {
  enabled: boolean;
  /** Cadence in weeks. 2 / 4 / 8 (DEFAULT 4) — the offered chips only. */
  intervalWeeks: number;
}

/** The offered cadences, ascending (the Settings chips). */
export const MEASURE_INTERVAL_WEEKS: readonly number[] = [2, 4, 8];

export const DEFAULT_MEASURE_INTERVAL_WEEKS = 4;

/** Off until the user opts in — the app never installs a notification
 *  unasked (the reminders.ts contract). */
export const DEFAULT_MEASURE_REMINDER_PREFS: Readonly<MeasureReminderPrefs> = {
  enabled: false,
  intervalWeeks: DEFAULT_MEASURE_INTERVAL_WEEKS,
};

const prefKey = accountStorageKey.measureReminders;
const lastKey = accountStorageKey.lastMeasure;

/** Full validation of anything read back from storage, the reminders.ts
 *  discipline: null = not a usable record (absent, unparsable, hostile). */
function parsePrefs(raw: string | null): MeasureReminderPrefs | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const { enabled, intervalWeeks } = parsed as Record<string, unknown>;
    if (typeof enabled !== "boolean") return null;
    if (typeof intervalWeeks !== "number" || !Number.isInteger(intervalWeeks)) return null;
    if (!MEASURE_INTERVAL_WEEKS.includes(intervalWeeks)) return null;
    return { enabled, intervalWeeks };
  } catch {
    return null;
  }
}

/** The stored preference, or the disabled default when absent/corrupt.
 *  Never throws — Settings reads this on mount. */
export async function getMeasureReminderPrefs(userId: string): Promise<MeasureReminderPrefs> {
  try {
    return parsePrefs(await AsyncStorage.getItem(prefKey(userId))) ?? { ...DEFAULT_MEASURE_REMINDER_PREFS };
  } catch {
    return { ...DEFAULT_MEASURE_REMINDER_PREFS };
  }
}

async function updatePrefs(userId: string, patch: Partial<MeasureReminderPrefs>): Promise<void> {
  await commitReminderPreferenceWrite(userId, async check => {
    const prefs = await getMeasureReminderPrefs(userId);
    check();
    await AsyncStorage.setItem(prefKey(userId), JSON.stringify({ ...prefs, ...patch }));
  });
}

/** Flip the opt-in, preserving the stored interval. Throws on a storage
 *  failure — the UI never pretends a preference was saved when it was not. */
export async function setMeasureReminderEnabled(userId: string, enabled: boolean): Promise<void> {
  await updatePrefs(userId, { enabled });
}

/** Choose the cadence (weeks). Out-of-offer values are refused
 *  defensively — never written as week 99. */
export async function setMeasureReminderInterval(userId: string, intervalWeeks: number): Promise<void> {
  if (!Number.isInteger(intervalWeeks) || !MEASURE_INTERVAL_WEEKS.includes(intervalWeeks)) return;
  await updatePrefs(userId, { intervalWeeks });
}

/** Account-deletion hygiene: the preference must not outlive its account. */
export async function clearMeasureReminderPrefs(userId: string): Promise<void> {
  await AsyncStorage.removeItem(prefKey(userId));
}

// ---------------------------------------------------------------------------
// The cadence clock
// ---------------------------------------------------------------------------

/** A REAL local date, not just date-shaped: "9999-99-99" matches the
 *  regex but is not a day any calendar has — hostile or half-written
 *  stamps must never reach the cadence math as a "date". */
function isValidLocalDate(iso: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) return false;
  const [y, m, d] = iso.split("-").map(Number);
  const date = new Date(y!, m! - 1, d!);
  return date.getFullYear() === y && date.getMonth() === m! - 1 && date.getDate() === d;
}

/** Record the LOCAL day a measure was completed (MeasuresScreen's success
 *  path). The stamp only ever moves FORWARD — a retry of an older
 *  questionnaire (the pending-measure flow) must not rewind the cadence
 *  and fire a nudge the user already answered. Never throws: a lost stamp
 *  only means one slightly-early nudge. */
export async function recordMeasureCompleted(userId: string, dateISO: string): Promise<void> {
  try {
    if (!isValidLocalDate(dateISO)) return;
    await commitReminderPreferenceWrite(userId, async check => {
      const current = await lastMeasureCompletedOn(userId);
      check();
      if (current !== null && current >= dateISO) return;
      await secureStore.setItem(lastKey(userId), dateISO);
    });
  } catch {
    // Disposable cadence metadata, never an error surface.
  }
}

/** The last completed measure's local day, or null when none is recorded
 *  (or the stamp is unreadable/hostile — which reads as "none", never as a
 *  fabricated date). Never throws. */
export async function lastMeasureCompletedOn(userId: string): Promise<string | null> {
  try {
    const raw = await secureStore.getItem(lastKey(userId));
    if (raw === null) return null;
    return isValidLocalDate(raw) ? raw : null;
  } catch {
    return null;
  }
}

/** Account-deletion hygiene for the cadence stamp. */
export async function clearLastMeasureDate(userId: string): Promise<void> {
  await secureStore.removeItem(lastKey(userId)).catch(() => {});
}

/** LOCAL midnight of an ISO local date — the same wall-calendar semantics
 *  as every other date in the app (never a UTC guess). */
function localMidnight(iso: string): Date {
  const [y, m, d] = iso.split("-").map(Number);
  return new Date(y!, m! - 1, d!);
}

/**
 * PURE: is a check-in nudge due? True when the last completed measure is
 * at least `intervalWeeks` old, counted in LOCAL calendar days (midnight
 * to midnight — DST-proof via local Date math, rounded to whole days).
 * Never due without a baseline: a user who has never completed a measure
 * has no cadence to be reminded OF (the toggle copy says exactly this),
 * and hostile/malformed input is never due.
 */
export function measureReminderDue(
  lastCompletedISO: string | null,
  intervalWeeks: number,
  now: Date,
): boolean {
  if (lastCompletedISO === null) return false;
  if (!isValidLocalDate(lastCompletedISO)) return false;
  if (!Number.isInteger(intervalWeeks) || intervalWeeks <= 0) return false;
  const last = localMidnight(lastCompletedISO);
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  // Across a DST boundary the raw difference is 23/25h off a whole day;
  // rounding to the nearest day keeps the CALENDAR count exact.
  const elapsedDays = Math.round((today.getTime() - last.getTime()) / 86_400_000);
  if (elapsedDays < 0) return false; // a future-dated stamp is corrupt, not due
  return elapsedDays >= intervalWeeks * 7;
}

/**
 * PURE: when a due nudge should fire — the next 20:00 local, the calm
 * evening default the daily reminder ships (never a morning alarm, never
 * "immediately": a nudge that interrupts the current moment is a push, not
 * an invitation). Local-time semantics throughout, the nextReminderFireTime
 * discipline: a slot already past rolls to tomorrow.
 */
export function nextMeasureReminderFireTime(now: Date, lastCompletedISO?: string | null, intervalWeeks = DEFAULT_MEASURE_INTERVAL_WEEKS): Date {
  if (lastCompletedISO && isValidLocalDate(lastCompletedISO) && MEASURE_INTERVAL_WEEKS.includes(intervalWeeks)) {
    const due = localMidnight(lastCompletedISO);
    due.setDate(due.getDate() + intervalWeeks * 7);
    due.setHours(20, 0, 0, 0);
    if (due.getTime() > now.getTime()) return due;
  }
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 20, 0, 0, 0);
  if (today.getTime() > now.getTime()) return today;
  return new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 20, 0, 0, 0);
}
