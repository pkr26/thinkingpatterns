/**
 * Opt-in check-in reminders at two-, four-, or eight-week intervals.
 *
 * Only the enabled flag, interval, and snooze date persist as local preferences.
 * Due checks use the measure history already decrypted by the view; no journal
 * content is inspected or sent. Dismissal snoozes the gentle prompt for three days.
 */
import { kv } from "./kvstore";
import { localDateISO } from "./dates";

export interface MeasureCadencePref {
  enabled: boolean;
  intervalWeeks: 2 | 4 | 8;
  /** Local calendar date (YYYY-MM-DD) until which a dismissed banner stays
   *  hidden — null when the banner was never dismissed. */
  snoozedUntil: string | null;
}

export const CADENCE_INTERVALS: readonly (2 | 4 | 8)[] = [2, 4, 8];

/** The DPIA-honest default: OFF until the patient opts in; 4 weeks (the
 *  standard MBC follow-up interval) once they do. */
export const DEFAULT_CADENCE: MeasureCadencePref = { enabled: false, intervalWeeks: 4, snoozedUntil: null };

const key = (userId: string): string => `mindpattern.measureCadence.${userId}`;

/** Full validation of anything read back from storage: a hostile or
 *  half-written record is the OFF default, never a fabricated cadence. */
export function parseCadence(raw: string | null): MeasureCadencePref {
  if (!raw) return { ...DEFAULT_CADENCE };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return { ...DEFAULT_CADENCE };
    const pref = parsed as Record<string, unknown>;
    const intervalWeeks = pref.intervalWeeks;
    const snoozedUntil = pref.snoozedUntil;
    return {
      enabled: pref.enabled === true,
      intervalWeeks: CADENCE_INTERVALS.includes(intervalWeeks as 2 | 4 | 8) ? (intervalWeeks as 2 | 4 | 8) : 4,
      snoozedUntil: typeof snoozedUntil === "string" && /^\d{4}-\d{2}-\d{2}$/.test(snoozedUntil) ? snoozedUntil : null,
    };
  } catch {
    return { ...DEFAULT_CADENCE };
  }
}

export async function readMeasureCadence(userId: string): Promise<MeasureCadencePref> {
  return parseCadence(await kv.getItem(key(userId)));
}

export async function writeMeasureCadence(userId: string, pref: MeasureCadencePref): Promise<void> {
  await kv.setItem(key(userId), JSON.stringify(pref));
}

/** Deletion hygiene: the preference must not outlive its account (the
 *  M-W3 per-account sweep; the slot is KV, so the mindpattern.* prefix
 *  wipe in localStorage does not reach it). */
export async function clearMeasureCadence(userId: string): Promise<void> {
  await kv.removeItem(key(userId));
}

/** Whole days between two local calendar dates (positive when `today` is
 *  later). Date-granular by design — measure dates carry no time of day. */
function daysBetween(fromISO: string, toISO: string): number {
  const from = Date.parse(`${fromISO}T00:00:00Z`);
  const to = Date.parse(`${toISO}T00:00:00Z`);
  if (!Number.isFinite(from) || !Number.isFinite(to)) return 0;
  return Math.round((to - from) / 86_400_000);
}

/** True when the gentle banner should render. The rule is a fact, not a
 *  judgment: the preference is ON, the last dismissal has lapsed, and the
 *  last completed measure (any instrument — a check-in is a check-in) is
 *  older than the chosen interval. A patient with no completed measures
 *  yet is "due" (the first check-in is available); a patient whose
 *  history failed to load passes lastCompletedDate undefined and sees
 *  nothing (unknown is not due). */
export function cadenceDue(
  pref: MeasureCadencePref,
  lastCompletedDate: string | null | undefined,
  todayISO: string = localDateISO(),
): boolean {
  if (!pref.enabled) return false;
  if (typeof pref.snoozedUntil === "string" && daysBetween(pref.snoozedUntil, todayISO) < 0) return false;
  if (lastCompletedDate === undefined) return false;
  if (lastCompletedDate === null) return true;
  return daysBetween(lastCompletedDate, todayISO) >= pref.intervalWeeks * 7;
}

/** "Not now": hide the banner for three days — a snooze, never an
 *  obligation tracker. */
export function snoozeCadence(pref: MeasureCadencePref, todayISO: string = localDateISO()): MeasureCadencePref {
  const snoozedUntil = new Date(`${todayISO}T00:00:00Z`);
  snoozedUntil.setUTCDate(snoozedUntil.getUTCDate() + 3);
  return { ...pref, snoozedUntil: snoozedUntil.toISOString().slice(0, 10) };
}
