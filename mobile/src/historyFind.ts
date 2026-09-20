/**
 * History search + calendar helpers (2026-09-17).
 *
 * Pure functions: the search box and the mood calendar filter the
 * DECRYPTED, on-device list — no query ever leaves the phone.
 *
 * monthLabel formats through Intl with the app locale's tag (2026-09-19
 * i18n wave) — the old pinned English MONTH_NAMES table is gone; a
 * garbage month still degrades to the raw number-shaped output rather
 * than throwing.
 */
import { dateLocaleTag } from "./strings";

export interface SearchableEntry {
  clientEntryId: string;
  entryDate: string;
  text: string;
}

/** Case-insensitive substring over the entry text, or an exact date match
 *  (so "2026-07" filters to July, "2026-07-14" to the day). */
export function filterEntries<T extends SearchableEntry>(entries: T[], query: string): T[] {
  const q = query.trim().toLowerCase();
  if (!q) return entries;
  return entries.filter((e) => e.text.toLowerCase().includes(q) || e.entryDate.toLowerCase().includes(q));
}

export interface CalendarDay {
  /** ISO date (YYYY-MM-DD) or null for the leading blanks. */
  iso: string | null;
  /** Day-of-month number to render. */
  day: number;
}

/** One month grid: leading blanks for the weekday offset, then every day.
 *  Weeks start Monday (matches the engine's weekday semantics). */
export function monthGrid(year: number, month1to12: number): CalendarDay[] {
  const first = new Date(Date.UTC(year, month1to12 - 1, 1));
  const daysInMonth = new Date(Date.UTC(year, month1to12, 0)).getUTCDate();
  // JS getUTCDay: Sunday=0 … Saturday=6; Monday-first offset:
  const lead = (first.getUTCDay() + 6) % 7;
  const cells: CalendarDay[] = [];
  for (let i = 0; i < lead; i++) cells.push({ iso: null, day: 0 });
  for (let d = 1; d <= daysInMonth; d++) {
    cells.push({
      iso: `${year}-${String(month1to12).padStart(2, "0")}-${String(d).padStart(2, "0")}`,
      day: d,
    });
  }
  return cells;
}

/** "September 2026" / "septiembre 2026" per the app locale (en → en-US
 *  capitalized month, es → es-ES lowercase, both via Intl — no tables). */
export function monthLabel(year: number, month1to12: number): string {
  const name = new Intl.DateTimeFormat(dateLocaleTag(), { month: "long", timeZone: "UTC" }).format(
    new Date(Date.UTC(year, month1to12 - 1, 1)),
  );
  return `${name} ${year}`;
}

/** Previous/next month stepping (wraps the year). */
export function stepMonth(year: number, month1to12: number, delta: -1 | 1): { year: number; month: number } {
  const zero = month1to12 - 1 + delta;
  return { year: year + Math.floor(zero / 12), month: ((zero % 12) + 12) % 12 + 1 };
}
