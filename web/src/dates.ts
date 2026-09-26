/**
 * Local-date helpers (extracted from mobile's moodLog.ts — the full
 * device-local mood log lands with P6). "Local" is deliberate: journal
 * dates are the user's calendar day, never UTC.
 */

export function localDateISO(d: Date = new Date()): string {
  const year = String(d.getFullYear()).padStart(4, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
