/**
 * Local calendar-date helpers. Journal dates follow the user's day, not UTC.
 */

export function localDateISO(d: Date = new Date()): string {
  const year = String(d.getFullYear()).padStart(4, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
