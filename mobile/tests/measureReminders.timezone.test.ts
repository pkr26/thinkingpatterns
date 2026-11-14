import { expect, it } from "vitest";

const { measureReminderDue } = await import("../src/measureReminders");

it("rejects the skipped Apia civil day without turning it into a due reminder", () => {
  // A real local calendar can skip an entire civil day. Native Date
  // normalizes Apia's absent 2011-12-30 to the next day; that must not
  // turn a hostile completion stamp into a due check-in.
  const originalTimezone = process.env.TZ;
  try {
    process.env.TZ = "Pacific/Apia";
    const skippedDay = new Date(2011, 11, 30);
    expect([skippedDay.getFullYear(), skippedDay.getMonth() + 1, skippedDay.getDate()]).toEqual([2011, 12, 31]);
    const afterCadence = new Date(2012, 0, 20, 12);
    expect(measureReminderDue("2011-12-31", 2, afterCadence)).toBe(true);
    expect(measureReminderDue("2011-12-30", 2, afterCadence)).toBe(false);
  } finally {
    if (originalTimezone === undefined) delete process.env.TZ;
    else process.env.TZ = originalTimezone;
  }
});
