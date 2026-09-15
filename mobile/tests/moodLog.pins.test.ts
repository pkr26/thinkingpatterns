/**
 * Deep-mutation pins for the mood log (2026-09-15 Stryker campaign).
 * Targets (see /tmp/surv_moodLog.ts.txt): the year padStart in localDateISO,
 * the strict ^YYYY-MM-DD$ anchors, the oldest-first sort, the MAX_DAYS=400
 * write cap (boundary: the 401st day drops the oldest), and recentMoods'
 * own -days slice. The localDateISO timezone block lives in moodLog.test.ts
 * and is deliberately not duplicated here.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";

const { recordMood, recentMoods, localDateISO } = await import("../src/moodLog");

const keyA = Buffer.alloc(32, 1);

const day = (offset: number): string => {
  const d = new Date(Date.UTC(2026, 8, 4 + offset));
  return d.toISOString().slice(0, 10);
};

beforeEach(() => {
  storage.__reset();
});

describe("moodLog pins: localDateISO year padding", () => {
  it("pads a sub-4-digit year with zeros (year 999 renders as 0999)", () => {
    const d = new Date(2026, 0, 5);
    d.setFullYear(999);
    // padStart(4, "0") is load-bearing: an empty pad string returns "999"
    // un-padded and the date would read "999-01-05".
    expect(localDateISO(d)).toBe("0999-01-05");
  });
});

describe("moodLog pins: strict date anchors in sanitize", () => {
  it("a date with junk before the YYYY-MM-DD body is dropped (leading ^ is strict)", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([
        { date: "x2026-09-01", value: 0.5 },
        { date: "2026-09-02", value: 0.4 },
      ]),
    );
    const days = await recentMoods(keyA, "u1", 30);
    expect(days).toEqual([{ date: "2026-09-02", value: 0.4 }]);
  });

  it("a date with trailing extra digits is dropped (trailing $ is strict)", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([
        { date: "2026-09-012", value: 0.5 },
        { date: "2026-09-03", value: 0.25 },
      ]),
    );
    const days = await recentMoods(keyA, "u1", 30);
    expect(days).toEqual([{ date: "2026-09-03", value: 0.25 }]);
  });
});

describe("moodLog pins: oldest-first ordering", () => {
  it("stored days are re-sorted by date, not kept in payload order", async () => {
    await storage.setItem(
      "mindpattern.moodlog.u1",
      JSON.stringify([
        { date: "2026-09-05", value: -0.5 },
        { date: "2026-09-04", value: 0.3 },
        { date: "2026-09-06", value: 0.9 },
      ]),
    );
    const days = await recentMoods(keyA, "u1", 30);
    expect(days.map((d) => d.date)).toEqual(["2026-09-04", "2026-09-05", "2026-09-06"]);
    expect(days.map((d) => d.value)).toEqual([0.3, -0.5, 0.9]);
  });
});

describe("moodLog pins: MAX_DAYS write cap", () => {
  it("recording the 401st day drops exactly the oldest day (400 survive)", async () => {
    // Days -400..0 = 401 distinct days; slice(-400) must keep -400..-1 EXCLUSIVE
    // of the oldest (-400 is dropped, keeping -399..0).
    for (let offset = -400; offset <= 0; offset += 1) {
      await recordMood(keyA, "u1", day(offset), 0.1);
    }
    const days = await recentMoods(keyA, "u1", 500);
    expect(days).toHaveLength(400);
    expect(days[0].date).toBe(day(-399));
    expect(days[399].date).toBe(day(0));
  });
});

describe("moodLog pins: recentMoods window", () => {
  it("recentMoods(days) returns exactly the newest N days", async () => {
    await recordMood(keyA, "u1", "2026-09-01", -1);
    await recordMood(keyA, "u1", "2026-09-02", 0);
    await recordMood(keyA, "u1", "2026-09-03", 1);
    const two = await recentMoods(keyA, "u1", 2);
    expect(two.map((d) => d.date)).toEqual(["2026-09-02", "2026-09-03"]);
    const four = await recentMoods(keyA, "u1", 4);
    expect(four).toHaveLength(3); // a window larger than the log keeps all
  });
});
