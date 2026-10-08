import { expect, it } from "vitest";
import { maxScoreForMeasure, measureComplete, measureScore, measureSafetyItemValue, measurePayload, safetyItemEndorsed, type MeasureId } from "../src/measures";

const instruments: Array<[MeasureId, number, number]> = [["phq9", 9, 27], ["gad7", 7, 21], ["phq2", 2, 6]];
it.each(instruments)("accepts only a complete set of standard picks for %s", (id, count) => {
  for (const pick of [0, 1, 2, 3]) expect(measureComplete(id, Array(count).fill(pick))).toBe(true);
  expect(measureComplete(id, Array(count - 1).fill(0))).toBe(false);
  expect(measureComplete(id, Array(count + 1).fill(0))).toBe(false);
  expect(measureComplete(id, Array<number>(count))).toBe(false);
  const partlyAnswered = Array(count).fill(0); delete partlyAnswered[count - 1];
  expect(measureComplete(id, partlyAnswered)).toBe(false);
  for (const pick of [null, undefined, NaN, Infinity, -Infinity, -1, 4, 0.5, "1"]) {
    const responses = Array(count).fill(0); responses[count - 1] = pick;
    expect(measureComplete(id, responses), `${id}: invalid pick ${String(pick)}`).toBe(false);
  }
});

it.each(instruments)("keeps guarded %s scoring separate from the strict completion gate", (id, count, ceiling) => {
  expect(measureScore(id, Array(count).fill(3))).toBe(ceiling);
  expect(measureScore(id, Array(count).fill(99))).toBe(ceiling);
  expect(measureScore(id, Array(count).fill(-99))).toBe(0);
  expect(measureScore(id, Array(count).fill(0.5))).toBe(count);
  expect(measureScore(id, Array(count).fill(2.49))).toBe(count * 2);
  expect(measureScore(id, Array(count).fill(NaN))).toBe(0);
  expect(measureScore(id, Array(count).fill(Infinity))).toBe(0);
  expect(measureScore(id, [...Array(count).fill(0), 3])).toBe(0);
});

it("keeps unknown measure names out of the patient's recorded-score scale", () => {
  for (const name of ["constructor", "toString", "__proto__", "future", null, 3, {}, { toString: null }, new String("phq9")]) expect(maxScoreForMeasure(name)).toBeNull();
  for (const [id, , ceiling] of instruments) expect(maxScoreForMeasure(id)).toBe(ceiling);
});

it("offers support only for a numeric endorsed safety item and leaves other instruments unendorsed", () => {
  for (const pick of [0, null, undefined, "2", "bad", NaN, -1]) {
    expect(safetyItemEndorsed("phq9", [...Array(8).fill(0), pick] as Array<number | null>)).toBe(false);
  }
  for (const pick of [1, 2, 3]) expect(safetyItemEndorsed("phq9", [...Array(8).fill(0), pick])).toBe(true);
  expect(safetyItemEndorsed("gad7", Array(7).fill(3))).toBe(false);
  expect(safetyItemEndorsed("phq2", Array(2).fill(3))).toBe(false);
});

it("shares the raw clamped PHQ-9 safety pick and omits unavailable safety fields", () => {
  for (const [pick, expected] of [[-1, 0], [0.5, 1], [2.49, 2], [4, 3], [NaN, null], [Infinity, null], [null, null]] as const) {
    const responses = [...Array(8).fill(0), pick];
    expect(measureSafetyItemValue("phq9", responses)).toBe(expected);
    const payload = JSON.parse(measurePayload("phq9", responses, "2026-10-05"));
    expect(payload).toEqual({ v: 1, measure: "phq9", score: expected ?? 0, ...(expected === null ? {} : { item9: expected }), completed_at: "2026-10-05" });
  }
  for (const id of ["gad7", "phq2"] as const) {
    expect(measureSafetyItemValue(id, [3, 3])).toBeNull();
    expect(JSON.parse(measurePayload(id, [3, 3], "2026-10-05"))).not.toHaveProperty("item9");
  }
});
