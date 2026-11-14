/** Public no-safety-item contract for ordinary Number response arrays.
 * Extra own properties do not assign a safety item to an instrument.
 * No prototype mutation, provider interception or clinical-validity claim. */
import { expect, it } from "vitest";
import { measurePayload, measureSafetyItemValue, safetyItemEndorsed } from "../src/measures";

it.each([["gad7", 7], ["phq2", 2]] as const)(
  "%s never exposes a safety item from an ordinary response array's extra own property",
  (id, items) => {
    const responses = Object.assign(Array<number>(items).fill(0), { undefined: 1 });
    expect(safetyItemEndorsed(id, responses)).toBe(false);
    expect(measureSafetyItemValue(id, responses)).toBeNull();
    const payload = JSON.parse(measurePayload(id, responses, "2026-10-05"));
    expect(payload).not.toHaveProperty("item9");
    expect(payload).toEqual({ v: 1, measure: id, score: 0, completed_at: "2026-10-05" });
  },
);
