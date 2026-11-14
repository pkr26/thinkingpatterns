import { expect, it } from "vitest";
import { INSTRUMENTS, measurePayload, safetyItemEndorsed, safetyItemValue } from "../src/measures";

it("exports the literal identifier of each standard questionnaire", () => {
  expect({
    phq9: INSTRUMENTS.phq9.id,
    gad7: INSTRUMENTS.gad7.id,
    phq2: INSTRUMENTS.phq2.id,
  }).toEqual({ phq9: "phq9", gad7: "gad7", phq2: "phq2" });
});

it("instruments without a safety item ignore unrelated ordinary array properties", () => {
  const examples = [
    ["gad7", Object.assign([0, 0, 0, 0, 0, 0, 0], { undefined: 3 })],
    ["phq2", Object.assign([0, 0], { undefined: 3 })],
  ] as const;
  for (const [id, picks] of examples) {
    expect(safetyItemValue(id, picks)).toBeNull();
    expect(safetyItemEndorsed(id, picks)).toBe(false);
    const payload = JSON.parse(measurePayload(id, picks, "2026-10-05T12:00:00Z")) as Record<string, unknown>;
    expect(payload).toEqual({ v: 1, measure: id, score: 0, completed_at: "2026-10-05T12:00:00Z" });
    expect(Object.hasOwn(payload, "item9")).toBe(false);
  }
});
