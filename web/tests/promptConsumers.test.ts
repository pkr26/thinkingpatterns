import { expect, it } from "vitest";
import { promptChipsFor } from "../src/promptChips";

it("keeps the approved bilingual writing starters stable for a known local calendar day", () => {
  const morning = new Date(2026, 8, 25, 0, 1), evening = new Date(2026, 8, 25, 23, 59);
  const en = ["Someone I thought of today…", "The best part of today…", "The hardest part of today…"];
  const es = ["Alguien en quien pensé hoy…", "Lo mejor de hoy…", "Lo más difícil de hoy…"];
  expect(promptChipsFor(morning)).toEqual(en); expect(promptChipsFor(evening)).toEqual(en);
  expect(promptChipsFor(morning, 3, "es")).toEqual(es); expect(promptChipsFor(evening, 3, "es")).toEqual(es);
  expect(promptChipsFor(morning, 0)).toEqual([]); expect(promptChipsFor(morning, 1)).toEqual(en.slice(0, 1));
  expect(promptChipsFor(morning, 25)).toHaveLength(20); expect(new Set(promptChipsFor(morning, 25)).size).toBe(20);
});
it("returns no unusable prompt when its supplied date is invalid", () => {
  expect(promptChipsFor(new Date(NaN))).toEqual([]);
});
