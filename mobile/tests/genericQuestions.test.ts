import { expect, it, vi } from "vitest";
import copy from "./fixtures/generic-visible-copy.json";

it("serves the approved English and Spanish daily question across all pool positions", async () => {
  const { genericQuestionForDate } = await import("../src/genericQuestions");
  for (const [date, english, spanish] of copy.rows) {
    const actualEnglish = genericQuestionForDate(date, "en");
    const actualSpanish = genericQuestionForDate(date, "es");
    if (actualEnglish !== english || actualSpanish !== spanish) {
      throw new Error(`Daily question on ${date}: expected ${JSON.stringify([english, spanish])}, received ${JSON.stringify([actualEnglish, actualSpanish])}`);
    }
  }
  vi.useFakeTimers();
  try {
    vi.setSystemTime(new Date(2025, 0, 1, 12));
    expect(genericQuestionForDate()).toBe(copy.rows[0]![1]);
  } finally {
    vi.useRealTimers();
  }
});
