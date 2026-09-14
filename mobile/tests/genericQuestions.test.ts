/**
 * Parity + invariant tests for the embedded generic question pool.
 *
 * src/genericQuestions.ts is an EMBEDDED COPY of shared/generic_questions.json
 * (Metro cannot import outside the project root). This suite reads the
 * shared file from disk and pins array parity, the content invariants
 * (questions end with "?", no advice language), and the rotation
 * properties (same question all day, rotates daily, always in-pool).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { GENERIC_QUESTIONS, genericQuestionForDate } from "../src/genericQuestions";

const here = dirname(fileURLToPath(import.meta.url));
const shared = JSON.parse(readFileSync(join(here, "..", "..", "shared", "generic_questions.json"), "utf8")) as {
  v: number;
  questions: string[];
};

describe("shared/generic_questions.json parity", () => {
  it("embeds the pool exactly", () => {
    expect(shared.v).toBe(1);
    expect([...GENERIC_QUESTIONS]).toEqual(shared.questions);
  });

  it("honors the content invariants: questions only, no advice language", () => {
    for (const question of GENERIC_QUESTIONS) {
      expect(question.endsWith("?")).toBe(true);
      expect(question.toLowerCase()).not.toContain("should");
    }
  });
});

describe("genericQuestionForDate rotation", () => {
  it("is deterministic: the same date always yields the same question", () => {
    expect(genericQuestionForDate("2026-09-07")).toBe(genericQuestionForDate("2026-09-07"));
  });

  it("always returns a pool member", () => {
    for (let day = 1; day <= 30; day++) {
      const date = `2026-09-${String(day).padStart(2, "0")}`;
      expect(GENERIC_QUESTIONS).toContain(genericQuestionForDate(date));
    }
  });

  it("rotates daily over a month (and month boundaries stay stable)", () => {
    const seen = new Set<string>();
    for (let day = 1; day <= 30; day++) {
      seen.add(genericQuestionForDate(`2026-09-${String(day).padStart(2, "0")}`));
    }
    // Not a constant pick; adjacent days step through the pool.
    expect(seen.size).toBeGreaterThanOrEqual(4);
    // Month boundaries are just dates: deterministic and in-pool.
    expect(GENERIC_QUESTIONS).toContain(genericQuestionForDate("2026-09-30"));
    expect(GENERIC_QUESTIONS).toContain(genericQuestionForDate("2026-10-01"));
    // The default form (today) returns a pool member.
    expect(GENERIC_QUESTIONS).toContain(genericQuestionForDate());
  });
});
