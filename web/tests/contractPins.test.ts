/** Cross-platform contract pins for the embedded copies: the crisis
 *  language contract and the reflective question pools must match
 *  shared/*.json exactly (the repo's copy-and-pin discipline, D-2). */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectCrisisLanguage, matchesCrisisSuppress } from "../src/crisisDetect";
import { genericQuestionForDate } from "../src/genericQuestions";

const here = dirname(fileURLToPath(import.meta.url));

describe("crisis-language contract (shared/crisis_phrases.json)", () => {
  const shared = JSON.parse(readFileSync(join(here, "..", "..", "shared", "crisis_phrases.json"), "utf8")) as {
    dialog: string[];
    suppress_extra: string[];
    benign_compounds: string[];
    fixtures: { dialog_fires: string[]; dialog_silent: string[]; suppress_only_fires: string[] };
  };

  it("the shared fixture corpus behaves identically through our detector", () => {
    for (const text of shared.fixtures.dialog_fires) expect(detectCrisisLanguage(text)).toBe(true);
    for (const text of shared.fixtures.dialog_silent) expect(detectCrisisLanguage(text)).toBe(false);
    for (const text of shared.fixtures.suppress_only_fires) expect(matchesCrisisSuppress(text)).toBe(true);
  });

  it("detection fires on crisis language and stays quiet on ordinary lows", () => {
    expect(detectCrisisLanguage("I want to kill myself")).toBe(true);
    expect(detectCrisisLanguage("end my life")).toBe(true);
    expect(detectCrisisLanguage("I had a slow, heavy day at work")).toBe(false);
    expect(detectCrisisLanguage("")).toBe(false);
    expect(matchesCrisisSuppress("I want to kill myself")).toBe(true);
  });
});

describe("reflective question pools (shared/generic_questions{,_es}.json)", () => {
  const en = (JSON.parse(readFileSync(join(here, "..", "..", "shared", "generic_questions.json"), "utf8")) as { questions: string[] }).questions;
  const es = (JSON.parse(readFileSync(join(here, "..", "..", "shared", "generic_questions_es.json"), "utf8")) as { questions: string[] }).questions;

  it("serves every approved English and Spanish question through the calendar rotation", () => {
    const servedEn = new Set<string>();
    const servedEs = new Set<string>();
    for (let day = 1; day <= 730; day++) {
      const date = new Date(2025, 0, day);
      const localDate = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
      const english = genericQuestionForDate(localDate, "en");
      const spanish = genericQuestionForDate(localDate, "es");
      expect(en).toContain(english);
      expect(es).toContain(spanish);
      expect(es[en.indexOf(english)]).toBe(spanish);
      for (const question of [english, spanish]) {
        expect(question.endsWith("?")).toBe(true);
        expect(question.toLowerCase()).not.toContain("should");
        expect(question.toLowerCase()).not.toContain("debería");
      }
      servedEn.add(english);
      servedEs.add(spanish);
    }
    expect(servedEn.size).toBe(en.length);
    expect(servedEs.size).toBe(es.length);
  });
});
