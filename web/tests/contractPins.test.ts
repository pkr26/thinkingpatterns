/** Cross-platform contract pins for the embedded copies: the crisis
 *  language contract and the reflective question pools must match
 *  shared/*.json exactly (the repo's copy-and-pin discipline, D-2). */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS, CRISIS_BENIGN_COMPOUNDS } from "../src/crisisPhrases";
import { detectCrisisLanguage, matchesCrisisSuppress } from "../src/crisisDetect";
import { GENERIC_QUESTIONS, GENERIC_QUESTIONS_ES } from "../src/genericQuestions";

const here = dirname(fileURLToPath(import.meta.url));

describe("crisis-language contract (shared/crisis_phrases.json)", () => {
  const shared = JSON.parse(readFileSync(join(here, "..", "..", "shared", "crisis_phrases.json"), "utf8")) as {
    dialog: string[];
    suppress_extra: string[];
    benign_compounds: string[];
    fixtures: { dialog_fires: string[]; dialog_silent: string[]; suppress_only_fires: string[] };
  };

  it("the dialog tier matches the shared contract", () => {
    expect([...CRISIS_DIALOG_PATTERNS].sort()).toEqual([...shared.dialog].sort());
  });

  it("the suppress tier matches the shared contract", () => {
    expect([...CRISIS_SUPPRESS_EXTRA_PATTERNS].sort()).toEqual([...shared.suppress_extra].sort());
  });

  it("the benign compounds match the shared contract", () => {
    expect([...CRISIS_BENIGN_COMPOUNDS].sort()).toEqual([...shared.benign_compounds].sort());
  });

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

  it("the English pool is position-identical to the shared contract", () => {
    expect(GENERIC_QUESTIONS).toEqual(en);
  });

  it("the Spanish pool is position-identical (audit E-3 parity)", () => {
    expect(GENERIC_QUESTIONS_ES).toEqual(es);
  });

  it("every question is a question and never advice", () => {
    for (const pool of [GENERIC_QUESTIONS, GENERIC_QUESTIONS_ES]) {
      for (const question of pool) {
        expect(question.endsWith("?")).toBe(true);
        expect(question.toLowerCase()).not.toContain("should");
        expect(question.toLowerCase()).not.toContain("debería");
      }
    }
  });
});
