/**
 * Parity + contract tests for the embedded crisis phrase lists.
 *
 * src/crisisPhrases.ts is an EMBEDDED COPY of shared/crisis_phrases.json
 * (Metro cannot import outside the project root — the same reason the
 * crypto vectors are verified by a node tool). This suite reads the shared
 * file from disk and pins:
 *   1. exact array parity for both tiers,
 *   2. every fixture in the shared contract (dialog_fires fire the dialog
 *      tier, dialog_silent do not, suppress_only_fires hit the suppress
 *      tier WITHOUT firing the dialog tier),
 *   3. the tier relationship: suppress = dialog + suppress_extra.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS } from "../src/crisisPhrases";
import { detectCrisisLanguage, matchesCrisisSuppress } from "../src/crisisDetect";

const here = dirname(fileURLToPath(import.meta.url));
const shared = JSON.parse(readFileSync(join(here, "..", "..", "shared", "crisis_phrases.json"), "utf8")) as {
  v: number;
  dialog: string[];
  suppress_extra: string[];
  fixtures: { dialog_fires: string[]; dialog_silent: string[]; suppress_only_fires: string[] };
};

describe("shared/crisis_phrases.json parity", () => {
  it("embeds the dialog and suppress_extra lists exactly", () => {
    expect(shared.v).toBe(1);
    expect([...CRISIS_DIALOG_PATTERNS]).toEqual(shared.dialog);
    expect([...CRISIS_SUPPRESS_EXTRA_PATTERNS]).toEqual(shared.suppress_extra);
  });

  it("every pattern compiles under ECMAScript RegExp (the mobile engine)", () => {
    for (const pattern of [...CRISIS_DIALOG_PATTERNS, ...CRISIS_SUPPRESS_EXTRA_PATTERNS]) {
      expect(() => new RegExp(pattern, "i")).not.toThrow();
    }
  });
});

describe("shared fixtures", () => {
  it.each(shared.fixtures.dialog_fires)("dialog tier fires on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(true);
  });

  it.each(shared.fixtures.dialog_silent)("dialog tier stays silent on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(false);
  });

  it.each(shared.fixtures.suppress_only_fires)("suppress tier (not dialog) fires on %j", (text) => {
    expect(matchesCrisisSuppress(text)).toBe(true);
    expect(detectCrisisLanguage(text)).toBe(false);
  });
});

describe("tier relationship", () => {
  it("the suppress tier is a strict superset of the dialog tier", () => {
    // Every dialog hit is necessarily a suppress hit.
    for (const text of [...shared.fixtures.dialog_fires, ...shared.fixtures.suppress_only_fires]) {
      if (detectCrisisLanguage(text)) expect(matchesCrisisSuppress(text)).toBe(true);
    }
  });

  it("broad everyday text hits neither tier", () => {
    expect(matchesCrisisSuppress("Had a good day. Walked the dog, called mom.")).toBe(false);
    expect(matchesCrisisSuppress("the exam was brutal")).toBe(false);
  });
});
