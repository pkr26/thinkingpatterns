import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { CRISIS_BENIGN_COMPOUNDS, CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS } from "../src/crisisPhrases";

it("ships the shared crisis phrase artifact", () => {
  const shared = JSON.parse(readFileSync(new URL("../../shared/crisis_phrases.json", import.meta.url), "utf8"));
  expect([...CRISIS_DIALOG_PATTERNS]).toEqual(shared.dialog);
  expect([...CRISIS_SUPPRESS_EXTRA_PATTERNS]).toEqual(shared.suppress_extra);
  expect([...CRISIS_BENIGN_COMPOUNDS]).toEqual(shared.benign_compounds);
});
