// Packaging parity stays in the ordinary suite. It is excluded from mutation
// execution, whose crisis oracles call the real text-level consumers instead.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CRISIS_DIALOG_PATTERNS, CRISIS_SUPPRESS_EXTRA_PATTERNS, CRISIS_BENIGN_COMPOUNDS } from "../src/crisisPhrases";

const shared = JSON.parse(readFileSync(new URL("../../shared/crisis_phrases.json", import.meta.url), "utf8"));
describe("embedded crisis artifact parity", () => {
  it("preserves dialog patterns", () => { expect([...CRISIS_DIALOG_PATTERNS]).toEqual(shared.dialog); });
  it("preserves suppress patterns", () => { expect([...CRISIS_SUPPRESS_EXTRA_PATTERNS]).toEqual(shared.suppress_extra); });
  it("preserves benign compound patterns", () => { expect([...CRISIS_BENIGN_COMPOUNDS]).toEqual(shared.benign_compounds); });
});
