// Asset integrity is a separate ordinary-suite check. Mutation campaigns use
// brainBehavior.test.ts consumer outputs; table equality cannot prove runtime kills.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LEXICON } from "../src/brain/lexicon";

describe("generated brain asset integrity", () => {
  it("the generated lexicon matches the shared generation input", () => {
    const shared = JSON.parse(readFileSync(join(import.meta.dirname, "../../shared/brain_lexicon.json"), "utf8"));
    expect(LEXICON).toEqual(shared);
  });
});
