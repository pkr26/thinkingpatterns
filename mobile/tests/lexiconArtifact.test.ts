import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { LEXICON } from "../src/brain/lexicon";

it("the shipped lexicon artifact matches the shared source of truth", () => {
  expect(LEXICON).toEqual(JSON.parse(readFileSync(new URL("../../shared/brain_lexicon.json", import.meta.url), "utf8")));
});
