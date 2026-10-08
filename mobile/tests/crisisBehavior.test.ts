import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { beforeEach, it, vi } from "vitest";

const corpus = JSON.parse(gunzipSync(readFileSync(new URL("../../shared/frontend_crisis_behavior.json.gz", import.meta.url))).toString("utf8")) as {
  rows: [string, boolean, boolean][];
  normalize: [string, string][];
  variants: [string, string[], string[]][];
};
beforeEach(() => { vi.resetModules(); });

it("honors independent dialog and quotation-suppression results for every phrase alternative", async () => {
  const { detectCrisisLanguage, matchesCrisisSuppress } = await import("../src/crisisDetect");
  for (const [text, dialog, suppress] of corpus.rows) {
    const actualDialog = detectCrisisLanguage(text);
    const actualSuppress = matchesCrisisSuppress(text);
    if (actualDialog !== dialog || actualSuppress !== suppress) throw new Error(JSON.stringify({ text, expected: [dialog, suppress], actual: [actualDialog, actualSuppress] }));
  }
}, 30_000);

it("preserves public cross-engine normalization at character and word boundaries", async () => {
  const { normalizeCrisisText } = await import("../src/crisisDetect");
  for (const [text, expected] of corpus.normalize) {
    const actual = normalizeCrisisText(text);
    if (actual !== expected) throw new Error(JSON.stringify({ text, expected, actual }));
  }
}, 30_000);


it("preserves the exported cross-engine matching variants for real input text", async () => {
  const { matchVariants, foldedVariants } = await import("../src/crisisDetect");
  for (const [text, expected, expectedFolded] of corpus.variants) {
    const actual = matchVariants(text);
    const actualFolded = foldedVariants(text);
    if (JSON.stringify(actual) !== JSON.stringify(expected) || JSON.stringify(actualFolded) !== JSON.stringify(expectedFolded)) {
      throw new Error(JSON.stringify({ text, expected, actual, expectedFolded, actualFolded }));
    }
  }
}, 30_000);
