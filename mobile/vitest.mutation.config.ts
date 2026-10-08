import { mergeConfig } from "vitest/config";
import base from "./vitest.config";

export default mergeConfig(base, {
  test: {
    coverage: { enabled: false },
    // These verify native files/source packaging, not JS mutant behavior.
    // The same-process bootstrap.runtime tests exercise the entry mutations.
    exclude: ["tests/healthBridge.pins.test.ts", "tests/nativeBuildTools.test.ts", "tests/bootstrap.test.ts", "tests/lexiconArtifact.test.ts", "tests/crisisArtifact.test.ts", "tests/genericQuestionsArtifact.test.ts"],
  },
});
