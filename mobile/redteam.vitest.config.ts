import { defineConfig, mergeConfig } from "vitest/config";
import base from "./vitest.config";

// Red-team specs run the REAL shipping modules under the same aliases as the
// suite (node:crypto engine, AsyncStorage mock, RN mocks) but are excluded
// from coverage thresholds: attacks are allowed to fail "tests" by design.
export default mergeConfig(
  base,
  defineConfig({
    test: {
      include: ["redteam/**/*.test.ts"],
      coverage: { enabled: false },
      testTimeout: 120_000,
    },
  }),
);
