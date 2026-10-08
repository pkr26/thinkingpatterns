import { runTestControl } from "./testControl";
/**
 * Vitest setupFiles entry: pins the suite's environment.
 *
 * 1. Locale: pinned to English for the whole suite. The 1,283 existing
 *    tests assert shipped English copy; the device locale of whatever
 *    machine runs the suite must not change what they see
 *    (tests/i18n.test.ts flips the seam explicitly and restores it).
 * 2. React Native build globals: a plain node evaluation has neither
 *    __DEV__ nor __APP_VERSION__, which Metro injects into a real bundle.
 *    The suite mirrors a DEV bundle (that is the world the tests were
 *    written against — the loopback dev server default in src/api/client.ts)
 *    and reads the version from the same manifest babel.config.cjs inlines
 *    it from, so the two can never disagree.
 */
import { afterEach, beforeEach, expect, vi } from "vitest";
import { __setLocaleForTests } from "../../src/strings";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import pkg from "../../package.json";

(globalThis as { __DEV__?: boolean }).__DEV__ = true;
(globalThis as { __APP_VERSION__?: string }).__APP_VERSION__ = pkg.version;

runTestControl(__setLocaleForTests, "en");

// A fixed fixture clock preserves meaningful displayed dates across days.
// Timers stay real unless a scenario explicitly controls them itself.
const fixtureClock = new Date("2026-10-06T04:00:00Z");
const visualScenario = () => expect.getState().testPath?.endsWith(".tsx") === true;
if (visualScenario()) {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(fixtureClock);
}

// Production starts with no active owner and therefore rejects account
// writes until credential hydration. Most legacy unit fixtures exercise a
// feature in isolation rather than booting the store, so give each test the
// explicit permissive test seam; lifecycle/boot regressions publish the
// concrete owner (or null) they need after this reset.
beforeEach(() => {
  // Register from setup, before any lazy screen helper import. Expect's
  // currentTestName may still hold a prior case until the first assertion.
  const scenarioKey = Symbol.for("mindpattern.test.publicSurfaceScenario");
  const context = globalThis as Record<symbol, number>;
  context[scenarioKey] = (context[scenarioKey] ?? 0) + 1;
  if (visualScenario()) {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(fixtureClock);
  }
  runTestControl(__resetLocalKeyLifecycleForTests);
});
afterEach(() => {
  (globalThis as Record<symbol, (() => void) | undefined>)[Symbol.for("mindpattern.test.flushPublicSurfaces")]?.();
  if (visualScenario()) vi.useRealTimers();
});
