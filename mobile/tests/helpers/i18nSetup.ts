/**
 * Vitest setupFiles entry: pin the app locale to English for the whole
 * suite. The 1,283 existing tests assert shipped English copy; the device
 * locale of whatever machine runs the suite must not change what they see
 * (tests/i18n.test.ts flips the seam explicitly and restores it).
 */
import { __setLocaleForTests } from "../../src/strings";

__setLocaleForTests("en");
