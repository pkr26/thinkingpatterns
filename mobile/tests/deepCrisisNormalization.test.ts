import { describe, expect, it } from "vitest";
import { detectCrisisLanguage, matchesCrisisSuppress } from "../src/crisisDetect";

describe("first-person pronouns before a partially split crisis word", () => {
  it.each(["I w a nt to die", "I w ant to die", "I k ill myself", "I h urt myself"])(
    "retains the crisis phrase in %s",
    (text) => {
      expect(detectCrisisLanguage(text)).toBe(true);
      expect(matchesCrisisSuppress(text)).toBe(true);
    },
  );

  it.each(["life i s n't worth living", "life i s n't worth living anymore", "life i s not worth living"])(
    "retains the original split-word interpretation in %s",
    (text) => {
      expect(detectCrisisLanguage(text)).toBe(true);
      expect(matchesCrisisSuppress(text)).toBe(true);
    },
  );

  it.each(["I w a nt to diet", "I w ant to dine", "I a m so sad", "I k now myself", "a rocky sunset"])(
    "preserves the benign boundary in %s",
    (text) => {
      expect(detectCrisisLanguage(text)).toBe(false);
      expect(matchesCrisisSuppress(text)).toBe(false);
    },
  );
});
