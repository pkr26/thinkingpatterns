/**
 * src/mood.ts: the five-point check-in scale, the nearest-label mapping
 * behind the history badges, and the quick text estimate (moved out of
 * EntryScreen unchanged — these cases pin the long-standing behavior).
 */
import { describe, expect, it } from "vitest";

const { MOOD_OPTIONS, moodLabel, localSentiment } = await import("../src/mood");

describe("MOOD_OPTIONS", () => {
  it("is five calm picks from Heavy to Light, inside [-1, 1]", () => {
    expect(MOOD_OPTIONS.map((o) => o.label)).toEqual(["Heavy", "Low", "Okay", "Good", "Light"]);
    expect(MOOD_OPTIONS.map((o) => o.value)).toEqual([-1, -0.5, 0, 0.5, 1]);
  });
});

describe("moodLabel", () => {
  it("maps exact picks to their labels", () => {
    for (const option of MOOD_OPTIONS) {
      expect(moodLabel(option.value)).toBe(option.label);
    }
  });

  it("snaps arbitrary quick scores to the nearest pick (ties break toward the lower one)", () => {
    expect(moodLabel(-0.9)).toBe("Heavy");
    expect(moodLabel(-0.4)).toBe("Low");
    expect(moodLabel(0.1)).toBe("Okay");
    expect(moodLabel(0.4)).toBe("Good");
    expect(moodLabel(0.8)).toBe("Light");
    expect(moodLabel(0.75)).toBe("Good"); // tie: 0.5 and 1 are equidistant
    expect(moodLabel(-0.75)).toBe("Heavy"); // tie: −1 and −0.5 are equidistant
    expect(moodLabel(0.25)).toBe("Okay"); // tie: 0 and 0.5 are equidistant
  });
});

describe("localSentiment — now the real graded engine (2026-09-19)", () => {
  it("scores text exactly as the server's deterministic engine would", () => {
    // Values pinned to the Python engine's verdicts (the same walk is
    // vector-pinned in tests/brainVectors.test.ts): strongly positive,
    // strongly negative, and a genuinely mixed day score by MAGNITUDE now,
    // not by positive-vs-negative word counts.
    expect(localSentiment("good great happy")).toBe(1);
    expect(localSentiment("bad sad anxious stressed")).toBe(-1);
    expect(localSentiment("good then bad news")).toBeCloseTo(0.0, 2);
    // The graded engine scores "nothing" mildly negative (VADER lineage).
    expect(localSentiment("nothing emotional here")).toBeCloseTo(-0.111, 2);
  });

  it("is case-insensitive; word identity comes from the lexicon, not substrings", () => {
    expect(localSentiment("GOOD day")).toBeCloseTo(0.475, 3);
    // "goodness" and "gracious" are their own graded words — the score is
    // their valence, never a substring match on "good".
    expect(localSentiment("goodness gracious")).toBe(1);
  });
});
