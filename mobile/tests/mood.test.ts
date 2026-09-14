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

describe("localSentiment (the Entry screen's long-standing estimate)", () => {
  it("scores positive, negative, mixed and neutral text exactly as before", () => {
    expect(localSentiment("good great happy")).toBe(1);
    expect(localSentiment("bad sad anxious stressed")).toBe(-1);
    expect(localSentiment("good then bad news")).toBe(0);
    expect(localSentiment("nothing emotional here")).toBe(0);
  });

  it("is case-insensitive and respects word boundaries", () => {
    expect(localSentiment("GOOD day")).toBe(1);
    expect(localSentiment("goodness gracious")).toBe(0);
  });
});
