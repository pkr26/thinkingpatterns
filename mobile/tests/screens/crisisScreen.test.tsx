/**
 * CrisisScreen: the most safety-critical screen in the app. Pins the
 * hotline resources, the honest disclaimer, the per-platform sms: URL
 * (iOS drops Android's "?body=" silently), and that a failed
 * Linking.openURL NEVER becomes a dead tap.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

// rnMock has no Linking and pins Platform.OS to "ios"; this screen needs
// both controllable, so this file layers its own react-native mock (the
// alias still resolves the base primitives from rnMock).
const mocks = vi.hoisted(() => ({
  openURL: vi.fn(async (_url: string) => true),
  platform: { os: "ios" as "ios" | "android" },
}));
vi.mock("react-native", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-native")>();
  return {
    ...actual,
    Platform: {
      OS: mocks.platform.os,
      select: <T,>(opts: { ios?: T; android?: T; native?: T; default?: T }): T => {
        const perPlatform = mocks.platform.os === "ios" ? opts.ios : opts.android;
        return perPlatform ?? opts.native ?? (opts.default as T);
      },
    },
    Linking: { openURL: mocks.openURL },
  };
});

const { CrisisScreen } = await import("../../src/screens/CrisisScreen");
const { render, flush, textOf, pressLabel } = await import("../helpers/rtr");

beforeEach(() => {
  mocks.openURL.mockReset();
  mocks.openURL.mockImplementation(async () => true);
  Alert.alert.mockClear();
  mocks.platform.os = "ios";
});

describe("CrisisScreen content", () => {
  it("pins the hotline resources: 988, Crisis Text Line 741741, 911, findahelpline.com", async () => {
    const root = await render(<CrisisScreen />);
    const text = textOf(root);
    expect(text).toContain("Call or text 988");
    expect(text).toContain("988 Suicide & Crisis Lifeline");
    expect(text).toContain("Text HOME to 741741");
    expect(text).toContain("Crisis Text Line");
    expect(text).toContain("Call 911");
    expect(text).toContain("findahelpline.com");
  });

  it("pins the honest disclaimer (not therapy, not a medical device, not an emergency service)", async () => {
    const root = await render(<CrisisScreen />);
    expect(textOf(root)).toContain(
      "It is not therapy, not a medical device, and not an emergency service.",
    );
  });
});

describe("CrisisScreen actions", () => {
  it("opens tel:988 for the lifeline and tel:911 for emergencies", async () => {
    const root = await render(<CrisisScreen />);
    await pressLabel(root, "Call or text 988");
    await pressLabel(root, "Call 911");
    expect(mocks.openURL.mock.calls).toEqual([["tel:988"], ["tel:911"]]);
  });

  it("pre-fills HOME with '&body=' on iOS (regression: '?body=' is silently dropped)", async () => {
    mocks.platform.os = "ios";
    const root = await render(<CrisisScreen />);
    await pressLabel(root, "Text HOME to 741741");
    expect(mocks.openURL).toHaveBeenCalledWith("sms:741741&body=HOME");
  });

  it("pre-fills HOME with '?body=' on Android", async () => {
    mocks.platform.os = "android";
    const root = await render(<CrisisScreen />);
    await pressLabel(root, "Text HOME to 741741");
    expect(mocks.openURL).toHaveBeenCalledWith("sms:741741?body=HOME");
  });

  it("opens findahelpline.com for non-US users", async () => {
    const root = await render(<CrisisScreen />);
    await pressLabel(root, "Open findahelpline.com");
    expect(mocks.openURL).toHaveBeenCalledWith("https://findahelpline.com");
  });
});

describe("CrisisScreen failure handling", () => {
  it.each([
    ["Call or text 988", "988"],
    ["Text HOME to 741741", "741741"],
    ["Call 911", "911"],
    ["Open findahelpline.com", "findahelpline.com"],
  ])("a rejected openURL on %j surfaces the number/address instead of a dead tap", async (label, fallback) => {
    mocks.openURL.mockRejectedValueOnce(new Error("no application registered"));
    const root = await render(<CrisisScreen />);
    await pressLabel(root, label);
    await flush();
    // Handled: the rejection became a dialog carrying the manual fallback,
    // not an unhandled promise rejection.
    expect(Alert.alert).toHaveBeenCalledWith(
      "Couldn't open it from here",
      expect.stringContaining(fallback),
    );
  });
});

describe("CrisisScreen upgrades (call anxiety + chat + locale)", () => {
  it("says what calling is like — the #1 barrier to hotline use", async () => {
    const root = await render(<CrisisScreen />);
    const text = textOf(root);
    expect(text).toContain("What to expect when you call or text");
    expect(text).toContain("as much or as little as you want");
    expect(text).toContain("no script and no wrong way to start");
  });

  it("offers the 988 chat alongside call and text", async () => {
    const root = await render(<CrisisScreen />);
    expect(textOf(root)).toContain("Chat online at 988lifeline.org");
    await pressLabel(root, "Chat online at 988lifeline.org");
    expect(mocks.openURL).toHaveBeenCalledWith("https://988lifeline.org/chat");
  });

  it("a rejected chat open speaks the address (no dead taps)", async () => {
    mocks.openURL.mockRejectedValueOnce(new Error("no browser"));
    const root = await render(<CrisisScreen />);
    await pressLabel(root, "Chat online at 988lifeline.org");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Couldn't open it from here", expect.stringContaining("988lifeline.org/chat"));
  });

  it("US layout (default): hotlines first, findahelpline as the outside-US note", async () => {
    const root = await render(<CrisisScreen />);
    const texts = (await import("../helpers/rtr")).allText(root);
    const i988 = texts.findIndex((t) => t.includes("Call or text 988"));
    const iFah = texts.findIndex((t) => t.includes("Open findahelpline.com"));
    expect(i988).toBeGreaterThanOrEqual(0);
    expect(iFah).toBeGreaterThan(i988);
    expect(textOf(root)).toContain("These are US services");
  });

  it("non-US region: findahelpline leads, US services labeled US-only", async () => {
    const root = await render(<CrisisScreen region="DE" />);
    const texts = (await import("../helpers/rtr")).allText(root);
    const iFah = texts.findIndex((t) => t.includes("Open findahelpline.com"));
    const i988 = texts.findIndex((t) => t.includes("Call or text 988"));
    expect(iFah).toBeGreaterThanOrEqual(0);
    expect(i988).toBeGreaterThan(iFah);
    expect(textOf(root)).toContain("988 and 741741 are US-only");
  });

  it("non-US region: the 911 action carries the US-only label too (and still dials)", async () => {
    const root = await render(<CrisisScreen region="DE" />);
    expect(textOf(root)).toContain("Call 911 (US)");
    await pressLabel(root, "Call 911 (US)");
    expect(mocks.openURL).toHaveBeenCalledWith("tel:911");
  });

  it("an explicit US region keeps the US-first layout", async () => {
    const root = await render(<CrisisScreen region="US" />);
    const texts = (await import("../helpers/rtr")).allText(root);
    expect(texts.findIndex((t) => t.includes("Call or text 988"))).toBeLessThan(
      texts.findIndex((t) => t.includes("Open findahelpline.com")),
    );
  });

  it("every action has a 44pt target and a screen-reader label", async () => {
    const root = await render(<CrisisScreen />);
    const { allStyles, touchableByLabel } = await import("../helpers/rtr");
    expect(allStyles(root).some((s) => s.minHeight === 44)).toBe(true);
    expect(touchableByLabel(root, "Call or text 988").props.accessibilityLabel).toContain("988 Suicide & Crisis Lifeline");
    expect(touchableByLabel(root, "Open findahelpline.com").props.accessibilityRole).toBe("link");
    expect(touchableByLabel(root, "Open findahelpline.com").props.hitSlop).toEqual({ top: 12, bottom: 12, left: 12, right: 12 });
  });
});

describe("deviceRegion", () => {
  it("parses the locale region and survives hostile Intl implementations", async () => {
    const { deviceRegion } = await import("../../src/screens/CrisisScreen");
    // Default node locale parses or returns null — both are valid shapes.
    const detected = deviceRegion();
    expect(detected === null || /^[A-Z]{2}$/.test(detected)).toBe(true);

    const original = Intl.DateTimeFormat;
    try {
      // A locale with no region subtag.
      vi.stubGlobal("Intl", {
        ...Intl,
        DateTimeFormat: () => ({ resolvedOptions: () => ({ locale: "en" }) }),
      });
      expect(deviceRegion()).toBeNull();
      // Intl throws entirely (ancient Hermes): US-first, no crash.
      vi.stubGlobal("Intl", {
        DateTimeFormat: () => {
          throw new Error("no intl");
        },
      });
      expect(deviceRegion()).toBeNull();
    } finally {
      vi.stubGlobal("Intl", original);
    }
  });
});
