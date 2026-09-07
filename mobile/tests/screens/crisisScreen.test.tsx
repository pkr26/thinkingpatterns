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
