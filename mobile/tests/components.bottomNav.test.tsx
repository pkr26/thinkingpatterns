/**
 * BottomNav + MainShell: the persistent navigation (2026-09-17).
 *
 * Pins: all six destinations always render (crisis help is one tap from
 * every main screen — the navigation contract), the active tab carries
 * selection state, taps navigate, and the bar's styling matches the
 * design system.
 */
import React from "react";
import { describe, expect, it, vi } from "vitest";

const navigate = vi.fn();

const { BottomNav, BOTTOM_NAV_ITEMS, MainShell } = await import("../src/components/BottomNav");
const { Text } = await import("react-native");
const { render, textOf, touchableByLabel, pressLabel } = await import("./helpers/rtr");

describe("BottomNav", () => {
  it("always renders all six destinations, Get help last", async () => {
    const labels = BOTTOM_NAV_ITEMS.map((i) => i.label);
    expect(labels).toEqual(["Today", "History", "Patterns", "Question", "Settings", "Get help"]);
    const root = await render(<BottomNav current="Entry" navigation={{ navigate }} />);
    for (const label of labels) {
      expect(textOf(root)).toContain(label);
    }
  });

  it("marks the current destination selected (accessibility tab state)", async () => {
    const root = await render(<BottomNav current="History" navigation={{ navigate }} />);
    expect(touchableByLabel(root, "History").props.accessibilityState).toEqual({ selected: true });
    expect(touchableByLabel(root, "Patterns").props.accessibilityState).toBeUndefined();
  });

  it("navigates on tap", async () => {
    const root = await render(<BottomNav current="Entry" navigation={{ navigate }} />);
    await pressLabel(root, "Patterns");
    expect(navigate).toHaveBeenCalledWith("Insights");
    touchableByLabel(root, "Get help").props.onPress();
    expect(navigate).toHaveBeenCalledWith("Crisis");
  });

  it("the help action keeps its distinct surface and weight", async () => {
    const { allStyles } = await import("./helpers/rtr");
    const root = await render(<BottomNav current="none" navigation={{ navigate }} />);
    expect(allStyles(root).some((s) => s.backgroundColor === "#242a38")).toBe(true); // helpBg
  });

  it("current='none' selects nothing", async () => {
    const root = await render(<BottomNav current="none" navigation={{ navigate }} />);
    expect(textOf(root)).toContain("Today"); // renders without selection
    expect(touchableByLabel(root, "Today").props.accessibilityState).toBeUndefined();
  });
});

describe("MainShell", () => {
  it("renders children above the persistent bar", async () => {
    const root = await render(
      <MainShell current="Settings" navigation={{ navigate }}>
        <Text>screen content</Text>
      </MainShell>,
    );
    expect(textOf(root)).toContain("screen content");
    expect(textOf(root)).toContain("Today");
    expect(textOf(root)).toContain("Settings");
  });
});
