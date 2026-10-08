import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { act } from "react-test-renderer";
import { Platform } from "react-native";
import { render, pressLabel, flush } from "./helpers/rtr";

// An empty Native View still occupies a layout cell. Keep an actual host
// node so React's committed placement/removal can be observed as Native
// grid geometry, including otherwise childless calendar placeholders.
vi.mock("react-native", async original => {
  const native = await original<typeof import("react-native")>();
  const View = (props: any) => React.createElement("NativeView", props, props.children);
  View.displayName = "View";
  return { ...native, View };
});

// Platform is a device property and is fixed before the style module loads.
Object.defineProperty(Platform, "OS", { value: "android", configurable: true });
const { BottomNav } = await import("../src/components/BottomNav");
const { MoodCalendar } = await import("../src/components/MoodCalendar");
afterEach(() => { vi.useRealTimers(); });

it("Android retains the bottom navigation's space below its touch targets", async () => {
  const root = await render(<BottomNav current="Entry" navigation={{ navigate() {} }} />);
  const bar = root.root.findAll(n => n.props.accessibilityRole === "tablist")[0]!;
  const style = Object.assign({}, ...bar.props.style);
  expect(style.paddingBottom).toBe(10);
});

it("a shell without an attached navigator remains usable when its tab is pressed", async () => {
  const root = await render(<BottomNav current="none" />);
  await pressLabel(root, "Today");
  expect(root.root.findAll(n => n.props.accessibilityRole === "tab")).toHaveLength(6);
});

it("month changes preserve every calendar day and its weekday alignment", async () => {
  vi.useFakeTimers({ toFake: ["Date"], now: new Date(2026, 0, 15, 12) });
  const root = await render(<MoodCalendar dayMoods={{}} journaledDays={new Set()} selectedDay={null} onSelectDay={() => {}} />);
  const months = [
    [31,34], [28,34], [31,37], [30,32], [31,35], [30,30],
    [31,33], [31,36], [30,31], [31,34], [30,36], [31,32],
  ];
  const check = (days: number, cells: number) => {
    const grid = (node: any): any => Array.isArray(node)
      ? node.map(grid).find(Boolean)
      : node?.props?.style?.flexWrap === "wrap"
        ? node : node?.children?.map(grid).find(Boolean);
    expect(grid(root.toJSON()).children).toHaveLength(cells + 7);
    const dates = root.root.findAll(n => typeof n.props.accessibilityLabel === "string" && n.props.accessibilityLabel.endsWith(", no entry"));
    expect(dates).toHaveLength(days);
    expect(new Set(dates.map(n => n.props.accessibilityLabel)).size).toBe(days);
  };
  const turn = async (label: string) => {
    const button = root.root.findAll(n => n.props.accessibilityLabel === label && typeof n.props.onPress === "function")[0]!;
    await act(async () => { button.props.onPress(); });
    await flush(0);
  };
  for (let i = 0; i < months.length; i++) {
    check(...months[i] as [number, number]);
    if (i < 11) await turn("Next month");
  }
  for (let i = 10; i >= 0; i--) {
    await turn("Previous month");
    check(...months[i] as [number, number]);
  }
});
