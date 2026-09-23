/**
 * Frontend mutation campaign 2026-09-22 — round 2 survivor pins (mobile).
 *
 * The MoodCalendar's mood-color semantics (the safety-relevant surface: a
 * green/red/gray dot is the at-a-glance mood signal), month navigation, and
 * the VoiceOver labels. MeasuresScreen and the remaining screens stay
 * documented residuals (see the campaign REPORT).
 */
import { describe, expect, it } from "vitest";
import React from "react";

const { MoodCalendar } = await import("../src/components/MoodCalendar");
const { monthLabel } = await import("../src/historyFind");
const { render, textOf } = await import("./helpers/rtr");
const { darkTheme: theme } = await import("../src/theme");
const { act } = await import("react-test-renderer");
const pressA11y = async (root: Awaited<ReturnType<typeof render>>, label: string): Promise<void> => {
  const { TouchableOpacity } = await import("react-native");
  const target = root.root.findAllByType(TouchableOpacity).find((n) => n.props.accessibilityLabel === label);
  if (!target) throw new Error(`no touchable labeled ${label}`);
  await act(async () => { target.props.onPress(); });
};

const thisMonth = () => {
  const now = new Date();
  return { year: now.getFullYear(), month: now.getMonth() + 1 };
};
const iso = (year: number, month: number, day: number): string =>
  `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;

describe("mutation pins 2026-09-22 round 2: MoodCalendar", () => {
  it("the mood dot color is the mood's sign — up green, down red, flat or missing gray", async () => {
    const { year, month } = thisMonth();
    const journaled = new Set([iso(year, month, 1), iso(year, month, 2), iso(year, month, 3), iso(year, month, 4)]);
    const dayMoods: Record<string, number> = {
      [iso(year, month, 1)]: 0.5, // up
      [iso(year, month, 2)]: -0.5, // down
      [iso(year, month, 3)]: 0, // flat
      [iso(year, month, 4)]: Number.NaN, // corrupt -> gray, never green/red
    };
    const root = await render(<MoodCalendar dayMoods={dayMoods} journaledDays={journaled} selectedDay={null} onSelectDay={() => undefined} />);
    const dotColors = new Set([theme.colors.muted, theme.colors.sparkDown, theme.colors.success]);
    const inline = (n: { props: { style?: unknown } }): string | undefined => {
      const style = n.props.style;
      if (Array.isArray(style) && style.length === 2 && typeof style[1] === "object" && style[1] !== null) {
        const bg = (style[1] as { backgroundColor?: string }).backgroundColor;
        return typeof bg === "string" ? bg : undefined;
      }
      return undefined;
    };
    const dots = root.root.findAll((n) => inline(n) !== undefined && dotColors.has(inline(n)!));
    const colors = dots.map((n) => inline(n)!).sort();
    expect(colors).toEqual([theme.colors.muted, theme.colors.muted, theme.colors.sparkDown, theme.colors.success].sort());
  });

  it("an un-journaled day carries no dot at all", async () => {
    const { year, month } = thisMonth();
    const journaled = new Set([iso(year, month, 15)]);
    const root = await render(<MoodCalendar dayMoods={{}} journaledDays={journaled} selectedDay={null} onSelectDay={() => undefined} />);
    const isDot = (n: { props: { style?: unknown } }): boolean => {
      const style = n.props.style;
      if (!Array.isArray(style) || style.length !== 2 || typeof style[1] !== "object" || style[1] === null) return false;
      const bg = (style[1] as { backgroundColor?: unknown }).backgroundColor;
      return bg === theme.colors.muted || bg === theme.colors.success || bg === theme.colors.sparkDown;
    };
    expect(root.root.findAll(isDot)).toHaveLength(1);
  });

  it("the header names the view month and steps back and forward", async () => {
    const { year, month } = thisMonth();
    const root = await render(<MoodCalendar dayMoods={{}} journaledDays={new Set()} selectedDay={null} onSelectDay={() => undefined} />);
    expect(textOf(root)).toContain(monthLabel(year, month));
    await pressA11y(root, "Previous month");
    const prev = month === 1 ? monthLabel(year - 1, 12) : monthLabel(year, month - 1);
    expect(textOf(root)).toContain(prev);
    await pressA11y(root, "Next month");
    expect(textOf(root)).toContain(monthLabel(year, month));
  });

  it("the calendar cell grid carries the month's accessible label", async () => {
    const { year, month } = thisMonth();
    const root = await render(<MoodCalendar dayMoods={{}} journaledDays={new Set()} selectedDay={null} onSelectDay={() => undefined} />);
    const labeled = root.root.findAll((n) => typeof n.props.accessibilityLabel === "string" && n.props.accessibilityLabel.length > 0);
    expect(labeled.length).toBeGreaterThan(0);
    expect(labeled.some((n) => n.props.accessibilityLabel.includes(monthLabel(year, month)))).toBe(true);
  });
});
