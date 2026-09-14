/**
 * The theme is a product contract: the palettes themselves, the scales, and
 * — critically — the WCAG AA contrast commitments from the audit (the old
 * #5c6370 fine print measured 3.13:1; the old #4f7cff button measured
 * 3.71:1). The ratios below are computed from first principles (sRGB
 * relative luminance), not transcribed, so a palette edit that breaks AA
 * fails here loudly.
 */
import { describe, expect, it, vi } from "vitest";
import React from "react";
import { useColorScheme } from "react-native";

const { darkTheme, lightTheme, useTheme } = await import("../src/theme");
const { render } = await import("./helpers/rtr");

/** WCAG relative luminance of a #rrggbb color. */
function luminance(hex: string): number {
  const channel = (i: number): number => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(fg: string, bg: string): number {
  const a = luminance(fg);
  const b = luminance(bg);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/** Render the hook through a probe component and capture its result. */
async function probeTheme(): Promise<typeof darkTheme> {
  let captured: typeof darkTheme | null = null;
  function Probe(): null {
    captured = useTheme();
    return null;
  }
  await render(<Probe />);
  if (!captured) throw new Error("probe did not render");
  return captured;
}

describe("theme scales", () => {
  it("dark and light share one spacing/radius/type contract", () => {
    expect(darkTheme.spacing).toEqual(lightTheme.spacing);
    expect(darkTheme.radius).toEqual(lightTheme.radius);
    expect(darkTheme.type).toEqual(lightTheme.type);
    expect(darkTheme.minTouch).toBe(44);
    expect(darkTheme.spacing).toEqual({ xs: 4, sm: 8, md: 12, lg: 16, xl: 20, xxl: 24, xxxl: 32 });
    // The two palettes differ in every color except onPrimary (white labels
    // sit on fills that were each darkened until white passed AA).
    for (const key of Object.keys(darkTheme.colors) as (keyof typeof darkTheme.colors)[]) {
      if (key === "onPrimary") continue;
      expect(lightTheme.colors[key]).not.toBe(darkTheme.colors[key]);
    }
  });
});

describe("theme contrast (WCAG AA, computed)", () => {
  it("dark: muted fine print reaches 4.5:1 on both backgrounds", () => {
    expect(contrast(darkTheme.colors.muted, darkTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.muted, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.muted, darkTheme.colors.cardDeep)).toBeGreaterThanOrEqual(4.5);
    // The audit's failing pair is the regression pin: 3.13:1 then, AA now.
    expect(contrast("#5c6370", "#0f1115")).toBeLessThan(4.5);
    expect(contrast(darkTheme.colors.muted, darkTheme.colors.bg)).toBeCloseTo(6.0, 0);
  });

  it("dark: button labels, body text, links and badges all pass on their surfaces", () => {
    expect(contrast(darkTheme.colors.onPrimary, darkTheme.colors.primary)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.onPrimary, darkTheme.colors.danger)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.body, darkTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.body, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.text, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.accent, darkTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.accent, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.accent, darkTheme.colors.helpBg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.error, darkTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.success, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(darkTheme.colors.text, darkTheme.colors.helpBg)).toBeGreaterThanOrEqual(4.5);
    // The old button pair is the second regression pin: 3.71:1 then.
    expect(contrast("#ffffff", "#4f7cff")).toBeLessThan(4.5);
  });

  it("light: the same promises hold on the light surfaces", () => {
    expect(contrast(lightTheme.colors.muted, lightTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.muted, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.muted, lightTheme.colors.cardDeep)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.onPrimary, lightTheme.colors.primary)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.onPrimary, lightTheme.colors.danger)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.body, lightTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.body, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.text, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.accent, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.accent, lightTheme.colors.helpBg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.error, lightTheme.colors.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.success, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.text, lightTheme.colors.helpBg)).toBeGreaterThanOrEqual(4.5);
  });

  it("placeholders meet the same 4.5:1 duty as muted text", () => {
    expect(contrast(darkTheme.colors.placeholder, darkTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(lightTheme.colors.placeholder, lightTheme.colors.card)).toBeGreaterThanOrEqual(4.5);
  });
});

describe("useTheme", () => {
  it("defaults to the dark palette and follows an explicit light scheme", async () => {
    vi.mocked(useColorScheme).mockReturnValue("dark");
    expect(await probeTheme()).toBe(darkTheme);

    vi.mocked(useColorScheme).mockReturnValue("light");
    expect(await probeTheme()).toBe(lightTheme);

    // An unrecognized value (or null) must never produce a broken theme:
    // calm default wins.
    vi.mocked(useColorScheme).mockReturnValue(null as never);
    expect(await probeTheme()).toBe(darkTheme);

    vi.mocked(useColorScheme).mockReturnValue("dark");
  });
});
