/** Design-token integrity (redesign 2026-09-26): the JS palette in
 *  src/tokens.ts must mirror the CSS custom properties in public/app.css
 *  for both themes — SVG charts draw with the JS values, the chrome with
 *  the CSS ones, and drift between them would quietly split the visual
 *  language. This test also pins the palette to WCAG-grade contrast for
 *  the text roles that matter (body/muted on bg and surface). */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PALETTES } from "../src/tokens";

const css = readFileSync(join(__dirname, "../public/app.css"), "utf8");

function tokenBlock(marker: string): string {
  const start = css.indexOf(marker);
  expect(start, `marker ${marker} found in app.css`).toBeGreaterThan(-1);
  const end = css.indexOf("}", start);
  return css.slice(start, end);
}

function cssToken(block: string, name: string): string {
  const match = block.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  expect(match, `--${name} present in block`).toBeDefined();
  return match![1]!.toLowerCase();
}

/** WCAG relative luminance + contrast ratio. */
function luminance(hex: string): number {
  const channel = (value: string): number => {
    const c = Number.parseInt(value, 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const r = channel(hex.slice(1, 3));
  const g = channel(hex.slice(3, 5));
  const b = channel(hex.slice(5, 7));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

const PAIRED_TOKENS: [jsKey: keyof typeof PALETTES.light, cssName: string][] = [
  ["primary", "primary"],
  ["primarySoft", "primary-soft"],
  ["mood2", "mood-2"],
  ["mood1", "mood-1"],
  ["mood0", "mood-0"],
  ["moodMinus1", "mood--1"],
  ["moodMinus2", "mood--2"],
  ["border", "border"],
  ["muted", "muted"],
  ["danger", "danger"],
];

describe("design tokens: JS mirrors CSS", () => {
  it("light palette matches the :root block", () => {
    const block = tokenBlock(":root {");
    for (const [jsKey, cssName] of PAIRED_TOKENS) {
      expect(PALETTES.light[jsKey]).toBe(cssToken(block, cssName));
    }
  });

  it("dark palette matches the [data-theme=\"dark\"] block", () => {
    const block = tokenBlock('[data-theme="dark"] {');
    for (const [jsKey, cssName] of PAIRED_TOKENS) {
      expect(PALETTES.dark[jsKey]).toBe(cssToken(block, cssName));
    }
  });
});

describe("design tokens: WCAG contrast floors", () => {
  const cases: { theme: "light" | "dark"; fg: string; bg: string; min: number; label: string }[] = [
    { theme: "light", fg: "#2a2520", bg: "#f8f5ef", min: 7, label: "text on bg" },
    { theme: "light", fg: "#4d463d", bg: "#fffefb", min: 7, label: "body on card" },
    { theme: "light", fg: "#6f675c", bg: "#fffefb", min: 4.5, label: "muted on card" },
    { theme: "light", fg: "#6f675c", bg: "#f4f0e7", min: 4.5, label: "muted on deep card" },
    { theme: "light", fg: "#ffffff", bg: "#5a7d5e", min: 4.5, label: "primary button label" },
    { theme: "light", fg: "#ffffff", bg: "#b3554e", min: 4.5, label: "danger button label" },
    { theme: "light", fg: "#9c443d", bg: "#faecea", min: 4.5, label: "danger text on danger soft" },
    { theme: "light", fg: "#7d5717", bg: "#f9f1e1", min: 4.5, label: "warn text on warn soft" },
    { theme: "dark", fg: "#ede8df", bg: "#211e1a", min: 7, label: "text on bg (dark)" },
    { theme: "dark", fg: "#cfc7ba", bg: "#2a2620", min: 7, label: "body on card (dark)" },
    { theme: "dark", fg: "#a29a8c", bg: "#2a2620", min: 4.5, label: "muted on card (dark)" },
    { theme: "dark", fg: "#1e1c17", bg: "#a9cba4", min: 4.5, label: "primary button label (dark)" },
    { theme: "dark", fg: "#2a1210", bg: "#d98a80", min: 4.5, label: "danger button label (dark)" },
  ];

  it.each(cases)("$theme: $label ≥ $min", ({ fg, bg, min }) => {
    expect(contrast(fg, bg)).toBeGreaterThanOrEqual(min);
  });
});
