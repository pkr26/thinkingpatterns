/** Design-token integrity (redesign 2026-09-26, hardened 2026-09-26 ii):
 *  the JS palette in src/tokens.ts must mirror the CSS custom properties
 *  in public/app.css for both themes — SVG charts draw with the JS
 *  values, the chrome with the CSS ones, and drift between them would
 *  quietly split the visual language.
 *
 *  Hardening: every WCAG case now DERIVES its colors from the parsed CSS
 *  (the first version hardcoded hex copies, so a palette could drift to
 *  something unreadable while the test kept blessing the old values),
 *  and the two tables the old test ignored are pinned too — the
 *  per-fill calendar inks (MOOD_INKS) and the theme-aware check-in face
 *  colors (MOOD_FACES), both of which had real AA failures before. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MOOD_FACES, MOOD_INKS, PALETTES } from "../src/tokens";

const css = readFileSync(join(__dirname, "../public/app.css"), "utf8");

function tokenBlock(marker: string): string {
  const start = css.indexOf(marker);
  expect(start, `marker ${marker} found in app.css`).toBeGreaterThan(-1);
  const end = css.indexOf("}", start);
  return css.slice(start, end);
}

const LIGHT_BLOCK = tokenBlock(":root {");
const DARK_BLOCK = tokenBlock('[data-theme="dark"] {');

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
    for (const [jsKey, cssName] of PAIRED_TOKENS) {
      expect(PALETTES.light[jsKey]).toBe(cssToken(LIGHT_BLOCK, cssName));
    }
  });

  it("dark palette matches the [data-theme=\"dark\"] block", () => {
    for (const [jsKey, cssName] of PAIRED_TOKENS) {
      expect(PALETTES.dark[jsKey]).toBe(cssToken(DARK_BLOCK, cssName));
    }
  });
});

/** Every contrast case is a PAIR OF CSS TOKEN NAMES resolved from the
 *  live stylesheet — editing app.css edits the test's inputs. */
function cssCase(theme: "light" | "dark", label: string, fgToken: string, bgToken: string, min: number) {
  const block = theme === "light" ? LIGHT_BLOCK : DARK_BLOCK;
  return { theme, label, fg: cssToken(block, fgToken), bg: cssToken(block, bgToken), min };
}

describe("design tokens: WCAG contrast floors (derived from app.css)", () => {
  const cases = [
    cssCase("light", "text on bg", "text", "bg", 7),
    cssCase("light", "body on card", "body", "surface", 7),
    cssCase("light", "muted on card", "muted", "surface", 4.5),
    cssCase("light", "muted on deep card", "muted", "surface-deep", 4.5),
    cssCase("light", "cal-day text on empty tile", "cal-text", "surface-deep", 4.5),
    cssCase("light", "primary button label", "primary-contrast", "primary", 4.5),
    cssCase("light", "danger button label", "danger-contrast", "danger", 4.5),
    cssCase("light", "danger text on danger soft", "danger-strong", "danger-soft", 4.5),
    cssCase("light", "warn text on warn soft", "warn-strong", "warn-soft", 4.5),
    cssCase("light", "help button label (Get help)", "warn-strong", "warn-soft", 4.5),
    cssCase("light", "ghost button text on surface", "primary-strong", "surface", 4.5),
    cssCase("dark", "text on bg (dark)", "text", "bg", 7),
    cssCase("dark", "body on card (dark)", "body", "surface", 7),
    cssCase("dark", "muted on card (dark)", "muted", "surface", 4.5),
    cssCase("dark", "cal-day text on empty tile (dark)", "cal-text", "surface-deep", 4.5),
    cssCase("dark", "primary button label (dark)", "primary-contrast", "primary", 4.5),
    cssCase("dark", "danger button label (dark)", "danger-contrast", "danger", 4.5),
    cssCase("dark", "warn text on warn soft (dark)", "warn-strong", "warn-soft", 4.5),
    cssCase("dark", "help button label (dark)", "warn-strong", "warn-soft", 4.5),
  ];

  it.each(cases)("$theme: $label ≥ $min", ({ fg, bg, min }) => {
    expect(contrast(fg, bg)).toBeGreaterThanOrEqual(min);
  });

  // Hover states must not dip below the floor either (the portal's hover
  // went 3.22 → 2.64 in the same redesign; this pins web's direction).
  it("light: primary-hover keeps the button label at AA", () => {
    expect(contrast(cssToken(LIGHT_BLOCK, "primary-contrast"), cssToken(LIGHT_BLOCK, "primary-hover"))).toBeGreaterThanOrEqual(4.5);
  });
  it("light: danger-hover keeps the button label at AA", () => {
    expect(contrast(cssToken(LIGHT_BLOCK, "danger-contrast"), cssToken(LIGHT_BLOCK, "danger-hover"))).toBeGreaterThanOrEqual(4.5);
  });
});

describe("design tokens: calendar ink on every mood fill (AA)", () => {
  // Day numbers are 12px/700 — small text, 4.5:1 required. The mid-tone
  // fills fail with EITHER all-dark or all-light ink, which is exactly
  // the bug this table fixes (dark ink on the light theme's saturated
  // greens, light ink on the dark theme's deep tiles, one dark ink on
  // dark's mid-green).
  const FILLS: { key: keyof typeof MOOD_INKS.light & string; paletteKey: keyof typeof PALETTES.light }[] = [
    { key: "2", paletteKey: "mood2" },
    { key: "1", paletteKey: "mood1" },
    { key: "0", paletteKey: "mood0" },
    { key: "-1", paletteKey: "moodMinus1" },
    { key: "-2", paletteKey: "moodMinus2" },
  ];
  for (const theme of ["light", "dark"] as const) {
    it.each(FILLS)(`${theme}: ink on ${theme === "light" ? "--mood-KEY" : "dark fill"} ${"$key"} ≥ 4.5`, (fill) => {
      expect(contrast(MOOD_INKS[theme][fill.key]!, PALETTES[theme][fill.paletteKey])).toBeGreaterThanOrEqual(4.5);
    });
  }
});

describe("design tokens: check-in face colors (AA, both themes)", () => {
  // The selected face draws its icon+label in faceStrong over faceSoft,
  // and its label over the CARD surface; both pairs must hold in both
  // themes (the pre-hardening single table failed on dark cards).
  for (const theme of ["light", "dark"] as const) {
    const surface = cssToken(theme === "light" ? LIGHT_BLOCK : DARK_BLOCK, "surface");
    it.each(MOOD_FACES[theme])(
      `${theme}: faceStrong on faceSoft ≥ 4.5 (${theme} level)`,
      (face) => {
        expect(contrast(face.faceStrong, face.faceSoft)).toBeGreaterThanOrEqual(4.5);
      },
    );
    it.each(MOOD_FACES[theme])(
      `${theme}: faceStrong on card ≥ 4.5 (selected label)`,
      (face) => {
        expect(contrast(face.faceStrong, surface)).toBeGreaterThanOrEqual(4.5);
      },
    );
  }
});
