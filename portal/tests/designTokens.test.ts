/** Design-token integrity (2026-09-26 audit, P3): the JS palette in
 *  src/ui.tsx must mirror the CSS custom properties in public/portal.css
 *  — the views draw inline-styled accents (charts, code text) with the JS
 *  values while the chrome renders through the CSS classes, and drift
 *  between the two quietly splits the visual language. Modeled on the
 *  patient web app's web/tests/designTokens.test.ts: plain file reads +
 *  regex parsing, no DOM. This suite also pins the WCAG-grade contrast
 *  the audit demanded — every ratio is computed FROM the parsed CSS
 *  values, never from hardcoded copies, so a palette regression fails
 *  here even if the mirror table is updated to match it. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { theme } from "../src/ui";

const css = readFileSync(join(__dirname, "../public/portal.css"), "utf8");

/** The :root block (the portal is single-theme; no dark/light split). */
function rootBlock(): string {
  const start = css.indexOf(":root {");
  expect(start, ":root block found in portal.css").toBeGreaterThan(-1);
  const end = css.indexOf("}", start);
  return css.slice(start, end);
}

function cssToken(name: string): string {
  const match = rootBlock().match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  expect(match, `--${name} present in :root`).not.toBeNull();
  return match![1]!.toLowerCase();
}

/** WCAG 2.x relative luminance + contrast ratio — the same formula the
 *  palette comment in portal.css documents. */
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
function contrast(fg: string, bg: string): number {
  const lf = luminance(fg);
  const lb = luminance(bg);
  return (Math.max(lf, lb) + 0.05) / (Math.min(lf, lb) + 0.05);
}

/** theme keys → the CSS custom property each one mirrors. The tone keys
 *  (warn/ok/danger) mirror the *-strong variants — the colors their
 *  Notes and banners actually render text with (.note--warn colors with
 *  --warn-strong, etc.); accentBright mirrors --primary-strong, the
 *  accent that is safe as TEXT on dark surfaces. */
const PAIRED_TOKENS: [jsKey: keyof typeof theme, cssName: string][] = [
  ["bg", "bg"],
  ["card", "surface"],
  ["cardDeep", "surface-deep"],
  ["text", "text"],
  ["body", "body"],
  ["muted", "muted"],
  ["accent", "primary"],
  ["accentBright", "primary-strong"],
  ["danger", "danger-strong"],
  ["ok", "ok-strong"],
  ["warn", "warn-strong"],
  ["border", "border"],
];

describe("design tokens: JS mirrors CSS", () => {
  it("every mirrored theme key matches the :root custom property", () => {
    for (const [jsKey, cssName] of PAIRED_TOKENS) {
      expect(theme[jsKey], `theme.${jsKey} mirrors --${cssName}`).toBe(cssToken(cssName));
    }
  });

  it("theme.radius mirrors --radius (number vs px string)", () => {
    expect(theme.radius).toBe(Number.parseInt(cssTokenPx("radius"), 10));
  });

  it("the token set this suite depends on exists (guards against silent renames)", () => {
    // 2026-09-26 audit P3: --body (renamed from --body-c to match web)
    // and --info-accent (the de-hardcoded info accent) are load-bearing.
    for (const name of [
      "body", "info-accent", "primary", "primary-hover", "primary-strong",
      "primary-focus", "danger", "danger-hover", "danger-strong",
      "warn-strong", "warn-soft", "ok-strong", "surface", "surface-deep",
    ]) {
      expect(cssToken(name), `--${name} defined`).toMatch(/^#[0-9a-f]{6}$/);
    }
    expect(css).not.toContain("--body-c");
  });
});

function cssTokenPx(name: string): string {
  const match = rootBlock().match(new RegExp(`--${name}:\\s*([0-9]+)px`));
  expect(match, `--${name} present in :root`).not.toBeNull();
  return match![1]!;
}

describe("design tokens: WCAG contrast floors (computed from the parsed CSS)", () => {
  const WHITE = "#ffffff"; // the .btn label color

  const cases: { fg: string; bg: string; min: number; label: string }[] = [
    // The four button pairs the audit failed (P2): white labels on the
    // primary/danger rest AND hover states.
    { fg: WHITE, bg: cssToken("primary"), min: 4.5, label: "btn label on --primary" },
    { fg: WHITE, bg: cssToken("primary-hover"), min: 4.5, label: "btn label on --primary-hover" },
    { fg: WHITE, bg: cssToken("danger"), min: 4.5, label: "danger btn label on --danger" },
    { fg: WHITE, bg: cssToken("danger-hover"), min: 4.5, label: "danger btn label on --danger-hover" },
    // Body/muted text roles.
    { fg: cssToken("body"), bg: cssToken("bg"), min: 4.5, label: "body text on --bg" },
    { fg: cssToken("muted"), bg: cssToken("surface"), min: 4.5, label: "muted text on card (--surface)" },
    // Banner/tone text on their soft backgrounds.
    { fg: cssToken("warn-strong"), bg: cssToken("warn-soft"), min: 4.5, label: "warn text on --warn-soft" },
    { fg: cssToken("danger-strong"), bg: cssToken("danger-soft"), min: 4.5, label: "danger banner text on --danger-soft" },
    { fg: cssToken("info-accent"), bg: cssToken("primary-soft"), min: 4.5, label: "info banner text on --primary-soft" },
    // 2026-09-28 palette wave: the new gold success tone as text on every
    // dark surface it renders on (notes, pw-meter label), plus the new
    // focus violet against the darkest surfaces (WCAG 1.4.11 non-text
    // floor for the focus indicator, applied with margin).
    { fg: cssToken("ok-strong"), bg: cssToken("bg"), min: 4.5, label: "ok text on --bg" },
    { fg: cssToken("ok-strong"), bg: cssToken("surface"), min: 4.5, label: "ok text on card (--surface)" },
    { fg: cssToken("primary-focus"), bg: cssToken("surface-deep"), min: 3, label: "focus ring on --surface-deep (non-text)" },
    { fg: cssToken("primary-focus"), bg: cssToken("surface"), min: 3, label: "focus ring on --surface (non-text)" },
    // Ghost-button label and the select chevron.
    { fg: cssToken("primary-strong"), bg: cssToken("bg"), min: 4.5, label: "ghost btn label on --bg" },
    { fg: cssToken("primary-strong"), bg: cssToken("primary-soft"), min: 4.5, label: "ghost btn hover label on --primary-soft" },
    { fg: cssToken("muted"), bg: cssToken("surface-deep"), min: 4.5, label: "select chevron on --surface-deep" },
  ];

  it.each(cases)("$label ≥ $min", ({ fg, bg, min }) => {
    expect(contrast(fg, bg)).toBeGreaterThanOrEqual(min);
  });

  it("hover states DARKEN (contrast increases on hover), mirroring the web app's pattern", () => {
    expect(contrast(WHITE, cssToken("primary-hover"))).toBeGreaterThan(contrast(WHITE, cssToken("primary")));
    expect(contrast(WHITE, cssToken("danger-hover"))).toBeGreaterThan(contrast(WHITE, cssToken("danger")));
  });
});
