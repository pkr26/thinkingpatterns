/**
 * The JS mirror of the CSS token layer (public/app.css). SVG charts and
 * the mood heatmap need CONCRETE color values at draw time (SVG fills
 * cannot reference a CSS class cleanly for dynamically generated marks),
 * so the palette lives here too and tests/designTokens.test.ts pins the
 * two sources together, token by token, light and dark.
 *
 * Redesign 2026-09-26 — warm & calming: sage primary, cream canvas,
 * lavender secondary. Chart/heatmap values below must stay in lockstep
 * with the custom properties in app.css.
 */

export interface ThemeColors {
  readonly primary: string;
  readonly primarySoft: string;
  readonly mood2: string;
  readonly mood1: string;
  readonly mood0: string;
  readonly moodMinus1: string;
  readonly moodMinus2: string;
  readonly border: string;
  readonly muted: string;
  readonly danger: string;
}

/** The two palettes, keyed exactly like the CSS blocks they mirror. */
export const PALETTES: { light: ThemeColors; dark: ThemeColors } = {
  light: {
    primary: "#5a7d5e",
    primarySoft: "#e9f0e7",
    mood2: "#8fb98d",
    mood1: "#c8ddc0",
    mood0: "#ebe5d9",
    moodMinus1: "#e6c6b8",
    moodMinus2: "#cd8f82",
    border: "#e7e0d4",
    muted: "#6f675c",
    danger: "#b3554e",
  },
  dark: {
    primary: "#a9cba4",
    primarySoft: "#31402f",
    mood2: "#6d9873",
    mood1: "#48604b",
    mood0: "#38342c",
    moodMinus1: "#5c4036",
    moodMinus2: "#74463a",
    border: "#3a352c",
    muted: "#a29a8c",
    danger: "#d98a80",
  },
};

/** Currently-applied document theme — "light" until the DOM exists
 *  (tests run in node; the value only drives chart fills). */
export function currentPalette(): ThemeColors {
  if (typeof document === "undefined") return PALETTES.light;
  return document.documentElement.dataset.theme === "dark" ? PALETTES.dark : PALETTES.light;
}

/** The 5-step mood heatmap fill for a value in [-1, 1] (null = no data). */
export function moodFill(value: number | null): string {
  const palette = currentPalette();
  if (value === null) return palette.mood0;
  if (value > 0.3) return palette.mood2;
  if (value > 0.05) return palette.mood1;
  if (value > -0.05) return palette.mood0;
  if (value > -0.3) return palette.moodMinus1;
  return palette.moodMinus2;
}

/** Face ring + label colors for the one-tap mood scale (per pick level). */
export const MOOD_FACE_COLORS: { face: string; faceSoft: string; faceStrong: string }[] = [
  { face: "#cd8f82", faceSoft: "#f7e5e0", faceStrong: "#9c443d" }, // Heavy
  { face: "#e0b3a4", faceSoft: "#f9ede7", faceStrong: "#9c443d" }, // Low
  { face: "#c9c2b2", faceSoft: "#efebe1", faceStrong: "#6f675c" }, // Okay
  { face: "#a9cba4", faceSoft: "#e9f0e7", faceStrong: "#44604a" }, // Good
  { face: "#8fb98d", faceSoft: "#e3eee0", faceStrong: "#35704f" }, // Light
];
