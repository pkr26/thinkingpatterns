/**
 * JavaScript palette values for SVG charts and the mood calendar.
 *
 * tests/designTokens.test.ts pins these values to public/app.css in both
 * themes. Each mood fill carries a contrast-appropriate text color. Palette
 * subscriptions redraw charts when the resolved theme changes.
 */

import { useSyncExternalStore } from "react";

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

/* ------------------------------------------------------- palette reactivity
   JS-drawn charts read currentPalette() at render time; before this hook
   existed, an OS dark/light flip under "auto" left every SVG fill on the
   stale palette until the next view swap. theme.ts bumps the version on
   every applied change; views that draw with these values call
   usePaletteVersion() so React re-renders them in lockstep. */
const paletteListeners = new Set<() => void>();
let paletteVersion = 0;

export function subscribePalette(listener: () => void): () => void {
  paletteListeners.add(listener);
  return () => paletteListeners.delete(listener);
}

/** Called by theme.ts whenever <html data-theme> changes. */
export function notifyPaletteChanged(): void {
  paletteVersion += 1;
  for (const listener of paletteListeners) listener();
}

export function currentPaletteVersion(): number {
  return paletteVersion;
}

/** Re-render on theme change (see subscribePalette). Node-test safe:
 * the store is a plain counter, no DOM involved. */
export function usePaletteVersion(): number {
  return useSyncExternalStore(subscribePalette, currentPaletteVersion, currentPaletteVersion);
}

/** Currently-applied document theme — "light" until the DOM exists
 *  (tests run in node; the value only drives chart fills). */
export function currentPalette(): ThemeColors {
  if (typeof document === "undefined") return PALETTES.light;
  return document.documentElement.dataset.theme === "dark" ? PALETTES.dark : PALETTES.light;
}

/* --------------------------------------------------------------- mood fills
   The 5-step mood heatmap fill for a value in [-1, 1] (null = no data),
   and the PER-FILL day-number ink that keeps 12px calendar text at AA
   contrast on every fill, both themes (pinned in designTokens.test.ts —
   the mid-tone fills fail 4.5:1 with the old single --cal-text ink). */

/** Ink for day numbers / small text ON a mood fill, per theme. */
export const MOOD_INKS: { light: Record<string, string>; dark: Record<string, string> } = {
  light: { "2": "#23321f", "1": "#3c4a33", "0": "#4d453a", "-1": "#4f3128", "-2": "#47231c" },
  dark: { "2": "#0f150f", "1": "#eef2e9", "0": "#eef2e9", "-1": "#f2ece8", "-2": "#f2ece8" },
};

function moodKey(value: number): string {
  if (value > 0.3) return "2";
  if (value > 0.05) return "1";
  if (value > -0.05) return "0";
  if (value > -0.3) return "-1";
  return "-2";
}

export function moodFill(value: number | null): string {
  const palette = currentPalette();
  if (value === null) return palette.mood0;
  const key = moodKey(value);
  return key === "2" ? palette.mood2 : key === "1" ? palette.mood1 : key === "0" ? palette.mood0 : key === "-1" ? palette.moodMinus1 : palette.moodMinus2;
}

/** AA ink for text sitting directly on a moodFill() background. */
export function moodInk(value: number | null): string {
  const theme = typeof document !== "undefined" && document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  return MOOD_INKS[theme][value === null ? "0" : moodKey(value)]!;
}

/* ------------------------------------------------------------------ faces
   Ring/fill/label colors for the one-tap mood scale, PER THEME: in dark
   theme the strong tones must be light tints (the light-theme values sit
   around 2.2:1 on a dark card — the selected label was unreadable-grade).
   Pairs (strong on soft, strong on card) are WCAG-pinned in
   tests/designTokens.test.ts for both tables. */

export interface MoodFaceColors { face: string; faceSoft: string; faceStrong: string }

const LIGHT_FACES: MoodFaceColors[] = [
  { face: "#cd8f82", faceSoft: "#f7e5e0", faceStrong: "#9c443d" }, // Heavy
  { face: "#e0b3a4", faceSoft: "#f9ede7", faceStrong: "#8f3d36" }, // Low
  { face: "#c9c2b2", faceSoft: "#efebe1", faceStrong: "#5c5347" }, // Okay
  { face: "#a9cba4", faceSoft: "#e9f0e7", faceStrong: "#44604a" }, // Good
  { face: "#8fb98d", faceSoft: "#e3eee0", faceStrong: "#35704f" }, // Light
];

const DARK_FACES: MoodFaceColors[] = [
  { face: "#cd8f82", faceSoft: "#3a221d", faceStrong: "#f0c4bc" }, // Heavy
  { face: "#e0b3a4", faceSoft: "#38251f", faceStrong: "#f2d6cd" }, // Low
  { face: "#c9c2b2", faceSoft: "#2e2b25", faceStrong: "#ded8ca" }, // Okay
  { face: "#a9cba4", faceSoft: "#243023", faceStrong: "#c7e2c2" }, // Good
  { face: "#8fb98d", faceSoft: "#1f2e1f", faceStrong: "#b9e0b3" }, // Light
];

export const MOOD_FACES: { light: MoodFaceColors[]; dark: MoodFaceColors[] } = {
  light: LIGHT_FACES,
  dark: DARK_FACES,
};

/** Face colors for scale level 0..4 (0 = heaviest), resolved for the
 * CURRENT theme (light in the node test environment). */
export function moodFaceColors(level: number): MoodFaceColors {
  const theme = typeof document !== "undefined" && document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  return MOOD_FACES[theme][Math.max(0, Math.min(4, Math.round(level)))]!;
}
