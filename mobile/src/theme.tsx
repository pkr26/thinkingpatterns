/**
 * The Fathom design system: one palette (dark is the default, light
 * follows the OS), plus the spacing / typography / radius scales every
 * screen is built from. No screen may hardcode a hex literal — if a color
 * is needed, it belongs here with its contrast checked.
 *
 * 2026-10-02 palette wave: both variants are the patient web app's tokens
 * ported verbatim (web/public/app.css) — warm charcoal + sage dark, warm
 * paper + sage light — so the phone, the web client, and the therapist
 * portal speak one visual language.
 *
 * Contrast commitments (WCAG AA, 4.5:1 for normal text; computed with the
 * sRGB relative-luminance formula and pinned by tests/theme.test.tsx —
 * every ratio below was recomputed for this palette):
 *
 *  dark.muted   #a29a8c — 5.96:1 on bg #211e1a, 5.40:1 on card #2a2620,
 *               5.83:1 on cardDeep #232019
 *  dark.onPrimary #1e1c17 on primary #a9cba4 — 9.54:1; on danger
 *               #d98a80 — 6.40:1 (the dark theme INVERTS: light sage and
 *               coral fills carry a near-black label, the web dark
 *               pattern; the light theme keeps white on dark fills)
 *  dark.accent  #b6a9e3 — 7.72:1 on bg, 7.00:1 on card, 7.56:1 on helpBg
 *               #1c1915 (the web app's lavender quiet-cue family)
 *  dark.body    #cfc7ba — 9.90:1 on bg, 8.97:1 on card
 *  dark.error   #eba49b — 8.15:1 on bg
 *  light.muted  #6f675c — 5.52:1 on card, 5.12:1 on bg #f8f5ef
 *  light.onPrimary #ffffff on primary #5a7d5e — 4.64:1; on danger
 *               #b3554e — 4.85:1
 *  light.accent #5d4f9e — 6.77:1 on card, 6.27:1 on bg, 6.00:1 on
 *               helpBg #f3eee4 (the web light theme's accent-STRONG —
 *               the text-grade form; the base #7465b7 misses AA on the
 *               help surface at 4.31:1)
 *
 * Tone: the palette stays flat and calm on purpose — no gradients, no
 * celebration colors; the one loud accent is reserved for crisis help.
 */
import React, { createContext, useContext, useEffect, useState } from "react";
import { useColorScheme } from "react-native";
import { useLocale } from "./strings";
import AsyncStorage from "@react-native-async-storage/async-storage";

/** User theme preference (2026-09-17): "system" follows the OS, "dark" and
 *  "light" pin the palette. Persisted per device (non-sensitive), loaded
 *  once by the provider in App.tsx. */
export type ThemeMode = "system" | "dark" | "light";

const THEME_STORAGE_KEY = "@mindpattern/theme.mode";

const ThemeModeContext = createContext<ThemeMode>("system");

export function themeStorageKey(): string {
  return THEME_STORAGE_KEY;
}

export interface ThemeColors {
  /** App background. */
  bg: string;
  /** Raised surfaces: cards, inputs, nav buttons. */
  card: string;
  /** Recessed panels inside cards (evidence panel, re-auth card). */
  cardDeep: string;
  /** Hairlines and dividers. */
  border: string;
  /** Primary text. */
  text: string;
  /** Body / secondary text. */
  body: string;
  /** Meta text and footnotes — safety fine print lives here, so this is
   *  contractually ≥ 4.5:1 on BOTH bg and card (see header). */
  muted: string;
  /** Input placeholders (same contrast duty as muted). */
  placeholder: string;
  /** Links, kind labels, inline affordances. */
  accent: string;
  /** Primary button fill — the onPrimary label sits on this (near-black
   *  in the dark theme's light-fill inversion, white in the light
   *  theme). */
  primary: string;
  /** Non-text fills only (progress bar, switch track): decorative, never
   *  used behind text. */
  primaryBright: string;
  /** Text on primary/danger fills — see primary for the per-theme
   *  inversion. */
  onPrimary: string;
  /** Destructive button fill. */
  danger: string;
  /** Error text. */
  error: string;
  /** Positive evidence badge / upward spark bars. */
  success: string;
  /** Downward spark bars (decorative). */
  sparkDown: string;
  /** The crisis-help surface: deliberately distinct from ordinary cards so
   *  "get help" never reads as just another nav row. */
  helpBg: string;
}

export interface Theme {
  dark: boolean;
  colors: ThemeColors;
  spacing: {
    xs: number; sm: number; md: number; lg: number; xl: number; xxl: number; xxxl: number;
  };
  radius: { sm: number; md: number; lg: number; xl: number };
  type: {
    display: { fontSize: number; fontWeight: "700" };
    question: { fontSize: number; fontWeight: "600"; lineHeight: number };
    titleLg: { fontSize: number; fontWeight: "700"; lineHeight: number };
    title: { fontSize: number; fontWeight: "700" };
    body: { fontSize: number; lineHeight: number };
    bodyLarge: { fontSize: number };
    bodySmall: { fontSize: number; lineHeight: number };
    meta: { fontSize: number };
    caption: { fontSize: number; fontWeight: "700"; letterSpacing: number };
  };
  /** Apple HIG / Android minimum touch target. Text links that cannot grow
   *  a 44pt box must at least carry touchSlop as hitSlop. */
  minTouch: number;
  touchSlop: { top: number; bottom: number; left: number; right: number };
}

const scales = {
  spacing: { xs: 4, sm: 8, md: 12, lg: 16, xl: 20, xxl: 24, xxxl: 32 },
  radius: { sm: 3, md: 10, lg: 12, xl: 14 },
  type: {
    display: { fontSize: 34, fontWeight: "700" as const },
    question: { fontSize: 22, fontWeight: "600" as const, lineHeight: 30 },
    titleLg: { fontSize: 20, fontWeight: "700" as const, lineHeight: 27 },
    title: { fontSize: 17, fontWeight: "700" as const },
    body: { fontSize: 15, lineHeight: 21 },
    bodyLarge: { fontSize: 16 },
    bodySmall: { fontSize: 13, lineHeight: 18 },
    meta: { fontSize: 12 },
    caption: { fontSize: 11, fontWeight: "700" as const, letterSpacing: 1 },
  },
  minTouch: 44,
  touchSlop: { top: 12, bottom: 12, left: 12, right: 12 },
};

export const darkTheme: Theme = {
  dark: true,
  colors: {
    bg: "#211e1a",
    card: "#2a2620",
    cardDeep: "#232019",
    border: "#3a352c",
    text: "#ede8df",
    body: "#cfc7ba",
    muted: "#a29a8c",
    placeholder: "#a29a8c",
    accent: "#b6a9e3",
    primary: "#a9cba4",
    primaryBright: "#b7d5b2",
    onPrimary: "#1e1c17",
    danger: "#d98a80",
    error: "#eba49b",
    success: "#93c7a6",
    sparkDown: "#d98a80",
    helpBg: "#1c1915",
  },
  ...scales,
};

export const lightTheme: Theme = {
  dark: false,
  colors: {
    bg: "#f8f5ef",
    card: "#fffefb",
    cardDeep: "#f4f0e7",
    border: "#e7e0d4",
    text: "#2a2520",
    body: "#4d463d",
    muted: "#6f675c",
    placeholder: "#6f675c",
    accent: "#5d4f9e",
    primary: "#5a7d5e",
    primaryBright: "#44604a",
    onPrimary: "#ffffff",
    danger: "#b3554e",
    error: "#9c443d",
    success: "#35704f",
    sparkDown: "#a0483f",
    helpBg: "#f3eee4",
  },
  ...scales,
};

/** The active theme: the user's explicit override when set, otherwise the
 *  OS color scheme — dark by default (and for any unrecognized scheme
 *  value). Screens render WITHOUT a provider in tests: the context default
 *  ("system") reproduces the old behavior exactly. */
export function useTheme(): Theme {
  useLocale();
  const scheme = useColorScheme();
  const mode = useContext(ThemeModeContext);
  if (mode === "dark") return darkTheme;
  if (mode === "light") return lightTheme;
  return scheme === "light" ? lightTheme : darkTheme;
}

/** App-level provider: loads the persisted override once, exposes the
 *  setter that re-renders the tree, and persists every change. */
export function ThemeProvider({ children }: { children: React.ReactNode }): React.JSX.Element {
  const [mode, setModeState] = useState<ThemeMode>("system");

  useEffect(() => {
    let cancelled = false;
    AsyncStorage.getItem(THEME_STORAGE_KEY)
      .then((stored: string | null) => {
        if (cancelled) return;
        if (stored === "dark" || stored === "light" || stored === "system") {
          setModeState(stored);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const setMode = (next: ThemeMode) => {
    setModeState(next);
    AsyncStorage.setItem(THEME_STORAGE_KEY, next).catch(() => {});
  };

  return (
    <ThemeSetterContext.Provider value={setMode}>
      <ThemeModeContext.Provider value={mode}>{children}</ThemeModeContext.Provider>
    </ThemeSetterContext.Provider>
  );
}

/** The setter Settings consumes (changing the override re-renders the
 *  tree through the provider's state). */
export function useSetThemeMode(): (mode: ThemeMode) => void {
  return useContext(ThemeSetterContext);
}

const ThemeSetterContext = createContext<(mode: ThemeMode) => void>(() => {});
