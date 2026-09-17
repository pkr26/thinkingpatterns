/**
 * The MindPattern design system: one palette (dark is the default, light
 * follows the OS), plus the spacing / typography / radius scales every
 * screen is built from. No screen may hardcode a hex literal — if a color
 * is needed, it belongs here with its contrast checked.
 *
 * Contrast commitments (WCAG AA, 4.5:1 for normal text; computed with the
 * sRGB relative-luminance formula and pinned by tests/theme.test.ts):
 *
 *  dark.muted   #8a91a3 — 6.0:1 on bg #0f1115, 5.3:1 on card #1a1e26
 *               (replaces #5c6370, which measured 3.13:1 — the failing
 *               gray that carried the crisis-screen fine print)
 *  dark.onPrimary on primary #3b5bdb — 5.7:1 (replaces #4f7cff, 3.71:1)
 *  dark.accent  #7f9bff — 7.2:1 on bg, 5.5:1 on helpBg #242a38
 *  dark.body    #b6bdc9 — 10.0:1 on bg, 8.8:1 on card
 *  dark.error   #ff6b6b — 6.8:1 on bg
 *  light.muted  #5a6272 — 6.1:1 on card, 5.7:1 on bg #f5f6fa
 *  light.onPrimary on primary #2f4bd0 — 6.9:1
 *  light.accent #2f4bd0 — 6.9:1 on card
 *
 * Tone: the palette stays flat and calm on purpose — no gradients, no
 * celebration colors; the one loud accent is reserved for crisis help.
 */
import React, { createContext, useContext, useEffect, useState } from "react";
import { useColorScheme } from "react-native";
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
  /** Primary button fill — white labels sit on this. */
  primary: string;
  /** Non-text fills only (progress bar, switch track): decorative, never
   *  used behind text. */
  primaryBright: string;
  /** Text on primary/danger fills. */
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
    bg: "#0f1115",
    card: "#1a1e26",
    cardDeep: "#141821",
    border: "#222733",
    text: "#e8eaf0",
    body: "#b6bdc9",
    muted: "#8a91a3",
    placeholder: "#8a91a3",
    accent: "#7f9bff",
    primary: "#3b5bdb",
    primaryBright: "#4f7cff",
    onPrimary: "#ffffff",
    danger: "#c0392b",
    error: "#ff6b6b",
    success: "#59c98a",
    sparkDown: "#e06c75",
    helpBg: "#242a38",
  },
  ...scales,
};

export const lightTheme: Theme = {
  dark: false,
  colors: {
    bg: "#f5f6fa",
    card: "#ffffff",
    cardDeep: "#eef0f6",
    border: "#d5dae4",
    text: "#161a22",
    body: "#3d4453",
    muted: "#5a6272",
    placeholder: "#5a6272",
    accent: "#2f4bd0",
    primary: "#2f4bd0",
    primaryBright: "#3b5bdb",
    onPrimary: "#ffffff",
    danger: "#b03525",
    error: "#c92f22",
    success: "#187a41",
    sparkDown: "#c64650",
    helpBg: "#e4e9f5",
  },
  ...scales,
};

/** The active theme: the user's explicit override when set, otherwise the
 *  OS color scheme — dark by default (and for any unrecognized scheme
 *  value). Screens render WITHOUT a provider in tests: the context default
 *  ("system") reproduces the old behavior exactly. */
export function useTheme(): Theme {
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
