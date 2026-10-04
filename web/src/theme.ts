/**
 * Persistent Light, Dark, or Auto display preference.
 *
 * Auto follows live prefers-color-scheme changes. public/theme-init.js sets
 * the first-paint theme; this module handles reactive updates and notifies
 * chart palettes. DOM access is guarded for the Node test environment.
 */

import { notifyPaletteChanged } from "./tokens";

export type ThemePref = "light" | "dark" | "auto";

/** Shared with public/theme-init.js (pinned together in
 *  tests/theme.test.ts so the pre-paint script can never drift). */
export const THEME_STORAGE_KEY = "mindpattern.theme.pref";

export function readThemePref(): ThemePref {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" || value === "auto" ? value : "auto";
  } catch {
    return "auto";
  }
}

export function writeThemePref(pref: ThemePref): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, pref);
  } catch {
    // Storage unavailable (private mode, tests): the choice lives for
    // this tab only.
  }
}

/** Pure resolution (unit-testable): explicit prefs win; "auto" follows
 *  the OS preference; anything unreadable resolves light. */
export function resolveTheme(pref: ThemePref, prefersDark: boolean): "light" | "dark" {
  if (pref === "light" || pref === "dark") return pref;
  return prefersDark ? "dark" : "light";
}

function systemPrefersDark(): boolean {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    return false;
  }
}

/** Apply a preference to the document (no-op outside the DOM). */
export function applyThemePref(pref: ThemePref): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = resolveTheme(pref, systemPrefersDark());
  notifyPaletteChanged();
}

/**
 * Install the startup theme and keep "auto" tracking the OS. Returns a
 * cleanup (unused in the app's lifetime, kept for completeness).
 */
export function initTheme(): () => void {
  applyThemePref(readThemePref());
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return () => undefined;
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const listener = (): void => {
    if (readThemePref() === "auto") applyThemePref("auto");
  };
  query.addEventListener?.("change", listener);
  return () => query.removeEventListener?.("change", listener);
}
