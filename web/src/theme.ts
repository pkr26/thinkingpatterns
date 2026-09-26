/**
 * Theme preference — Light / Dark / Auto (redesign 2026-09-26).
 *
 * The preference is a device-local cosmetic choice stored under the
 * mindpattern.* prefix (so account sign-out's privacy sweep clears it —
 * acceptable for a display setting). "auto" follows the OS
 * prefers-color-scheme and re-resolves live; the resolved value lands on
 * <html data-theme="…"> which app.css's token blocks key off.
 *
 * Hardening 2026-09-26 (ii): the FIRST paint is covered by the tiny
 * synchronous public/theme-init.js in <head> (before the stylesheet) —
 * this module remains the reactive half (live OS tracking + writes) and
 * is idempotent with it. applyThemePref also notifies tokens.ts so
 * JS-drawn charts re-render on every change (auto mode included).
 *
 * Every DOM touch is guarded: the test environment is node, where
 * window/document do not exist and these functions are inert.
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
