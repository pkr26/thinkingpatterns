/**
 * Theme preference — Light / Dark / Auto (redesign 2026-09-26).
 *
 * The preference is a device-local cosmetic choice stored under the
 * mindpattern.* prefix (so account sign-out's privacy sweep clears it —
 * acceptable for a display setting). "auto" follows the OS
 * prefers-color-scheme and re-resolves live; the resolved value lands on
 * <html data-theme="…"> which app.css's token blocks key off.
 *
 * Every DOM touch is guarded: the test environment is node, where
 * window/document do not exist and these functions are inert.
 */

export type ThemePref = "light" | "dark" | "auto";

const STORAGE_KEY = "mindpattern.theme.pref";

export function readThemePref(): ThemePref {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" || value === "auto" ? value : "auto";
  } catch {
    return "auto";
  }
}

export function writeThemePref(pref: ThemePref): void {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Storage unavailable (private mode, tests): the choice lives for
    // this tab only.
  }
}

function resolve(pref: ThemePref): "light" | "dark" {
  if (pref !== "auto") return pref;
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

/** Apply a preference to the document (no-op outside the DOM). */
export function applyThemePref(pref: ThemePref): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = resolve(pref);
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
