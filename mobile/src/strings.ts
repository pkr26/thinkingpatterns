/**
 * The i18n module (2026-09-19) — the public seam for every user-visible
 * string in the app.
 *
 * History: this file began (2026-09-17) as a 17-key English-only catalog
 * covering the safety-critical crisis/unlock copy. This wave rebuilds it
 * as the full two-locale module: every screen and component now resolves
 * its copy through t(), the catalogs live in src/locales/{en,es}.ts, and
 * the device locale (resolved ONCE at startup) picks the language. The
 * original 17 keys are folded in and RECONCILED against the shipped copy
 * — where the old catalog and the screens had drifted, the shipped screen
 * copy won and the screens now consume these keys for real.
 *
 * Contract:
 *  - `t()` is synchronous and total: it NEVER throws. A key missing in
 *    the active locale falls back to English; a key missing everywhere
 *    returns the key itself (visible in review, never a crash).
 *  - "{name}"-style placeholders interpolate from the optional vars bag;
 *    an unknown placeholder stays literal so gaps surface in review.
 *  - Locale selection starts with the device default ("es-*" → es, else
 *    en), then applies the saved Language setting. Subscribers refresh
 *    open screens without unmounting their drafts.
 *  - Dates and numbers format through `dateLocaleTag()` so Intl calls
 *    ("es-ES" / "en-US") follow the same selection.
 */

import { useSyncExternalStore } from "react";
import { en } from "./locales/en";
import { es } from "./locales/es";

export type Locale = "en" | "es";

/** Locale tag for Intl date/number formatting (dateLocaleTag-dependent). */
export function dateLocaleTag(): string {
  return currentLocale === "es" ? "es-ES" : "en-US";
}

/** Detect the device default; the persisted preference is applied at startup. */
function detectLocale(): Locale {
  try {
    const locale = Intl.DateTimeFormat().resolvedOptions().locale;
    return locale.startsWith("es") ? "es" : "en";
  } catch {
    return "en";
  }
}

let currentLocale: Locale = detectLocale();
const localeListeners = new Set<() => void>();
export function useLocale(): Locale {
  return useSyncExternalStore((listener) => { localeListeners.add(listener); return () => { localeListeners.delete(listener); }; }, getLocale, getLocale);
}

export function setLocale(locale: Locale): void {
  if (currentLocale === locale) return;
  currentLocale = locale;
  for (const listener of localeListeners) listener();
}

/** 2026-09-29 deep audit (P2): the in-app language override's "Device"
 * option returns to the startup detection. */
export function resetToDeviceLocale(): void {
  setLocale(detectLocale());
}

export function getLocale(): Locale {
  return currentLocale;
}

/** Test seam: pin the locale for the suite (tests run deterministic under
 *  "en" regardless of the machine running them; i18n tests flip it). */
export function __setLocaleForTests(locale: Locale): void {
  currentLocale = locale;
}

const catalogs: Record<Locale, Record<string, string>> = { en, es };

/** Catalog lookup with "{name}" interpolation. Missing key in the active
 *  locale → English; missing everywhere → the raw key. Never throws. */
export function t(key: string, vars?: Record<string, string | number>): string {
  const template = catalogs[currentLocale][key] ?? en[key] ?? key;
  if (!vars) return template;
  return template.replace(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g, (match, name: string) =>
    name in vars ? String(vars[name]) : match,
  );
}

// Re-exported for the completeness test (es must carry every en key) and
// for tooling that audits the catalogs.
export { en as enCatalog, es as esCatalog };
