/**
 * English and Spanish catalogs with synchronous fallback and interpolation.
 * Missing translations fall back to English, then to the key. Unknown
 * {name} placeholders remain visible for review.
 *
 * The device locale provides the default; the saved language preference can
 * override it. Subscribers refresh open screens without unmounting drafts.
 * Date and number formatting use the same locale through dateLocaleTag().
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

/** Restore the current device locale when the user selects Device. */
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
