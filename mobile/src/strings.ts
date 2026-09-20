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
 *  - Locale selection is device-driven ("es-*" → es, else en). There is
 *    deliberately NO in-app language override this wave — a manual
 *    Language setting is a residual, not an omission.
 *  - Dates and numbers format through `dateLocaleTag()` so Intl calls
 *    ("es-ES" / "en-US") follow the same selection.
 */

import { en } from "./locales/en";
import { es } from "./locales/es";

export type Locale = "en" | "es";

/** Locale tag for Intl date/number formatting (dateLocaleTag-dependent). */
export function dateLocaleTag(): string {
  return currentLocale === "es" ? "es-ES" : "en-US";
}

/** Resolved ONCE from the device locale — the app has no language switch,
 *  so re-reading it per call would only invite inconsistency. */
function detectLocale(): Locale {
  try {
    const locale = Intl.DateTimeFormat().resolvedOptions().locale;
    return locale.startsWith("es") ? "es" : "en";
  } catch {
    return "en";
  }
}

let currentLocale: Locale = detectLocale();

export function setLocale(locale: Locale): void {
  currentLocale = locale;
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
