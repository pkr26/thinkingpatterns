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
 *  - Locale selection: "auto" resolves from the device locale ("es-*" →
 *    es, else en); an explicit "en"/"es" override wins (the Language
 *    setting, audit 2026-09-26 LOW). The preference persists locally and
 *    applies on the next load AND live (subscribeLanguage).
 *  - Dates and numbers format through `dateLocaleTag()` so Intl calls
 *    ("es-ES" / "en-US") follow the same selection.
 */

import { localStore } from "./platform";
import { en } from "./locales/en";
import { es } from "./locales/es";

export type Locale = "en" | "es";

/** The Language setting: follow the device, or pin a catalog. */
export type LanguagePref = "auto" | "en" | "es";

/** Locale tag for Intl date/number formatting (dateLocaleTag-dependent). */
export function dateLocaleTag(): string {
  return currentLocale === "es" ? "es-ES" : "en-US";
}

/** Resolved from the device locale whenever the preference is "auto". */
function detectLocale(): Locale {
  try {
    const locale = Intl.DateTimeFormat().resolvedOptions().locale;
    return locale.startsWith("es") ? "es" : "en";
  } catch {
    return "en";
  }
}

/** The persisted preference — the theme-pref idiom (mindpattern.* so the
 *  sign-out privacy sweep clears it; acceptable for a display setting).
 *  Reads/writes run through the platform's localStorage seam, which is
 *  inert outside a DOM instead of throwing. */
export const LANGUAGE_STORAGE_KEY = "mindpattern.language.pref";

function storedLanguagePref(): LanguagePref {
  const value = localStore.get(LANGUAGE_STORAGE_KEY);
  return value === "en" || value === "es" ? value : "auto";
}

function writeLanguagePref(pref: LanguagePref): void {
  localStore.set(LANGUAGE_STORAGE_KEY, pref);
}

function resolveLocale(pref: LanguagePref): Locale {
  return pref === "auto" ? detectLocale() : pref;
}

let languagePref: LanguagePref = storedLanguagePref();
let currentLocale: Locale = resolveLocale(languagePref);

/** 2026-09-28 audit (INFO): the document's own language tag follows the
 *  active locale (applyLanguagePref, and the module boot below) so
 *  screen readers and translation tooling see the language the UI is
 *  actually rendering. Guarded — the module also loads in DOM-less
 *  runtimes (node tests) where `document` does not exist. */
function announceLocale(): void {
  const doc = (globalThis as { document?: { documentElement?: { lang: string } } }).document;
  if (doc?.documentElement) doc.documentElement.lang = currentLocale;
}
announceLocale();

type LanguageListener = () => void;
const languageListeners = new Set<LanguageListener>();

function notifyLanguageChanged(): void {
  for (const listener of languageListeners) listener();
}

/** Apply a language preference NOW (live) and persist it: the catalog
 *  swaps immediately and every subscriber (App) re-renders. */
export function applyLanguagePref(pref: LanguagePref): void {
  languagePref = pref;
  writeLanguagePref(pref);
  currentLocale = resolveLocale(pref);
  announceLocale();
  notifyLanguageChanged();
}

/** The preference currently in force (never the raw storage bytes). */
export function getLanguagePref(): LanguagePref {
  return languagePref;
}

/** Live-apply subscription: fires whenever applyLanguagePref changes the
 *  active catalog. Returns an unsubscribe function. */
export function subscribeLanguage(listener: LanguageListener): () => void {
  languageListeners.add(listener);
  return () => {
    languageListeners.delete(listener);
  };
}

export function getLocale(): Locale {
  return currentLocale;
}

/** Test seam: pin the locale for the suite (tests run deterministic under
 *  "en" regardless of the machine running them; i18n tests flip it).
 *  2026-09-28 audit (INFO): the old setLocale() export was a test-only
 *  backdoor that bypassed notify/persist — production code must go
 *  through applyLanguagePref, so the seam is folded here (with the
 *  documentElement tag kept in step like every other path). */
export function __setLocaleForTests(locale: Locale): void {
  currentLocale = locale;
  announceLocale();
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
