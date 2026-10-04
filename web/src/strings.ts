/**
 * English and Spanish message lookup with a persistent language preference.
 *
 * Missing translations fall back to English, then to the key itself. Unknown
 * interpolation placeholders remain visible. Auto mode follows the startup
 * device locale; explicit preferences apply immediately through subscriptions.
 * Date and number formatting use the same resolved locale.
 */

import { localStore } from "./platform";
import { en, es } from "./locales/preauth";

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
  void loadFullCatalogs(currentLocale).catch(() => undefined);
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
const fullCatalogs: Partial<Record<Locale, Promise<void>>> = {};
/** Keep first paint small and load only the active authenticated locale. */
export function loadFullCatalogs(locale: Locale = currentLocale): Promise<void> {
  const existing = fullCatalogs[locale];
  if (existing) return existing;
  const pending: Promise<void> = (locale === "en" ? import("./locales/en") : import("./locales/es"))
    .then((module) => {
      catalogs[locale] = locale === "en"
        ? (module as typeof import("./locales/en")).en
        : (module as typeof import("./locales/es")).es;
      notifyLanguageChanged();
    })
    .catch((error) => { delete fullCatalogs[locale]; throw error; });
  fullCatalogs[locale] = pending;
  return pending;
}

/** Catalog lookup with "{name}" interpolation. Missing key in the active
 *  locale → English; missing everywhere → the raw key. Never throws. */
export function t(key: string, vars?: Record<string, string | number>): string {
  const template = catalogs[currentLocale][key] ?? catalogs.en[key] ?? key;
  if (!vars) return template;
  return template.replace(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g, (match, name: string) =>
    name in vars ? String(vars[name]) : match,
  );
}
