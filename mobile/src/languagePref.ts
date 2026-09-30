/**
 * The in-app language override (deep audit 2026-09-29, P2): a bilingual
 * user with an English-locale device used to get a forced-English app —
 * for a mental-health product where emotional nuance IS the product,
 * language is not a nice-to-have. The choice is device-level (UI chrome
 * precedes any account), stored in the encrypted secure store, and
 * applied BOTH at startup (App.tsx mount) and immediately on change
 * (per-render tr() lookups follow currentLocale; the two former
 * module-load tables became per-render for exactly this reason).
 */
import { resetToDeviceLocale, setLocale, type Locale } from "./strings";
import { secureStore } from "./secureStore";

export type LanguageChoice = "device" | "en" | "es";

const LANGUAGE_KEY = "@mindpattern/language_pref";

function isChoice(value: string | null): value is LanguageChoice {
  return value === "device" || value === "en" || value === "es";
}

export async function readLanguageChoice(): Promise<LanguageChoice> {
  try {
    const raw = await secureStore.getItem(LANGUAGE_KEY);
    return isChoice(raw) ? raw : "device";
  } catch {
    return "device";
  }
}

export function applyLanguageChoice(choice: LanguageChoice): void {
  if (choice === "device") resetToDeviceLocale();
  else setLocale(choice as Locale);
}

export async function writeLanguageChoice(choice: LanguageChoice): Promise<void> {
  await secureStore.setItem(LANGUAGE_KEY, choice);
  applyLanguageChoice(choice);
}

/** Startup application (App.tsx mount): unreadable storage keeps the
 * device-detected locale — the override never blocks boot. */
export async function applyStoredLanguageChoice(): Promise<void> {
  applyLanguageChoice(await readLanguageChoice());
}
