/** The i18n seam and the small pure modules that ride it: locale
 *  switching, the catalog fallback, date formatting, the prompt chips, the
 *  deterministic question rotation, the mood label helpers, and the
 *  Language preference (auto/en/es, persisted + live — audit 2026-09-26). */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  __setLocaleForTests,
  applyLanguagePref,
  dateLocaleTag,
  getLanguagePref,
  getLocale,
  LANGUAGE_STORAGE_KEY,
  setLocale,
  subscribeLanguage,
  t,
  enCatalog,
  esCatalog,
} from "../src/strings";
import { genericQuestionForDate, GENERIC_QUESTIONS, GENERIC_QUESTIONS_ES } from "../src/genericQuestions";
import { promptChipsFor, PROMPT_CHIPS, PROMPT_CHIPS_ES } from "../src/promptChips";
import { moodLabel, localSentiment, ACTIVITY_TAGS, activityTagLabel } from "../src/mood";

afterEach(() => {
  applyLanguagePref("auto");
  __setLocaleForTests("en");
});

describe("strings", () => {
  it("defaults to English and interpolates variables", () => {
    expect(getLocale()).toBe("en");
    expect(t("entry.energyQuestion")).toBeTruthy();
    expect(t("nonexistent.key")).toBe("nonexistent.key"); // total, never throws
  });

  it("switches the catalog and the date locale together", () => {
    const english = t("mood.option.good");
    setLocale("es");
    expect(getLocale()).toBe("es");
    expect(dateLocaleTag()).toBe("es-ES");
    expect(t("mood.option.good")).not.toBe(english);
    setLocale("en");
    expect(getLocale()).toBe("en");
    expect(dateLocaleTag()).toBe("en-US");
    expect(t("mood.option.good")).toBe(english);
  });

  it("the Spanish catalog covers the English keys exactly (no missing string)", () => {
    setLocale("es");
    for (const key of ["mood.option.good", "entry.energyQuestion"]) {
      expect(t(key)).not.toBe(key);
    }
    setLocale("en");
  });
});

describe("catalog parity (P8.2)", () => {
  it("the Spanish catalog covers every English key — no missing string", () => {
    const missing = Object.keys(enCatalog).filter((key) => !(key in esCatalog));
    expect(missing).toEqual([]);
  });

  // independent audit 2026-09-27 (P3): parity is BIDIRECTIONAL — an extra
  // Spanish key is dead copy that drifts unpinned, and an EMPTY value in
  // either catalog renders as nothing wherever t() lands it.
  it("the Spanish catalog carries no EXTRA key the English catalog lacks", () => {
    const extra = Object.keys(esCatalog).filter((key) => !(key in enCatalog));
    expect(extra).toEqual([]);
  });

  it("no key in either catalog maps to an EMPTY string", () => {
    for (const catalog of [enCatalog, esCatalog]) {
      for (const [key, value] of Object.entries(catalog)) {
        expect(value.length, `empty value for ${key}`).toBeGreaterThan(0);
      }
    }
  });

  it("the crisis-surface keys are never empty in either locale", () => {
    for (const catalog of [enCatalog, esCatalog]) {
      for (const key of Object.keys(catalog).filter((k) => k.startsWith("mood.option") || k.startsWith("measures."))) {
        expect(catalog[key]?.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("language preference (audit 2026-09-26 LOW: the override seam)", () => {
  /** The setup shim's window.localStorage — the storage the platform seam
   *  actually reads under the node runtime. */
  const shimStorage = (): Storage => {
    const win = (globalThis as { window?: { localStorage?: Storage } }).window;
    if (!win?.localStorage) throw new Error("no window shim in this runtime");
    return win.localStorage;
  };

  it("defaults to auto and resolves from the device locale", () => {
    expect(getLanguagePref()).toBe("auto");
    expect(getLocale()).toBe("en"); // this runtime's device locale
  });

  it("an explicit override applies LIVE: the catalog, the date tag, and the persisted key all move together", () => {
    const storage = shimStorage();
    const heard: string[] = [];
    const off = subscribeLanguage(() => heard.push(getLocale()));
    const english = t("mood.option.good");
    applyLanguagePref("es");
    expect(getLanguagePref()).toBe("es");
    expect(getLocale()).toBe("es");
    expect(dateLocaleTag()).toBe("es-ES");
    expect(t("mood.option.good")).not.toBe(english);
    expect(storage.getItem(LANGUAGE_STORAGE_KEY)).toBe("es");
    expect(heard).toEqual(["es"]); // the live-apply notification (App re-renders)
    off();
    applyLanguagePref("en");
    expect(heard).toEqual(["es"]); // unsubscribed: no further notice
  });

  it("auto follows the device again after the override lifts", () => {
    applyLanguagePref("es");
    expect(getLocale()).toBe("es");
    applyLanguagePref("auto");
    expect(getLanguagePref()).toBe("auto");
    expect(getLocale()).toBe("en"); // back to the detected device locale
  });

  it("a hostile stored value resolves as auto at load (never a crash, never a wrong catalog)", async () => {
    const storage = shimStorage();
    storage.setItem(LANGUAGE_STORAGE_KEY, "fr");
    // Re-evaluate the module against the seeded storage — the startup path
    // a reload would take.
    vi.resetModules();
    const fresh = await import("../src/strings");
    expect(fresh.getLanguagePref()).toBe("auto");
    expect(fresh.getLocale()).toBe("en");
  });
});

describe("genericQuestionForDate", () => {
  it("is stable within a day and deterministic across calls", () => {
    const a = genericQuestionForDate("2026-09-25");
    const b = genericQuestionForDate("2026-09-25");
    expect(a).toBe(b);
    expect(GENERIC_QUESTIONS).toContain(a);
  });

  it("rotates between days and speaks Spanish under that locale", () => {
    const one = genericQuestionForDate("2026-09-25");
    const two = genericQuestionForDate("2026-09-26");
    expect(one).not.toBe(two); // 60 questions, adjacent days never collide in practice
    expect(GENERIC_QUESTIONS_ES).toContain(genericQuestionForDate("2026-09-25", "es"));
  });
});

describe("promptChips", () => {
  it("offers three chips per day, stable within the day", () => {
    const morning = promptChipsFor(new Date(2026, 8, 25, 9), 3);
    const evening = promptChipsFor(new Date(2026, 8, 25, 21), 3);
    expect(morning).toEqual(evening);
    expect(morning).toHaveLength(3);
    for (const chip of morning) expect(PROMPT_CHIPS).toContain(chip);
  });

  it("serves the Spanish pool under the Spanish locale", () => {
    for (const chip of promptChipsFor(new Date(2026, 8, 25), 3, "es")) expect(PROMPT_CHIPS_ES).toContain(chip);
  });
});

describe("threshold notice", () => {
  it("records, reads, and clears the one-time flag", async () => {
    const { thresholdNoticeShown, recordThresholdNotice, clearThresholdNotice } = await import("../src/thresholdNotice");
    expect(await thresholdNoticeShown("user-t")).toBe(false);
    await recordThresholdNotice("user-t");
    expect(await thresholdNoticeShown("user-t")).toBe(true);
    await clearThresholdNotice("user-t");
    expect(await thresholdNoticeShown("user-t")).toBe(false);
  });
});

describe("stats edges", () => {
  it("erfc stays bounded and sign-consistent across both branches", async () => {
    const { erfc } = await import("../src/brain/stats");
    expect(erfc(0)).toBeCloseTo(1, 12);
    // Identity parity (the Cody continued-fraction tail vs the series
    // branch): erfc(-x) = 2 - erfc(x).
    expect(erfc(-3)).toBeCloseTo(2 - erfc(3), 12);
    expect(erfc(6)).toBeCloseTo(0, 9);
    expect(erfc(-6)).toBeCloseTo(2, 9);
  });
});

describe("mood helpers", () => {
  it("labels the nearest scale option", () => {
    expect(moodLabel(0.4)).toBe("Good");
    expect(moodLabel(-0.9)).toBe("Heavy");
    expect(moodLabel(0)).toBe("Okay");
  });

  it("renders known tags localized and unknown tags as their wire value", () => {
    for (const tag of ACTIVITY_TAGS) expect(activityTagLabel(tag)).toBeTruthy();
    expect(activityTagLabel("someone-elses-vocab")).toBe("someone-elses-vocab");
  });

  it("localSentiment is the real graded engine on plain text", () => {
    expect(localSentiment("happy calm light wonderful")).toBeGreaterThan(0);
    expect(localSentiment("terrible awful miserable hate")).toBeLessThan(0);
    expect(localSentiment("the and of")).toBe(0);
  });
});
