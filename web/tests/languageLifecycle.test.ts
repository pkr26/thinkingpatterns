import { afterEach, beforeEach, expect, it, vi } from "vitest";
beforeEach(() => { vi.resetModules(); window.localStorage.clear(); vi.stubGlobal("document", { documentElement: { lang: "" } }); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.doUnmock("../src/locales/en"); vi.doUnmock("../src/locales/es"); });
function device(locale: string) { vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({ resolvedOptions: () => ({ locale }) } as Intl.DateTimeFormat); }

it.each([["en", "es-MX", "Today", "en"], ["es", "en-US", "Hoy", "es"], ["auto", "es-MX", "Hoy", "es"], ["unknown", "en-US", "Today", "en"]])("restores the saved preference %s under device locale %s and announces its visible language", async (pref, locale, today, lang) => {
  window.localStorage.setItem("mindpattern.language.pref", pref!); device(locale!);
  const module = await import("../src/strings");
  expect(module.t("nav.today")).toBe(today); expect(document.documentElement.lang).toBe(lang);
  expect(module.getLanguagePref()).toBe(pref === "en" || pref === "es" ? pref : "auto");
});
it("falls back to English if the device locale cannot be queried, and works without a document", async () => {
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => { throw new Error("locale lookup unavailable"); });
  vi.stubGlobal("document", undefined); const module = await import("../src/strings");
  expect(module.t("nav.today")).toBe("Today"); expect(module.getLocale()).toBe("en");
  module.applyLanguagePref("es"); expect(module.t("nav.today")).toBe("Hoy");
  expect(window.localStorage.getItem("mindpattern.language.pref")).toBe("es");
});
it("updates the document tag, visible copy and subscribers immediately, then stops notifying a disposed consumer", async () => {
  device("en-US"); const module = await import("../src/strings");
  const observe = vi.fn(() => module.t("nav.today")); const dispose = module.subscribeLanguage(observe);
  module.applyLanguagePref("es"); expect(observe).toHaveBeenCalled(); expect(observe.mock.results[0]!.value).toBe("Hoy");
  expect(document.documentElement.lang).toBe("es"); await module.loadFullCatalogs("es");
  dispose(); observe.mockClear(); module.applyLanguagePref("en"); await module.loadFullCatalogs("en"); expect(observe).not.toHaveBeenCalled();
});
it("retries a failed authenticated catalog load and publishes the recovered copy once", async () => {
  device("en-US"); const module = await import("../src/strings");
  vi.doMock("../src/locales/en", () => { throw new Error("catalog transport failed"); });
  await expect(module.loadFullCatalogs("en")).rejects.toThrow();
  vi.doMock("../src/locales/en", () => ({ en: { "catalog.recovery": "Recovered visible copy" } }));
  const observe = vi.fn(() => module.t("catalog.recovery")); module.subscribeLanguage(observe);
  await module.loadFullCatalogs("en"); expect(module.t("catalog.recovery")).toBe("Recovered visible copy"); expect(observe).toHaveBeenCalledExactlyOnceWith();
  await module.loadFullCatalogs("en"); expect(observe).toHaveBeenCalledOnce();
});
it("keeps date formatting and the announced document language in step with explicitly selected rendering locales", async () => {
  const module = await import("../src/strings");
  for (const [locale, tag] of [["es", "es-ES"], ["en", "en-US"]] as const) {
    module.__setLocaleForTests(locale);
    expect(document.documentElement.lang).toBe(locale); expect(module.dateLocaleTag()).toBe(tag);
  }
});
