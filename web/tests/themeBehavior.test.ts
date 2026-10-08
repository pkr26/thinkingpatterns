import { afterEach, describe, expect, it, vi } from "vitest";
import { applyThemePref, initTheme, readThemePref, writeThemePref } from "../src/theme";
import { subscribePalette } from "../src/tokens";

afterEach(() => { vi.unstubAllGlobals(); });

function browser(options: { pref?: string | null; dark?: boolean; listeners?: boolean } = {}) {
  const values = new Map<string, string>();
  if (options.pref !== undefined && options.pref !== null) values.set("mindpattern.theme.pref", options.pref);
  const dataset: Record<string, string> = {};
  const callbacks = new Set<() => void>();
  const query = {
    matches: options.dark ?? false,
    ...(options.listeners === false ? {} : {
      addEventListener: (event: string, callback: () => void) => { if (event === "change") callbacks.add(callback); },
      removeEventListener: (event: string, callback: () => void) => { if (event === "change") callbacks.delete(callback); },
    }),
  };
  vi.stubGlobal("document", { documentElement: { dataset } });
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  });
  vi.stubGlobal("window", { matchMedia: (condition: string) => {
    if (condition !== "(prefers-color-scheme: dark)") throw new Error("unexpected media query");
    return query;
  } });
  return { dataset, values, changeOs(dark: boolean) { query.matches = dark; for (const callback of callbacks) callback(); } };
}

describe("theme preference consumer behavior", () => {
  it.each([
    ["light", "light"], ["dark", "dark"], ["auto", "auto"],
    [null, "auto"], ["", "auto"], ["unexpected", "auto"],
  ] as const)("resolves stored %s to %s", (pref, expected) => {
    browser({ pref });
    expect(readThemePref()).toBe(expected);
  });

  it("updates chart subscribers when the visible theme changes", () => {
    const dom = browser();
    const themes: string[] = [];
    const off = subscribePalette(() => themes.push(dom.dataset.theme!));
    try {
      applyThemePref("dark");
      applyThemePref("light");
      expect(themes).toEqual(["dark", "light"]);
    } finally { off(); }
  });

  it("tracks live OS changes in auto, preserves explicit preference, and stops after cleanup", () => {
    const dom = browser({ dark: false });
    const cleanup = initTheme();
    expect(dom.dataset.theme).toBe("light");
    dom.changeOs(true);
    expect(dom.dataset.theme).toBe("dark");
    writeThemePref("light");
    applyThemePref("light");
    dom.changeOs(false);
    dom.changeOs(true);
    expect(dom.dataset.theme).toBe("light");
    writeThemePref("auto");
    dom.changeOs(true);
    expect(dom.dataset.theme).toBe("dark");
    cleanup();
    dom.changeOs(false);
    expect(dom.dataset.theme).toBe("dark");
  });

  it("keeps initial theme when old browsers lack media-query event methods", () => {
    const dom = browser({ pref: "dark", listeners: false });
    const cleanup = initTheme();
    expect(dom.dataset.theme).toBe("dark");
    expect(() => cleanup()).not.toThrow();
  });

  it("applies light when the OS query throws without losing an explicit dark preference", () => {
    const dom = browser();
    vi.stubGlobal("window", { matchMedia: () => { throw new Error("blocked"); } });
    applyThemePref("auto");
    expect(dom.dataset.theme).toBe("light");
    applyThemePref("dark");
    expect(dom.dataset.theme).toBe("dark");
  });

  it("initializes without an OS-query API and returns a safe cleanup", () => {
    const dom = browser({ pref: "dark" });
    vi.stubGlobal("window", {});
    const cleanup = initTheme();
    expect(dom.dataset.theme).toBe("dark");
    expect(() => cleanup()).not.toThrow();
  });

  it("is safe without browser globals and emits no palette notification", () => {
    const notify = vi.fn();
    const off = subscribePalette(notify);
    vi.stubGlobal("window", undefined);
    vi.stubGlobal("document", undefined);
    try {
      expect(() => applyThemePref("auto")).not.toThrow();
      expect(() => initTheme()()).not.toThrow();
      expect(notify).not.toHaveBeenCalled();
    } finally { off(); }
  });
});
