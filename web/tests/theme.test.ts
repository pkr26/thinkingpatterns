/** Theme module (hardening 2026-09-26 ii): pure resolution logic, the
 *  storage-key contract shared with the pre-paint script, and the
 *  palette-change notification that keeps JS-drawn charts in sync. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { currentPaletteVersion, notifyPaletteChanged, subscribePalette } from "../src/tokens";
import { resolveTheme, THEME_STORAGE_KEY, type ThemePref , applyThemePref, initTheme, readThemePref, writeThemePref } from "../src/theme";

describe("resolveTheme (pure)", () => {
  it("explicit preferences win regardless of the OS setting", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });
  it("auto follows the OS preference", () => {
    expect(resolveTheme("auto", true)).toBe("dark");
    expect(resolveTheme("auto", false)).toBe("light");
  });
});

describe("readThemePref default", () => {
  it("treats unreadable storage as auto (never crashes boot)", async () => {
    vi.resetModules();
    const storage = {
      getItem: () => {
        throw new Error("private mode");
      },
    };
    const globals = globalThis as Record<string, unknown>;
    globals.localStorage = storage;
    try {
      const { readThemePref } = await import("../src/theme");
      expect(readThemePref()).toBe<ThemePref>("auto");
    } finally {
      delete globals.localStorage;
    }
  });
});

describe("pre-paint script stays in sync with the module", () => {
  const script = readFileSync(join(__dirname, "../public/theme-init.js"), "utf8");

  // Executing the actual early script in a browser-like global also needs
  // the mutation runner's activation context, just as an imported module does.
  function runBoot(context: Record<string, unknown>) {
    const runnerGlobals = Object.fromEntries(Object.getOwnPropertyNames(globalThis)
      .filter((key) => key.startsWith("__stryker"))
      .map((key) => [key, (globalThis as Record<string, unknown>)[key]]));
    return runInNewContext(script, { process, ...runnerGlobals, ...context });
  }

  function boot(pref: string | null, prefersDark: boolean, withMedia = true) {
    const dataset: Record<string, string> = {};
    const getItem = vi.fn((key: string) => key === THEME_STORAGE_KEY ? pref : null);
    const matchMedia = vi.fn((query: string) => ({ matches: query === "(prefers-color-scheme: dark)" && prefersDark }));
    runBoot({
      localStorage: { getItem },
      window: withMedia ? { matchMedia } : {},
      document: { documentElement: { dataset } },
    });
    return { dataset, getItem, matchMedia };
  }

  it.each([
    ["dark", false, "dark"], ["dark", true, "dark"],
    ["light", false, "light"], ["light", true, "light"],
    ["auto", false, "light"], ["auto", true, "dark"],
    [null, false, "light"], [null, true, "dark"],
    ["invalid", true, "light"],
  ] as const)("boots preference %s with OS dark %s to %s", (pref, osDark, expected) => {
    const { dataset, getItem } = boot(pref, osDark);
    expect(getItem).toHaveBeenCalledWith(THEME_STORAGE_KEY);
    expect(dataset.theme).toBe(expected);
  });

  it("boots in light when matchMedia is unavailable", () => {
    expect(boot("auto", true, false).dataset.theme).toBe("light");
  });

  it("keeps boot available when preference storage or the OS query throws", () => {
    const dataset = {};
    expect(() => runBoot({
      localStorage: { getItem: () => { throw new Error("private mode"); } },
      window: {}, document: { documentElement: { dataset } },
    })).not.toThrow();
    expect(dataset).toEqual({});
    expect(() => runBoot({
      localStorage: { getItem: () => "auto" },
      window: { matchMedia: () => { throw new Error("unavailable"); } },
      document: { documentElement: { dataset } },
    })).not.toThrow();
  });

  it("index.html loads it before the stylesheet (pre-paint)", () => {
    const html = readFileSync(join(__dirname, "../index.html"), "utf8");
    const scriptAt = html.indexOf('/theme-init.js');
    const cssAt = html.indexOf('href="/app.css"');
    expect(scriptAt).toBeGreaterThan(-1);
    expect(cssAt).toBeGreaterThan(-1);
    expect(scriptAt).toBeLessThan(cssAt);
  });
});

describe("palette change notification", () => {
  it("notifies subscribers and bumps the version", () => {
    const before = currentPaletteVersion();
    const seen: number[] = [];
    const off = subscribePalette(() => seen.push(currentPaletteVersion()));
    notifyPaletteChanged();
    off();
    notifyPaletteChanged(); // off() unsubscribed: no further calls
    expect(seen).toEqual([before + 1]);
    expect(currentPaletteVersion()).toBe(before + 2);
  });
});

// 2026-09-29 (P2 coverage gate): the DOM-touching half of the module —
// writeThemePref / applyThemePref / initTheme — was untested (22%
// functions). Minimal document/window stubs exercise them in node.
describe("applyThemePref / initTheme / writeThemePref (DOM half)", () => {
  function stubDom(prefersDark: boolean): { restore: () => void; dataset: Record<string, string> } {
    const dataset: Record<string, string> = {};
    const listeners: Array<() => void> = [];
    const documentStub = { documentElement: { dataset } } as unknown as Document;
    const windowStub = {
      matchMedia: (q: string) => ({
        matches: q.includes("dark") ? prefersDark : false,
        addEventListener: (_: string, fn: () => void) => listeners.push(fn),
        removeEventListener: (_: string, fn: () => void) => {
          const at = listeners.indexOf(fn);
          if (at >= 0) listeners.splice(at, 1);
        },
      }),
    } as unknown as Window & typeof globalThis;
    const store: Record<string, string> = {};
    const localStorageStub = {
      getItem: (k: string) => (k in store ? store[k]! : null),
      setItem: (k: string, v: string) => {
        store[k] = String(v);
      },
      removeItem: (k: string) => {
        delete store[k];
      },
    };
    const realDocument = globalThis.document;
    const realWindow = globalThis.window;
    const realStorage = (globalThis as { localStorage?: Storage }).localStorage;
    Object.defineProperty(globalThis, "document", { value: documentStub, configurable: true });
    Object.defineProperty(globalThis, "window", { value: windowStub, configurable: true });
    Object.defineProperty(globalThis, "localStorage", { value: localStorageStub, configurable: true });
    return {
      restore: () => {
        Object.defineProperty(globalThis, "document", { value: realDocument, configurable: true });
        Object.defineProperty(globalThis, "window", { value: realWindow, configurable: true });
        Object.defineProperty(globalThis, "localStorage", { value: realStorage, configurable: true });
      },
      dataset,
    };
  }

  it("applyThemePref resolves and writes the document attribute", () => {
    const dom = stubDom(true);
    try {
      applyThemePref("light");
      expect(dom.dataset.theme).toBe("light");
      applyThemePref("auto"); // OS prefers dark
      expect(dom.dataset.theme).toBe("dark");
    } finally {
      dom.restore();
    }
  });

  it("initTheme installs the OS listener for auto and the cleanup removes it", () => {
    const dom = stubDom(false);
    try {
      const cleanup = initTheme();
      expect(typeof cleanup).toBe("function");
      // Default pref (auto, no stored value) follows the OS verdict.
      expect(dom.dataset.theme).toBe("light");
      cleanup();
      expect(() => cleanup()).not.toThrow();
    } finally {
      dom.restore();
    }
  });

  it("writeThemePref round-trips through storage", () => {
    const dom = stubDom(false);
    try {
      writeThemePref("dark");
      expect(readThemePref()).toBe("dark");
      writeThemePref("auto");
      expect(readThemePref()).toBe("auto");
    } finally {
      dom.restore();
    }
  });
});
