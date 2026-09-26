/** Theme module (hardening 2026-09-26 ii): pure resolution logic, the
 *  storage-key contract shared with the pre-paint script, and the
 *  palette-change notification that keeps JS-drawn charts in sync. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { currentPaletteVersion, notifyPaletteChanged, subscribePalette } from "../src/tokens";
import { resolveTheme, THEME_STORAGE_KEY, type ThemePref } from "../src/theme";

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

  it("references the same storage key as THEME_STORAGE_KEY", () => {
    expect(script).toContain(`"${THEME_STORAGE_KEY}"`);
  });

  it("writes the same attribute the CSS keys off", () => {
    expect(script).toContain('dataset.theme');
    expect(script).toMatch(/"dark" : "light"/);
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
