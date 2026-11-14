import { afterEach, expect, it, vi } from "vitest";
import { JSDOM } from "jsdom";

afterEach(() => {
  vi.unstubAllGlobals();
});

it("preserves the local storage API in a cold browser environment", async () => {
  const dom = new JSDOM("", { url: "https://example.test" });
  vi.stubGlobal("window", dom.window);
  vi.resetModules();
  try {
    const { localStore } = await import("../src/platform");
    const key = "mindpattern.language.pref";
    localStore.set(key, "es");
    expect(dom.window.localStorage.getItem(key)).toBe("es");
    expect(localStore.get(key)).toBe("es");
    localStore.remove(key);
    expect(dom.window.localStorage.getItem(key)).toBeNull();
    expect(localStore.get(key)).toBeNull();
  } finally {
    dom.window.close();
  }
});
