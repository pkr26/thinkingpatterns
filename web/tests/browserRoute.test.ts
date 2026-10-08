import { afterEach, describe, expect, it, vi } from "vitest";
import { JSDOM } from "jsdom";
import { readBrowserView, writeBrowserView } from "../src/browserRoute";
afterEach(() => vi.unstubAllGlobals());
describe("authenticated browser routes", () => {
  it("round trips through browser Location and History without changing the document title", () => {
    const page = new JSDOM("<title>Fathom</title>", { url: "https://fathom.test/" });
    vi.stubGlobal("window", page.window);
    page.window.location.hash = "history";
    expect(page.window.location.hash).toBe("#history");
    expect(readBrowserView()).toBe("history");
    writeBrowserView("safetyplan");
    expect(readBrowserView()).toBe("safetyplan");
    expect(page.window.location.hash).toBe("#/safetyplan");
    expect(page.window.history.state).toBeNull();
    expect(page.window.document.title).toBe("Fathom");
    page.window.close();
  });
  it.each(["today", "history", "patterns", "question", "measures", "safetyplan", "share", "settings", "privacy"])(
    "round trips %s with both supported fragment spellings", (view) => {
      const location = { hash: "#/unknown" };
      const pushState = vi.fn((_state, _title, hash: string) => { location.hash = hash; });
      vi.stubGlobal("window", { location, history: { pushState } });
      writeBrowserView(view);
      expect(pushState).toHaveBeenCalledWith(null, expect.any(String), `#/${view}`);
      expect(readBrowserView()).toBe(view);
      location.hash = `#${view}`;
      expect(readBrowserView()).toBe(view);
    },
  );

  it("rejects text preceding a fragment route marker", () => {
    vi.stubGlobal("window", { location: { hash: "prefix#/history" } });
    expect(readBrowserView()).toBe("today");
  });
  it("accepts only known destinations and stores no journal content", () => {
    const location = { hash: "#/patterns" };
    const pushState = vi.fn((_state, _title, hash) => { location.hash = hash; });
    vi.stubGlobal("window", { location, history: { pushState } });
    expect(readBrowserView()).toBe("patterns");
    writeBrowserView("history");
    expect(pushState).toHaveBeenCalledWith(null, expect.any(String), "#/history");
    writeBrowserView("history");
    expect(pushState).toHaveBeenCalledTimes(1);
    location.hash = "#/not-an-application-view";
    expect(readBrowserView()).toBe("today");
    writeBrowserView("login");
    expect(pushState).toHaveBeenCalledTimes(1);
  });
  it("supports restricted hosts without history", () => {
    vi.stubGlobal("window", undefined);
    expect(readBrowserView()).toBe("today");
    expect(() => writeBrowserView("today")).not.toThrow();
  });
});
