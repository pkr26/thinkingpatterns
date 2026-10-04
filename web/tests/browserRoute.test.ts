// @ts-nocheck
import { afterEach, describe, expect, it, vi } from "vitest";
import { readBrowserView, writeBrowserView } from "../src/browserRoute";
afterEach(() => vi.unstubAllGlobals());
describe("authenticated browser routes", () => {
  it("accepts only known destinations and stores no journal content", () => {
    const location = { hash: "#/patterns" };
    const pushState = vi.fn((_state, _title, hash) => { location.hash = hash; });
    vi.stubGlobal("window", { location, history: { pushState } });
    expect(readBrowserView()).toBe("patterns");
    writeBrowserView("history");
    expect(pushState).toHaveBeenCalledWith(null, "", "#/history");
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
