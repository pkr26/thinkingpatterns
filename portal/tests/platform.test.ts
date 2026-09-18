/** The platform seam: origin + localStorage access degrade safely when
 * the DOM is absent or storage is hostile. */
import { describe, expect, it } from "vitest";
import { currentOrigin, localStore } from "../src/platform";

const realWindow = (globalThis as { window?: unknown }).window;

describe("platform seam", () => {
  it("reads the origin when a window exists", () => {
    expect(currentOrigin()).toBe("http://localhost:5173");
  });

  it("degrades to empty when there is no window", () => {
    delete (globalThis as { window?: unknown }).window;
    expect(currentOrigin()).toBe("");
    expect(localStore.get("k")).toBeNull();
    localStore.set("k", "v"); // must not throw
    (globalThis as { window?: unknown }).window = realWindow;
  });

  it("degrades when localStorage throws (private mode)", () => {
    (globalThis as { window?: unknown }).window = {
      location: { origin: "https://x" },
      localStorage: {
        getItem: () => {
          throw new Error("denied");
        },
        setItem: () => {
          throw new Error("denied");
        },
      },
    };
    expect(currentOrigin()).toBe("https://x");
    expect(localStore.get("k")).toBeNull();
    localStore.set("k", "v");
    (globalThis as { window?: unknown }).window = realWindow;
  });

  it("stores values when storage works", () => {
    localStore.set("k", "v");
    expect(localStore.get("k")).toBe("v");
  });

  it("removes only a requested metadata namespace", () => {
    localStore.set("mindpattern.lastVisit.t1.u1", "today");
    localStore.set("mindpattern.lastVisit.t1.u2", "today");
    localStore.set("other.application.key", "keep");
    localStore.removePrefix("mindpattern.lastVisit.t1.");
    expect(localStore.get("mindpattern.lastVisit.t1.u1")).toBeNull();
    expect(localStore.get("mindpattern.lastVisit.t1.u2")).toBeNull();
    expect(localStore.get("other.application.key")).toBe("keep");
  });
});
