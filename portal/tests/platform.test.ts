/** The platform seam: origin + localStorage/sessionStorage access degrade
 *  safely when the DOM is absent or storage is hostile. */
import { describe, expect, it } from "vitest";
import { currentOrigin, localStore, sessionStore, visitAnchorStore } from "../src/platform";

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

describe("visitAnchorStore (L-75 decision, 2026-09-20)", () => {
  it("prefers writable sessionStorage and never touches localStorage there", () => {
    expect(visitAnchorStore.sessionBacked()).toBe(true);
    visitAnchorStore.set("mindpattern.lastVisit.t1.u1", "2026-09-20");
    expect(sessionStore.get("mindpattern.lastVisit.t1.u1")).toBe("2026-09-20");
    expect(visitAnchorStore.get("mindpattern.lastVisit.t1.u1")).toBe("2026-09-20");
    // The localStorage fallback store must stay untouched while the
    // session-backed one is live — a stale duplicate there would survive
    // the browser session.
    expect(localStore.get("mindpattern.lastVisit.t1.u1")).toBeNull();
  });

  it("falls back to localStorage when sessionStorage is absent", () => {
    const withLocalStorageOnly = {
      location: { origin: "https://x" },
      localStorage: realWindow && (realWindow as { localStorage: Storage }).localStorage,
    };
    (globalThis as { window?: unknown }).window = withLocalStorageOnly;
    try {
      expect(visitAnchorStore.sessionBacked()).toBe(false);
      visitAnchorStore.set("mindpattern.lastVisit.t2.u1", "2026-09-20");
      expect(localStore.get("mindpattern.lastVisit.t2.u1")).toBe("2026-09-20");
      expect(visitAnchorStore.get("mindpattern.lastVisit.t2.u1")).toBe("2026-09-20");
    } finally {
      (globalThis as { window?: unknown }).window = realWindow;
    }
  });

  it("a hostile (throwing) sessionStorage degrades to the localStorage fallback", () => {
    const hostile = {
      location: { origin: "https://x" },
      sessionStorage: {
        setItem: (): void => {
          throw new Error("denied");
        },
      },
      localStorage: realWindow && (realWindow as { localStorage: Storage }).localStorage,
    };
    (globalThis as { window?: unknown }).window = hostile;
    try {
      // The write PROBE fails, so the anchor routes to localStorage even
      // though a sessionStorage property exists.
      expect(visitAnchorStore.sessionBacked()).toBe(false);
      visitAnchorStore.set("mindpattern.lastVisit.t3.u1", "2026-09-20");
      expect(localStore.get("mindpattern.lastVisit.t3.u1")).toBe("2026-09-20");
    } finally {
      (globalThis as { window?: unknown }).window = realWindow;
    }
  });
});
