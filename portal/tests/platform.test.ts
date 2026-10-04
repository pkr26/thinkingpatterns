/** The platform seam: origin + localStorage/sessionStorage access degrade
 *  safely when the DOM is absent or storage is hostile. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { copyToClipboard, currentOrigin, downloadTextFile, localStore, sessionStore, visitAnchorStore } from "../src/platform";

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

describe("shown-once TOTP affordance seams (2026-09-26 audit round L)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("copyToClipboard writes through navigator.clipboard and reports success", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyToClipboard("A2B3C4D5E6")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("A2B3C4D5E6");
  });

  it("copyToClipboard degrades to false with no clipboard or a denied one", async () => {
    // No clipboard API at all (the node runtime's bare navigator shape)…
    vi.stubGlobal("navigator", {});
    await expect(copyToClipboard("code")).resolves.toBe(false);
    // …and a clipboard that withholds permission.
    const denied = vi.fn(async () => { throw new Error("not allowed"); });
    vi.stubGlobal("navigator", { clipboard: { writeText: denied } });
    await expect(copyToClipboard("code")).resolves.toBe(false);
  });

  it("downloadTextFile keeps its Blob URL alive long enough for WebKit to start the download", () => {
    vi.useFakeTimers();
    // The node runtime has no document (the setup shim defines one only for
    // the App suite; this file predates it, so assert through a stub).
    const anchor = { href: "", download: "", click: vi.fn() };
    const created: string[] = [];
    vi.stubGlobal("document", {
      createElement: (tag: string) => {
        created.push(tag);
        return anchor;
      },
    });
    const revokeURL = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: () => "blob:x", revokeObjectURL: revokeURL });
    expect(() => downloadTextFile("codes.txt", "body")).not.toThrow();
    expect(created).toEqual(["a"]);
    expect(anchor.download).toBe("codes.txt");
    expect(anchor.click).toHaveBeenCalledTimes(1);
    expect(revokeURL).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30_000);
    expect(revokeURL).toHaveBeenCalledWith("blob:x");
    vi.useRealTimers();
  });
});
