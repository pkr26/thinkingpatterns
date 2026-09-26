/** The platform seam: origin + storage + downloads + locks + connectivity
 *  all degrade safely when the DOM is absent or hostile (WEB_PLAN R-7). */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  currentOrigin,
  downloadTextFile,
  isOnline,
  localStore,
  onWindowEvent,
  randomBytes,
  sessionStore,
  withLock,
} from "../src/platform";

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

  it("keeps localStorage and sessionStorage separate", () => {
    localStore.set("persistent", "a");
    sessionStore.set("perTab", "b");
    expect(sessionStore.get("persistent")).toBeNull();
    expect(localStore.get("perTab")).toBeNull();
    expect(sessionStore.get("perTab")).toBe("b");
  });

  it("removes only a requested metadata namespace from each store", () => {
    localStore.set("mindpattern.prefs.u1", "x");
    localStore.set("other.application.key", "keep");
    sessionStore.set("mindpattern.prefs.u1", "x");
    sessionStore.set("other.application.key", "keep");
    localStore.removePrefix("mindpattern.prefs.");
    sessionStore.removePrefix("mindpattern.prefs.");
    expect(localStore.get("mindpattern.prefs.u1")).toBeNull();
    expect(sessionStore.get("mindpattern.prefs.u1")).toBeNull();
    expect(localStore.get("other.application.key")).toBe("keep");
    expect(sessionStore.get("other.application.key")).toBe("keep");
  });
});

describe("randomBytes seam", () => {
  it("returns the requested length and fresh bytes", () => {
    const a = randomBytes(16);
    const b = randomBytes(16);
    expect(a.length).toBe(16);
    expect(b.length).toBe(16);
    expect(a).not.toEqual(b);
  });
});

describe("downloadTextFile seam", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    (globalThis as { window?: unknown }).window = realWindow;
  });

  const stubWindow = (document?: unknown): void => {
    (globalThis as { window?: unknown }).window = { location: { origin: "https://x" }, document };
  };

  it("initiates a download and revokes the blob URL", async () => {
    const clicks: { href: string; download: string; rel: string }[] = [];
    stubWindow({
      createElement: () => {
        const anchor = {
          href: "",
          download: "",
          rel: "",
          click: function (this: { href: string; download: string; rel: string }) {
            clicks.push({ href: this.href, download: this.download, rel: this.rel });
          },
        };
        return anchor;
      },
    });
    const revoked: string[] = [];
    vi.stubGlobal("URL", {
      createObjectURL: () => "blob:opaque",
      revokeObjectURL: (url: string) => revoked.push(url),
    });
    expect(downloadTextFile("export.json", "{}", "application/json")).toBe(true);
    expect(clicks).toEqual([{ href: "blob:opaque", download: "export.json", rel: "noopener" }]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(revoked).toEqual(["blob:opaque"]);
  });

  it("degrades to false with no window / no document / no URL factory", () => {
    expect(downloadTextFile("a", "x", "text/plain")).toBe(false);
    stubWindow(undefined);
    expect(downloadTextFile("a", "x", "text/plain")).toBe(false);
    stubWindow({ createElement: () => ({ click: () => undefined }) });
    vi.stubGlobal("URL", {});
    expect(downloadTextFile("a", "x", "text/plain")).toBe(false);
  });

  it("degrades to false when the URL factory throws", () => {
    stubWindow({ createElement: () => ({ click: () => undefined }) });
    vi.stubGlobal("URL", {
      createObjectURL: () => {
        throw new Error("denied");
      },
    });
    expect(downloadTextFile("a", "x", "text/plain")).toBe(false);
  });
});

describe("withLock seam", () => {
  it("runs directly when the Web Locks API is absent (single-tab fallback)", async () => {
    vi.stubGlobal("navigator", {});
    try {
      const ran: string[] = [];
      const result = await withLock("queue-flush", async () => {
        ran.push("ran");
        return 7;
      });
      expect(ran).toEqual(["ran"]);
      expect(result).toBe(7);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("delegates to navigator.locks.request with the lock name", async () => {
    const seen: string[] = [];
    vi.stubGlobal("navigator", {
      locks: {
        request: async <T,>(name: string, callback: () => Promise<T>): Promise<T> => {
          seen.push(name);
          return callback();
        },
      },
    });
    try {
      const result = await withLock("reconcile", async () => "done");
      expect(result).toBe("done");
      expect(seen).toEqual(["reconcile"]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("connectivity + event seams", () => {
  it("isOnline reads navigator.onLine and defaults to true", () => {
    expect(isOnline()).toBe(true); // no navigator.onLine in this runtime
    vi.stubGlobal("navigator", { onLine: false });
    try {
      expect(isOnline()).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("subscribes and unsubscribes window events through the seam", () => {
    const heard: string[] = [];
    const off = onWindowEvent("online", () => heard.push("online"));
    (realWindow as { dispatchEvent: (e: { type: string }) => boolean }).dispatchEvent({ type: "online" });
    expect(heard).toEqual(["online"]);
    off();
    (realWindow as { dispatchEvent: (e: { type: string }) => boolean }).dispatchEvent({ type: "online" });
    expect(heard).toEqual(["online"]);
  });

  it("returns a no-op unsubscribe without a window", () => {
    delete (globalThis as { window?: unknown }).window;
    try {
      const off = onWindowEvent("online", () => undefined);
      expect(off()).toBeUndefined();
    } finally {
      (globalThis as { window?: unknown }).window = realWindow;
    }
  });
});
