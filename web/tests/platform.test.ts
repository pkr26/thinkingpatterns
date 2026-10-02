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

  it("removes only a requested metadata namespace", () => {
    localStore.set("mindpattern.prefs.u1", "x");
    localStore.set("other.application.key", "keep");
    localStore.removePrefix("mindpattern.prefs.");
    expect(localStore.get("mindpattern.prefs.u1")).toBeNull();
    expect(localStore.get("other.application.key")).toBe("keep");
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
    // 2026-10-01 audit L-5: the revoke moved to a 60 s delay — the
    // next-macrotask revoke could abort an in-progress multi-MB download.
    // Fake timers BEFORE the call so the delay is observable without
    // waiting a real minute; nothing is revoked immediately, the URL is
    // reclaimed after the window.
    vi.useFakeTimers();
    try {
      expect(downloadTextFile("export.json", "{}", "application/json")).toBe(true);
      expect(clicks).toEqual([{ href: "blob:opaque", download: "export.json", rel: "noopener" }]);
      expect(revoked).toEqual([]);
      vi.advanceTimersByTime(60_000);
      expect(revoked).toEqual(["blob:opaque"]);
    } finally {
      vi.useRealTimers();
    }
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

/** L-7 (2026-09-28 audit): browsers without navigator.locks (Safari < 15.2)
 *  used to run every "locked" section UNLOCKED — the cross-tab
 *  last-write-wins the lock exists to prevent silently returned. The
 *  localStorage bakery restores real serialization. The test shim's
 *  window.localStorage plays the coherent same-origin store. */
describe("withLock bakery fallback (audit 2026-09-28 L-7)", () => {
  it("serializes concurrent sections on one lock name — never overlapping", async () => {
    vi.stubGlobal("navigator", {});
    try {
      let active = 0;
      let maxActive = 0;
      const section = async (label: string): Promise<string> =>
        withLock("queue-flush", async () => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 5 + Math.random() * 5));
          active -= 1;
          return label;
        });
      const results = await Promise.all(["a", "b", "c"].map(section));
      expect(results.sort()).toEqual(["a", "b", "c"]);
      expect(maxActive).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("a crashed holder's stale vote is swept — the lock cannot deadlock", async () => {
    vi.stubGlobal("navigator", {});
    try {
      const storage = (globalThis as { window?: { localStorage?: Storage } }).window?.localStorage;
      expect(storage).toBeTruthy();
      // A vote stamped LONG ago: the tab that wrote it is long dead.
      storage!.setItem("mindpattern.lockvote.queue-flush.deadbeef", JSON.stringify({ ts: Date.now() - 60_000 }));
      const started = Date.now();
      await withLock("queue-flush", async () => "ok");
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(storage!.getItem("mindpattern.lockvote.queue-flush.deadbeef")).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("releases the vote on completion — the store carries no residue", async () => {
    vi.stubGlobal("navigator", {});
    try {
      await withLock("one-shot", async () => 1);
      const storage = (globalThis as { window?: { localStorage?: Storage } }).window?.localStorage;
      const residue = [] as string[];
      for (let index = 0; index < storage!.length; index += 1) {
        const key = storage!.key(index);
        if (key?.startsWith("mindpattern.lockvote.")) residue.push(key);
      }
      expect(residue).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

/** T-1 (pentest 2026-09-29): with neither Web Locks NOR usable storage
 *  (locked-down private modes) the fallback used to run the section
 *  UNLOCKED — two same-tab read-modify-writes over the offline queue could
 *  interleave and last-write-wins dropped a queued entry. The per-name
 *  in-memory mutex closes the same-tab half; cross-tab was never possible
 *  without storage and stays delegated to server-side idempotency. */
describe("withLock in-memory fallback (pentest 2026-09-29 T-1)", () => {
  /** The storage-free world: no navigator.locks AND no window at all. */
  const enterStorageFreeWorld = (): void => {
    vi.stubGlobal("navigator", {});
    delete (globalThis as { window?: unknown }).window;
  };
  const leaveStorageFreeWorld = (): void => {
    vi.unstubAllGlobals();
    (globalThis as { window?: unknown }).window = realWindow;
  };

  it("serializes concurrent sections on one lock name — never overlapping", async () => {
    enterStorageFreeWorld();
    try {
      let active = 0;
      let maxActive = 0;
      const section = (label: string): Promise<string> =>
        withLock("queue-flush", async () => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 5 + Math.random() * 5));
          active -= 1;
          return label;
        });
      const results = await Promise.all(["a", "b", "c"].map(section));
      expect(results.sort()).toEqual(["a", "b", "c"]);
      expect(maxActive).toBe(1);
    } finally {
      leaveStorageFreeWorld();
    }
  });

  it("preserves each section's result and lets a REJECTING section release the chain", async () => {
    enterStorageFreeWorld();
    try {
      const boom = withLock("faulty", async () => {
        throw new Error("section failed");
      });
      await expect(boom).rejects.toThrow("section failed");
      // The failure must not wedge the name: the next section still runs,
      // and its result reaches the caller untouched.
      await expect(withLock("faulty", async () => "recovered")).resolves.toBe("recovered");
    } finally {
      leaveStorageFreeWorld();
    }
  });

  it("different lock names interleave — the fallback serializes per name only", async () => {
    enterStorageFreeWorld();
    try {
      let active = 0;
      let maxActive = 0;
      const section = (name: string): Promise<string> =>
        withLock(name, async () => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 5));
          active -= 1;
          return name;
        });
      const results = await Promise.all([section("queue-flush"), section("reconcile"), section("queue-flush")]);
      expect(results.sort()).toEqual(["queue-flush", "queue-flush", "reconcile"]);
      // Two DISTINCT names were genuinely concurrent — per-name exclusion
      // did not degrade into a global lock.
      expect(maxActive).toBe(2);
    } finally {
      leaveStorageFreeWorld();
    }
  });
});
