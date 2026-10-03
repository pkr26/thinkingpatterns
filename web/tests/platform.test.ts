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
  it("fails closed when Web Locks is unavailable despite usable localStorage", async () => {
    vi.stubGlobal("navigator",{});
    try { const ran=vi.fn(async()=>7); await expect(withLock("queue-flush",ran)).rejects.toThrow("Web Locks"); expect(ran).not.toHaveBeenCalled(); }
    finally { vi.unstubAllGlobals(); }
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

describe("unsafe localStorage lease fallback is refused", () => {
 it("simultaneous unsupported-host mutations never overlap or claim success",async()=>{
  vi.stubGlobal("navigator",{});const ran=vi.fn(async()=>"saved");
  try {const results=await Promise.allSettled([withLock("shared",ran),withLock("shared",ran),withLock("shared",ran)]);expect(results.every(result=>result.status==="rejected")).toBe(true);expect(ran).not.toHaveBeenCalled();}
  finally{vi.unstubAllGlobals();}
 });
 it("an old vote cannot be mistaken for permission to execute an unsupported mutation",async()=>{
  vi.stubGlobal("navigator",{});const storage=window.localStorage;const vote="mindpattern.lockvote.queue-flush.deadbeef";storage.setItem(vote,JSON.stringify({ts:Date.now()-60_000}));
  try {const ran=vi.fn(async()=>1);await expect(withLock("queue-flush",ran)).rejects.toThrow();expect(ran).not.toHaveBeenCalled();expect(storage.getItem(vote)).not.toBeNull();}
  finally{storage.removeItem(vote);vi.unstubAllGlobals();}
 });
 it("failed unsupported mutations do not create lock residue",async()=>{
  vi.stubGlobal("navigator",{});
  try{await expect(withLock("one-shot",async()=>1)).rejects.toThrow();const keys=Array.from({length:window.localStorage.length},(_,index)=>window.localStorage.key(index));expect(keys.filter(key=>key?.startsWith("mindpattern.lockvote."))).toEqual([]);}
  finally{vi.unstubAllGlobals();}
 });
});

/** T-1 (pentest 2026-09-29): with neither Web Locks NOR usable storage
 *  (locked-down private modes) the fallback used to run the section
 *  UNLOCKED — two same-tab read-modify-writes over the offline queue could
 *  interleave and last-write-wins dropped a queued entry. The per-name
 *  in-memory mutex closes the same-tab half; cross-tab was never possible
 *  without storage and stays delegated to server-side idempotency. */
describe("withLock without any shared exclusion primitive",()=>{
 it("rejects every mutation without running its critical section",async()=>{
   const saved = (globalThis as {window?:unknown}).window;
   vi.stubGlobal("navigator",{}); delete (globalThis as {window?:unknown}).window;
   try { const ran=vi.fn(async()=>1);await expect(withLock("queue-flush",ran)).rejects.toThrow("Safe shared storage locking is unavailable");expect(ran).not.toHaveBeenCalled(); }
   finally { vi.unstubAllGlobals();(globalThis as {window?:unknown}).window=saved; }
 });
});
