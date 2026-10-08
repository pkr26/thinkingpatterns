/** The platform seam: origin + localStorage/sessionStorage access degrade
 *  safely when the DOM is absent or storage is hostile. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { copyToClipboard, currentOrigin, downloadTextFile, localStore, printPage, randomBytes, sessionStore, visitAnchorStore } from "../src/platform";

const realWindow = (globalThis as { window?: unknown }).window;

it("prints through the host and returns independently generated random bytes of the requested size", () => {
  const print = vi.fn();
  vi.stubGlobal("window", { print });
  try {
    printPage();
    expect(print).toHaveBeenCalledTimes(1);
    const first = randomBytes(32);
    const second = randomBytes(32);
    expect(first).toBeInstanceOf(Uint8Array);
    expect(first).toHaveLength(32);
    expect(first.some(byte => byte !== 0)).toBe(true);
    expect(second).not.toEqual(first);
    expect(randomBytes(0)).toHaveLength(0);
    vi.stubGlobal("window", undefined);
    expect(() => printPage()).not.toThrow();
  } finally { vi.unstubAllGlobals(); }
});

it("returns an inert origin when the browser denies access to location", () => {
  vi.stubGlobal("window", { get location() { throw new Error("location denied"); } });
  try { expect(currentOrigin()).toBe(""); } finally { vi.unstubAllGlobals(); }
});

it("keeps both storage namespaces isolated and removes the writable-storage probe", () => {
  const local = (realWindow as {localStorage: Storage}).localStorage;
  const session = (realWindow as {sessionStorage: Storage}).sessionStorage;
  for (const [storage, seam] of [[local, localStore], [session, sessionStore]] as const) {
    storage.clear();
    storage.setItem("Stryker was here", "unrelated saved preference");
    storage.setItem("other.preference", "also keep");
    seam.set("visit.patient.one", "yesterday");
    seam.set("visit.patient.two", "today");
    seam.removePrefix("visit.patient.");
    expect(storage.length).toBe(2);
    expect(storage.getItem("Stryker was here")).toBe("unrelated saved preference");
    expect(storage.getItem("other.preference")).toBe("also keep");
  }
  const before = session.length;
  expect(visitAnchorStore.sessionBacked()).toBe(true);
  expect(session.length).toBe(before);
});

it("continues namespace cleanup past an empty slot reported by a changing host storage", () => {
  const entries = new Map([["visit.patient.one","today"],["unrelated.preference","keep"]]);
  const slots = [null,"visit.patient.one","unrelated.preference"];
  const storage = {get length(){return slots.length;},key:(index:number)=>slots[index]??null,getItem:(key:string)=>entries.get(key)??null,setItem:(key:string,value:string)=>entries.set(key,value),removeItem:(key:string)=>entries.delete(key)};
  vi.stubGlobal("window",{localStorage:storage,sessionStorage:storage});
  try {
    localStore.removePrefix("visit.");
    expect(entries.get("visit.patient.one")).toBeUndefined();
    expect(entries.get("unrelated.preference")).toBe("keep");
    entries.set("visit.patient.one","today");sessionStore.removePrefix("visit.");
    expect(entries.get("visit.patient.one")).toBeUndefined();
    expect(entries.get("unrelated.preference")).toBe("keep");
  }finally{vi.unstubAllGlobals();}
});

it("allocates no retained download blob when the host has no document",()=>{
  const live=new Set<Blob>();
  vi.stubGlobal("document",undefined);
  vi.stubGlobal("URL",{createObjectURL:(blob:Blob)=>{live.add(blob);return "blob:undeliverable";},revokeObjectURL:()=>{live.clear();}});
  try{downloadTextFile("codes.txt","sensitive one-time codes");expect(live.size).toBe(0);}finally{vi.unstubAllGlobals();}
});

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

it("preserves the downloaded recovery-code text and MIME type through the full delay", async () => {
  vi.useFakeTimers();
  const anchor = { href: "", download: "", click: vi.fn() };
  let downloaded: Blob | undefined;
  const revoked = vi.fn();
  vi.stubGlobal("document", { createElement: () => anchor });
  vi.stubGlobal("URL", {
    createObjectURL: (blob: Blob) => { downloaded = blob; return "blob:recovery-codes"; },
    revokeObjectURL: revoked,
  });
  try {
    downloadTextFile("recovery-codes.txt", "A2B3C4D5E6\nF7G8H9J2K3\n");
    expect(anchor.href).toBe("blob:recovery-codes");
    expect(anchor.download).toBe("recovery-codes.txt");
    expect(downloaded?.type).toBe("text/plain");
    await expect(downloaded?.text()).resolves.toBe("A2B3C4D5E6\nF7G8H9J2K3\n");
    vi.advanceTimersByTime(29_999);
    expect(revoked).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(revoked).toHaveBeenCalledExactlyOnceWith("blob:recovery-codes");
  } finally {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  }
});
