// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://clinic.example","storageQuota":128}
// REVIEW DRAFT ONLY. No ordinary/typecheck/mutation execution or tracked-source promotion.
// Native DOM click + native Node Blob/URL/fetch protocol; no physical browser download claim.
import { Blob as NativeBlob } from "node:buffer";
import { URL as NativeURL } from "node:url";
import { expect, it, vi } from "vitest";
import { downloadTextFile, visitAnchorStore } from "../src/platform";

const nativeCreate = NativeURL.createObjectURL;
const nativeRevoke = NativeURL.revokeObjectURL;
const nativeFetch = globalThis.fetch.bind(globalThis);
const CONTENT = "Fathom recovery codes\nA2B3C4D5E6\nF7G8H9J2K3\n";

async function qualifyNativeBlobUrls(): Promise<void> {
  const uri = nativeCreate.call(NativeURL, new NativeBlob(["independent provider canary"], { type: "text/plain" }));
  try {
    const response = await nativeFetch(uri);
    expect(response.headers.get("content-type")).toBe("text/plain");
    await expect(response.text()).resolves.toBe("independent provider canary");
  } finally { nativeRevoke.call(NativeURL, uri); }
  await expect(nativeFetch(uri)).rejects.toBeDefined();
}

function observeOwnedNativeUrl() {
  const observation: { uri?: string } = {};
  const descriptor = Object.getOwnPropertyDescriptor(NativeURL, "createObjectURL");
  vi.stubGlobal("URL", NativeURL);
  vi.stubGlobal("Blob", NativeBlob);
  Object.defineProperty(NativeURL, "createObjectURL", {
    configurable: true,
    writable: true,
    value: (blob: NativeBlob) => {
      // Preserve the real allocation, input, return token and native registry.
      const uri = nativeCreate.call(NativeURL, blob);
      observation.uri = uri;
      return uri;
    },
  });
  return {
    observation,
    restore() {
      if (observation.uri !== undefined) nativeRevoke.call(NativeURL, observation.uri);
      if (descriptor) Object.defineProperty(NativeURL, "createObjectURL", descriptor);
      else Reflect.deleteProperty(NativeURL, "createObjectURL");
    },
  };
}

it("delivers the literal recovery file through a native anchor click and retires its emitted native URL after the public lease", async () => {
  await qualifyNativeBlobUrls();
  const owned = observeOwnedNativeUrl();
  const hostDocument = document;
  const createElement = hostDocument.createElement;
  const ownCreateDescriptor = Object.getOwnPropertyDescriptor(hostDocument, "createElement");
  const delivered: { uri?: string; pending?: Promise<{ filename: string; mime: string | null; text: string }> } = {};
  Object.defineProperty(hostDocument, "createElement", {
    configurable: true,
    writable: true,
    value: (...args: unknown[]) => {
      const element = Reflect.apply(createElement, hostDocument, args) as HTMLElement;
      if (element.tagName === "A") {
        const anchor = element as HTMLAnchorElement;
        anchor.addEventListener("click", event => {
          // Observe a genuine native DOM click; prevent unsupported physical navigation.
          event.preventDefault();
          delivered.uri = anchor.href;
          delivered.pending = nativeFetch(anchor.href).then(async response => ({
            filename: anchor.download,
            mime: response.headers.get("content-type"),
            text: await response.text(),
          }));
        });
      }
      return element;
    },
  });
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    downloadTextFile("recovery-codes.txt", CONTENT);
    const file = delivered.pending === undefined ? null : await delivered.pending;
    // First public oracle: actual emitted host file, not createElement/click counts.
    expect(file).toEqual({ filename: "recovery-codes.txt", mime: "text/plain", text: CONTENT });
    const uri = delivered.uri!;
    await vi.advanceTimersByTimeAsync(29_999);
    await expect(nativeFetch(uri).then(response => response.text())).resolves.toBe(CONTENT);
    await vi.advanceTimersByTimeAsync(1);
    // Public native grant/refusal after the declared lease, no error-copy assertion.
    await expect(nativeFetch(uri)).rejects.toBeDefined();
  } finally {
    try { await vi.runOnlyPendingTimersAsync(); }
    finally {
      if (ownCreateDescriptor) Object.defineProperty(hostDocument, "createElement", ownCreateDescriptor);
      else Reflect.deleteProperty(hostDocument, "createElement");
      owned.restore();
      vi.useRealTimers();
      vi.unstubAllGlobals();
    }
  }
});

it("leaves no readable owned native URL resource when the host has no document", async () => {
  await qualifyNativeBlobUrls();
  const owned = observeOwnedNativeUrl();
  vi.stubGlobal("document", undefined);
  try {
    downloadTextFile("recovery-codes.txt", CONTENT);
    const uri = owned.observation.uri;
    const readableOwnedResource = uri === undefined ? null : await nativeFetch(uri).then(response => response.text(), () => null);
    // Resource liveness only. Production emitted no anchor/href in this domain.
    // A readable captured allocation is NOT a finite delivered-download witness.
    expect(readableOwnedResource).toBeNull();
  } finally {
    owned.restore();
    vi.unstubAllGlobals();
  }
});

it("preserves an authored review anchor through the local fallback when real session storage lacks space", () => {
  const session = window.sessionStorage;
  const local = window.localStorage;
  const key = "mindpattern.lastVisit.clinician.patient";
  const date = "2026-09-20";
  const retained = "x".repeat(103);
  session.clear(); local.clear();
  try {
    // Real DOM Storage: 128-unit capacity, 8+103 existing units =>17 free.
    // Qualify capacities with native public operations, never inspect the private probe.
    session.setItem("retained", retained);
    expect(() => session.setItem(key, date)).toThrow();
    local.setItem(key, date);
    expect(local.getItem(key)).toBe(date);
    local.removeItem(key);
    expect(local.getItem(key)).toBeNull();
    visitAnchorStore.set(key, date);
    // First application oracle is the exported public roundtrip with independent date.
    expect(visitAnchorStore.get(key)).toBe(date);
    expect(local.getItem(key)).toBe(date);
    expect(session.getItem(key)).toBeNull();
    expect(session.getItem("retained")).toBe(retained);
  } finally { session.clear(); local.clear(); }
});

// Additive v2: native opaque-origin refusal and native local fallback, no helper patch.
import { createRequire } from "node:module";
const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
  JSDOM: new (html: string, options: { url: string }) => {
    window: Pick<Window, "localStorage" | "sessionStorage" | "close">;
  };
};
import { localStore } from "../src/platform";

it("degrades a genuine opaque-origin local storage refusal to the declared null public result", () => {
  const opaque = new JSDOM("", { url: "about:blank" });
  try {
    // Independently qualify the actual native opaque-origin Storage getter refusal.
    expect(() => opaque.window.localStorage).toThrow();
    vi.stubGlobal("window", opaque.window);
    // First application oracle: exported inert default, not exception text or a fake getter.
    expect(localStore.get("mindpattern.lastVisit.opaque.patient")).toBeNull();
  } finally {
    vi.unstubAllGlobals();
    opaque.window.close();
  }
});

it("reports no session backing after a genuine opaque-origin session storage refusal", () => {
  const opaque = new JSDOM("", { url: "about:blank" });
  try {
    expect(() => opaque.window.sessionStorage).toThrow();
    vi.stubGlobal("window", opaque.window);
    // First application oracle: exported backing decision on a genuine host refusal.
    expect(visitAnchorStore.sessionBacked()).toBe(false);
  } finally {
    vi.unstubAllGlobals();
    opaque.window.close();
  }
});

it("roundtrips the literal authored anchor through native local storage when the declared host has no session storage", () => {
  const localRealm = new JSDOM("", { url: "https://clinician.example" });
  const local = localRealm.window.localStorage;
  const key = "mindpattern.lastVisit.absent-session.patient";
  const date = "2026-09-20";
  try {
    // Qualify the real owned native Storage independently, then remove that fixture.
    local.setItem("independent.host.canary", "native local storage");
    expect(local.getItem("independent.host.canary")).toBe("native local storage");
    local.removeItem("independent.host.canary");
    // The seam explicitly supports a declared host lacking sessionStorage.
    vi.stubGlobal("window", { localStorage: local });
    visitAnchorStore.set(key, date);
    // First application oracle is independent literal public completion/value.
    expect(visitAnchorStore.get(key)).toBe(date);
    // Native final data is supplemental; no private storage/probe call count.
    expect(local.getItem(key)).toBe(date);
  } finally {
    vi.unstubAllGlobals();
    local.clear();
    localRealm.window.close();
  }
});
