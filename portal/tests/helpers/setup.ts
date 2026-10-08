import { drainPortalDraftWritesForTests, runTestControl } from "./testControl";
import "fake-indexeddb/auto";
/** Node-runtime window shim: the views read location.origin,
 *  localStorage and sessionStorage through the platform seam; tests need
 *  all three to exist.  sessionStorage is a SEPARATE map from localStorage
 *  so the L-75 anchor-store decision (sessionStorage first, localStorage
 *  fallback) is observable exactly as in a browser. */
const mem = new Map<string, string>();
const sessionMem = new Map<string, string>();
const makeStorage = (store: Map<string, string>) => ({
  get length() { return store.size; },
  key: (index: number) => [...store.keys()][index] ?? null,
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
  clear: () => void store.clear(),
});
// Minimal EventTarget (2026-09-19): the App registers real listeners
// (idle-lock bump, bfcache pageshow) — a no-op addEventListener left them
// untestable. dispatchEvent takes any object with a .type so tests can
// synthesize events (e.g. a persisted pageshow) without a DOM.
const listeners = new Map<string, Set<(event: unknown) => void>>();

// 2026-09-26 audit round (idle lock): the visibilitychange handler
// registers on document (the event does not bubble to window), so the shim
// needs a document too — its OWN listener map, a mutable `hidden` flag the
// tests flip, and the same dispatchEvent shape as window.
const documentListeners = new Map<string, Set<(event: unknown) => void>>();

// The shim is for the DEFAULT node environment only. The jest-axe a11y
// suite (audit H-9c, delivered 2026-09-22) runs under
// `@vitest-environment jsdom`, where a REAL window exists — installing the
// shim there would replace it and break DOM rendering + axe.
if (typeof (globalThis as { window?: unknown }).window === "undefined") {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://localhost:5173" },
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners.has(type)) listeners.set(type, new Set());
        listeners.get(type)!.add(listener as (event: unknown) => void);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        listeners.get(type)?.delete(listener as (event: unknown) => void);
      },
      dispatchEvent: (event: { type: string }) => {
        for (const listener of listeners.get(event.type) ?? []) {
          listener(event);
        }
        return true;
      },
      print: () => undefined,
      localStorage: makeStorage(mem),
      sessionStorage: makeStorage(sessionMem),
    },
  });
}

if (typeof (globalThis as { document?: unknown }).document === "undefined") {
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      hidden: false,
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!documentListeners.has(type)) documentListeners.set(type, new Set());
        documentListeners.get(type)!.add(listener as (event: unknown) => void);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        documentListeners.get(type)?.delete(listener as (event: unknown) => void);
      },
      dispatchEvent: (event: { type: string }) => {
        for (const listener of documentListeners.get(event.type) ?? []) {
          listener(event);
        }
        return true;
      },
    },
  });
}

// Keep encrypted draft slots isolated per test; production has durable IndexedDB only.
import { beforeEach } from "vitest";

import { setKvBackendForTests } from "../../src/kvstore";
beforeEach(async () => {
  await drainPortalDraftWritesForTests();
  const drafts = new Map<string,string>();
  runTestControl(setKvBackendForTests, { getItem: async key => drafts.get(key) ?? null, setItem: async (key,value) => { drafts.set(key,value); }, removeItem: async key => { drafts.delete(key); }, keys: async () => [...drafts.keys()] });
});
