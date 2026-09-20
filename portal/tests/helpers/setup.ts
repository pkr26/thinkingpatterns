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
