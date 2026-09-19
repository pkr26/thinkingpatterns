/** Node-runtime window shim: the views read location.origin and
 * localStorage through the platform seam; tests need both to exist. */
const mem = new Map<string, string>();
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
    localStorage: {
      get length() { return mem.size; },
      key: (index: number) => [...mem.keys()][index] ?? null,
      getItem: (k: string) => mem.get(k) ?? null,
      setItem: (k: string, v: string) => void mem.set(k, v),
      removeItem: (k: string) => void mem.delete(k),
      clear: () => void mem.clear(),
    },
  },
});
