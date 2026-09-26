/** React 19 requires an explicit act() environment outside jsdom;
 *  without it every act() warns and update flushing is unreliable. */
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/** Node-runtime window shim: views read location.origin, localStorage and
 *  sessionStorage through the platform seam; tests need all three to
 *  exist. sessionStorage is a SEPARATE map from localStorage so
 *  per-tab vs persistent behavior is observable exactly as in a browser. */
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
// Minimal EventTarget: App and the platform seam register real listeners
// (online/offline, visibility, pageshow); dispatchEvent takes any object
// with a .type so tests can synthesize events without a DOM.
const listeners = new Map<string, Set<(event?: unknown) => void>>();

// The shim is for the DEFAULT node environment only. A future a11y suite
// runs under `@vitest-environment jsdom`, where a REAL window exists —
// installing the shim there would replace it and break DOM rendering.
if (typeof (globalThis as { window?: unknown }).window === "undefined") {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://localhost:5173" },
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners.has(type)) listeners.set(type, new Set());
        listeners.get(type)!.add(listener);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        listeners.get(type)?.delete(listener);
      },
      dispatchEvent: (event: { type: string }) => {
        for (const listener of listeners.get(event.type) ?? []) {
          listener(event);
        }
        return true;
      },
      localStorage: makeStorage(mem),
      sessionStorage: makeStorage(sessionMem),
    },
  });
}
