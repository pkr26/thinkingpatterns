/** Node-runtime window shim: the views read location.origin and
 * localStorage through the platform seam; tests need both to exist. */
const mem = new Map<string, string>();

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: { origin: "http://localhost:5173" },
    // 2026-09-17: App's idle auto-lock + session-expiry hook need
    // add/removeEventListener and print.
    addEventListener: (_type: string, _listener: () => void) => undefined,
    removeEventListener: (_type: string, _listener: () => void) => undefined,
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
