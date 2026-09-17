/** Node-runtime window shim: the views read location.origin and
 * localStorage through the platform seam; tests need both to exist. */
const mem = new Map<string, string>();

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: { origin: "http://localhost:5173" },
    localStorage: {
      getItem: (k: string) => mem.get(k) ?? null,
      setItem: (k: string, v: string) => void mem.set(k, v),
      removeItem: (k: string) => void mem.delete(k),
      clear: () => void mem.clear(),
    },
  },
});
