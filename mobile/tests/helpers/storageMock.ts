/**
 * Minimal in-memory AsyncStorage replacement for tests (vitest aliases
 * @react-native-async-storage/async-storage to this module).
 */
const store = new Map<string, string>();

export default {
  getItem: async (key: string): Promise<string | null> => store.get(key) ?? null,
  setItem: async (key: string, value: string): Promise<void> => {
    store.set(key, String(value));
  },
  removeItem: async (key: string): Promise<void> => {
    store.delete(key);
  },
  multiSet: async (pairs: readonly [string, string][]): Promise<void> => {
    for (const [k, v] of pairs) store.set(k, String(v));
  },
  multiRemove: async (keys: readonly string[]): Promise<void> => {
    for (const k of keys) store.delete(k);
  },
  getAllKeys: async (): Promise<string[]> => Array.from(store.keys()),
  __reset: (): void => store.clear(),
};
