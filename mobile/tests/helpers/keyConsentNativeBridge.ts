/** Synthetic lowest native transport. It returns raw native [key,value]
 * tuples, including empty strings. The installed shipping JS facade owns
 * normalization, public Promises, callback delivery and error conversion. */
type NativeError = { message: string; key?: string };
type NativeCallback = (errors: NativeError[] | null, result?: Array<[string, string | null]>) => void;
const records = new Map<string, string>();
const deliver = (callback: () => void) => queueMicrotask(callback);

export function resetNativeTransport(): void { records.clear(); }
export default {
  multiGet(keys: string[], callback: NativeCallback): void {
    deliver(() => callback(null, keys.map(key => [key, records.get(key) ?? null])));
  },
  multiSet(pairs: Array<[string, string]>, callback: NativeCallback): void {
    deliver(() => { for (const [key, value] of pairs) records.set(key, value); callback(null); });
  },
  multiRemove(keys: string[], callback: NativeCallback): void {
    deliver(() => { for (const key of keys) records.delete(key); callback(null); });
  },
  getAllKeys(callback: (errors: NativeError[] | null, keys: string[]) => void): void {
    deliver(() => callback(null, [...records.keys()]));
  },
  clear(callback: NativeCallback): void { deliver(() => { records.clear(); callback(null); }); },
};
