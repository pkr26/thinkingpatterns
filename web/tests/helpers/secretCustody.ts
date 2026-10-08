import { vi } from "vitest";

/** Narrow white-box security evidence: retain physical copies of a known
 * caller-owned secret while a real public operation runs. This observes
 * secret custody, without depending on allocation counts or source shape.
 * Prefer WebCrypto input/output observers whenever those expose the buffer.
 */
export async function observeSecretCopies<T>(secret: Uint8Array, operation: () => Promise<T>): Promise<{ result: T; copies: Uint8Array[] }> {
  const NativeBytes = Uint8Array, expected = secret.slice(), copies = new Set<Uint8Array>();
  const retain = (value: Uint8Array) => {
    if (value.buffer !== secret.buffer && value.length === expected.length && value.every((byte, i) => byte === expected[i])) copies.add(value);
  };
  const originalSet = NativeBytes.prototype.set;
  const observer = vi.spyOn(NativeBytes.prototype, "set").mockImplementation(function (this: Uint8Array, source: ArrayLike<number>, offset?: number) {
    originalSet.call(this, source, offset); retain(this);
  });
  const allocator = new Proxy(NativeBytes, { construct(target, argumentsList) {
    const value = Reflect.construct(target, argumentsList) as Uint8Array; retain(value); return value;
  } });
  vi.stubGlobal("Uint8Array", allocator);
  try { return { result: await operation(), copies: [...copies] }; }
  finally { observer.mockRestore(); vi.stubGlobal("Uint8Array", NativeBytes); expected.fill(0); }
}
