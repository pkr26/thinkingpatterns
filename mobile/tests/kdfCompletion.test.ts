import { describe, expect, it } from "vitest";
import { engine } from "./helpers/nodeEngine";
import { deriveMasterKeyAsync, MIN_ITERATIONS } from "../src/crypto/kdf";

describe("async derivation completes after the native callback", () => {
  it.each(["key", "error", "missing"])("settles the %s result without leaving callers suspended", async kind => {
    const original = engine.pbkdf2;
    const produced = Buffer.alloc(32, 7);
    let state = "pending";
    let result: Buffer | undefined;
    let error: unknown;
    let request: unknown[] | undefined;
    try {
      engine.pbkdf2 = ((_p: unknown, _s: unknown, _i: unknown, _k: unknown, _d: unknown, callback: (error: Error | null, key?: Buffer) => void) => {
        request = [_p, _s, _i, _k, _d];
        callback(kind === "error" ? new Error("native derivation failed") : null, kind === "key" ? produced : undefined);
      }) as typeof engine.pbkdf2;
      void deriveMasterKeyAsync("password", Buffer.alloc(8, 3), MIN_ITERATIONS).then(value => {
        state = "resolved"; result = value;
      }, reason => { state = "rejected"; error = reason; });
      // The callback already happened synchronously. Flush Promise jobs,
      // then assert completion explicitly instead of relying on a timeout.
      for (let turn = 0; turn < 4; turn++) await Promise.resolve();
      expect(state).toBe(kind === "key" ? "resolved" : "rejected");
      expect(request).toEqual(["password", Buffer.alloc(8, 3), 100000, 32, "sha256"]);
      if (kind === "key") {
        expect(result).toEqual(Buffer.alloc(32, 7));
        expect(produced).toEqual(Buffer.alloc(32));
      } else {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe(kind === "error" ? "native derivation failed" : "pbkdf2 produced no key");
      }
    } finally { engine.pbkdf2 = original; }
  });
});
