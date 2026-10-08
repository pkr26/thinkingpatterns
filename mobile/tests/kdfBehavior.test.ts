import { afterEach, expect, it, vi } from "vitest";
import { engine } from "./helpers/nodeEngine";
import { deriveAuthKey, deriveDataKey, deriveMasterKey, deriveMasterKeyAsync, zeroize } from "../src/crypto/kdf";

afterEach(() => vi.restoreAllMocks());

it("derives the interoperable native password key with the declared cost, length and digest", () => {
  const original = engine.pbkdf2Sync, password = "native-password", salt = Buffer.alloc(8, 3);
  const expected = original(password, salt, 100000, 32, "sha256");
  const operation = vi.spyOn(engine, "pbkdf2Sync");
  expect(deriveMasterKey(password, salt, 100000)).toEqual(expected);
  expect(operation).toHaveBeenLastCalledWith(password, salt, 100000, 32, "sha256");
  deriveMasterKey(password, salt);
  expect(operation).toHaveBeenLastCalledWith(password, salt, 600000, 32, "sha256");
  expect(() => deriveMasterKey(password, Buffer.alloc(7))).toThrow("salt must be at least 8 bytes");
  expect(() => deriveMasterKey(password, salt, 99999)).toThrow("iterations must be at least 100000 (got 99999; the cross-platform contract is 600000)");
});

it("settles malformed async derivations with actionable failures before dispatching native work", async () => {
  for (const [salt, iterations, message] of [
    [Buffer.alloc(7), 100000, "salt must be at least 8 bytes"],
    [Buffer.alloc(8), 99999, "iterations must be at least 100000 (got 99999; the cross-platform contract is 600000)"],
  ] as const) {
    let state = "pending", error: unknown;
    void deriveMasterKeyAsync("password", salt, iterations).then(() => { state = "resolved"; }, reason => { state = "rejected"; error = reason; });
    for (let turn = 0; turn < 4; turn++) await Promise.resolve();
    expect(state).toBe("rejected"); expect(error).toBeInstanceOf(Error); expect((error as Error).message).toBe(message);
  }
});

it("returns independent domain-separated keys while scrubbing engine-owned HKDF results", () => {
  const original = engine.hkdfSync, master = Buffer.alloc(32, 5);
  const auth = Buffer.from(original("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const data = Buffer.from(original("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/data/v1"), 32));
  const held: ArrayBuffer[] = [];
  vi.spyOn(engine, "hkdfSync").mockImplementation((...args) => { const result = original(...args); held.push(result); return result; });
  expect(deriveAuthKey(master)).toEqual(auth); expect(deriveDataKey(master)).toEqual(data);
  expect(held).toHaveLength(2);
  for (const bytes of held) expect(new Uint8Array(bytes).every(byte => byte === 0)).toBe(true);
  expect(master).toEqual(Buffer.alloc(32, 5));
  zeroize(undefined, null, master); expect(master).toEqual(Buffer.alloc(32));
});
