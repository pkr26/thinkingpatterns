/**
 * Vault lifecycle: memory-only key custody, zeroization on rotation and
 * lock, locked-access failure, and observer notification semantics.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

import { vault } from "../src/vault";

const keysOf = (fill: number) => ({
  masterKey: Buffer.alloc(32, fill),
  authKey: Buffer.alloc(32, fill + 1),
  dataKey: Buffer.alloc(32, fill + 2),
});

beforeEach(() => {
  vault.lock(); // reset to a known locked state; also drops stale listeners? (it does not — see below)
});

describe("vault", () => {
  it("starts locked: get() throws and isUnlocked() is false", () => {
    expect(vault.isUnlocked()).toBe(false);
    expect(() => vault.get()).toThrow("vault is locked");
  });

  it("unlock stores keys and notifies subscribers; get() returns them", () => {
    const listener = vi.fn();
    const unsubscribe = vault.subscribe(listener);
    const keys = keysOf(1);
    vault.unlock(keys);
    expect(vault.isUnlocked()).toBe(true);
    // L5: get() returns a fresh object each call — callers cannot mutate the
    // vault's own reference — while sharing the underlying buffers so
    // zeroize-on-lock still reaches every copy.
    expect(vault.get()).toStrictEqual(keys);
    expect(listener).toHaveBeenCalledTimes(1);

    // The master key is zeroized on hand-off: only auth/data remain useful.
    expect(keys.masterKey.equals(Buffer.alloc(32))).toBe(true);
    expect(keys.authKey.equals(Buffer.alloc(32, 2))).toBe(true);

    unsubscribe();
  });

  it("re-unlocking zeroizes the previous session's keys first", () => {
    const first = keysOf(10);
    vault.unlock(first);
    vault.unlock(keysOf(20));
    expect(first.authKey.equals(Buffer.alloc(32))).toBe(true);
    expect(first.dataKey.equals(Buffer.alloc(32))).toBe(true);
    expect(vault.get().authKey.equals(Buffer.alloc(32, 21))).toBe(true);
  });

  it("lock zeroizes the current keys, clears state and notifies", () => {
    const keys = keysOf(30);
    vault.unlock(keys);
    const listener = vi.fn();
    vault.subscribe(listener);
    vault.lock();
    expect(vault.isUnlocked()).toBe(false);
    expect(keys.authKey.equals(Buffer.alloc(32))).toBe(true);
    expect(keys.dataKey.equals(Buffer.alloc(32))).toBe(true);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(() => vault.get()).toThrow("vault is locked");
  });

  it("lock() on an already-locked vault is a safe no-op that still notifies", () => {
    const listener = vi.fn();
    vault.subscribe(listener);
    vault.lock();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("unsubscribe stops further notifications", () => {
    const listener = vi.fn();
    const unsubscribe = vault.subscribe(listener);
    vault.unlock(keysOf(40));
    unsubscribe();
    vault.lock();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("notifies every subscribed listener", () => {
    const a = vi.fn();
    const b = vi.fn();
    vault.subscribe(a);
    const offB = vault.subscribe(b);
    vault.unlock(keysOf(50));
    offB();
    vault.lock();
    expect(a).toHaveBeenCalledTimes(2);
    expect(b).toHaveBeenCalledTimes(1);
  });
});
