/** The memory-only key vault: unlock/lock lifecycle, owner binding,
 *  zeroization on lock, and observable subscription. */
import { describe, expect, it, vi } from "vitest";
import { vault } from "../src/vault";
import type { Bytes } from "../src/crypto/core";

const keyBytes = (seed: number): Bytes => {
  const out = new Uint8Array(new ArrayBuffer(32));
  out.fill(seed);
  return out;
};

describe("vault", () => {
  it("starts locked and get() throws", () => {
    vault.lock(); // normalize state between tests
    expect(vault.isUnlocked()).toBe(false);
    expect(() => vault.get()).toThrow("vault is locked");
    expect(vault.ownerUserId()).toBeNull();
  });

  it("unlock stores keys bound to the account and zeroes the master key", () => {
    const master = keyBytes(9);
    const authKey = keyBytes(1);
    const dataKey = keyBytes(2);
    vault.unlock({ authKey, dataKey, masterKey: master }, "user-1");
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("user-1");
    expect([...master]).toEqual(new Array<number>(32).fill(0));
    expect(vault.get().dataKey).toBe(dataKey);
  });

  it("get() returns a fresh object per call (no reference to vault state)", () => {
    vault.unlock({ authKey: keyBytes(1), dataKey: keyBytes(2) }, "user-1");
    const first = vault.get();
    const second = vault.get();
    expect(first).not.toBe(second);
    // The buffers are shared ON PURPOSE: zeroize-on-lock must reach copies.
    expect(first.dataKey).toBe(second.dataKey);
  });

  it("lock() zeroizes both keys, clears the owner, and notifies", () => {
    const listener = vi.fn();
    const off = vault.subscribe(listener);
    const authKey = keyBytes(3);
    const dataKey = keyBytes(4);
    vault.unlock({ authKey, dataKey }, "user-2");
    expect(listener).toHaveBeenCalledTimes(1); // unlock notified
    vault.lock();
    expect(listener).toHaveBeenCalledTimes(2); // lock notified
    expect([...authKey]).toEqual(new Array<number>(32).fill(0));
    expect([...dataKey]).toEqual(new Array<number>(32).fill(0));
    expect(vault.isUnlocked()).toBe(false);
    expect(vault.ownerUserId()).toBeNull();
    off();
    vault.lock();
    expect(listener).toHaveBeenCalledTimes(2); // unsubscribed
  });

  it("a second unlock zeroizes the previous keys (no orphaned live key)", () => {
    const first = { authKey: keyBytes(5), dataKey: keyBytes(6) };
    vault.unlock(first, "user-1");
    vault.unlock({ authKey: keyBytes(7), dataKey: keyBytes(8) }, "user-1");
    expect([...first.authKey]).toEqual(new Array<number>(32).fill(0));
    expect([...first.dataKey]).toEqual(new Array<number>(32).fill(0));
    vault.lock();
  });
});
