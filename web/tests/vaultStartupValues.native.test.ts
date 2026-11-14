import { expect, it, vi } from "vitest";

it("accepts a public lock before the first key handoff", async () => {
  vi.resetModules();
  const { vault } = await import("../src/vault");
  // This is the operation under test, inside the body, before any reset
  // through the vault API could consume the startup observation.
  expect(() => vault.lock()).not.toThrow();
  expect(vault.isUnlocked()).toBe(false);
  expect(vault.ownerUserId()).toBeNull();
  expect(() => vault.get()).toThrow();
});

it("makes the first handed-off keys and owner available to the caller", async () => {
  vi.resetModules();
  const { vault } = await import("../src/vault");
  const authKey = new Uint8Array(new ArrayBuffer(32)).fill(2);
  const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(3);
  const masterKey = new Uint8Array(new ArrayBuffer(32)).fill(1);
  try {
    vault.unlock({ authKey, dataKey, masterKey }, "first-key-owner");
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("first-key-owner");
    expect(vault.get()).toEqual({
      authKey: new Uint8Array(new ArrayBuffer(32)).fill(2),
      dataKey: new Uint8Array(new ArrayBuffer(32)).fill(3),
    });
    expect(vault.get().authKey).toBe(authKey);
    expect(vault.get().dataKey).toBe(dataKey);
    expect(masterKey).toEqual(new Uint8Array(new ArrayBuffer(32)));
  } finally {
    vault.lock();
  }
  expect(authKey).toEqual(new Uint8Array(new ArrayBuffer(32)));
  expect(dataKey).toEqual(new Uint8Array(new ArrayBuffer(32)));
  expect(vault.isUnlocked()).toBe(false);
  expect(vault.ownerUserId()).toBeNull();
});
