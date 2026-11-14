import { expect, it, vi } from "vitest";

it("accepts locking before the application's first key handoff", async () => {
  vi.resetModules();
  const { vault } = await import("../src/vault");
  // Session cleanup is a public operation even on a fresh process. A
  // beforeEach cleanup would consume this observation before the test.
  expect(() => vault.lock()).not.toThrow();
  expect(vault.isUnlocked()).toBe(false);
  expect(vault.canReauthenticate()).toBe(false);
  expect(vault.ownerUserId()).toBeNull();
  expect(() => vault.get()).toThrow();
});

it("makes the first handed-off session usable with a known authentication key", async () => {
  vi.resetModules();
  const { vault } = await import("../src/vault");
  const keys = { masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 3) };
  try {
    vault.unlock(keys, "fresh-startup-owner");
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.canReauthenticate()).toBe(true);
    expect(vault.ownerUserId()).toBe("fresh-startup-owner");
    expect(vault.get()).toEqual({ authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 3), authKeyKnown: true });
    expect(keys.masterKey).toEqual(Buffer.alloc(32));
  } finally {
    vault.lock();
  }
});
