/**
 * H3: session material is encrypted at rest. A device backup must not
 * contain a greppable bearer token or username.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { secureStore } from "../src/secureStore";

beforeEach(() => {
  storage.__reset();
});

describe("secureStore", () => {
  it("round-trips values", async () => {
    await secureStore.setItem("@mindpattern/token", "tok-abc");
    expect(await secureStore.getItem("@mindpattern/token")).toBe("tok-abc");
    await secureStore.removeItem("@mindpattern/token");
    expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  });

  it("never persists the plaintext value", async () => {
    await secureStore.setItem("@mindpattern/token", "tok-secret-value");
    const raw = await storage.getItem("@mindpattern/token");
    expect(raw).not.toBeNull();
    expect(raw).not.toBe("tok-secret-value");
    expect(raw).not.toContain("tok-secret-value");
    // And nothing else in the store holds it either.
    for (const [key, value] of (storage as unknown as { __entries?: [string, string][] }).__entries ?? []) {
      expect(value).not.toContain("tok-secret-value");
    }
  });

  it("corrupt ciphertext reads as absent instead of throwing", async () => {
    await secureStore.setItem("k", "v");
    await storage.setItem("k", "garbage-not-ciphertext");
    expect(await secureStore.getItem("k")).toBeNull();
  });

  it("different values encrypt to different ciphertexts (random nonces)", async () => {
    await secureStore.setItem("a", "same");
    await secureStore.setItem("b", "same");
    expect(await storage.getItem("a")).not.toBe(await storage.getItem("b"));
  });

  // First-use race: two concurrent first calls used to both see null and
  // generate DIFFERENT device keys — the module cache then disagreed with
  // storage and half the ciphertext was undecryptable after a restart.
  it("concurrent first calls share a single device-key generation", async () => {
    // A fresh module graph (fresh key cache) backed by a fresh storage
    // instance: resetModules re-instantiates the aliased AsyncStorage mock,
    // so grab THAT instance to drive and inspect the race.
    vi.resetModules();
    const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
    const fresh = (await import("../src/secureStore")).secureStore;

    // Park the first device-key read so both callers enter initialization
    // before either finishes.
    const originalGetItem = freshStorage.getItem.bind(freshStorage);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let parked = true;
    freshStorage.getItem = async (key: string) => {
      if (parked && key === "@mindpattern/device_k") {
        parked = false;
        await gate;
      }
      return originalGetItem(key);
    };
    const setItemSpy = vi.spyOn(freshStorage, "setItem");

    const first = fresh.setItem("k1", "v1");
    const second = fresh.setItem("k2", "v2");
    release();
    await Promise.all([first, second]);

    // Exactly ONE key was generated and persisted...
    const keyWrites = setItemSpy.mock.calls.filter(([key]) => key === "@mindpattern/device_k");
    expect(keyWrites).toHaveLength(1);
    // ...and both values decrypt through the same module cache.
    expect(await fresh.getItem("k1")).toBe("v1");
    expect(await fresh.getItem("k2")).toBe("v2");
  });

  it("loads an existing device key from storage instead of regenerating (restart path)", async () => {
    vi.resetModules();
    const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
    const fresh = (await import("../src/secureStore")).secureStore;
    // Pre-seed a device key: the app restarted, the key is already on disk.
    const existing = Buffer.alloc(32, 9).toString("base64");
    await freshStorage.setItem("@mindpattern/device_k", existing);
    const setItemSpy = vi.spyOn(freshStorage, "setItem");

    await fresh.setItem("k", "v");

    expect(await fresh.getItem("k")).toBe("v");
    // No new key was generated or written over the existing one.
    expect(setItemSpy.mock.calls.filter(([key]) => key === "@mindpattern/device_k")).toHaveLength(0);
    expect(await freshStorage.getItem("@mindpattern/device_k")).toBe(existing);
  });

  it("a failed key initialization does not poison later callers", async () => {
    vi.resetModules();
    const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
    const fresh = (await import("../src/secureStore")).secureStore;
    const originalGetItem = freshStorage.getItem.bind(freshStorage);
    let broken = true;
    freshStorage.getItem = async (key: string) => {
      if (broken && key === "@mindpattern/device_k") throw new Error("storage read failed");
      return originalGetItem(key);
    };

    await expect(fresh.setItem("k", "v")).rejects.toThrow("storage read failed");

    // The failed promise was dropped: the next call initializes fresh.
    broken = false;
    await fresh.setItem("k", "v");
    expect(await fresh.getItem("k")).toBe("v");
  });

  // Disk-full path: if persisting the derived key fails, the unpersisted key
  // must NOT stay in the module cache — otherwise the retry short-circuits,
  // nothing is ever written, and the session's ciphertext is undecryptable
  // after a restart.
  it("a failed device-key persist does not cache the unpersisted key", async () => {
    vi.resetModules();
    const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
    const fresh = (await import("../src/secureStore")).secureStore;
    const originalSetItem = freshStorage.setItem.bind(freshStorage);
    let rejectedKey: string | null = null;
    let broken = true;
    freshStorage.setItem = async (key: string, value: string) => {
      if (broken && key === "@mindpattern/device_k") {
        rejectedKey = value;
        throw new Error("disk full");
      }
      return originalSetItem(key, value);
    };

    await expect(fresh.setItem("k", "v")).rejects.toThrow("disk full");
    expect(await freshStorage.getItem("@mindpattern/device_k")).toBeNull();

    // The failed init poisoned nothing: the next call retries the full
    // derive+persist instead of reusing the never-stored key.
    broken = false;
    await fresh.setItem("k", "v");
    const persisted = await freshStorage.getItem("@mindpattern/device_k");
    expect(persisted).not.toBeNull();
    expect(persisted).not.toBe(rejectedKey);
    expect(await fresh.getItem("k")).toBe("v");
  });

  it("a stored device key with the wrong length is treated as absent and replaced", async () => {
    vi.resetModules();
    const freshStorage = (await import("@react-native-async-storage/async-storage")).default as typeof storage;
    const fresh = (await import("../src/secureStore")).secureStore;
    await freshStorage.setItem("@mindpattern/device_k", Buffer.from("short").toString("base64"));

    await fresh.setItem("k", "v");

    const persisted = await freshStorage.getItem("@mindpattern/device_k");
    expect(persisted).not.toBeNull();
    expect(Buffer.from(persisted as string, "base64")).toHaveLength(32);
    expect(await fresh.getItem("k")).toBe("v");
  });
});
