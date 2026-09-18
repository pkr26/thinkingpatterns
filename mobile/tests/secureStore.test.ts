/** Device-key custody regression tests: ciphertext may use AsyncStorage;
 * its key must not. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as Keychain from "react-native-keychain";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";

beforeEach(() => {
  storage.__reset();
  (Keychain as unknown as { __reset: () => void }).__reset();
  setSecureStoreBackend(null);
});

describe("secureStore", () => {
  it("round-trips encrypted values without persisting plaintext or a device key in AsyncStorage", async () => {
    await secureStore.setItem("@mindpattern/token", "tok-secret-value");
    expect(await secureStore.getItem("@mindpattern/token")).toBe("tok-secret-value");
    const encrypted = await storage.getItem("@mindpattern/token");
    expect(encrypted).not.toContain("tok-secret-value");
    expect(await storage.getItem("@mindpattern/device_k")).toBeNull();
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })).toMatchObject({
      username: "mindpattern-device-key",
    });
  });

  it("uses random encryption nonces for repeated plaintext values", async () => {
    await secureStore.setItem("a", "same");
    await secureStore.setItem("b", "same");
    expect(await storage.getItem("a")).not.toBe(await storage.getItem("b"));
  });

  it("reads corrupt payloads as absent rather than throwing", async () => {
    await secureStore.setItem("k", "v");
    await storage.setItem("k", "not-a-valid-envelope");
    expect(await secureStore.getItem("k")).toBeNull();
  });

  it("migrates a valid legacy device key into Keychain then removes the file copy", async () => {
    const legacy = Buffer.alloc(32, 9).toString("base64");
    await storage.setItem("@mindpattern/device_k", legacy);

    await secureStore.setItem("k", "v");
    expect(await storage.getItem("@mindpattern/device_k")).toBeNull();
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })).toMatchObject({
      password: legacy,
    });
    expect(await secureStore.getItem("k")).toBe("v");
  });

  it("removes malformed legacy key material instead of retaining it in AsyncStorage", async () => {
    await storage.setItem("@mindpattern/device_k", Buffer.alloc(31, 9).toString("base64"));
    await secureStore.setItem("k", "v");
    expect(await storage.getItem("@mindpattern/device_k")).toBeNull();
    expect(await secureStore.getItem("k")).toBe("v");
  });

  it("does not cache an unpersisted device key when native custody fails", async () => {
    const failing = {
      readDeviceKey: async () => null,
      writeDeviceKey: async () => { throw new Error("secure hardware unavailable"); },
      getItem: async (key: string) => storage.getItem(key),
      setItem: async (key: string, value: string) => storage.setItem(key, value),
      removeItem: async (key: string) => storage.removeItem(key),
    };
    setSecureStoreBackend(failing);
    await expect(secureStore.setItem("k", "v")).rejects.toThrow("secure hardware unavailable");
    expect(await storage.getItem("k")).toBeNull();
    setSecureStoreBackend(null);
    await secureStore.setItem("k", "v");
    expect(await secureStore.getItem("k")).toBe("v");
  });

  it("accepts a test-injected secure backend without touching AsyncStorage", async () => {
    const values = new Map<string, string>();
    const backend = {
      readDeviceKey: async () => values.get("device") ?? null,
      writeDeviceKey: async (value: string) => void values.set("device", value),
      getItem: async (key: string) => values.get(key) ?? null,
      setItem: async (key: string, value: string) => void values.set(key, value),
      removeItem: async (key: string) => void values.delete(key),
    };
    try {
      setSecureStoreBackend(backend);
      await secureStore.setItem("token", "private");
      expect(await storage.getItem("token")).toBeNull();
      expect(await secureStore.getItem("token")).toBe("private");
    } finally {
      setSecureStoreBackend(null);
    }
  });
});
