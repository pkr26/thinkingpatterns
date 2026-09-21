/** Device-key custody regression tests: ciphertext may use AsyncStorage;
 * its key must not. */
import { beforeEach, describe, expect, it } from "vitest";
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

  it("fails closed when Keychain REJECTS the write (returns false), never falling back to AsyncStorage", async () => {
    // Mutation-campaign pin (2026-09-18, mutant F8): making writeDeviceKey
    // park the device key in AsyncStorage on Keychain rejection survived
    // the whole suite — the false-return seam (vs a thrown error) was never
    // exercised. Custody must fail closed: no throw-less degradation into
    // the unencrypted plist/SQLite store.
    (Keychain as unknown as { __failWrites: (v: boolean) => void }).__failWrites(true);
    try {
      await expect(secureStore.setItem("k", "v")).rejects.toThrow("device secure storage rejected");
      expect(await storage.getItem("@mindpattern/device_k")).toBeNull();
      expect(await storage.getItem("k")).toBeNull();
    } finally {
      (Keychain as unknown as { __failWrites: (v: boolean) => void }).__failWrites(false);
    }
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

  it("reuses the persisted Keychain key across a restart instead of regenerating it", async () => {
    await secureStore.setItem("first", "value-one");
    const persisted = (await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })) as {
      password: string;
    };

    // Simulate a process restart: nothing in memory, same Keychain bytes.
    setSecureStoreBackend(null);
    await secureStore.setItem("second", "value-two");

    const after = (await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })) as {
      password: string;
    };
    expect(after.password).toBe(persisted.password);
    // Ciphertext from before the restart still decrypts — proof the key
    // was reused, not rotated.
    expect(await secureStore.getItem("first")).toBe("value-one");
  });

  it("regenerates a corrupt (wrong-length) Keychain key and keeps the store usable", async () => {
    await Keychain.setGenericPassword("mindpattern-device-key", Buffer.alloc(16, 3).toString("base64"), {
      service: "com.mindpattern.session-device-key.v1",
    });
    await secureStore.setItem("k", "v");
    const after = (await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })) as {
      password: string;
    };
    expect(Buffer.from(after.password, "base64")).toHaveLength(32);
    expect(await secureStore.getItem("k")).toBe("v");
  });

  it("concurrent first callers share ONE device-key generation (single flight)", async () => {
    let reads = 0;
    const slowBackend = {
      readDeviceKey: async () => {
        reads += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return null;
      },
      writeDeviceKey: async (value: string) => {
        await Keychain.setGenericPassword("mindpattern-device-key", value, {
          service: "com.mindpattern.session-device-key.v1",
        });
      },
      getItem: async (key: string) => storage.getItem(key),
      setItem: async (key: string, value: string) => storage.setItem(key, value),
      removeItem: async (key: string) => storage.removeItem(key),
    };
    setSecureStoreBackend(slowBackend);
    await Promise.all([
      secureStore.setItem("a", "one"),
      secureStore.setItem("b", "two"),
      secureStore.setItem("c", "three"),
    ]);

    // Without the single-flight keyPromise, the three overlapping first
    // calls each read null, generate DIFFERENT keys, and race their writes:
    // half the ciphertext becomes undecryptable after a restart.
    expect(reads).toBe(1);
    expect(await secureStore.getItem("a")).toBe("one");
    expect(await secureStore.getItem("b")).toBe("two");
    expect(await secureStore.getItem("c")).toBe("three");
    setSecureStoreBackend(null);
    // Still decryptable after the backend swap drops the in-memory cache.
    expect(await secureStore.getItem("a")).toBe("one");
  });

  it("migrates a legacy bare-base64 value envelope on read and rewrites it as v1", async () => {
    await secureStore.setItem("seed", "x"); // establish the device key
    const direct = await storage.getItem("seed");
    expect(direct).toBeTruthy();

    // Write a legacy-format value (bare base64 ciphertext, no envelope)
    // encrypted under the SAME device key, as an older build would have.
    const { encrypt } = await import("../src/crypto/envelope");
    const persisted = (await Keychain.getGenericPassword({ service: "com.mindpattern.session-device-key.v1" })) as {
      password: string;
    };
    const key = Buffer.from(persisted.password, "base64");
    const legacyBlob = encrypt(key, Buffer.from("legacy-secret", "utf8")).toString("base64");
    await storage.setItem("legacy-value", legacyBlob);
    expect((await storage.getItem("legacy-value")) as string).not.toContain("{");

    expect(await secureStore.getItem("legacy-value")).toBe("legacy-secret");
    const rewritten = await storage.getItem("legacy-value");
    expect(rewritten).toBeTruthy();
    expect(rewritten!.startsWith("{")).toBe(true); // now a v1 envelope
    expect(rewritten).not.toContain("legacy-secret");
  });

  it("reads unknown envelope versions and malformed ciphertext as absent", async () => {
    await secureStore.setItem("seed", "x");
    await storage.setItem("v2-envelope", JSON.stringify({ v: 2, c: "AAAA" }));
    await storage.setItem("c-array", JSON.stringify({ v: 1, c: ["not", "a", "string"] }));
    await storage.setItem("not-json-object", "{not json");
    await storage.setItem("bare-short", "AAAA");

    expect(await secureStore.getItem("v2-envelope")).toBeNull();
    expect(await secureStore.getItem("c-array")).toBeNull();
    expect(await secureStore.getItem("not-json-object")).toBeNull();
    expect(await secureStore.getItem("bare-short")).toBeNull();
  });
});

describe("secureStore Keychain accessibility class (audit fix 9, 2026-09-21)", () => {
  it("the device key demands a passcode, matching the biometric wrap's class", async () => {
    // WHEN_PASSCODE_SET_THIS_DEVICE_ONLY, not the weaker WHEN_UNLOCKED
    // variant that left the bearer token OS-sandbox-only on a passcode-less
    // device.
    await secureStore.setItem("k", "v");
    const lastSet = (Keychain as unknown as {
      __lastSetCall(): { username: string; options?: Record<string, unknown> } | undefined;
    }).__lastSetCall();
    expect(lastSet?.username).toBe("mindpattern-device-key");
    expect(lastSet?.options?.accessible).toBe(Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY);
    expect(lastSet?.options?.accessible).not.toBe(Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY);
  });
});
