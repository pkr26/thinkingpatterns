import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv } from "node:crypto";
import * as Keychain from "react-native-keychain";
import * as native from "./helpers/keychainMock";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
const key = Buffer.alloc(32, 21);
beforeEach(() => { vi.restoreAllMocks(); native.__reset(); storage.__reset(); runTestControl(setSecureStoreBackend, null); });
afterEach(() => vi.restoreAllMocks());

it.each(["versioned", "legacy"])("opens an installed %s credential using the actual native keychain identity", async format => {
  const value = "installed original bearer", nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce);
  const blob = Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]).toString("base64");
  await Keychain.setGenericPassword("mindpattern-device-key", key.toString("base64"), { service: "com.mindpattern.session-device-key.v1" });
  await storage.setItem("@mindpattern/token", format === "versioned" ? JSON.stringify({ v: 1, c: blob }) : blob);
  expect(await secureStore.getItem("@mindpattern/token")).toBe(value);
  runTestControl(setSecureStoreBackend, null); expect(await secureStore.getItem("@mindpattern/token")).toBe(value);
});

it("does not adopt another native credential label as the session device key", async () => {
  const nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce), value = "foreign native identity bearer";
  const blob = Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]).toString("base64");
  await Keychain.setGenericPassword("other-keychain-owner", key.toString("base64"), { service: "com.mindpattern.session-device-key.v1" });
  await storage.setItem("@mindpattern/token", JSON.stringify({ v: 1, c: blob }));
  expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
});

it("keeps an installed native key authoritative when a stale legacy file key also remains", async () => {
  const nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce), value = "installed authoritative native bearer";
  const blob = Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]).toString("base64");
  await Keychain.setGenericPassword("mindpattern-device-key", key.toString("base64"), { service: "com.mindpattern.session-device-key.v1" });
  await storage.setItem("@mindpattern/device_k", Buffer.alloc(32, 9).toString("base64")); await storage.setItem("@mindpattern/token", JSON.stringify({ v: 1, c: blob }));
  expect(await secureStore.getItem("@mindpattern/token")).toBe(value);
});

it("rejects a future envelope version and non-string ciphertext even when its embedded bytes authenticate", async () => {
  const nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce), value = "strict envelope bearer";
  const blob = Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]);
  await Keychain.setGenericPassword("mindpattern-device-key", key.toString("base64"), { service: "com.mindpattern.session-device-key.v1" });
  for (const record of [{ v: 2, c: blob.toString("base64") }, { v: 1, c: [...blob] }, { v: 1, c: blob.toJSON() }]) {
    await storage.setItem("@mindpattern/token", JSON.stringify(record)); expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  }
  await storage.setItem("@mindpattern/token", "{malformed envelope"); expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
});

it("recovers a malformed historical file key without an unnecessary native key publication", async () => {
  await storage.setItem("@mindpattern/device_k", Buffer.alloc(31, 9).toString("base64"));
  const write = Keychain.setGenericPassword; let accepted = false;
  vi.spyOn(Keychain, "setGenericPassword").mockImplementation(async (...args) => {
    if (accepted) throw new Error("Native service became unavailable after the first durable write");
    const result = await write(...args); accepted = true; return result;
  });
  await expect(secureStore.setItem("@mindpattern/token", "recovered bearer")).resolves.toBeUndefined();
  runTestControl(setSecureStoreBackend, null); expect(await secureStore.getItem("@mindpattern/token")).toBe("recovered bearer");
});
it("creates a usable credential when no historical key exists and its absent-slot deletion is unavailable", async () => {
  const remove = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => {
    if (slot === "@mindpattern/device_k") throw new Error("Native deletion service unavailable");
    return remove(slot);
  });
  await expect(secureStore.setItem("@mindpattern/token", "fresh installed bearer")).resolves.toBeUndefined();
  expect(await secureStore.getItem("@mindpattern/token")).toBe("fresh installed bearer");
});
it("rejects a malformed leading-brace record without waiting for native key custody", async () => {
  await storage.setItem("@mindpattern/token", "{invalid credential envelope");
  let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; }), read = Keychain.getGenericPassword;
  vi.spyOn(Keychain, "getGenericPassword").mockImplementation(async (...args) => { await held; return read(...args); });
  const reading = secureStore.getItem("@mindpattern/token");
  try {
    expect(await Promise.race([reading, new Promise<string>(resolve => setTimeout(() => resolve("blocked on native key"), 100))])).toBeNull();
  } finally { release(); await reading; }
});
