import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, ApiError, canonicalOrigin, DEFAULT_BASE_URL, detailToMessage, parseServerUrl, setBaseUrl } from "../src/api/client";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { captureLocalWritePermit, changeLocalSessionOwner, installLocalDataKey } from "../src/localWriteGuard";
import * as Keychain from "react-native-keychain";
import * as keychainMock from "./helpers/keychainMock";
import Module from "node:module";
import * as fileSystem from "./helpers/expoFsMock";
import { originBoundStorageInventory } from "../src/accountStorage";

const USER = "dddddddddddddddddddddddddddddddd", OTHER = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
// Installed-client native credential names are inputs to the custody boundary.
const TOKEN = "@mindpattern/token", OWNER = "@mindpattern/user_id", NAME = "@mindpattern/username", PIN = "@mindpattern/pinned_origin";
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); keychainMock.__reset(); runTestControl(setSecureStoreBackend, null); });
afterEach(() => vi.restoreAllMocks());

it("adopts a still-current authentication attempt and publishes its usable identity", async () => {
  await expect(api.setSession("current-token", USER, "alice", { stillCurrent: () => true })).resolves.toBeUndefined();
  expect(await api.isLoggedIn()).toBe(true); expect(await api.getUserId()).toBe(USER); expect(await api.getUsername()).toBe("alice");
});

it("retires a session when an installed base setting cannot be parsed as an origin", async () => {
  await storage.setItem("@mindpattern/base_url", "::::corrupt-installed-origin"); await api.setSession("old-token", USER, "alice");
  await expect(setBaseUrl("https://new-trusted.example")).resolves.toBeNull();
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
});

it("retires an upgrade-era account's native key even when its owner inventory marker is absent", async () => {
  await api.setSession("old-token", USER, "alice");
  const service = `com.mindpattern.biometric-unlock.v1.${USER}`;
  await Keychain.setGenericPassword(USER, Buffer.alloc(32, 7).toString("base64"), { service });
  await expect(setBaseUrl("https://new-trusted.example")).resolves.toBeNull();
  expect(await Keychain.hasGenericPassword({ service })).toBe(false);
});

it("origin retirement invalidates fresh producers before the next login-state read", async () => {
  const key = Buffer.alloc(32, 7); await api.setSession("old-token", USER, "alice"); installLocalDataKey(USER, key);
  expect(() => captureLocalWritePermit(USER, key)).not.toThrow(); await setBaseUrl("https://new-trusted.example");
  expect(() => captureLocalWritePermit(USER, key)).toThrow();
});

it("keeps the documented lowercase, whitespace-free URL input grammar", () => {
  for (const candidate of ["https://example.test/path private", "HTTPS://example.test/path/http://inside.example"]) expect(parseServerUrl(candidate)).toBeNull();
});

it.each(["http://127.0.0.1:8000/installed/path", "http://localhost:8000/installed/path", "http://[::1]:8000/installed/path"])("pins the origin of a configured loopback base path (%s)", candidate => {
  expect(canonicalOrigin(candidate)).toBe("http://127.0.0.1:8000");
});

it("switches an empty installation when the native storage backend refuses an empty deletion batch", async () => {
  const remove = storage.multiRemove;
  vi.spyOn(storage, "multiRemove").mockImplementation(async slots => {
    if (slots.length === 0) throw new Error("native backend rejects an empty batch");
    return remove(slots);
  });
  await expect(setBaseUrl("https://new-empty-installation.example")).resolves.toBeNull();
  expect(await api.isLoggedIn()).toBe(false);
});

it("serves an installed current salt without waiting for an unnecessary native rewrite", async () => {
  await api.cacheSalt("alice", "installed-current-salt");
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const write = storage.setItem;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { await held; return write(slot, value); });
  const reading = api.getCachedSalt("alice");
  try {
    const result = await Promise.race([
      reading.then(value => ({ value })),
      new Promise<{ blocked: true }>(resolve => setTimeout(() => resolve({ blocked: true }), 100)),
    ]);
    expect(result).toEqual({ value: "installed-current-salt" });
  } finally { release(); await reading; }
});

it("rejects a retired queued server switch before an unavailable native origin lookup", async () => {
  let release!: () => void, entered!: () => void, firstRead = true;
  const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; }), read = storage.getItem;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot !== "@mindpattern/base_url") return read(slot);
    if (firstRead) { firstRead = false; entered(); await gate; return read(slot); }
    throw new Error("Native origin database is unavailable");
  });
  const first = setBaseUrl("https://first-queued.example").catch(error => error);
  await Promise.race([reached, first.then(() => { throw new Error("Server switch skipped its origin lookup"); })]);
  const retired = setBaseUrl("https://retired-queued.example").catch(error => error), replacement = setBaseUrl("https://replacement-queued.example").catch(error => error);
  release(); await first;
  expect(await retired).toMatchObject({ code: "stale_operation" }); await replacement;
});

it("rejects a retired queued cache before an unavailable native origin lookup", async () => {
  let release!: () => void, entered!: () => void, firstRead = true;
  const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; }), read = storage.getItem;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot !== "@mindpattern/base_url") return read(slot);
    if (firstRead) { firstRead = false; entered(); await gate; return read(slot); }
    throw new Error("Native origin database is unavailable");
  });
  const first = api.cacheSalt("alice", "first-cache").catch(error => error);
  await Promise.race([reached, first.then(() => { throw new Error("Cache write skipped its origin lookup"); })]);
  const retired = api.cacheKeyEnvelope("alice", { scheme: "v1", saltB64: "retired-cache", wrappedB64: null, kdfParams: null }).catch(error => error), replacement = api.setSession("replacement-token", OTHER, "bob").catch(error => error);
  release(); await first;
  expect(await retired).toMatchObject({ code: "stale_operation" }); await replacement;
});

it("does not resurrect an old origin's salt inventory through a delayed compatibility rewrite", async () => {
  await storage.setItem("@mindpattern/salt_YWxpY2U", JSON.stringify({ o: DEFAULT_BASE_URL, s: "installed-legacy-salt" }));
  const read = storage.getItem; let switched = false, switching: Promise<unknown> | undefined;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (slot === "@mindpattern/base_url" && !switched) { switched = true; switching = setBaseUrl("https://new-cache-origin.example"); }
    return value;
  });
  await api.getCachedSalt("alice"); expect(switched).toBe(true); await switching;
  expect(await originBoundStorageInventory()).toEqual([]);
});
it("refreshes an installed pre-version salt into the current native interoperability record", async () => {
  const slot = "@mindpattern/salt_YWxpY2U";
  await storage.setItem(slot, JSON.stringify({ o: DEFAULT_BASE_URL, s: "installed-pre-version-salt" }));
  expect(await api.getCachedSalt("alice")).toBe("installed-pre-version-salt");
  const current = JSON.parse((await storage.getItem(slot))!);
  expect(current).toEqual({ v: 1, o: DEFAULT_BASE_URL, s: "installed-pre-version-salt" });
});

it.each([
  ["read-identity", OTHER, "bob", true, null],
  ["retire-token", OTHER, "bob", false, null],
  ["write-identity", USER, "bob", false, null],
  ["write-username", USER, "alice", false, null],
  ["read-pin", USER, "alice", false, null],
  ["write-pin", USER, "alice", false, "http://127.0.0.1:8000"],
] as const)("authentication stops after its native %s boundary retires", async (boundary, owner, name, loggedIn, pin) => {
  await api.setSession("existing-token", OTHER, "bob"); await secureStore.removeItem(PIN);
  let retired = false;
  const retire = () => { retired = true; changeLocalSessionOwner(OTHER); };
  if (boundary === "read-identity" || boundary === "read-pin") {
    const read = secureStore.getItem;
    vi.spyOn(secureStore, "getItem").mockImplementation(async slot => {
      const value = await read(slot);
      if (!retired && slot === (boundary === "read-identity" ? OWNER : PIN)) retire();
      return value;
    });
  } else if (boundary === "retire-token") {
    const remove = secureStore.removeItem;
    vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => { await remove(slot); if (!retired && slot === TOKEN) retire(); });
  } else {
    const write = secureStore.setItem, target = boundary === "write-identity" ? OWNER : boundary === "write-username" ? NAME : PIN;
    vi.spyOn(secureStore, "setItem").mockImplementation(async (slot, value) => { await write(slot, value); if (!retired && slot === target) retire(); });
  }
  const error = await api.setSession("retired-token", USER, "alice").catch((error: unknown) => error);
  expect(retired).toBe(true); expect(error).toBeInstanceOf(ApiError); expect(error).toMatchObject({ code: "stale_operation" });
  expect(await api.getUserId()).toBe(owner); expect(await api.getUsername()).toBe(name); expect(await api.pinnedOrigin()).toBe(pin); expect(await api.isLoggedIn()).toBe(loggedIn);
});

it.each([1, 2, 3])("session clearing stops after native tuple removal %s retires", async boundary => {
  await api.setSession("old-token", USER, "alice"); const remove = secureStore.removeItem; let count = 0;
  vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => { await remove(slot); if (++count === boundary) changeLocalSessionOwner(OTHER); });
  await expect(api.clearSession()).rejects.toMatchObject({ code: "stale_operation" });
  expect(await api.getUserId()).toBe(boundary === 1 ? USER : null); expect(await api.getUsername()).toBe(boundary < 3 ? "alice" : null); expect(await api.isLoggedIn()).toBe(false);
});

it.each([1, 2, 3])("deleted-session cleanup stops after native tuple removal %s retires", async boundary => {
  await api.setSession("old-token", USER, "alice"); const remove = secureStore.removeItem; let count = 0;
  vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => { await remove(slot); if (++count === boundary) changeLocalSessionOwner(OTHER); });
  await expect(api.retireDeletedSession(USER)).rejects.toMatchObject({ code: "stale_operation" });
  expect(await api.getUserId()).toBe(boundary === 1 ? USER : null); expect(await api.getUsername()).toBe(boundary < 3 ? "alice" : null); expect(await api.isLoggedIn()).toBe(false);
});

it("serves a newer installed salt record that arrives during a legacy read", async () => {
  const next = "@mindpattern/salt_YWxpY2U", legacy = "@mindpattern/salt_alice";
  await storage.setItem(legacy, JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "legacy-salt" }));
  const read = storage.getItem; let encodedReads = 0;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot === next && ++encodedReads === 2) await storage.setItem(next, JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "newer-installed-salt" }));
    return read(slot);
  });
  expect(await api.getCachedSalt("alice")).toBe("newer-installed-salt");
  expect(await api.getCachedSalt("alice")).toBe("newer-installed-salt");
});

it("still serves a historical salt when the preferred native cache read fails", async () => {
  await storage.setItem("@mindpattern/salt_alice", JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "historical-salt" }));
  vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("preferred cache unavailable"));
  expect(await api.getCachedSalt("alice")).toBe("historical-salt");
});

it("degrades repeated failures reading both historical cache namespaces to no usable salt", async () => {
  vi.spyOn(storage, "getItem").mockRejectedValue(new Error("native cache database unavailable"));
  expect(await api.getCachedSalt("alice")).toBeNull();
});

it.each([
  ["before journal.example:12/private-notes after", "before after"],
  ["before journal.example:1/private-notes after", "before after"],
  ["1234", "request failed (400)"],
  ["123", "123"],
  ["1 23 4", "request failed (400)"],
  ["before1234after", "before after"],
] as const)("safe public error copy for %s", (input, expected) => {
  expect(detailToMessage(input, 400)).toBe(expected);
});

it("can switch an empty installation when native key deletion closes after its one required retirement", async () => {
  const remove = Keychain.resetGenericPassword; let retired = false;
  vi.spyOn(Keychain, "resetGenericPassword").mockImplementation(async options => {
    if (retired) throw new Error("Native Keychain retirement service closed");
    const result = await remove(options); retired = true; return result;
  });
  await expect(setBaseUrl("https://empty-retirement.example")).resolves.toBeNull();
  expect(await api.isLoggedIn()).toBe(false);
});

it.each([TOKEN, OWNER])("a server switch stops at retired native credential deletion %s", async boundary => {
  await api.setSession("old-token", USER, "alice"); const remove = secureStore.removeItem; let retired = false;
  vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => {
    if (retired) throw new Error("The replacement account owns native credential custody");
    await remove(slot); if (slot === boundary) { retired = true; changeLocalSessionOwner(OTHER); }
  });
  await expect(setBaseUrl("https://retired-native-credentials.example")).rejects.toMatchObject({ code: "stale_operation" });
  expect(retired).toBe(true);
});

it("a retired server switch keeps native biometric custody after its inventory read", async () => {
  await api.setSession("old-token", USER, "alice");
  const service = `com.mindpattern.biometric-unlock.v1.${USER}`;
  await Keychain.setGenericPassword(USER, Buffer.alloc(32, 7).toString("base64"), { service });
  const list = storage.getAllKeys; let retired = false;
  vi.spyOn(storage, "getAllKeys").mockImplementation(async () => {
    const values = await list(); if (!retired) { retired = true; changeLocalSessionOwner(OTHER); } return values;
  });
  await expect(setBaseUrl("https://retired-inventory.example")).rejects.toMatchObject({ code: "stale_operation" });
  expect(await Keychain.hasGenericPassword({ service })).toBe(true);
});

it.each(["base", "legacy-consent"])("reports retirement while publishing the native %s server setting", async boundary => {
  const write = storage.setItem, target = boundary === "base" ? "@mindpattern/base_url" : "@mindpattern/insecure_http_ok";
  let retired = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (retired) throw new Error("The replacement account owns native server preferences");
    await write(slot, value); if (slot === target) { retired = true; changeLocalSessionOwner(OTHER); }
  });
  await expect(setBaseUrl("https://retired-native-publication.example")).rejects.toMatchObject({ code: "stale_operation" });
  expect(retired).toBe(true);
});

it("keeps historical salt when encoded publication retires before historical removal", async () => {
  const old = "@mindpattern/salt_alice", next = "@mindpattern/salt_YWxpY2U", raw = JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "historic-during-retirement" });
  await storage.setItem(old, raw); const write = storage.setItem;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { await write(slot, value); if (slot === next) changeLocalSessionOwner(OTHER); });
  expect(await api.getCachedSalt("alice")).toBe("historic-during-retirement");
  expect(await storage.getItem(old)).toBe(raw);
});

it("does not return retired salt after its historical record was removed", async () => {
  const old = "@mindpattern/salt_alice", raw = JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "removed-during-retirement" });
  await storage.setItem(old, raw); const remove = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => { await remove(slot); if (slot === old) changeLocalSessionOwner(OTHER); });
  expect(await api.getCachedSalt("alice")).toBeNull();
});

it("rejects cache completion retired between its inner commit and public settlement", async () => {
  const write = storage.setItem; let retired = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    await write(slot, value);
    if (slot === "@mindpattern/salt_YWxpY2U") queueMicrotask(() => queueMicrotask(() => { retired = true; changeLocalSessionOwner(OTHER); }));
  });
  await expect(api.cacheSalt("alice", "committed-before-retirement")).rejects.toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true);
});

it("stops a retired origin calculation before accessing replacement native credentials", async () => {
  const read = storage.getItem; let retired = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (slot === "@mindpattern/base_url") queueMicrotask(() => queueMicrotask(() => { retired = true; changeLocalSessionOwner(OTHER); }));
    return value;
  });
  const credentials = secureStore.getItem;
  vi.spyOn(secureStore, "getItem").mockImplementation(slot => retired ? Promise.reject(new Error("Replacement credential storage is unavailable")) : credentials(slot));
  await expect(setBaseUrl("https://retired-calculation.example")).rejects.toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true);
});

it("does not adopt a newer transition's epoch after a delayed native owner lookup", async () => {
  await api.setSession("old-token", USER, "alice"); const read = secureStore.getItem; let retired = false;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === OWNER && !retired) { retired = true; changeLocalSessionOwner(OTHER); } return value; });
  await expect(setBaseUrl("https://retired-owner-lookup.example")).rejects.toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true);
  expect(await api.isLoggedIn()).toBe(true);
});

it("a retired origin cleanup does not publish server settings after its final inventory deletion", async () => {
  const stale = `@mindpattern/reminders_${USER}`; await storage.setItem(stale, JSON.stringify({ enabled: true, hour: 20, minute: 0 }));
  const remove = storage.multiRemove, write = storage.setItem; let retired = false;
  vi.spyOn(storage, "multiRemove").mockImplementation(async slots => { await remove(slots); if (slots.includes(stale)) { retired = true; changeLocalSessionOwner(OTHER); } });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => retired ? Promise.reject(new Error("Replacement preferences are unavailable")) : write(slot, value));
  await expect(setBaseUrl("https://retired-final-inventory.example")).rejects.toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true);
});
it("a retired biometric cleanup cannot cancel replacement native notifications", async () => {
  const pending = new Set(["replacement-account-reminder"]), linked = { requestPermission: async () => true, createTriggerNotification: async () => {}, cancelAllNotifications: async () => { pending.clear(); } };
  const loader = Module as unknown as { _load: (name: string, ...args: unknown[]) => unknown }, load = loader._load;
  vi.spyOn(loader, "_load").mockImplementation((name, ...args) => name === "@notifee/react-native" ? linked : load.call(Module, name, ...args));
  const biometrics = await import("../src/biometricUnlock"), erase = biometrics.eraseOriginBiometricUnlocks;
  vi.spyOn(biometrics, "eraseOriginBiometricUnlocks").mockImplementation(async owners => { await erase(owners); changeLocalSessionOwner(OTHER); });
  await expect(setBaseUrl("https://retired-native-notifications.example")).rejects.toMatchObject({ code: "stale_operation" }); expect([...pending]).toEqual(["replacement-account-reminder"]);
});
it("a retired native notification cleanup cannot delete replacement audio files", async () => {
  fileSystem.__resetFiles(); const native = await import("../src/nativeFeatures"), cancel = native.cancelOriginNotifications, file = `${fileSystem.documentDirectory}mindpattern-audio/replacement-account/retained.bin`;
  vi.spyOn(native, "cancelOriginNotifications").mockImplementation(async () => { const result = await cancel(); changeLocalSessionOwner(OTHER); fileSystem.__seedFile(file, "replacement encrypted audio"); return result; });
  await expect(setBaseUrl("https://retired-native-file-cleanup.example")).rejects.toMatchObject({ code: "stale_operation" }); expect(fileSystem.__hasFile(file)).toBe(true); fileSystem.__resetFiles();
});
it("a retired native file cleanup cannot delete newly published account preferences", async () => {
  fileSystem.__resetFiles(); const slot = `@mindpattern/reminders_${USER}`, oldValue = JSON.stringify({ enabled: false, hour: 19, minute: 0 }), newValue = JSON.stringify({ enabled: true, hour: 21, minute: 30 });
  await storage.setItem(slot, oldValue); const remove = fileSystem.deleteAsync.getMockImplementation()!; let retired = false;
  vi.spyOn(fileSystem, "deleteAsync").mockImplementation(async (uri, options) => { await remove(uri, options); if (uri === `${fileSystem.documentDirectory}mindpattern-audio/`) { retired = true; changeLocalSessionOwner(USER); await storage.setItem(slot, newValue); } });
  await expect(setBaseUrl("https://retired-native-inventory-cleanup.example")).rejects.toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true); const { getReminderPrefs } = await import("../src/reminders"); expect(await getReminderPrefs(USER)).toEqual({ enabled: true, hour: 21, minute: 30 }); fileSystem.__resetFiles();
});
it.each(["authenticate", "clear", "delete"])("a %s continuation refuses replacement native custody after its drain settles", async operation => {
  await api.setSession("old-token", USER, "alice"); let retired = false; const read = secureStore.getItem, remove = secureStore.removeItem;
  vi.spyOn(secureStore, "getItem").mockImplementation(slot => retired ? Promise.reject(new Error("Replacement account credential read unavailable")) : read(slot));
  vi.spyOn(secureStore, "removeItem").mockImplementation(slot => retired ? Promise.reject(new Error("Replacement account credential removal unavailable")) : remove(slot));
  const pending = (operation === "authenticate" ? api.setSession("retired-token", USER, "alice") : operation === "clear" ? api.clearSession() : api.retireDeletedSession(USER)).catch((error: unknown) => error);
  queueMicrotask(() => { retired = true; changeLocalSessionOwner(OTHER); });
  expect(await pending).toMatchObject({ code: "stale_operation", message: "A newer account/server transition superseded this operation" }); expect(retired).toBe(true);
});
it.each(["salt", "envelope"])("rejects a malformed %s cache origin without waiting on native server preferences", async kind => {
  const slot = kind === "salt" ? "@mindpattern/salt_YWxpY2U" : "@mindpattern/keyenvelope_YWxpY2U", value = kind === "salt" ? { v: 1, o: 7, s: "installed-salt" } : { v: 1, o: 7, scheme: "v1", saltB64: "installed-salt", wrappedB64: null, kdfParams: null };
  await storage.setItem(slot, JSON.stringify(value)); const read = storage.getItem; let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { if (slot === "@mindpattern/base_url") await held; return read(slot); });
  const result = kind === "salt" ? api.getCachedSalt("alice") : api.getCachedKeyEnvelope("alice");
  try { expect(await Promise.race([result.then(value => ({ value })), new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ value: null }); }
  finally { release(); await result; }
});
it.each(["before preferred read", "before encoded write"])("a retired compatibility salt read remains available %s", async boundary => {
  const old = "@mindpattern/salt_alice", next = "@mindpattern/salt_YWxpY2U"; await storage.setItem(old, JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: "retired-compatibility-salt" }));
  const read = storage.getItem, write = storage.setItem; let preferredRead = false, retired = false, release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (slot === next && retired) await held; const value = await read(slot);
    if (boundary === "before preferred read" && slot === old && !retired) { retired = true; changeLocalSessionOwner(OTHER); }
    if (boundary === "before encoded write" && slot === next) { if (preferredRead && !retired) { retired = true; changeLocalSessionOwner(OTHER); } preferredRead = true; }
    return value;
  });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (retired && slot === next) await held; return write(slot, value); });
  const result = api.getCachedSalt("alice");
  try { expect(await Promise.race([result.then(value => ({ value })), new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ value: "retired-compatibility-salt" }); }
  finally { release(); await result; }
});
it.each(["authenticate", "clear", "delete"])("a retired %s queue entry settles without waiting on already admitted native writes", async operation => {
  await api.setSession("old-token", USER, "alice"); const { savePendingMeasure } = await import("../src/pendingMeasure"), write = storage.setItem; let entered!: () => void, release!: () => void;
  const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/pending_measure_${USER}`) { entered(); await gate; } return write(slot, value); });
  const admitted = savePendingMeasure(Buffer.alloc(32, 7), USER, { kind: "phq2", clientMeasureId: "held-old-write", picks: [1, 2], date: "2026-10-05" }); await reached; let current = true;
  const result = (operation === "authenticate" ? api.setSession("retired-token", USER, "alice", { stillCurrent: () => current }) : operation === "clear" ? api.clearSession() : api.retireDeletedSession(USER)).catch((error: unknown) => error);
  current = false; if (operation !== "authenticate") changeLocalSessionOwner(OTHER);
  try { expect(await Promise.race([result.then(error => ({ error })), new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toMatchObject({ error: { code: "stale_operation" } }); }
  finally { release(); await admitted; await result; }
});
it("an origin switch stops before native credential erasure when its admitted write drain retires", async () => {
  await api.setSession("old-token", USER, "alice"); const { savePendingMeasure } = await import("../src/pendingMeasure"), write = storage.setItem, remove = secureStore.removeItem; let entered!: () => void, release!: () => void, retired = false;
  const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === `@mindpattern/pending_measure_${USER}`) { entered(); await gate; await write(slot, value); retired = true; changeLocalSessionOwner(OTHER); } else await write(slot, value); });
  vi.spyOn(secureStore, "removeItem").mockImplementation(slot => retired ? Promise.reject(new Error("Replacement native credentials are unavailable")) : remove(slot));
  const admitted = savePendingMeasure(Buffer.alloc(32, 7), USER, { kind: "phq2", clientMeasureId: "held-origin-write", picks: [1, 2], date: "2026-10-05" }); await reached;
  const result = setBaseUrl("https://retired-admitted-drain.example").catch((error: unknown) => error); for (let tick = 0; tick < 30; tick++) await Promise.resolve(); release(); await admitted;
  expect(await result).toMatchObject({ code: "stale_operation" }); expect(retired).toBe(true);
});
it("a superseded authentication cleanup reports its original failure before unavailable replacement custody", async () => {
  await api.setSession("existing-token", OTHER, "bob"); const write = secureStore.setItem, remove = secureStore.removeItem, interruption = new Error("Native identity publication failed"); let failed = false, replacement: Promise<unknown> | undefined, release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(secureStore, "setItem").mockImplementation((slot, value) => { if (!failed && slot === OWNER && value === USER) { failed = true; return Promise.reject(interruption); } return write(slot, value); });
  vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => {
    if (replacement && slot === OWNER) await held; await remove(slot);
    if (failed && !replacement && slot === TOKEN) replacement = api.setSession("replacement-token", OTHER, "bob").catch((error: unknown) => error);
  });
  const result = api.setSession("interrupted-token", USER, "alice").catch((error: unknown) => error);
  try { expect(await Promise.race([result.then(error => ({ error })), new Promise(resolve => setTimeout(() => resolve({ blocked: true }), 100))])).toEqual({ error: interruption }); }
  finally { release(); await result; if (replacement) await replacement; }
  expect(await api.getUserId()).toBe(OTHER); expect(await api.isLoggedIn()).toBe(true);
});
it("reports transition retirement before a mismatched native owner can choose different public copy", async () => {
  await api.setSession("existing-token", OTHER, "bob"); const read = secureStore.getItem; let retired = false;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const value = await read(slot); if (slot === OWNER) { retired = true; changeLocalSessionOwner(USER); } return value; });
  await expect(api.retireDeletedSession(USER)).rejects.toMatchObject({ status: 0, code: "stale_operation", message: "A newer account/server transition superseded this operation" }); expect(retired).toBe(true);
});
