import { beforeEach, expect, it, vi } from "vitest";
import * as Keychain from "react-native-keychain";
import * as native from "./helpers/keychainMock";
import storage from "./helpers/storageMock";
import { biometricsSupported, enableBiometricUnlock, disableBiometricUnlock, eraseBiometricUnlock, eraseOriginBiometricUnlocks, hasBiometricUnlock, unwrapBiometricDataKey } from "../src/biometricUnlock";
import { changeLocalSessionOwner } from "../src/localWriteGuard";

const SERVICE = "com.mindpattern.biometric-unlock.v1", KEY = Buffer.alloc(32, 7);
const owned = (owner: string) => `${SERVICE}.${owner}`;
beforeEach(() => { vi.restoreAllMocks(); native.__reset(); storage.__reset(); });

it("degrades unavailable native biometry and legacy tombstone reads to the password path", async () => {
  vi.spyOn(Keychain, "getSupportedBiometryType").mockRejectedValue(new Error("native enrollment unavailable"));
  expect(await biometricsSupported()).toBe(false);
  await Keychain.setGenericPassword("alice", KEY.toString("base64"), { service: SERVICE });
  vi.spyOn(storage, "getItem").mockRejectedValue(new Error("disk unavailable"));
  expect(await hasBiometricUnlock("alice")).toBe(false);
  expect(await unwrapBiometricDataKey("alice")).toBeNull(); expect(native.__getReadCount()).toBe(0);
});

it("quiet legacy presence remains a boolean when native metadata rejects", async () => {
  native.__failReads(true);
  expect(await hasBiometricUnlock("never-enabled-owner")).toBe(false);
  expect(await unwrapBiometricDataKey("never-enabled-owner")).toBeNull();
});

it("falls back to password when the explicit native unlock prompt is cancelled with an error", async () => {
  await Keychain.setGenericPassword("cancelled-native-prompt", KEY.toString("base64"), { service: owned("cancelled-native-prompt") });
  vi.spyOn(Keychain, "getGenericPassword").mockRejectedValueOnce(new Error("User cancelled authentication"));
  expect(await unwrapBiometricDataKey("cancelled-native-prompt")).toBeNull();
});

it.each([0, 31, 33])("rejects a %s-byte key before publishing native custody", async bytes => {
  await expect(enableBiometricUnlock("invalid-owner", Buffer.alloc(bytes))).rejects.toThrow("Invalid biometric data key");
  expect(await hasBiometricUnlock("invalid-owner")).toBe(false); expect(await Keychain.hasGenericPassword({ service: owned("invalid-owner") })).toBe(false);
});

it("re-enables an authenticated legacy owner by retiring the obsolete wrap", async () => {
  await Keychain.setGenericPassword("legacy-enable-owner", KEY.toString("base64"), { service: SERVICE });
  expect(await unwrapBiometricDataKey("legacy-enable-owner")).toEqual(KEY);
  const rotated = Buffer.alloc(32, 8); await enableBiometricUnlock("legacy-enable-owner", rotated);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false);
  expect(await unwrapBiometricDataKey("legacy-enable-owner")).toEqual(rotated);
  await Keychain.setGenericPassword("foreign-upgrade-owner", KEY.toString("base64"), { service: SERVICE });
  await disableBiometricUnlock("legacy-enable-owner"); expect(await hasBiometricUnlock("legacy-enable-owner")).toBe(false);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(true);
});

it("suppresses unverified legacy fallback if an enabled account's current native wrap later disappears", async () => {
  await Keychain.setGenericPassword("foreign-fallback-owner", KEY.toString("base64"), { service: SERVICE });
  await enableBiometricUnlock("enabled-no-fallback", KEY);
  await Keychain.resetGenericPassword({ service: owned("enabled-no-fallback") });
  expect(await hasBiometricUnlock("enabled-no-fallback")).toBe(false);
  expect(await unwrapBiometricDataKey("enabled-no-fallback")).toBeNull(); expect(native.__getReadCount()).toBe(0);
});

it.each(["disable", "account-erasure"])("a completed %s retires authenticated legacy ownership before a later foreign wrap", async action => {
  const owner = `authenticated-${action}`;
  await Keychain.setGenericPassword(owner, KEY.toString("base64"), { service: SERVICE });
  expect(await unwrapBiometricDataKey(owner)).toEqual(KEY);
  if (action === "disable") await disableBiometricUnlock(owner); else await eraseBiometricUnlock(owner);
  await Keychain.setGenericPassword("later-foreign-owner", KEY.toString("base64"), { service: SERVICE });
  await enableBiometricUnlock(owner, Buffer.alloc(32, 9));
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(true);
});

it("erases both the account wrap and unattributable legacy wrap without a prompting read", async () => {
  await enableBiometricUnlock("erased-owner", KEY);
  await Keychain.setGenericPassword("unattributable-owner", Buffer.alloc(32, 9).toString("base64"), { service: SERVICE });
  const reads = native.__getReadCount(); await eraseBiometricUnlock("erased-owner");
  expect(await hasBiometricUnlock("erased-owner")).toBe(false);
  expect(await Keychain.hasGenericPassword({ service: owned("erased-owner") })).toBe(false);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false); expect(native.__getReadCount()).toBe(reads);
  // Reintroducing an upgrade-era wrap demonstrates that compatibility metadata was erased too.
  await Keychain.setGenericPassword("erased-owner", KEY.toString("base64"), { service: SERVICE });
  expect(await unwrapBiometricDataKey("erased-owner")).toEqual(KEY);
});

it("origin retirement removes every inventoried wrap, keeps unlisted owners and retires the legacy singleton", async () => {
  await enableBiometricUnlock("retired-a", KEY);
  await enableBiometricUnlock("retired-b", KEY);
  for (const owner of ["retired-a", "retired-b", "retained-c"]) await Keychain.setGenericPassword(owner, KEY.toString("base64"), { service: owned(owner) });
  await Keychain.setGenericPassword("legacy-origin-owner", KEY.toString("base64"), { service: SERVICE });
  expect(await unwrapBiometricDataKey("legacy-origin-owner")).toEqual(KEY);
  const resets = vi.spyOn(Keychain, "resetGenericPassword");
  await eraseOriginBiometricUnlocks(["retired-a", "retired-b", "retired-a"]);
  for (const owner of ["retired-a", "retired-b"]) expect(await Keychain.hasGenericPassword({ service: owned(owner) })).toBe(false);
  expect(await Keychain.hasGenericPassword({ service: owned("retained-c") })).toBe(true);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false);
  expect(resets.mock.calls.filter(([options]) => options?.service === owned("retired-a"))).toHaveLength(1);
  expect((await storage.getAllKeys()).filter(key => key.includes("retired-a") || key.includes("retired-b"))).toEqual([]);
  // Authentication of the now-retired legacy slot must not permit deleting a future foreign wrap.
  await Keychain.setGenericPassword("foreign-owner", KEY.toString("base64"), { service: SERVICE });
  await enableBiometricUnlock("legacy-origin-owner", KEY);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(true);
});

it.each(["disable", "account-erasure", "origin-erasure"])("a queued %s cannot remove a replacement session's native wrap", async action => {
  let release: (() => void) | undefined;
  const original = Keychain.setGenericPassword;
  const entered = new Promise<void>(resolve => {
    vi.spyOn(Keychain, "setGenericPassword").mockImplementationOnce(async (owner, password, options) => {
      resolve(); await new Promise<void>(done => { release = done; }); return original(owner, password, options);
    });
  });
  const blocking = enableBiometricUnlock("lane-blocker", KEY).then(() => undefined, (error: unknown) => { throw error; });
  await Promise.race([entered, blocking.then(() => { throw new Error("Native publication skipped the serialized operation"); })]);
  const operation = action === "disable" ? disableBiometricUnlock("replacement-owner") : action === "account-erasure" ? eraseBiometricUnlock("replacement-owner") : eraseOriginBiometricUnlocks(["replacement-owner"]);
  const completion = operation.then(() => ({ accepted: true }), (error: unknown) => ({ error }));
  try {
    changeLocalSessionOwner("replacement-owner");
    await original("replacement-owner", Buffer.alloc(32, 9).toString("base64"), { service: owned("replacement-owner") });
  } finally { release?.(); }
  await blocking; const result = await completion;
  expect(result).toHaveProperty("error");
  expect((result as { error: Error }).error.message).toContain(action === "origin-erasure" ? "retired origin" : "retired session");
  expect(await Keychain.getGenericPassword({ service: owned("replacement-owner") })).toEqual({ username: "replacement-owner", password: Buffer.alloc(32, 9).toString("base64") });
});

it("refuses a queued native key publication after its producer session is retired", async () => {
  let release: (() => void) | undefined;
  const original = Keychain.setGenericPassword;
  const entered = new Promise<void>(resolve => {
    vi.spyOn(Keychain, "setGenericPassword").mockImplementationOnce(async (owner, password, options) => {
      resolve(); await new Promise<void>(done => { release = done; }); return original(owner, password, options);
    });
  });
  const blocking = enableBiometricUnlock("queued-producer", KEY);
  await Promise.race([entered, blocking.then(() => { throw new Error("Native publication skipped the serialized operation"); })]);
  const queued = enableBiometricUnlock("queued-producer", Buffer.alloc(32, 9)).then(() => ({ accepted: true }), (error: unknown) => ({ error }));
  try { changeLocalSessionOwner("new-active-account"); } finally { release?.(); }
  await blocking; expect(await queued).toHaveProperty("error");
  expect(await Keychain.getGenericPassword({ service: owned("queued-producer") })).toEqual({ username: "queued-producer", password: KEY.toString("base64") });
});

it("origin retirement with no recoverable owners still removes the old unlabelled native key", async () => {
  await Keychain.setGenericPassword("legacy-no-inventory", KEY.toString("base64"), { service: SERVICE });
  await eraseOriginBiometricUnlocks([]);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false); expect(native.__getReadCount()).toBe(0);
});

it("does not require the account database when origin retirement has no owner metadata", async () => {
  await Keychain.setGenericPassword("legacy-database-offline", KEY.toString("base64"), { service: SERVICE });
  vi.spyOn(storage, "multiRemove").mockRejectedValueOnce(new Error("Account database unavailable"));
  await expect(eraseOriginBiometricUnlocks([])).resolves.toBeUndefined();
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false);
});

it("propagates a failed native erasure and permits the serialized next retry", async () => {
  await enableBiometricUnlock("retry-erasure", KEY);
  const resets = vi.spyOn(Keychain, "resetGenericPassword").mockRejectedValueOnce(new Error("native reset unavailable"));
  await expect(eraseBiometricUnlock("retry-erasure")).rejects.toThrow("native reset unavailable");
  expect(await hasBiometricUnlock("retry-erasure")).toBe(true);
  resets.mockRestore(); await eraseBiometricUnlock("retry-erasure"); expect(await hasBiometricUnlock("retry-erasure")).toBe(false);
});

it("reports a retired origin after native cleanup spans a replacement session", async () => {
  await Keychain.setGenericPassword("old-origin", KEY.toString("base64"), { service: owned("old-origin") });
  let release!: () => void; const entered = new Promise<void>(resolve => {
    const original = Keychain.resetGenericPassword;
    vi.spyOn(Keychain, "resetGenericPassword").mockImplementationOnce(async options => { resolve(); await new Promise<void>(done => { release = done; }); return original(options); });
  });
  const pending = eraseOriginBiometricUnlocks(["old-origin"]).then(() => ({ accepted: true }), (error: unknown) => ({ error }));
  await Promise.race([entered, pending.then(() => { throw new Error("Native erasure skipped its owned slot"); })]);
  changeLocalSessionOwner("replacement-origin"); release(); const result = await pending;
  expect(result).toHaveProperty("error"); expect((result as { error: Error }).error.message).toContain("retired origin");
});
