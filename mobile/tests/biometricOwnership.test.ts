import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as Keychain from "react-native-keychain";
import * as mock from "./helpers/keychainMock";
import storage from "./helpers/storageMock";
import { api } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { enableBiometricUnlock, disableBiometricUnlock, hasBiometricUnlock } from "../src/biometricUnlock";
import { eraseDeletedAccountLocals } from "../src/accountErasure";
vi.mock("../src/nativeFeatures", () => ({ cancelDailyReminder: vi.fn(async () => true), cancelMeasureReminder: vi.fn(async () => true) }));
const USER = "11111111111111111111111111111111", OTHER = "22222222222222222222222222222222";
const SERVICE = `com.mindpattern.biometric-unlock.v1.${USER}`;
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); mock.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(setSecureStoreBackend, null);
  await api.setSession("owner-token", USER, "alice");
});
afterEach(() => { vi.restoreAllMocks(); });

it("erasure drains an admitted biometric key write so its raw data key cannot reappear after cleanup", async () => {
  const original = Keychain.setGenericPassword, started = deferred(), release = deferred();
  vi.spyOn(Keychain, "setGenericPassword").mockImplementation(async (username, password, options) => {
    if (options?.service === SERVICE) { started.resolve(); await release.promise; }
    return original(username, password, options);
  });
  const enabling = enableBiometricUnlock(USER, Buffer.alloc(32, 7)); await started.promise;
  let erased = false;
  const erasure = eraseDeletedAccountLocals(USER, "alice", { preserveSession: true }).then(result => { erased = true; return result; });
  await new Promise<void>(r => setImmediate(r));
  const waited = !erased; release.resolve(); await enabling; expect(await erasure).toEqual([]);
  expect(waited).toBe(true);
  expect(await hasBiometricUnlock(USER)).toBe(false);
  expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(false);
});

it("credential replacement drains an admitted biometric deletion before the replacement can enable its wrap", async () => {
  await enableBiometricUnlock(USER, Buffer.alloc(32, 7));
  const original = Keychain.resetGenericPassword, started = deferred(), release = deferred();
  vi.spyOn(Keychain, "resetGenericPassword").mockImplementation(async options => {
    if (options?.service === SERVICE) { started.resolve(); await release.promise; }
    return original(options);
  });
  const disabling = disableBiometricUnlock(USER); await started.promise;
  let replaced = false; const replacement = api.setSession("other-token", OTHER, "bob").then(() => { replaced = true; });
  await new Promise<void>(r => setImmediate(r));
  const waited = !replaced; release.resolve(); await disabling; await replacement;
  expect(waited).toBe(true); expect(await api.getUserId()).toBe(OTHER);
});
