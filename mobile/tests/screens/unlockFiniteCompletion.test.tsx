/** draft: real UnlockScreen/public native handlers and actual
 * crypto/protocol/storage consumers under the existing Node native seams.
 * Never await an unreachable test producer gate or poll only for success.
 * Promote only after the initial sequential mutation campaigns finish. */


import crypto from "node:crypto";
import "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Alert, TextInput, TouchableOpacity } from "../helpers/rnMock";
import { UnlockScreen } from "../../src/screens/UnlockScreen";
import { ThemeProvider } from "../../src/theme";
import { SessionProvider } from "../../src/store";
import { api } from "../../src/api/client";
import { vault } from "../../src/vault";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { prepareLocalRekey, pendingLocalRekey } from "../../src/localRekey";
import { storeUnlockProof, verifyUnlockProof } from "../../src/unlockProof";
import { unlockFailureCount } from "../../src/unlockBackoff";
import { accountStorageKey } from "../../src/accountStorage";
import { runTestControl } from "../helpers/testControl";
import { engine } from "../helpers/nodeEngine";
import storage from "../helpers/storageMock";
import * as files from "../helpers/expoFsMock";
import * as keychain from "../helpers/keychainMock";

const USER = "a".repeat(32), SALT = Buffer.alloc(16, 3);
const PASSWORD = "the account's known password", NAME = "alice";
const NEXT_PASSWORD = "the account's previously chosen new password";
const NEXT_SALT = Buffer.alloc(16, 12), RANDOM_DATA = Buffer.alloc(32, 7);
const MASTER = crypto.pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
const hkdf = (key: Buffer, salt: Buffer, label: string): Buffer => Buffer.from(crypto.hkdfSync("sha256", key, salt, label, 32));
const AUTH = hkdf(MASTER, Buffer.alloc(32), "mindpattern/auth/v1");
const LEGACY_DATA = hkdf(MASTER, Buffer.alloc(32), "mindpattern/data/v1");
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 };
const nativeDelete = files.deleteAsync.getMockImplementation()!;
type Root = ReturnType<typeof ReactTestRenderer.create>;
let root: Root | undefined;
let serverSalt: Buffer, serverVerifier: string, loginStatus: number, rekeyStatus: number, envelope: unknown;
let protocol: string[];

function genuineEnvelope(): Record<string, unknown> {
  const kek = hkdf(MASTER, SALT, "mindpattern/envelope/v2");
  const nonce = Buffer.alloc(12, 6);
  const cipher = crypto.createCipheriv("aes-256-gcm", kek, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: PARAMS, username: NAME })));
  const wrapped = Buffer.concat([nonce, cipher.update(RANDOM_DATA), cipher.final(), cipher.getAuthTag()]);
  kek.fill(0);
  return { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: wrapped.toString("base64") };
}

function response(url: string, value: unknown, status = 200): Response {
  const result = new Response(JSON.stringify(value), { status });
  Object.defineProperty(result, "url", { value: url });
  return result;
}

async function flush(): Promise<void> {
  await act(async () => { for (let index = 0; index < 64; index++) await Promise.resolve(); });
}

/** Missing producer completion remains an ordinary execution failure. */
async function nativeCompletion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: native producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>((resolve) => setImmediate(resolve)); });
  }
  await flush();
}

function button(label = "Unlock") {
  return root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
}
function password() {
  return root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password")!;
}
async function mount(): Promise<void> {
  await act(async () => {
    root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><UnlockScreen navigation={{ navigate: () => undefined }} /></SessionProvider></ThemeProvider>);
  });
  await flush();
}
async function typePassword(value = PASSWORD): Promise<void> {
  await act(async () => { password().props.onChangeText(value); });
}

beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks();
  storage.__reset(); files.__resetFiles(); files.deleteAsync.mockImplementation(nativeDelete);
  keychain.__reset(); keychain.__setBiometryType(null);
  runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); await api.clearSession(); Alert.alert.mockClear();
  serverSalt = Buffer.from(SALT); serverVerifier = AUTH.toString("base64");
  loginStatus = 0; rekeyStatus = 200; envelope = undefined; protocol = [];
  await api.setSession("synthetic-prior-bearer", USER, NAME);
  await api.cacheSalt(NAME, SALT.toString("base64"));
  await storeUnlockProof(LEGACY_DATA, USER);
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    protocol.push(path);
    if (path.endsWith("/auth/salt")) return response(url, { salt: serverSalt.toString("base64") });
    if (path.endsWith("/auth/login")) {
      const status = loginStatus || (body.verifier === serverVerifier ? 200 : 401);
      return response(url, status === 200 ? { token: "synthetic-fresh-bearer", user_id: USER } : { code: "invalid_credentials" }, status);
    }
    if (path.endsWith("/auth/key-envelope")) return response(url, envelope ?? { detail: "legacy endpoint" }, envelope ? 200 : 404);
    if (path.endsWith("/account/password")) {
      serverSalt = Buffer.from(body.new_salt, "base64");
      serverVerifier = body.new_verifier;
      envelope = { key_scheme: "v2", salt: body.new_salt, kdf_params: body.new_kdf_params ?? PARAMS, wrapped_data_key: body.wrapped_data_key };
      return response(url, {});
    }
    if (path.endsWith("/processing/sessions")) return response(url, { session_token: "synthetic-processing-receipt" });
    if (path.endsWith("/processing/rekey")) {
      if (rekeyStatus !== 200) return response(url, { detail: "synthetic credential transaction refused" }, rekeyStatus);
      serverSalt = Buffer.from(body.new_salt, "base64");
      serverVerifier = body.new_verifier;
      return response(url, { credential_rotated: true, operation_id: body.operation_id, entries: 1, insights: 0, measures: 0, consents_rewrapped: 0, recovery_invalidated: true });
    }
    if (path.endsWith("/consents")) return response(url, []);
    if (path.endsWith("/insights")) return response(url, { active_days: 5 });
    if (path.endsWith("/meta")) return response(url, { unlock_days: 30 });
    if (path.endsWith("/auth/logout")) return response(url, {});
    throw new Error(`Unexpected synthetic route: ${path}`);
  });
});

afterEach(async () => {
  if (root) { await act(async () => { root!.unmount(); }); root = undefined; }


  vi.useRealTimers(); vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

describe("finite public native Unlock completion", () => {
  for (const saltSource of ["checkpoint-salt-without-cache", "cached-salt-without-checkpoint-context"]) {
    it(`completes interrupted rotation using ${saltSource} with explicit outcomes after native busy-finally`, async () => {

      const plannedMaster = crypto.pbkdf2Sync(NEXT_PASSWORD, NEXT_SALT, 600_000, 32, "sha256");
      const plannedData = hkdf(plannedMaster, Buffer.alloc(32), "mindpattern/data/v1");
      await storage.setItem(accountStorageKey.pendingRotationSalt(USER), NEXT_SALT.toString("base64"));
      await prepareLocalRekey(USER, LEGACY_DATA, plannedData, saltSource === "checkpoint-salt-without-cache" ? { oldSaltB64: SALT.toString("base64") } : undefined);
      plannedMaster.fill(0); plannedData.fill(0);
      if (saltSource === "checkpoint-salt-without-cache") await api.clearCachedSalt(NAME);
      await mount();
      await nativeCompletion("quiet checkpoint probe renders public rotation action", () => !!button("Finish interrupted password change"));
      await typePassword();
      await act(async () => {
        root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Previously chosen new password")!.props.onChangeText(NEXT_PASSWORD);
      });
      const read = secureStore.getItem;
      let entered = false, release!: () => void;
      const held = new Promise<void>((resolve) => { release = resolve; });
      vi.spyOn(secureStore, "getItem").mockImplementation(async key => {
        const value = await read(key);
        if (key === "@mindpattern/user_id" && !entered) { entered = true; await held; }
        return value;
      });
      try {
        const action = button("Finish interrupted password change")!;
        expect(action.props.disabled).toBe(false);

        await act(async () => { action.props.onPress(); });
        await flush();

        // No await on the producer-entry promise: a removed/early-refused
        // callback reaches these finite public admission assertions.
        expect(entered).toBe(true);
        expect(button()!.props.accessibilityState.busy).toBe(true);
        expect(button("Finish interrupted password change")!.props.disabled).toBe(true);
        expect(vault.isUnlocked()).toBe(false);
        await act(async () => { release(); });

        await nativeCompletion("actual rotation finally releases its admitted public busy state", () => button()!.props.accessibilityState.busy === false);

        expect(Alert.alert.mock.calls).toEqual([["Password changed", "The password change is complete. Unlock with your new password."]]);
        expect(protocol.filter(path => path.endsWith("/account/password") || path.endsWith("/processing/rekey"))).toHaveLength(1);
        expect(await pendingLocalRekey(USER)).toBe(false);
        expect(vault.isUnlocked()).toBe(false);
        expect(vault.ownerUserId()).toBeNull();
        expect(password().props.value).toBe("");
        expect(button("Finish interrupted password change")).toBeUndefined();

      }  finally { release(); }
    });
  }

  it("completes a refused genuine rotation delivery with finite failure feedback and retired restricted keys", async () => {

    rekeyStatus = 503;
    const plannedMaster = crypto.pbkdf2Sync(NEXT_PASSWORD, NEXT_SALT, 600_000, 32, "sha256");
    const plannedData = hkdf(plannedMaster, Buffer.alloc(32), "mindpattern/data/v1");
    await storage.setItem(accountStorageKey.pendingRotationSalt(USER), NEXT_SALT.toString("base64"));
    await prepareLocalRekey(USER, LEGACY_DATA, plannedData, { oldSaltB64: SALT.toString("base64") });
    plannedMaster.fill(0); plannedData.fill(0);
    await mount();
    await nativeCompletion("refused-flow quiet probe renders actual rotation action", () => !!button("Finish interrupted password change"));
    await typePassword();
    await act(async () => {
      root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Previously chosen new password")!.props.onChangeText(NEXT_PASSWORD);
    });
    const read = secureStore.getItem;
    let entered = false, release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(secureStore, "getItem").mockImplementation(async key => {
      const value = await read(key);
      if (key === "@mindpattern/user_id" && !entered) { entered = true; await held; }
      return value;
    });
    const owned: Buffer[] = [];
    const unsubscribe = vault.subscribe(() => {
      if (vault.canReauthenticate()) { const keys = vault.get(); owned.push(keys.authKey, keys.dataKey); }
    });
    try {
      expect(button("Finish interrupted password change")!.props.disabled).toBe(false);
      await act(async () => { button("Finish interrupted password change")!.props.onPress(); });
      await flush();

      expect(entered).toBe(true);
      expect(button()!.props.accessibilityState.busy).toBe(true);
      await act(async () => { release(); });

      await nativeCompletion("real refused delegate reaches public busy-finally", () => button()!.props.accessibilityState.busy === false);

      expect(protocol.filter(path => path.endsWith("/processing/rekey"))).toHaveLength(1);
      expect(Alert.alert.mock.calls).toHaveLength(1);
      expect(Alert.alert.mock.calls[0]![0]).toBe("Could not change password");
      expect(await pendingLocalRekey(USER)).toBe(true);
      expect(vault.isUnlocked()).toBe(false);
      expect(vault.canReauthenticate()).toBe(false);
      expect(vault.ownerUserId()).toBeNull();
      expect(owned.length).toBeGreaterThanOrEqual(2);
      expect(owned.every(key => key.every(byte => byte === 0))).toBe(true);
      expect(password().props.value).toBe(PASSWORD);
      expect(button("Finish interrupted password change")).toBeDefined();

    }  finally { release(); unsubscribe(); }
  });

  it("completes a matching-cost genuine v2 envelope when the next native KDF provider refuses", async () => {

    envelope = genuineEnvelope(); await mount(); await typePassword();
    const derive = engine.pbkdf2;
    let derivations = 0;
    vi.spyOn(engine, "pbkdf2").mockImplementation((passwordValue, salt, cost, length, hash, done) => {
      derivations += 1;
      if (derivations === 1) return derive(passwordValue, salt, cost, length, hash, done);
      queueMicrotask(() => done(new Error("Synthetic native second KDF provider unavailable")));
    });
    {
      expect(button()!.props.disabled).toBe(false);
      // Unlike the rotation GhostButton, the public primary action exposes
      // the production async promise; await that genuine completion.
      await act(async () => { await button()!.props.onPress(); });
      await flush();

      expect(vault.isUnlocked()).toBe(true);
      expect(vault.ownerUserId()).toBe(USER);
      expect(vault.get().dataKey).toEqual(RANDOM_DATA);
      expect(await verifyUnlockProof(RANDOM_DATA, USER)).toBe("ok");
      expect(Alert.alert.mock.calls).toEqual([]);
      expect(button()!.props.accessibilityState.busy).toBe(false);

    }
  });

  it("finishes the first genuine wrong-password attempt at its native 500ms retry floor without awaiting a lost timer callback", async () => {

    loginStatus = 401; await mount(); await typePassword();
    const write = storage.setItem;
    let counterWritten = false;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      await write(key, value);
      if (key === accountStorageKey.unlockFailure(NAME)) counterWritten = true;
    });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let completed = false;
    await act(async () => {
      // The native primary callback's settlement is observable. Do not await
      // it until a timer that might have been removed has had its deadline.
      void button()!.props.onPress().then(() => { completed = true; });
    });
    {
      await nativeCompletion("real rejected API proof reaches its durable counter write", () => counterWritten);

      await act(async () => { await vi.advanceTimersByTimeAsync(499); });
      expect(completed).toBe(false);
      expect(button()!.props.accessibilityState.busy).toBe(true);
      expect(Alert.alert.mock.calls).toEqual([]);
      await act(async () => { await vi.advanceTimersByTimeAsync(1); });
      await flush();
      // Even an empty Promise executor reaches an explicit finite failure
      // here; no pending promise is awaited in the assertion or cleanup.
      expect(completed).toBe(true);
      expect(button()!.props.accessibilityState.busy).toBe(false);
      expect(vault.isUnlocked()).toBe(false);
      expect(await unlockFailureCount(NAME)).toBe(1);
      expect(Alert.alert.mock.calls).toEqual([["Unlock failed", "Wrong password."]]);

    }
  });
});
