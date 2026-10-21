/** finite public Login/REGISTER completion. The genuine
 * PrimaryButton callback returns the production async handler Promise.
 * Assertions follow its completion; success-only polling is never used. */
import crypto from "node:crypto";


import "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { Alert, Text, TextInput, Switch, TouchableOpacity } from "./helpers/rnMock";
import { LoginScreen } from "../src/screens/LoginScreen";
import { SessionProvider, useSession } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { verifyUnlockProof } from "../src/unlockProof";
import { takePendingOnboarding } from "../src/onboarding";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import * as files from "./helpers/expoFsMock";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "a".repeat(32), NAME = "alice", PASSWORD = "Native strong Passphrase 2026!";
const SALT = Buffer.alloc(16, 3), DATA = Buffer.alloc(32, 7), PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
const MASTER = crypto.pbkdf2Sync(PASSWORD, SALT, PARAMS.iterations, 32, "sha256");
const hkdf = (master: Buffer, salt: Buffer, label: string) => Buffer.from(crypto.hkdfSync("sha256", master, salt, label, 32));
const AUTH = hkdf(MASTER, Buffer.alloc(32), "mindpattern/auth/v1"), LEGACY_DATA = hkdf(MASTER, Buffer.alloc(32), "mindpattern/data/v1");
function wrap() {
  const nonce = Buffer.alloc(12, 9), cipher = crypto.createCipheriv("aes-256-gcm", hkdf(MASTER, SALT, "mindpattern/envelope/v2"), nonce);
  cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: PARAMS, username: NAME })));
  return Buffer.concat([nonce, cipher.update(DATA), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
const WRAP = wrap();
function openRegistration(body: any) {
  if (body.username !== NAME || body.age_attestation !== "minimum_age_confirmed_v1") throw new Error("registration identity contract refused");
  const salt = Buffer.from(body.salt, "base64"), params = body.kdf_params;
  if (salt.length !== 16 || params.algorithm !== "pbkdf2-sha256" || params.version !== 1 || params.iterations !== 600000) throw new Error("registration key cost contract refused");
  const master = crypto.pbkdf2Sync(PASSWORD, salt, params.iterations, 32, "sha256"), auth = hkdf(master, Buffer.alloc(32), "mindpattern/auth/v1");
  if (body.verifier !== auth.toString("base64")) throw new Error("registration verifier refused");
  const blob = Buffer.from(body.wrapped_data_key, "base64"), decipher = crypto.createDecipheriv("aes-256-gcm", hkdf(master, salt, "mindpattern/envelope/v2"), blob.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: NAME }))); decipher.setAuthTag(blob.subarray(-16));
  const data = Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]); master.fill(0); auth.fill(0); return data;
}
let root: ReturnType<typeof ReactTestRenderer.create> | undefined, scheme: "v1" | "v2", rejectLogin: boolean, registration: any, registeredData: Buffer | undefined;
let state: { auth: string; unlocked: boolean } | undefined;
let receipt: any;
const nativeDelete = files.deleteAsync.getMockImplementation()!;
function State() { const session = useSession(); state = { auth: session.authStatus, unlocked: session.unlocked }; return <Text>{`Finite session ${session.authStatus} unlocked=${session.unlocked}`}</Text>; }
function answer(url: string, body: unknown, status = 200) { const result = new Response(JSON.stringify(body), { status }); Object.defineProperty(result, "url", { value: url }); return result; }
function button(label: string) { const result = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label); if (!result) throw new Error(`SetupError: FiniteLoginSetupFault: missing native action ${label}`); return result; }
function input(label: string) { const result = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label); if (!result) throw new Error(`SetupError: FiniteLoginSetupFault: missing native input ${label}`); return result; }
async function flush() { await act(async () => { for (let i = 0; i < 64; i++) await Promise.resolve(); }); }
async function fill(label: string, value: string) { await act(async () => input(label).props.onChangeText(value)); }
async function mount() { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><LoginScreen navigation={{ navigate: () => undefined }} /><State /></SessionProvider></ThemeProvider>); }); await flush(); }
async function complete(label: string) {
  const action = button(label); expect(action.props.disabled).toBe(false);

  await act(async () => {
    const pending = action.props.onPress();
    if (!pending || typeof pending.then !== "function") throw new Error("SetupError: FiniteLoginSetupFault: actual public primary handler Promise is unavailable");
    await pending;
  });
  await flush();


}
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles(); files.deleteAsync.mockImplementation(nativeDelete);
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); await api.clearSession(); await setBaseUrl("http://localhost:8000"); takePendingOnboarding(); Alert.alert.mockClear();
  state = undefined; scheme = "v2"; rejectLogin = false; registration = undefined; registeredData = undefined;
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const route = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) : {};

    if (route.endsWith("/auth/salt")) return answer(url, { salt: SALT.toString("base64") });
    if (route.endsWith("/auth/login")) return rejectLogin || body.username !== NAME || body.verifier !== AUTH.toString("base64") ? answer(url, { code: "invalid_credentials" }, 401) : answer(url, { token: "independently verified finite login bearer", user_id: USER, role: "user" });
    if (route.endsWith("/auth/register")) {
      try { registeredData = openRegistration(body); registration = body; return answer(url, { token: "independently verified finite registration bearer", user_id: USER, role: "user" }); }
      catch { return answer(url, { code: "invalid_request" }, 400); }
    }
    if (route.endsWith("/auth/key-envelope")) return answer(url, scheme === "v1" ? { key_scheme: "v1", salt: SALT.toString("base64") } : { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: WRAP });
    if (route.endsWith("/insights")) return answer(url, { active_days: 12 });
    if (route.endsWith("/meta")) return answer(url, { unlock_days: 30 });
    if (route.endsWith("/auth/logout")) return answer(url, {});
    throw new Error(`SetupError: FiniteLoginSetupFault: unexpected native HTTP route ${route}`);
  });
});
afterEach(async () => {
  if (receipt) {



  }
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

for (const selected of ["v1", "v2"] as const) it(`finite actual ${selected} login completion adopts verified keys and offline material`, async () => {
  scheme = selected; await mount(); await fill("Username", NAME); await fill("Password", PASSWORD); await complete("Sign in");
  const expected = selected === "v2" ? DATA : LEGACY_DATA;
  expect(vault.isUnlocked()).toBe(true); expect(vault.ownerUserId()).toBe(USER); expect(vault.get().dataKey).toEqual(expected); expect(vault.get().authKey).toEqual(AUTH);
  expect(state).toEqual({ auth: "loggedIn", unlocked: true }); expect(await verifyUnlockProof(expected, USER)).toBe("ok");
  expect(await api.getCachedSalt(NAME)).toBe(SALT.toString("base64")); expect(await api.getCachedKeyEnvelope(NAME)).toMatchObject({ scheme: selected });
  expect(input("Password").props.value).toBe(""); expect(button("Sign in").props.accessibilityState.busy).toBe(false); expect(Alert.alert.mock.calls).toEqual([]); expect(takePendingOnboarding()).toBe(false);

}, 15000);
it("finite actual REGISTER completion adopts the independently decrypted random key and onboarding intent", async () => {
  await mount(); await act(async () => button("New here? Create an account").props.onPress());
  await fill("Username", NAME); await fill("Password", PASSWORD); await fill("Confirm password", PASSWORD); await act(async () => root!.root.findByType(Switch).props.onValueChange(true));
  await complete("Create account");
  expect(registration).toBeDefined(); expect(registeredData).toHaveLength(32); expect(vault.isUnlocked()).toBe(true); expect(vault.ownerUserId()).toBe(USER); expect(vault.get().dataKey).toEqual(registeredData);
  expect(state).toEqual({ auth: "loggedIn", unlocked: true }); expect(await verifyUnlockProof(registeredData!, USER)).toBe("ok");
  expect(await api.getCachedSalt(NAME)).toBe(registration.salt); expect(await api.getCachedKeyEnvelope(NAME)).toMatchObject({ scheme: "v2", saltB64: registration.salt, wrappedB64: registration.wrapped_data_key });
  expect(input("Password").props.value).toBe(""); expect(input("Confirm password").props.value).toBe(""); expect(button("Create account").props.accessibilityState.busy).toBe(false); expect(Alert.alert.mock.calls).toEqual([]); expect(takePendingOnboarding()).toBe(true);

}, 15000);
it("finite actual rejected login completion remains locked and publishes current failure feedback", async () => {
  rejectLogin = true; await mount(); await fill("Username", NAME); await fill("Password", PASSWORD); await complete("Sign in");
  expect(vault.isUnlocked()).toBe(false); expect(state).toEqual({ auth: "loggedOut", unlocked: false }); expect(await api.getUserId()).toBeNull();
  expect(button("Sign in").props.accessibilityState.busy).toBe(false); expect(input("Password").props.value).toBe(PASSWORD);
  expect(Alert.alert.mock.calls).toEqual([["Sign in failed", "That username or password didn't match."]]);

}, 15000);
