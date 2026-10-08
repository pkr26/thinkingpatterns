import React from "react";
import crypto from "node:crypto";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Alert, TextInput, TouchableOpacity } from "react-native";
import { SettingsScreen } from "../../src/screens/SettingsScreen";
import { UnlockScreen } from "../../src/screens/UnlockScreen";
import { AppNavigator } from "../../src/navigation";
import { ThemeProvider } from "../../src/theme";
import { SessionProvider } from "../../src/store";
import { api, canonicalOrigin, getBaseUrl } from "../../src/api/client";
import { vault } from "../../src/vault";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests, installLocalDataKey, captureLocalWritePermit } from "../../src/localWriteGuard";
import { recordOnboardingSeen } from "../../src/onboarding";
import { cachedEnvelope } from "../../src/keyScheme";
import { pendingLocalRekey } from "../../src/localRekey";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as files from "../helpers/expoFsMock";
import * as keychain from "../helpers/keychainMock";
import { publicSurface } from "../helpers/publicSurface";
import { assertPublicSurface } from "../helpers/publicSurfaceOracle";
import { nativeGrantedPress } from "../helpers/nativePressability";
import { accountStorageKey, ACCOUNT_STORAGE_PREFIX } from "../../src/accountStorage";
import { encryptAudio, decryptAudio } from "../../src/crypto/journalCrypto";
import { enqueueAudio } from "../../src/audioQueue";
import * as sharing from "../helpers/expoSharingMock";

// The native stack visits Settings in the actual main branch and unmounts it
// when AppNavigator changes session branch. Controller and session stay real.
const nativeNavigation = vi.hoisted(() => ({ listeners: new Map<string, Set<() => void>>(), mainRoute: "Settings" }));
vi.mock("@react-navigation/native-stack", async () => {
  const React = await import("react");
  const navigation = { navigate: () => {}, popToTop: () => {}, addListener: (event: string, callback: () => void) => { const listeners = nativeNavigation.listeners.get(event) ?? new Set(); listeners.add(callback); nativeNavigation.listeners.set(event, listeners); return () => listeners.delete(callback); } };
  const routes = (children: any): any[] => React.Children.toArray(children).flatMap((child: any) => React.isValidElement(child) && child.type === React.Fragment ? routes((child.props as any).children) : [child]);
  return { createNativeStackNavigator: () => ({
    Navigator: ({ children }: any) => { const choices = routes(children); return choices.find(node => node.props?.name === nativeNavigation.mainRoute) ?? choices[0] ?? null; },
    Screen: ({ component: Component }: any) => Component ? React.createElement(Component, { navigation }) : null,
  }) };
});

const USER = "d".repeat(32), OTHER = "e".repeat(32), SALT = Buffer.alloc(16, 3);
const OLD = "Native current password42!", NEW = "Cedar ridge!73 Oak", DATA = Buffer.alloc(32, 7);
const master = crypto.pbkdf2Sync(OLD, SALT, 600000, 32, "sha256");
const auth = Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const derivedData = Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/data/v1", 32));
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let scheme: "v1" | "v2", serverSalt: Buffer, verifier: string, envelopeData: Buffer;
let passwordStatus: number, rekeyStatus: number, envelopeStatus: number, upgradeStatus: number, upgradeCode: string;
let wrapped: string | undefined, newParams: unknown, passwordBody: any, rekeyBody: any, upgradeBody: any;
let processingKeys: string[], paths: string[], boundary: ((path: string, body: any) => Promise<void>) | undefined;
let responseBoundary: ((path: string) => Promise<void>) | undefined, distinctLogins: boolean, loginNumber: number;
let recoveryStatus: number;
const releases: Array<() => void> = [];
function hold() { let entered = false, release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { entered: () => entered, release, run: async () => { entered = true; await pending; } }; }
function wrap(data: Buffer) {
  const key = Buffer.from(crypto.hkdfSync("sha256", master, SALT, "mindpattern/envelope/v2", 32)), nonce = Buffer.alloc(12, 6), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, username: "alice" })));
  return Buffer.concat([nonce, cipher.update(data), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
function button(label: string) { return root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label)!; }
async function press(label: string, waitForCompletion = true) { expect(button(label), label).toBeDefined(); await act(async () => { const completion = button(label).props.onPress(); if (waitForCompletion) await completion; }); }
function field(label: string) { return root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label)!; }
async function mount() {
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><AppNavigator /></SessionProvider></ThemeProvider>); });
  await vi.waitFor(() => expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(1));
  await vi.waitFor(() => expect(button("Change password")).toBeDefined());
  if (scheme === "v1") await vi.waitFor(() => expect(button("Upgrade now")).toBeDefined());
}
async function rotation(old = OLD, next = NEW) {
  await press("Change password");
  await act(async () => { field("Password confirmation").props.onChangeText(old); field("New password").props.onChangeText(next); });
  await press(scheme === "v2" ? "Change password and sign in again" : "Rotate keys and sign in again");
}
async function upgrade(waitForCompletion = true) {
  await press("Upgrade now");
  await act(async () => field("Password confirmation").props.onChangeText(OLD));
  await press("Confirm with password", waitForCompletion);
}
function v2() {
  scheme = "v2"; envelopeData = DATA;
  vault.unlock({ masterKey: Buffer.from(master), authKey: Buffer.from(auth), dataKey: Buffer.from(DATA) }, USER);
  installLocalDataKey(USER, vault.get().dataKey);
}

beforeEach(async () => {
  nativeNavigation.listeners.clear();
  nativeNavigation.mainRoute = "Settings";
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); files.__resetFiles(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  scheme = "v1"; serverSalt = Buffer.from(SALT); verifier = auth.toString("base64"); envelopeData = derivedData;
  passwordStatus = rekeyStatus = envelopeStatus = upgradeStatus = 200; upgradeCode = ""; wrapped = undefined; newParams = undefined;
  passwordBody = rekeyBody = upgradeBody = undefined; processingKeys = []; paths = []; boundary = undefined; Alert.alert.mockClear();
  responseBoundary = undefined; distinctLogins = false; loginNumber = 0;
  recoveryStatus = 200;
  sharing.shareAsync.mockReset().mockResolvedValue(); sharing.isAvailableAsync.mockResolvedValue(true);
  await api.setSession("current Native bearer", USER, "alice"); await api.cacheSalt("alice", SALT.toString("base64")); await recordOnboardingSeen(USER);
  vault.unlock({ masterKey: Buffer.from(master), authKey: Buffer.from(auth), dataKey: Buffer.from(derivedData) }, USER); installLocalDataKey(USER, vault.get().dataKey);
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) : undefined; paths.push(path);
    let value: unknown = {}, status = 200;
    if (path.endsWith("/meta")) value = { unlock_days: 30 };
    else if (path.endsWith("/insights")) value = { active_days: 2 };
    else if (path.endsWith("/account/llm-consent") || path.endsWith("/account/voice-consent")) value = { enabled: false, active_for_current_policy: true };
    else if (path.endsWith("/account/recovery")) { status = recoveryStatus; value = { enabled: false, set_at: null, scheme: "v1" }; }
    else if (path.endsWith("/auth/salt")) value = { salt: serverSalt.toString("base64") };
    else if (path.endsWith("/auth/key-envelope")) { status = envelopeStatus; value = { key_scheme: scheme, salt: serverSalt.toString("base64"), kdf_params: scheme === "v2" ? newParams ?? { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 } : null, wrapped_data_key: scheme === "v2" ? wrapped ?? wrap(envelopeData) : null }; }
    else if (path.endsWith("/processing/sessions")) { processingKeys.push(body.data_key); value = { session_token: "Native possession token" }; }
    else if (path.endsWith("/account/password")) { passwordBody = body; status = passwordStatus; if (status === 200 && body.verifier !== verifier) status = 403; if (status === 200) { serverSalt = Buffer.from(body.new_salt, "base64"); verifier = body.new_verifier; wrapped = body.wrapped_data_key; newParams = body.new_kdf_params; } }
    else if (path.endsWith("/processing/rekey")) { rekeyBody = body; status = rekeyStatus; if (status === 200) { serverSalt = Buffer.from(body.new_salt, "base64"); verifier = body.new_verifier; value = { credential_rotated: true, operation_id: body.operation_id, entries: 0, insights: 0, measures: 0, consents_rewrapped: 0, recovery_invalidated: true }; } }
    else if (path.endsWith("/account/key-envelope/upgrade")) { upgradeBody = body; status = upgradeStatus; if (status === 200) { scheme = "v2"; wrapped = body.wrapped_data_key; newParams = body.kdf_params; } }
    else if (path.endsWith("/auth/login")) { status = body.verifier === verifier ? 200 : 401; value = { token: distinctLogins ? `handoff Native bearer ${++loginNumber}` : "rotated Native bearer", user_id: USER }; }
    else if (path.endsWith("/consents")) value = [];
    else if (!path.endsWith("/auth/logout")) throw new Error("Unexpected Native Settings route: " + path);
    if (status !== 200) value = { code: upgradeCode || "native_refusal", detail: "Untrusted server failure" };
    if (boundary) await boundary(path, body);
    const response = new Response(JSON.stringify(value), { status }); Object.defineProperty(response, "url", { value: url });
    if (responseBoundary) { const json = response.json.bind(response); response.json = async () => { const result = await json(); await responseBoundary?.(path); return result; }; }
    return response;
  });
});

it("a theme receipt delivered after Native navigation leaves the current Root vault unlocked", async () => {
  v2();
  const receipt = hold(), get = storage.getItem.bind(storage);
  let themeRead = 0;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key);
    if (key === "@mindpattern/theme.mode" && ++themeRead === 2) await receipt.run();
    return value;
  });
  await mount(); await vi.waitFor(() => expect(receipt.entered()).toBe(true));
  await act(async () => {
    nativeNavigation.mainRoute = "Privacy";
    root!.update(<ThemeProvider><SessionProvider><AppNavigator /></SessionProvider></ThemeProvider>);
  });
  expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(0);
  recoveryStatus = 401;
  receipt.release();
  await act(async () => { for (let i = 0; i < 16; i++) await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(vault.isUnlocked()).toBe(true);
  expect(await secureStore.getItem("@mindpattern/token")).toBe("current Native bearer");
  expect(vault.get().dataKey).toEqual(DATA);
});

it("a granted Native rotation release while Share owns busy keeps the password and retained recording", async () => {
  v2();
  const id = "native-root-busy-rotation", plain = Buffer.from("recoverable Native recording during Share");
  await enqueueAudio({ userId: USER, clientEntryId: id, ...encryptAudio({ dataKey: DATA }, USER, id, plain), mime: "audio/m4a", durationSeconds: 4, parentPending: true }, captureLocalWritePermit(USER, vault.get().dataKey));
  const slot = `${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(await getBaseUrl())}:${USER}:${id}`;
  const raw = (await storage.getItem(slot))!, descriptor = JSON.parse(raw);
  await mount(); await vi.waitFor(() => expect(button("Export encrypted recording 1")).toBeDefined());
  await press("Change password");
  await act(async () => { field("Password confirmation").props.onChangeText(OLD); field("New password").props.onChangeText(NEW); });
  const target = button("Change password and sign in again"), gesture = nativeGrantedPress(target.props), receipt = hold();
  sharing.shareAsync.mockImplementationOnce(async () => { await receipt.run(); });
  await press("Export encrypted recording 1"); await vi.waitFor(() => expect(receipt.entered()).toBe(true));
  try {
    await act(async () => { expect(target.props.disabled).toBe(true); gesture.configure(target.props); gesture.release(); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 1500)); });
    expect(passwordBody).toBeUndefined();
    expect(Alert.alert.mock.calls).toEqual([]);
    expect(await secureStore.getItem("@mindpattern/token")).toBe("current Native bearer");
    expect(await storage.getItem(slot)).toBe(raw);
    expect(decryptAudio({ dataKey: DATA }, USER, id, await files.readAsStringAsync(descriptor.uri))).toEqual(plain);
    expect(button("Change password and sign in again").props.disabled).toBe(true);
  } finally { gesture.dispose(); receipt.release(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); }
});
afterEach(async () => {
  for (const release of releases.splice(0)) release();
  assertPublicSurface({ view: root ? publicSurface(root) : null, alerts: Alert.alert.mock.calls.map(([title, message, choices]: any[]) => ({ title, message, choices: choices?.map((choice: any) => ({ text: choice.text, style: choice.style })) })) }, 1);
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

it.each(["v1", "v2"] as const)("completes actual Native Settings %s rotation with the matching public recovery disclosure", async target => {
  if (target === "v2") v2(); await mount(); await rotation(); await vi.waitFor(() => expect(Alert.alert.mock.calls[0]?.[0]).toBe("Password changed"), { timeout: 4000 });
  expect(Alert.alert.mock.calls).toHaveLength(1); expect(Alert.alert.mock.calls[0][1].includes("recovery kit")).toBe(target === "v1");
  expect(await secureStore.getItem("@mindpattern/token")).toBe("rotated Native bearer");
  const transaction = target === "v1" ? rekeyBody : passwordBody, fresh = crypto.pbkdf2Sync(NEW, Buffer.from(transaction.new_salt, "base64"), 600000, 32, "sha256");
  expect(transaction.new_verifier).toBe(Buffer.from(crypto.hkdfSync("sha256", fresh, Buffer.alloc(32), "mindpattern/auth/v1", 32)).toString("base64"));
  expect(processingKeys[0]).toBe((target === "v1" ? derivedData : DATA).toString("base64"));
  if (target === "v1") expect(vault.canReauthenticate()).toBe(false); else expect(vault.get().dataKey).toEqual(DATA);
});

it.each(["v1", "v2"] as const)("single-shot Native Settings %s rotation acknowledgement cannot sign out a newer login", async target => {
  if (target === "v2") v2(); await mount(); await rotation(); await vi.waitFor(() => expect(Alert.alert.mock.calls[0]?.[0]).toBe("Password changed"), { timeout: 4000 });
  const choice = Alert.alert.mock.calls[0][2]![0]; expect(choice.text).toBe("OK");
  await api.setSession("replacement Native bearer", OTHER, "bob"); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 8), dataKey: Buffer.alloc(32, 9) }, OTHER);
  await act(async () => choice.onPress!());
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement Native bearer"); expect(vault.ownerUserId()).toBe(OTHER); expect(vault.get().dataKey).toEqual(Buffer.alloc(32, 9));
});

it.each(["v1", "v2"] as const)("reports actual Native Settings %s transaction refusal without a success disclosure", async target => {
  if (target === "v2") v2(); rekeyStatus = passwordStatus = 503; await mount(); await rotation();
  if (target === "v1") {
    await vi.waitFor(() => expect(button("Finish interrupted password change")).toBeDefined(), { timeout: 4000 });
    expect(root!.root.findAllByType(UnlockScreen)).toHaveLength(1); expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(0);
    expect(await pendingLocalRekey(USER)).toBe(true); expect(vault.canReauthenticate()).toBe(false); expect(Alert.alert.mock.calls).toEqual([]);
  } else {
    await vi.waitFor(() => expect(Alert.alert.mock.calls).toHaveLength(1), { timeout: 4000 });
    expect(Alert.alert.mock.calls[0][0]).toBe("Could not change password"); expect(Alert.alert.mock.calls[0][1]).not.toContain("Untrusted");
  }
  expect(await secureStore.getItem("@mindpattern/token")).toBe("current Native bearer");
});

it.each(["tiny", "alllowercasepassword"])("rejects the Native Settings password policy before key shipment: %s", async next => {
  await mount(); await rotation(OLD, next); expect(Alert.alert.mock.calls).toHaveLength(1); expect(processingKeys).toEqual([]); expect(passwordBody).toBeUndefined(); expect(rekeyBody).toBeUndefined();
});

it("upgrades through actual Native proof, possession and envelope providers without changing the data key", async () => {
  await mount(); const key = vault.get().dataKey; await upgrade(); await vi.waitFor(() => expect(Alert.alert.mock.calls[0]?.[0]).toBe("Key protection upgraded"), { timeout: 4000 });
  expect(vault.get().dataKey).toBe(key); expect(processingKeys).toEqual([derivedData.toString("base64")]); expect(upgradeBody).toBeDefined(); expect((await cachedEnvelope("alice"))?.scheme).toBe("v2"); expect(button("Upgrade now")).toBeUndefined();
});

it("reports a Native server upgrade completed after the initial v1 card as already protected", async () => {
  await mount(); scheme = "v2"; await upgrade(); await vi.waitFor(() => expect(Alert.alert.mock.calls).toHaveLength(1), { timeout: 4000 });
  expect(upgradeBody).toBeUndefined(); expect(processingKeys).toEqual([]); expect(Alert.alert.mock.calls[0][0]).toBe("Already upgraded");
});

it.each([[403, "envelope_key_mismatch"], [403, "verification_failed"], [503, ""]] as const)("keeps actual Native upgrade refusal honest: %s %s", async (status, code) => {
  upgradeStatus = status; upgradeCode = code; await mount(); await upgrade(); await vi.waitFor(() => expect(Alert.alert.mock.calls).toHaveLength(1), { timeout: 4000 });
  expect(Alert.alert.mock.calls[0][0]).not.toBe("Key protection upgraded"); expect(Alert.alert.mock.calls[0][1]).not.toContain("Untrusted"); expect(vault.get().dataKey).toEqual(derivedData); expect((await cachedEnvelope("alice"))?.scheme).not.toBe("v2");
  if (code === "envelope_key_mismatch") expect(Alert.alert.mock.calls[0][0]).toBe("Could not upgrade key protection");
});

it("keeps a late Native upgrade receipt quiet after the Settings route retires", async () => {
  const held = hold(); boundary = async path => { if (path.endsWith("/account/key-envelope/upgrade")) await held.run(); }; await mount(); await upgrade(false); await vi.waitFor(() => expect(held.entered()).toBe(true), { timeout: 4000 });
  await act(async () => vault.lock()); expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(0); held.release();
  for (let i = 0; i < 128; i++) await act(async () => { await Promise.resolve(); }); expect(Alert.alert.mock.calls).toEqual([]); expect(vault.canReauthenticate()).toBe(false);
});

it("keeps a late Native upgrade disclosure quiet after a navigation blur retires its confirmation", async () => {
  const held = hold(); boundary = async path => { if (path.endsWith("/account/key-envelope/upgrade")) await held.run(); }; await mount(); await upgrade(false);
  await vi.waitFor(() => expect(held.entered()).toBe(true), { timeout: 4000 });
  await act(async () => { for (const callback of nativeNavigation.listeners.get("blur") ?? []) callback(); }); held.release();
  for (let i = 0; i < 128; i++) await act(async () => { await Promise.resolve(); });
  expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(1); expect(vault.get().dataKey).toEqual(derivedData); expect(Alert.alert.mock.calls).toEqual([]);
});

it.each(["v1", "v2"] as const)("keeps a late actual Native Settings %s rotation result from changing a replacement account", async target => {
  if (target === "v2") v2(); const held = hold(); boundary = async path => { if (path.endsWith(target === "v1" ? "/processing/rekey" : "/account/password")) await held.run(); };
  await mount(); await rotation(); await vi.waitFor(() => expect(held.entered()).toBe(true), { timeout: 4000 });
  await api.setSession("replacement Native bearer", OTHER, "bob"); await act(async () => vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 8), dataKey: Buffer.alloc(32, 9) }, OTHER)); held.release();
  for (let i = 0; i < 128; i++) await act(async () => { await Promise.resolve(); });
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement Native bearer"); expect(vault.ownerUserId()).toBe(OTHER); expect(vault.get().dataKey).toEqual(Buffer.alloc(32, 9)); expect(Alert.alert.mock.calls).toEqual([]);
});

it("two installed Native rotation releases before commit keep one v2 password transaction and its public result", async () => {
  v2(); const held = hold(); boundary = async path => { if (path.endsWith("/account/password") && !held.entered()) await held.run(); };
  await mount(); await press("Change password");
  await act(async () => { field("Password confirmation").props.onChangeText(OLD); field("New password").props.onChangeText(NEW); });
  await act(async () => {
    for (let i = 0; i < 2; i++) {
      const props = button("Change password and sign in again").props, tap = nativeGrantedPress(props);
      try { tap.configure(button("Change password and sign in again").props); tap.release(); } finally { tap.dispose(); }
    }
  });
  await vi.waitFor(() => expect(held.entered()).toBe(true), { timeout: 4000 });
  for (let i = 0; i < 128; i++) await act(async () => { await Promise.resolve(); }); held.release();
  await vi.waitFor(() => expect(Alert.alert.mock.calls.some(call => call[0] === "Password changed")).toBe(true), { timeout: 4000 });
  expect(Alert.alert.mock.calls).toHaveLength(1); expect(Alert.alert.mock.calls[0][0]).toBe("Password changed"); expect(vault.get().dataKey).toEqual(DATA);
  const fresh = crypto.pbkdf2Sync(NEW, serverSalt, 600000, 32, "sha256"); expect(verifier).toBe(Buffer.from(crypto.hkdfSync("sha256", fresh, Buffer.alloc(32), "mindpattern/auth/v1", 32)).toString("base64"));
  expect(await secureStore.getItem("@mindpattern/token")).toBe("rotated Native bearer");
});

it.each((["unlock-first", "rotation-first"] as const).flatMap(order => Array.from({ length: 13 }, (_, index) => [order, index] as const)))("preserves actual Root Native rotation and unlock handoff at %s body phase %s", async (order, phase) => {
  distinctLogins = true; const rekey = hold(), unlocking = hold(), rotating = hold(); let loginBodies = 0;
  boundary = async path => { if (path.endsWith("/processing/rekey")) await rekey.run(); };
  responseBoundary = async path => { if (path.endsWith("/auth/login")) { if (++loginBodies === 1) await unlocking.run(); else await rotating.run(); } };
  await mount(); await rotation(); await vi.waitFor(() => expect(rekey.entered()).toBe(true), { timeout: 4000 });
  expect(root!.root.findAllByType(UnlockScreen)).toHaveLength(1);
  await act(async () => field("Password").props.onChangeText(NEW)); let pending!: Promise<void>;
  await act(async () => { pending = field("Password").props.onSubmitEditing(); }); await vi.waitFor(() => expect(unlocking.entered()).toBe(true), { timeout: 4000 });
  rekey.release(); await vi.waitFor(() => expect(rotating.entered()).toBe(true), { timeout: 4000 });
  await act(async () => {
    const first = order === "unlock-first" ? unlocking : rotating, second = order === "unlock-first" ? rotating : unlocking;
    first.release(); let remaining = phase; const next = () => { if (--remaining > 0) queueMicrotask(next); else second.release(); }; if (phase === 0) second.release(); else queueMicrotask(next);
    await pending; for (let i = 0; i < 256; i++) await Promise.resolve();
  });
  expect(await secureStore.getItem("@mindpattern/token")).toMatch(/^handoff Native bearer [12]$/); expect(await api.getUserId()).toBe(USER);
  if (vault.canReauthenticate()) {
    const fresh = crypto.pbkdf2Sync(NEW, serverSalt, 600000, 32, "sha256");
    expect(vault.get().dataKey).toEqual(Buffer.from(crypto.hkdfSync("sha256", fresh, Buffer.alloc(32), "mindpattern/data/v1", 32)));
  }
});

it.each(Array.from({ length: 33 }, (_, phase) => phase))("preserves the actual Root Native final rotation cleanup and newly admitted unlock at delivery phase %s", async phase => {
  const cleanup = hold(), unlocking = hold();
  const remove = storage.removeItem.bind(storage), slot = accountStorageKey.biometricOwner(USER);
  let cleanupReceipts = 0;
  vi.spyOn(storage, "removeItem").mockImplementation(async key => {
    await remove(key);
    // The second actual owner-marker removal belongs to rotation's final
    // cleanup, after its new credentials are physically published.
    if (key === slot && ++cleanupReceipts === 2) {
      await cleanup.run();
      let remaining = phase;
      const next = () => { if (--remaining > 0) queueMicrotask(next); else unlocking.release(); };
      if (phase === 0) unlocking.release(); else queueMicrotask(next);
    }
  });
  responseBoundary = async path => { if (path.endsWith("/auth/login") && cleanup.entered()) await unlocking.run(); };
  await mount(); await rotation();
  await vi.waitFor(() => expect(cleanup.entered()).toBe(true), { timeout: 4000 });
  expect(root!.root.findAllByType(UnlockScreen)).toHaveLength(1);
  expect(await secureStore.getItem("@mindpattern/token")).toBe("rotated Native bearer");
  await act(async () => field("Password").props.onChangeText(NEW));
  let pending!: Promise<void>;
  await act(async () => { pending = field("Password").props.onSubmitEditing(); });
  await vi.waitFor(() => expect(unlocking.entered()).toBe(true), { timeout: 4000 });
  await act(async () => { cleanup.release(); await pending; for (let i = 0; i < 128; i++) await Promise.resolve(); });
  expect(await api.getUserId()).toBe(USER);
  expect(await secureStore.getItem("@mindpattern/token")).toBe("rotated Native bearer");
  const fresh = crypto.pbkdf2Sync(NEW, serverSalt, 600000, 32, "sha256");
  expect(vault.get().dataKey).toEqual(Buffer.from(crypto.hkdfSync("sha256", fresh, Buffer.alloc(32), "mindpattern/data/v1", 32)));
});
