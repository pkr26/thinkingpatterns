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

afterEach(async () => {
  for (const release of releases.splice(0)) release();
  assertPublicSurface({ view: root ? publicSurface(root) : null, alerts: Alert.alert.mock.calls.map(([title, message, choices]: any[]) => ({ title, message, choices: choices?.map((choice: any) => ({ text: choice.text, style: choice.style })) })) }, 1);
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

// Full Root remains mounted while Native navigation disposes Settings.
// The credential replacement below exercises public API+actual encrypted
// storage; it does not claim that Privacy itself produces a login.
it.each(["retry", "remove"] as const)("a disposed Settings %s continuation leaves the physical Native credential worker available", async action => {
  v2();
  const id = "root-native-audio-handoff", plain = Buffer.from("kept Native audio handoff");
  await enqueueAudio({ userId: USER, clientEntryId: id, ...encryptAudio({ dataKey: DATA }, USER, id, plain), mime: "audio/m4a", durationSeconds: 4, parentPending: true }, captureLocalWritePermit(USER, vault.get().dataKey));
  await mount(); await vi.waitFor(() => expect(button("Export encrypted recording 1")).toBeDefined());
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage), list = storage.getAllKeys.bind(storage);
  const deleteFile = files.deleteAsync.getMockImplementation()!, request = globalThis.fetch, held = hold();
  let worker: Promise<unknown> = Promise.resolve(), retired = false, replacementStarted = false, replacementFinished = false;
  let replacement: Promise<void> | undefined, timer: ReturnType<typeof setTimeout> | undefined, directories = 0;
  const nativeJob = <T,>(operation: () => Promise<T>): Promise<T> => { const job = worker.then(operation, operation); worker = job.catch(() => {}); return job; };
  const retire = () => {
    retired = true;
    nativeNavigation.mainRoute = "Privacy";
    act(() => root!.update(<ThemeProvider><SessionProvider><AppNavigator /></SessionProvider></ThemeProvider>));
    setImmediate(() => { replacementStarted = true; replacement = api.setSession("new Native saved-audio handoff bearer", USER, "alice"); void replacement.then(() => { replacementFinished = true; }); });
  };
  // Actual installed Android AsyncStorage uses a FIFO SerialExecutor. The
  // body frees that worker before delivering its JS result. A slow already
  // admitted obsolete UID read must therefore queue current credential IO.
  vi.spyOn(storage, "getItem").mockImplementation(slot => {
    const obsoleteDispatch = retired && !replacementStarted && slot === "@mindpattern/user_id";
    return nativeJob(async () => { if (obsoleteDispatch) { timer ??= setTimeout(held.release, 800); await held.run(); } return read(slot); });
  });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => nativeJob(() => write(slot, value)));
  vi.spyOn(storage, "removeItem").mockImplementation(slot => nativeJob(() => remove(slot)));
  vi.spyOn(storage, "getAllKeys").mockImplementation(async () => {
    const answer = await nativeJob(list);
    // Retry's first directory enumerates descriptors; the second is the
    // actual flush directory whose retired row is refused before upload.
    if (action === "retry" && ++directories === 2) retire();
    return answer;
  });
  files.deleteAsync.mockImplementation(async (...args) => {
    const answer = await deleteFile(...args);
    if (action === "remove" && String(args[0]).endsWith("/exports/" + Buffer.from(id).toString("base64url") + ".json")) retire();
    return answer;
  });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    if (new URL(url).pathname.endsWith("/entries/" + id)) { const response = new Response(JSON.stringify({ detail: "Parent not committed" }), { status: 404 }); Object.defineProperty(response, "url", { value: url }); return response; }
    return request(url, init);
  });
  try {
    if (action === "retry") await press("Retry saved recordings", false);
    else { await press("Remove saved recording 1"); const choice = Alert.alert.mock.calls.at(-1)![2]!.find((choice: any) => choice.style === "destructive")!; await act(async () => choice.onPress!()); }
    await vi.waitFor(() => expect(retired).toBe(true));
    expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(0);
    await vi.waitFor(() => expect(replacementFinished).toBe(true), { timeout: 250, interval: 5 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("new Native saved-audio handoff bearer");
  } finally { held.release(); if (timer) clearTimeout(timer); await replacement; await worker; }
});
