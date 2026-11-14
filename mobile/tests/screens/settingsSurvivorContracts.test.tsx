/** Settings actions through the actual credential, HTTP, crypto, Keychain
 * and storage providers. Held completions exercise a replacement vault. */
import React from "react";
import crypto from "node:crypto";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { EventEmitter } from "node:events";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import ReactTestRenderer, { act } from "react-test-renderer";
import { Alert, AppState, Text, TextInput, TouchableOpacity, Switch, ScrollView } from "react-native";
import { api, DEFAULT_BASE_URL, canonicalOrigin, setBaseUrl } from "../../src/api/client";
import { SettingsScreen } from "../../src/screens/SettingsScreen";
import { ThemeProvider, themeStorageKey } from "../../src/theme";
import { engine } from "../helpers/nodeEngine";
import { nativeGrantedPress } from "../helpers/nativePressability";
import { nativeInputChange } from "../helpers/nativeEntryEvents";
// Execute the installed navigator event publisher; only linked host views are replaced.
// @ts-expect-error The installed JavaScript hook has no standalone declaration.
import { useEventEmitter } from "../../node_modules/@react-navigation/core/lib/module/useEventEmitter.js";
import { accountStorageKey, ACCOUNT_STORAGE_PREFIX } from "../../src/accountStorage";
import { vault } from "../../src/vault";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { setLocale } from "../../src/strings";
import { enableBiometricUnlock, unwrapBiometricDataKey } from "../../src/biometricUnlock";
import { __resetLocalKeyLifecycleForTests, installLocalDataKey, captureLocalWritePermit } from "../../src/localWriteGuard";
import { encryptAudio, decryptAudio, encryptEntry } from "../../src/crypto/journalCrypto";
import { enqueueAudio, abortInFlightAudioFlush, prepareAudioRekey, cleanupAudioRekey } from "../../src/audioQueue";
import { prepareLocalRekey } from "../../src/localRekey";
import * as sharing from "../helpers/expoSharingMock";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import * as files from "../helpers/expoFsMock";
import { emitAppState } from "../helpers/rnMock";
vi.mock("../../src/store", async original => ({ ...await original<typeof import("../../src/store")>(), useSession: () => ({ touchActivity: () => {}, signOut: async () => { await api.clearSession(); } }) }));
// The Node runner cannot load linked native pods synchronously. These
// device capability facts expose the actual shipped preferences/actions.
vi.mock("../../src/nativeFeatures", async original => ({ ...await original<typeof import("../../src/nativeFeatures")>(), reminderCapability: () => ({ available: true }) }));
vi.mock("../../src/healthkit", async original => ({ ...await original<typeof import("../../src/healthkit")>(), healthKitCapability: () => ({ available: true }) }));
const { notificationDevice, healthDevice } = vi.hoisted(() => ({ healthDevice: { authorize: async () => true }, notificationDevice: { notifications: new Map<string, unknown>(), permission: async (): Promise<unknown> => ({ authorizationStatus: 1 }) } }));
vi.mock("@notifee/react-native", () => ({ default: {
  requestPermission: () => notificationDevice.permission(), createChannel: async () => "channel",
  getTriggerNotifications: async () => [], getDisplayedNotifications: async () => [],
  createTriggerNotification: async (record: { id: string }, trigger: unknown) => { notificationDevice.notifications.set(record.id, trigger); return record.id; },
  cancelNotification: async (id: string) => { notificationDevice.notifications.delete(id); }, cancelAllNotifications: async () => { notificationDevice.notifications.clear(); },
}, TriggerType: { TIMESTAMP: 0 }, RepeatFrequency: { DAILY: 1 } }));
vi.mock("react-native-health", () => ({ default: { requestAuthorization: () => healthDevice.authorize(), getAuthorizationStatus: async () => ({ stateOfMind: 2 }), saveStateOfMind: async () => true } }));
const USER = "a".repeat(32), PASSWORD = "native settings password proof", SALT = Buffer.alloc(16, 3);
const MASTER = crypto.pbkdf2Sync(PASSWORD, SALT, 600000, 32, "sha256");
const AUTH = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const DATA = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/data/v1", 32));
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let boundary: ((path: string, method: string) => Promise<void>) | undefined;
let nativeRouteEvents: { emit(event: { type: string; target: string }): void } | undefined;
let recoverySealed: string | undefined;
let consent: boolean, voice: boolean, recovery: boolean, serverAccountPresent: boolean, setupStatus: number, recoveryRemoveStatus: number, consentWriteStatus: number, recoveryReadStatus: number, deleteStatus: number;
const releases: Array<() => void> = [];
function pause() { let entered = false, release!: () => void; const wait = new Promise<void>(resolve => { release = resolve; }); releases.push(release); return { run: async () => { entered = true; await wait; }, entered: () => entered, release }; }
function text() { const flatten = (value: unknown): string => Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" || typeof value === "number" ? String(value) : ""; return root!.root.findAllByType(Text).map(node => flatten(node.props.children)).join(" "); }
function control(label: string) { return root!.root.findAllByType(Switch).find(node => node.props.accessibilityLabel === label)!; }
async function press(label: string, wait = true) { const node = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label); expect(node, label).toBeDefined(); await act(async () => { const result = node!.props.onPress(); if (wait) await result; }); }
async function button(label: string) { const calls = vi.mocked(Alert.alert).mock.calls, selected = calls.at(-1)?.[2]?.find(node => node.text === label); expect(selected, label).toBeDefined(); await act(async () => { await selected!.onPress?.(); }); }
async function flush() { await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); }
async function mount() { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SettingsScreen navigation={{ navigate: () => {}, popToTop: () => {} }}/></ThemeProvider>); }); await flush(); }
async function confirm(wait = true) { const field = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!; expect(field).toBeDefined(); await act(async () => field.props.onChangeText(PASSWORD)); await press("Confirm with password", wait); }
function alert() { return vi.mocked(Alert.alert).mock.calls.at(-1); }
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); setLocale("en"); storage.__reset(); keychain.__reset(); files.__resetFiles(); runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  await api.setSession("native bearer", USER, "alice"); await api.cacheSalt("alice", SALT.toString("base64"));
  vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER);
  installLocalDataKey(USER, vault.get().dataKey);
  abortInFlightAudioFlush(); sharing.isAvailableAsync.mockResolvedValue(true); sharing.shareAsync.mockResolvedValue();
  boundary = undefined; nativeRouteEvents = undefined; recoverySealed = undefined; consent = false; voice = false; recovery = false; serverAccountPresent = true; setupStatus = 200; recoveryRemoveStatus = 200; consentWriteStatus = 200; recoveryReadStatus = 200; deleteStatus = 200; vi.mocked(Alert.alert).mockClear(); notificationDevice.notifications = new Map(); notificationDevice.permission = async () => ({ authorizationStatus: 1 }); healthDevice.authorize = async () => true;
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname, method = init.method ?? "GET";
    let value: unknown = {}, status = 200;
    if (path.endsWith("/meta")) value = { unlock_days: 30, llm_available: true, llm_provider_name: "Native LLM", sharing_available: true, audio_available: true, stt_provider_name: "Native transcription" };
    else if (path.endsWith("/auth/key-envelope")) value = { key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null };
    else if (path.endsWith("/account/llm-consent") || path.endsWith("/account/voice-consent")) {
      const isVoice = path.endsWith("/account/voice-consent");
      if (method === "PUT") {
        const body = JSON.parse(String(init.body));
        status = consentWriteStatus;
        if (body.verifier !== AUTH.toString("base64")) status = 403;
        if (status === 200) { if (isVoice) voice = body.enabled; else consent = body.enabled; }
      }
      value = status === 200 ? { enabled: isVoice ? voice : consent, active_for_current_policy: true } : { error: { code: "verification_failed", message: "Proof rejected" } };
    } else if (path.endsWith("/account/recovery")) {
      if (method === "GET") status = recoveryReadStatus;
      if (method === "PUT") { status = setupStatus; if (status === 200) { recovery = true; recoverySealed = JSON.parse(String(init.body)).wrapped_key; } }
      if (method === "DELETE") { status = recoveryRemoveStatus; if (status === 200) recovery = false; }
      value = status === 200 ? { enabled: recovery, set_at: recovery ? "2026-10-07T04:00:00Z" : null, scheme: "v2" } : { error: { code: "server_error", message: "Recovery setup unavailable" } };
    } else if (path.endsWith("/account") && method === "DELETE") { status = deleteStatus; if (new Headers(init.headers).get("X-Account-Verifier") !== AUTH.toString("base64")) status = 403; if (status === 200) serverAccountPresent = false; value = status === 200 ? {} : { error: { code: status === 403 ? "verification_failed" : "server_error", message: "Native account deletion refused" } };
    } else if (path.endsWith("/auth/login")) { const body = JSON.parse(String(init.body)); status = body.verifier === AUTH.toString("base64") ? 200 : 401; value = { token: "native password-proof bearer", user_id: USER }; }
    else if (path.endsWith("/auth/logout")) value = {};
    else throw new Error("Unexpected Native route " + path);
    const response = new Response(JSON.stringify(value), { status }); Object.defineProperty(response, "url", { value: url });
    const json = response.json.bind(response); response.json = async () => { const answer = await json(); await boundary?.(path, method); return answer; }; return response;
  });
});
afterEach(async () => { for (const release of releases.splice(0)) release(); await flush(); if (root) { await act(async () => root!.unmount()); root = undefined; } vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals(); vi.useRealTimers(); });

// Focused public contracts for residual Settings operators.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
it.each(["first open", "after nested cancel"] as const)("rotation password fields are empty on %s", async phase => {
  await mount(); await press("Change password");
  const input = (label: string) => root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label);
  if (phase === "after nested cancel") {
    await act(async () => { input("Password confirmation")!.props.onChangeText("old credential"); input("New password")!.props.onChangeText("unused new credential"); });
    await press("Cancel"); await press("Change password");
  }
  expect(input("Password confirmation")?.props.value).toBe("");
  expect(input("New password")?.props.value).toBe("");
});

it("a mounted granted confirmation cannot change the old account after the vault owner changes in place", async () => {
  await mount();
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  const input = () => root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation");
  await act(async () => input()!.props.onChangeText(PASSWORD));
  const button = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Confirm with password")!;
  const granted = nativeGrantedPress(button.props);
  // Await real KDF work admitted by the release before observing the server;
  // no guessed delay or job-count assertion decides the contract.
  const derivations: Promise<void>[] = [];
  const derive = engine.pbkdf2.bind(engine);
  vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => {
    let finish!: () => void;
    derivations.push(new Promise<void>(resolve => { finish = resolve; }));
    derive(password, salt, iterations, length, digest, (error, key) => { callback(error, key); finish(); });
  });
  try {
    await act(async () => {
      // This release remains on its mounted host, before React commits.
      // A public vault owner change may reuse the physical key allocation.
      const dataKey = vault.get().dataKey;
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey }, "d".repeat(32));
      granted.release();
    });
    await flush();
    await act(async () => { await Promise.all(derivations); }); await flush();
    expect(consent).toBe(false);
    expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
    expect(control("Allow third-party transcript translation").props.value).toBe(false);
  } finally { granted.dispose(); }
});

it.each(["create", "remove"] as const)("a retired recovery %s cannot release a newer held password confirmation", async action => {
  recovery = action === "remove"; await mount();
  const old = pause(), current = pause();
  boundary = async (path, method) => {
    if (path.endsWith("/account/recovery") && method === (action === "create" ? "PUT" : "DELETE")) await old.run();
    if (path.endsWith("/account/llm-consent") && method === "PUT") await current.run();
  };
  await press(action === "create" ? "Create recovery kit" : "Remove kit"); await confirm(false);
  await vi.waitFor(() => expect(old.entered()).toBe(true));
  await act(async () => { emitAppState("inactive"); emitAppState("active"); });
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(false);
  await vi.waitFor(() => expect(current.entered()).toBe(true));
  old.release(); await flush();
  const password = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation");
  const confirmation = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Cancel");
  expect(password?.props.value).toBe(PASSWORD);
  expect(confirmation?.props.disabled).toBe(true);
  expect(text()).toContain("Verifying");
  current.release(); await flush();
  expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")).toBeUndefined();
  expect(control("Allow third-party transcript translation").props.value).toBe(true);
});

it("the first mounted appearance reflects the saved dark preference", async () => {
  await storage.setItem(themeStorageKey(), "dark"); await mount();
  const dark = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Theme: Dark");
  expect(dark?.props.accessibilityState.selected).toBe(true);
});

it("an old saved-recording action reports a damaged session without exporting across vault owners", async () => {
  const id = "settings-owner-protected-recording";
  const words = Buffer.from("retained private recording");
  const blob = encryptAudio({ dataKey: DATA }, USER, id, words);
  await enqueueAudio({ userId: USER, clientEntryId: id, ...blob, mime: "audio/m4a", durationSeconds: 4 }, captureLocalWritePermit(USER, vault.get().dataKey));
  await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  await act(async () => {
    const dataKey = vault.get().dataKey;
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey }, "d".repeat(32));
  });
  await press("Export encrypted recording 1"); await flush();
  expect(alert()?.slice(0, 2)).toEqual(["Export failed", "Session damaged"]);
  expect(sharing.shareAsync).not.toHaveBeenCalled();
  const retained = JSON.parse((await storage.getItem(`${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:${id}`))!);
  expect(decryptAudio({ dataKey: DATA }, USER, id, await files.readAsStringAsync(retained.uri))).toEqual(words);
});

it("a refused old-owner recording action leaves the physical credential worker available", async () => {
  const id = "settings-owner-worker-recording";
  const blob = encryptAudio({ dataKey: DATA }, USER, id, Buffer.from("retained worker witness"));
  await enqueueAudio({ userId: USER, clientEntryId: id, ...blob, mime: "audio/m4a", durationSeconds: 4 }, captureLocalWritePermit(USER, vault.get().dataKey));
  await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  await act(async () => {
    const dataKey = vault.get().dataKey;
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey }, "d".repeat(32));
  });
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage);
  const held = pause(); let worker: Promise<unknown> = Promise.resolve(), replacement: Promise<void> | undefined, replacementFinished = false;
  let admitted = false, timer: ReturnType<typeof setTimeout> | undefined;
  const nativeJob = <T,>(body: () => Promise<T>): Promise<T> => { const next = worker.then(body); worker = next.catch(() => {}); return next; };
  // Installed Android AsyncStorage uses a FIFO SerialExecutor. A late UID
  // read can occupy that physical worker after its screen proof is refused.
  vi.spyOn(storage, "getItem").mockImplementation(slot => {
    const obsolete = slot === "@mindpattern/user_id" && !replacement && !admitted;
    if (obsolete) admitted = true;
    return nativeJob(async () => { if (obsolete) { timer = setTimeout(held.release, 800); await held.run(); } return read(slot); });
  });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => nativeJob(() => write(slot, value)));
  vi.spyOn(storage, "removeItem").mockImplementation(slot => nativeJob(() => remove(slot)));
  try {
    await press("Export encrypted recording 1");
    replacement = api.setSession("settings new credential worker bearer", USER, "alice");
    void replacement.then(() => { replacementFinished = true; });
    await vi.waitFor(() => expect(replacementFinished).toBe(true), { timeout: 250, interval: 5 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("settings new credential worker bearer");
    expect(sharing.shareAsync).not.toHaveBeenCalled();
  } finally { held.release(); if (timer) clearTimeout(timer); await replacement; await worker; }
});

it("write-suspended vault custody cannot remove an existing recovery kit", async () => {
  recovery = true; await mount(); await press("Remove kit");
  await act(async () => {
    const dataKey = vault.get().dataKey;
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey }, USER, { writeSuspended: true });
  });
  await confirm();
  await vi.waitFor(() => expect(alert()?.slice(0, 2)).toEqual(["Recovery kit", "The kit could not be removed — try again."]));
  expect(recovery).toBe(true);
  expect(text()).toContain("Remove kit");
});

it("a retired biometric identity failure cannot interrupt a newer password confirmation", async () => {
  keychain.__setBiometryType("FaceID"); await mount();
  await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable");
  const old = pause(), current = pause(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (first && slot === "@mindpattern/user_id") { first = false; await old.run(); throw new Error("Native identity read temporarily unavailable"); }
    return value;
  });
  await confirm(false); await vi.waitFor(() => expect(old.entered()).toBe(true));
  await act(async () => { emitAppState("inactive"); emitAppState("active"); });
  boundary = async (path, method) => { if (path.endsWith("/account/llm-consent") && method === "PUT") await current.run(); };
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(false);
  await vi.waitFor(() => expect(current.entered()).toBe(true)); vi.mocked(Alert.alert).mockClear();
  old.release(); await flush();
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")?.props.value).toBe(PASSWORD);
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Cancel")?.props.disabled).toBe(true);
  current.release(); await flush(); expect(control("Allow third-party transcript translation").props.value).toBe(true);
});

it("a mismatched vault owner after a native delete-identity receipt is reported as local failure", async () => {
  await mount(); await press("Delete my account and data"); await button("Continue"); await button("Continue to password");
  const held = pause(), read = secureStore.getItem.bind(secureStore); let usernameReads = 0;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    // Reauthentication reads first; deletion's own identity receipt is held.
    if (slot === "@mindpattern/username" && ++usernameReads === 2) await held.run();
    return value;
  });
  await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => {
    const dataKey = vault.get().dataKey;
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey }, "d".repeat(32));
  });
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush();
  await vi.waitFor(() => expect(alert()?.slice(0, 2)).toEqual(["Delete failed", "Something went wrong — try again."]));
  expect(serverAccountPresent).toBe(true);
});

it("a retired initial theme receipt leaves the physical credential worker available", async () => {
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage);
  const theme = pause(), language = pause(); let retired = false, worker: Promise<unknown> = Promise.resolve();
  let replacement: Promise<void> | undefined, replacementFinished = false, timer: ReturnType<typeof setTimeout> | undefined;
  const nativeJob = <T,>(body: () => Promise<T>): Promise<T> => { const next = worker.then(body); worker = next.catch(() => {}); return next; };
  vi.spyOn(storage, "getItem").mockImplementation(slot => {
    const obsolete = retired && slot === "@mindpattern/language_pref";
    const physical = nativeJob(async () => { if (obsolete) { timer ??= setTimeout(language.release, 800); await language.run(); } return read(slot); });
    // Native completes before its JS promise receipt; hold only that receipt.
    return physical.then(async value => { if (slot === themeStorageKey()) await theme.run(); return value; });
  });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => nativeJob(() => write(slot, value)));
  vi.spyOn(storage, "removeItem").mockImplementation(slot => nativeJob(() => remove(slot)));
  try {
    await mount(); await vi.waitFor(() => expect(theme.entered()).toBe(true));
    await act(async () => { root!.unmount(); root = undefined; }); retired = true;
    await act(async () => { theme.release(); }); await flush();
    replacement = api.setSession("settings new initial receipt bearer", USER, "alice");
    void replacement.then(() => { replacementFinished = true; });
    await vi.waitFor(() => expect(replacementFinished).toBe(true), { timeout: 250, interval: 5 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("settings new initial receipt bearer");
  } finally { theme.release(); language.release(); if (timer) clearTimeout(timer); await replacement; await worker; }
});

it("an admitted native confirmation release refuses the password cleared through its current input", async () => {
  await mount();
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  const field = () => root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation");
  await act(async () => nativeInputChange(field()!.props, PASSWORD));
  const enabled = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Confirm with password")!;
  expect(enabled.props.disabled).toBe(false);
  const derivations: Promise<void>[] = [], derive = engine.pbkdf2.bind(engine);
  vi.spyOn(engine, "pbkdf2").mockImplementation((password, salt, iterations, length, digest, callback) => {
    let finish!: () => void; derivations.push(new Promise<void>(resolve => { finish = resolve; }));
    derive(password, salt, iterations, length, digest, (error, key) => { callback(error, key); finish(); });
  });
  const granted = nativeGrantedPress(enabled.props);
  try {
    await act(async () => nativeInputChange(field()!.props, ""));
    const current = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Confirm with password")!;
    expect(current.props.disabled).toBe(true);
    // Installed Pressability reconfigures the already granted responder.
    // Its touch-release path forwards current onPress even after disabled.
    granted.configure(current.props);
    await act(async () => granted.release());
    await act(async () => { await Promise.all(derivations); }); await flush();
    expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
    expect(field()?.props.value).toBe("");
    expect(control("Allow third-party transcript translation").props.value).toBe(false);
    expect(consent).toBe(false);
  } finally {
    granted.dispose(); await act(async () => { await Promise.all(derivations); }); await flush();
  }
});
