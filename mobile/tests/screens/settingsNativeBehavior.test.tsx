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
import { ThemeProvider } from "../../src/theme";
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
let nativeRouteEvents: { emit(event: { type: string; target: string }): unknown } | undefined;
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

it.each(["llm", "voice"] as const)("a completed native %s consent proof publishes the acknowledged state", async kind => {
  await mount(); const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling";
  await act(async () => control(label).props.onValueChange(true)); await confirm(); await flush();
  expect(control(label).props.value).toBe(true); expect(text()).not.toContain("Confirm with password");
});
it("a second accessible password confirmation cannot interrupt a held Native consent write", async () => {
  await mount(); const held = pause(); let first = true;
  boundary = async (path, method) => { if (first && method === "PUT" && path.endsWith("/account/llm-consent")) { first = false; await held.run(); } };
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(false);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); consentWriteStatus = 500;
  await press("Confirm with password");
  const field = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation");
  expect(field).toBeDefined(); expect(field!.props.value).toBe(PASSWORD); expect(control("Allow third-party transcript translation").props.value).toBe(false);
  held.release(); await flush(); expect(control("Allow third-party transcript translation").props.value).toBe(true);
});
it.each(["llm", "voice"] as const)("a late native %s initial read cannot erase an acknowledged new consent", async kind => {
  const held = pause(); boundary = async (path, method) => { if (method === "GET" && path.endsWith("/account/" + kind + "-consent")) await held.run(); };
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling";
  await act(async () => control(label).props.onValueChange(true)); await confirm(); await flush(); expect(control(label).props.value).toBe(true);
  held.release(); await flush(); expect(control(label).props.value).toBe(true);
});
it("a late native initial recovery read cannot undo an acknowledged kit removal", async () => {
  recovery = true; const held = pause(); let initial = true;
  boundary = async (path, method) => { if (initial && method === "GET" && path.endsWith("/account/recovery")) { initial = false; await held.run(); } };
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  // Native creation is allowed while the initial status is unknown. Its
  // acknowledgement establishes the visible current state and removal.
  await press("Create recovery kit"); await confirm(); await flush(); await press("I saved the key");
  await press("Remove kit"); await confirm(); await flush(); expect(text()).not.toContain("Remove kit");
  held.release(); await flush(); expect(text()).not.toContain("Remove kit"); expect(text()).toContain("No recovery kit.");
});
it.each(["llm", "voice"] as const)("a refused native %s change still accepts the initial current consent", async kind => {
  consent = true; voice = true; consentWriteStatus = 403;
  const held = pause(); boundary = async (path, method) => { if (method === "GET" && path.endsWith("/account/" + kind + "-consent")) await held.run(); };
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling";
  await act(async () => control(label).props.onValueChange(false)); await confirm();
  expect(text()).toContain("Confirm with password"); held.release(); await flush(); expect(control(label).props.value).toBe(true);
});
it("a refused native kit creation still accepts the initial existing kit", async () => {
  recovery = true; setupStatus = 500; const held = pause();
  boundary = async (path, method) => { if (method === "GET" && path.endsWith("/account/recovery")) await held.run(); };
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await press("Create recovery kit"); await confirm(); expect(text()).not.toContain("mindpattern-recovery:v2:");
  held.release(); await flush(); expect(text()).toContain("Remove kit");
});
it("a late refused native status read cannot hide an acknowledged new kit", async () => {
  recoveryReadStatus = 500; const held = pause(); let first = true;
  boundary = async (path, method) => { if (first && method === "GET" && path.endsWith("/account/recovery")) { first = false; await held.run(); } };
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await press("Create recovery kit"); await confirm(); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]); await press("I saved the key"); expect(text()).toContain("Remove kit");
  held.release(); await flush(); expect(text()).toContain("Remove kit");
});
it("held native preference reads retain the advertised initial selections", async () => {
  const held = pause(), read = storage.getItem.bind(storage);
  const keys = new Set(["@mindpattern/haptics.enabled", "@mindpattern/theme.mode", accountStorageKey.reminders(USER), accountStorageKey.measureReminders(USER), accountStorageKey.healthMirror(USER)]);
  vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (keys.has(key)) await held.run(); return value; });
  await mount(); expect(held.entered()).toBe(true);
  expect(control("Haptics").props.value).toBe(true); expect(control("Daily reminder").props.value).toBe(false);
  expect(control("Check-in reminders").props.value).toBe(false); expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false);
  const selected = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Theme: System");
  expect(selected!.props.accessibilityState.selected).toBe(true); held.release(); await flush();
});
it("saved Native haptics, language, and check-in cadence publish their actual initial choices",async()=>{
 await storage.setItem("@mindpattern/haptics.enabled","off");await secureStore.setItem("@mindpattern/language_pref","es");await storage.setItem(accountStorageKey.measureReminders(USER),JSON.stringify({enabled:true,intervalWeeks:2}));await mount();expect(control("Haptics").props.value).toBe(false);expect(control("Check-in reminders").props.value).toBe(true);for(const label of ["App language: Español","Check-in interval: 2 weeks"]){expect(root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel===label)?.props.accessibilityState.selected,label).toBe(true);}
});
it.each(["haptics", "theme", "daily", "measure", "health"] as const)("an initial Native %s preference read cannot undo a newer choice", async kind => {
  const key = kind === "haptics" ? "@mindpattern/haptics.enabled" : kind === "theme" ? "@mindpattern/theme.mode" : kind === "daily" ? accountStorageKey.reminders(USER) : kind === "measure" ? accountStorageKey.measureReminders(USER) : accountStorageKey.healthMirror(USER);
  await storage.setItem(key, kind === "haptics" ? "off" : kind === "theme" ? "dark" : kind === "daily" ? JSON.stringify({ enabled: false, hour: 20, minute: 0 }) : kind === "measure" ? JSON.stringify({ enabled: false, intervalWeeks: 4 }) : JSON.stringify({ enabled: false }));
  const notifications = new Map<string, unknown>();
  vi.stubGlobal("require", (name: string) => {
    if (name === "@notifee/react-native") return { default: { requestPermission: async () => ({ authorizationStatus: 1 }), createChannel: async () => "channel", getTriggerNotifications: async () => [], getDisplayedNotifications: async () => [], createTriggerNotification: async (record: { id: string }, trigger: unknown) => { notifications.set(record.id, trigger); return record.id; }, cancelNotification: async (id: string) => { notifications.delete(id); }, cancelAllNotifications: async () => { notifications.clear(); } }, TriggerType: { TIMESTAMP: 0 }, RepeatFrequency: { DAILY: 1 } };
    if (name === "react-native-health") return { requestAuthorization: () => healthDevice.authorize(), getAuthorizationStatus: async () => ({ stateOfMind: 2 }), saveStateOfMind: async () => true };
    throw new Error("Unavailable Native module " + name);
  });
  const held = pause(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async requested => { const value = await read(requested); if (requested === key && (first || kind === "theme")) { first = false; await held.run(); } return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const label = kind === "haptics" ? "Haptics" : kind === "daily" ? "Daily reminder" : kind === "measure" ? "Check-in reminders" : "Mirror mood check-ins to the Health app";
  if (kind === "theme") await press("Theme: Light");
  else {
    if (kind === "haptics") await act(async () => { await control(label).props.onValueChange(false); });
    await act(async () => { await control(label).props.onValueChange(true); });
  }
  held.release(); await flush();
  if (kind === "theme") {
    const selected = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Theme: Light")!;
    expect(selected.props.accessibilityState.selected).toBe(true); expect(root!.root.findAllByType(ScrollView)[0].props.style[1].backgroundColor).toBe("#f8f5ef");
  } else expect(control(label).props.value).toBe(true);
});
it.each(["daily", "measure"] as const)("an initial Native %s read cannot undo a newer schedule choice", async kind => {
  const key = kind === "daily" ? accountStorageKey.reminders(USER) : accountStorageKey.measureReminders(USER);
  await storage.setItem(key, JSON.stringify(kind === "daily" ? { enabled: true, hour: 20, minute: 0 } : { enabled: true, intervalWeeks: 8 }));
  const held = pause(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async requested => { const value = await read(requested); if (first && requested === key) { first = false; await held.run(); } return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => { await control(kind === "daily" ? "Daily reminder" : "Check-in reminders").props.onValueChange(true); });
  const label = kind === "daily" ? "Reminder time: Morning 9:00" : "Check-in interval: 2 weeks";
  await press(label); held.release(); await flush();
  const selected = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label)!;
  expect(selected.props.accessibilityState.selected).toBe(true);
  expect(JSON.parse((await storage.getItem(key))!)).toMatchObject(kind === "daily" ? { hour: 9, minute: 0 } : { intervalWeeks: 2 });
});
it("an initial Native biometric presence read cannot undo a completed wrap", async () => {
  keychain.__setBiometryType("FaceID"); const held = pause(), has = keychain.hasGenericPassword; let first = true;
  vi.spyOn(keychain, "hasGenericPassword").mockImplementation(async options => { const value = await has(options); if (first && options?.service === "com.mindpattern.biometric-unlock.v1." + USER) { first = false; await held.run(); } return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable"); await confirm();
  held.release(); await flush(); expect(control("Biometric unlock").props.value).toBe(true);
});
it("an initial encrypted Native language read cannot undo a newer language selection", async () => {
  await secureStore.setItem("@mindpattern/language_pref", "device"); const held = pause(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (first && key === "@mindpattern/language_pref") { first = false; await held.run(); } return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true)); await press("App language: English"); await flush();
  held.release(); await flush();
  const selected = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "App language: English")!;
  expect(selected.props.accessibilityState.selected).toBe(true); expect(await secureStore.getItem("@mindpattern/language_pref")).toBe("en");
});
it("an acknowledged encrypted Native Spanish choice rerenders the current screen", async () => {
  await mount(); await press("App language: Español"); await flush();
  expect(await secureStore.getItem("@mindpattern/language_pref")).toBe("es"); expect(text()).toContain("Idioma");
});
it.each(["llm", "voice"] as const)("a native %s acknowledgement cannot grant permission after backgrounding", async kind => {
  await mount(); const held = pause();
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/" + kind + "-consent")) await held.run(); };
  const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling";
  await act(async () => control(label).props.onValueChange(true)); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => emitAppState("background")); held.release(); await flush();
  expect(control(label).props.value).toBe(false); expect(text()).not.toContain("Confirm with password");
});
it("a Native biometric write publishes the actual completed preference", async () => {
  keychain.__setBiometryType("FaceID"); await mount();
  await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable"); await confirm(); await flush();
  expect(control("Biometric unlock").props.value).toBe(true);
  expect(await keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1." + USER })).toBe(true);
});
it("a pending Native biometric write cannot revive a retired foreground proof", async () => {
  keychain.__setBiometryType("FaceID"); await mount(); const held = pause(), write = keychain.setGenericPassword;
  vi.spyOn(keychain, "setGenericPassword").mockImplementation(async (...args) => { const answer = await write(...args); if (args[2]?.service?.startsWith("com.mindpattern.biometric-unlock.v1.")) await held.run(); return answer; });
  await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable"); await confirm(false);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); vi.mocked(Alert.alert).mockClear(); await act(async () => emitAppState("background")); held.release(); await flush();
  expect(control("Biometric unlock").props.value).toBe(false); expect(text()).not.toContain("Confirm with password");
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it.each(["llm", "voice", "recovery"] as const)("an old native %s acknowledgement cannot publish into a replacement data key", async kind => {
  await mount(); const held = pause();
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith(kind === "recovery" ? "/account/recovery" : "/account/" + kind + "-consent")) await held.run(); };
  if (kind === "recovery") await press("Create recovery kit");
  else await act(async () => control(kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling").props.onValueChange(true));
  await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const replacement = Buffer.alloc(32, 9); installLocalDataKey(USER, replacement);
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.from(AUTH), dataKey: replacement }, USER); held.release(); await flush();
  if (kind === "recovery") expect(text()).not.toContain("mindpattern-recovery:v2:");
  else expect(control(kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling").props.value).toBe(false);
  expect(vault.get().dataKey).toEqual(Buffer.alloc(32, 9));
});
it("a held native legacy-queue inventory does not announce recovery before a record is found", async () => {
  const held = pause(), read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (key === "@mindpattern/queue.legacy-unscoped.v1") await held.run(); return value; });
  await mount(); expect(held.entered()).toBe(true); expect(text()).not.toContain("Older offline entries need recovery"); held.release(); await flush();
});
it.each(["llm", "voice"] as const)("a held native %s consent read does not invent stale or current permission", async kind => {
  const held = pause(); boundary = async path => { if (path.endsWith("/account/" + kind + "-consent")) await held.run(); };
  await mount(); expect(held.entered()).toBe(true);
  expect(control(kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling").props.value).toBe(false);
  expect(text()).not.toContain(kind === "llm" ? "Your earlier choice no longer authorizes transcript translation" : "Your earlier choice no longer authorizes uploads under the current voice terms"); held.release(); await flush();
});
it.each(["inactive", "background"] as const)("a pending native recovery response cannot reveal its key after %s", async state => {
  await mount(); const held = pause(); boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/recovery")) await held.run(); };
  await press("Create recovery kit"); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => emitAppState(state)); held.release(); await flush();
  expect(text()).not.toContain("mindpattern-recovery:v2:"); expect(text()).not.toContain("Confirm with password");
});
function nativeNotifications(requestPermission: () => Promise<unknown> = async () => ({authorizationStatus:1})) {
 const notifications = new Map<string,unknown>(); notificationDevice.notifications = notifications; notificationDevice.permission = requestPermission; vi.stubGlobal("require",(name:string)=>{
  if(name!=="@notifee/react-native")throw new Error("Unavailable Native module "+name);
  return {default:{requestPermission,createChannel:async()=>"channel",getTriggerNotifications:async()=>[],getDisplayedNotifications:async()=>[],createTriggerNotification:async(record:{id:string},trigger:unknown)=>{notifications.set(record.id,trigger);return record.id;},cancelNotification:async(id:string)=>{notifications.delete(id);},cancelAllNotifications:async()=>{notifications.clear();}},TriggerType:{TIMESTAMP:0},RepeatFrequency:{DAILY:1}};
 }); return notifications;
}
const reminderActions=["daily","time","measure","interval"] as const;
function reminderChoice(kind:typeof reminderActions[number],first:boolean){
 if(kind==="daily"||kind==="measure")return control(kind==="daily"?"Daily reminder":"Check-in reminders").props.onValueChange(true);
 return root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===(kind==="time"?(first?"Reminder time: Morning 9:00":"Reminder time: Evening 20:00"):(first?"Check-in interval: 2 weeks":"Check-in interval: 4 weeks")))!.props.onPress();
}
function unchangedReminderChoice(kind:typeof reminderActions[number]){
 if(kind==="daily"||kind==="measure")expect(control(kind==="daily"?"Daily reminder":"Check-in reminders").props.value).toBe(false);
 else expect(root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===(kind==="time"?"Reminder time: Evening 20:00":"Check-in interval: 4 weeks"))!.props.accessibilityState.selected).toBe(true);
}
it.each(reminderActions.flatMap(kind=>[false,true].map(failure=>({kind,failure}))))("a superseded Native $kind write failure=$failure cannot publish over the pending newer choice",async({kind,failure})=>{
 nativeNotifications();const key=kind==="daily"||kind==="time"?accountStorageKey.reminders(USER):accountStorageKey.measureReminders(USER);
 if(kind==="time"||kind==="interval")await storage.setItem(key,JSON.stringify(kind==="time"?{enabled:true,hour:20,minute:0}:{enabled:true,intervalWeeks:4}));
 await mount();const prior=pause(),next=pause(),write=storage.setItem.bind(storage);let first=true;
 vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{if(slot!==key)return write(slot,value);if(first){first=false;await prior.run();if(failure)throw new Error("The prior Native write failed");return write(slot,value);}await next.run();return write(slot,value);});
 let firstResult:Promise<unknown>|undefined,secondResult:Promise<unknown>|undefined;await act(async()=>{firstResult=reminderChoice(kind,true);});await vi.waitFor(()=>expect(prior.entered()).toBe(true));await act(async()=>{secondResult=reminderChoice(kind,false);});vi.mocked(Alert.alert).mockClear();prior.release();
 await vi.waitFor(()=>expect(next.entered()).toBe(true));await flush();unchangedReminderChoice(kind);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
 next.release();await act(async()=>{await Promise.all([firstResult,secondResult]);});await flush();if(kind==="daily"||kind==="measure")expect(control(kind==="daily"?"Daily reminder":"Check-in reminders").props.value).toBe(true);else unchangedReminderChoice(kind);
});
it.each(reminderActions)("an admitted Native $kind lookup cannot save into a replacement vault",async kind=>{
 nativeNotifications();const key=kind==="daily"||kind==="time"?accountStorageKey.reminders(USER):accountStorageKey.measureReminders(USER);
 if(kind==="time"||kind==="interval")await storage.setItem(key,JSON.stringify(kind==="time"?{enabled:true,hour:20,minute:0}:{enabled:true,intervalWeeks:4}));await mount();const previous=await storage.getItem(key),held=pause(),read=secureStore.getItem.bind(secureStore);let first=true;
 vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await read(slot);if(first&&slot==="@mindpattern/user_id"){first=false;await held.run();}return value;});let result:Promise<unknown>|undefined;await act(async()=>{result=reminderChoice(kind,true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));
 const replacement=Buffer.alloc(32,9);installLocalDataKey(USER,replacement);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(AUTH),dataKey:replacement},USER);held.release();await act(async()=>{await result;});await flush();expect(await storage.getItem(key)).toBe(previous);unchangedReminderChoice(kind);
});
it("a completed Native daily schedule shows the enabled preference without a denial alert",async()=>{
 const notifications=nativeNotifications();await mount();vi.mocked(Alert.alert).mockClear();await act(async()=>{await control("Daily reminder").props.onValueChange(true);});await flush();expect(control("Daily reminder").props.value).toBe(true);expect(notifications.size).toBe(1);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("a late Native scheduling denial cannot warn after a newer daily opt-out",async()=>{
 const held=pause(),notifications=nativeNotifications(async()=>{await held.run();return {authorizationStatus:0};});await mount();let pending:Promise<unknown>|undefined;await act(async()=>{pending=control("Daily reminder").props.onValueChange(true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));
 await act(async()=>{await control("Daily reminder").props.onValueChange(false);});vi.mocked(Alert.alert).mockClear();held.release();await act(async()=>{await pending;});await flush();expect(control("Daily reminder").props.value).toBe(false);expect(JSON.parse((await storage.getItem(accountStorageKey.reminders(USER)))!).enabled).toBe(false);expect(notifications.size).toBe(0);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("an actual Native light preference paints enabled control tracks with the light palette",async()=>{
 await mount();await press("Theme: Light");await flush();expect(control("Daily reminder").props.trackColor.true).toBe("#44604a");expect(control("Check-in reminders").props.trackColor.true).toBe("#44604a");
});
it.each([false,true])("Native recovery creation failure=%s erases the actual recovery/verifier allocation at its acknowledged boundary",async failure=>{
 await mount();const recoveryInputs:Buffer[]=[],verifiers:Buffer[]=[],derive=engine.hkdfSync.bind(engine),held=pause();
 vi.spyOn(engine,"hkdfSync").mockImplementation((digest,ikm,salt,info,length)=>{const output=derive(digest,ikm,salt,info,length),label=info.toString("utf8");if(label.startsWith("mindpattern/recovery-"))recoveryInputs.push(ikm);if(label==="mindpattern/recovery-verifier/v2")verifiers.push(Buffer.from(output));return output;});
 setupStatus=failure?500:200;if(!failure)boundary=async(path,method)=>{if(method==="GET"&&path.endsWith("/account/recovery"))await held.run();};await press("Create recovery kit");await confirm(failure);
 if(!failure)await vi.waitFor(()=>expect(held.entered()).toBe(true));else await flush();
 expect(recoveryInputs.length).toBeGreaterThan(0);expect(verifiers.length).toBeGreaterThan(0);for(const value of [...recoveryInputs,...verifiers])expect(value.every(byte=>byte===0)).toBe(true);expect(vault.get().dataKey).toEqual(DATA);
 held.release();await flush();
});
it("a failed Native recovery acknowledgement stays quiet after its foreground proof retires",async()=>{
 await mount();setupStatus=500;const held=pause();boundary=async(path,method)=>{if(method==="PUT"&&path.endsWith("/account/recovery"))await held.run();};await press("Create recovery kit");await confirm(false);await vi.waitFor(()=>expect(held.entered()).toBe(true));vi.mocked(Alert.alert).mockClear();await act(async()=>emitAppState("background"));held.release();await flush();expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);expect(text()).not.toContain("mindpattern-recovery:v2:");
});
async function deletePrompt(){
 await press("Delete my account and data"); expect(alert()?.[0]).toBe("Delete everything?");
 expect(alert()?.[1]).toBe("All entries, patterns and your account will be permanently deleted from the server. Your local encrypted queue is also wiped. This cannot be undone. You will be asked for your password.");
 await button("Continue"); expect(alert()?.[0]).toBe("Final confirmation");
 expect(alert()?.[1]).toBe("Deleting is irreversible. You will be asked for your password next.");
 await button("Continue to password");
}
it("a completed Native account deletion retires credentials and removes actual registered local records",async()=>{
 await mount();await storage.setItem(accountStorageKey.feedback(USER),"old encrypted native receipt");await storage.setItem(accountStorageKey.moodLog(USER),"old encrypted native mood record");await deletePrompt();await confirm();await flush();expect(await api.getUserId()).toBeNull();expect(vault.isUnlocked()).toBe(false);expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();expect(await storage.getItem(accountStorageKey.moodLog(USER))).toBeNull();expect(alert()?.[0]).toBe("Deleted");expect(alert()?.[1]).toBe("Your account and data were deleted from the server. If anything failed to clear on this device, reinstalling the app removes the remnants.");
});
it.each([403,500])("a refused Native account deletion status=%i preserves real local data and current credentials",async status=>{
 await mount();deleteStatus=status;await storage.setItem(accountStorageKey.feedback(USER),"still-owned native receipt");await deletePrompt();await confirm();await flush();expect(await api.getUserId()).toBe(USER);expect(vault.get().dataKey).toEqual(DATA);expect(await storage.getItem(accountStorageKey.feedback(USER))).toBe("still-owned native receipt");expect(alert()?.[0]).not.toBe("Deleted");if(status===403)expect(text()).toContain("Confirm with password");else expect(text()).not.toContain("Confirm with password");
});
it("a completed old Native delete response cannot erase a replacement vault's physical feedback",async()=>{
 await mount();const held=pause();boundary=async(path,method)=>{if(method==="DELETE"&&path.endsWith("/account"))await held.run();};await deletePrompt();await confirm(false);await vi.waitFor(()=>expect(held.entered()).toBe(true));const next=Buffer.alloc(32,51);await act(async()=>{vault.unlock({masterKey:Buffer.alloc(32,52),authKey:Buffer.alloc(32,53),dataKey:next},USER);installLocalDataKey(USER,next);});await storage.setItem(accountStorageKey.feedback(USER),"replacement native receipt");vi.mocked(Alert.alert).mockClear();held.release();await flush();expect(await storage.getItem(accountStorageKey.feedback(USER))).toBe("replacement native receipt");expect(await api.getUserId()).toBe(USER);expect(vault.get().dataKey).toEqual(next);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it.each(["create","remove"] as const)("a retired Native recovery %s cannot clear the replacement operation's busy admission",async oldKind=>{
 recovery=oldKind==="remove";await mount();const old=pause(),fresh=pause();let write=0;
 boundary=async(path,method)=>{if(!path.endsWith("/account/recovery")||!(method==="PUT"||method==="DELETE"))return;write++;await (write===1?old:fresh).run();};
 await press(oldKind==="create"?"Create recovery kit":"Remove kit");await confirm(false);await vi.waitFor(()=>expect(old.entered()).toBe(true));
 const next=Buffer.alloc(32,63);await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});
 if(oldKind==="create")await press("Create recovery kit");else{await press("Replace kit key");await button("Replace kit key");}await confirm(false);await vi.waitFor(()=>expect(fresh.entered()).toBe(true));old.release();await flush();
 const confirmation=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Confirm with password");expect(confirmation).toBeDefined();expect(text()).toContain("Verifying…");expect(root!.root.findAllByType(TextInput).find(node=>node.props.accessibilityLabel==="Password confirmation")?.props.value).toBe(PASSWORD);fresh.release();await flush();
});
it("an older completed Native Health preference cannot undo a newer saved choice",async()=>{
 await mount();const key=accountStorageKey.healthMirror(USER),held=pause(),write=storage.setItem.bind(storage);let first=true;vi.spyOn(storage,"setItem").mockImplementation(async(slot,value)=>{if(slot===key&&first){first=false;await held.run();}return write(slot,value);});
 let oldResult:Promise<unknown>|undefined;await act(async()=>{oldResult=control("Mirror mood check-ins to the Health app").props.onValueChange(true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));let freshResult:Promise<unknown>|undefined;await act(async()=>{freshResult=control("Mirror mood check-ins to the Health app").props.onValueChange(false);});held.release();await act(async()=>{await Promise.all([oldResult,freshResult]);});await flush();expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false);expect(JSON.parse((await storage.getItem(key))!).enabled).toBe(false);
});
it("a late Native Health permission denial cannot report an obsolete enabled choice",async()=>{
 await mount();const held=pause();healthDevice.authorize=async()=>{await held.run();return false;};let pending:Promise<unknown>|undefined;await act(async()=>{pending=control("Mirror mood check-ins to the Health app").props.onValueChange(true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>{await control("Mirror mood check-ins to the Health app").props.onValueChange(false);});vi.mocked(Alert.alert).mockClear();held.release();await act(async()=>{await pending;});await flush();expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("an admitted Native Health account lookup cannot persist into a replacement vault",async()=>{
 await mount();const held=pause(),get=secureStore.getItem.bind(secureStore);let first=true;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const answer=await get(slot);if(slot==="@mindpattern/user_id"&&first){first=false;await held.run();}return answer;});let pending:Promise<unknown>|undefined;await act(async()=>{pending=control("Mirror mood check-ins to the Health app").props.onValueChange(true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));const next=Buffer.alloc(32,61);await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});const prior=await storage.getItem(accountStorageKey.healthMirror(USER));held.release();await act(async()=>{await pending;});await flush();expect(await storage.getItem(accountStorageKey.healthMirror(USER))).toBe(prior);expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false);
});
it.each(["retry", "export", "remove"] as const)("a retired Native saved-audio %s cannot warn or clear a replacement password proof", async kind => {
  const id = "native-settings-recording", words = Buffer.from("my still-owned native recording");
  const blob = encryptAudio({ dataKey: DATA }, USER, id, words);
  await enqueueAudio({ userId: USER, clientEntryId: id, ...blob, mime: "audio/m4a", durationSeconds: 4 }, captureLocalWritePermit(USER, vault.get().dataKey));
  const slot = `${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:${id}`;
  const original = (await storage.getItem(slot))!, descriptor = JSON.parse(original);
  await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  const old = pause(), fresh = pause(), get = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async key => { const answer = await get(key); if (key === "@mindpattern/user_id" && first) { first = false; await old.run(); } return answer; });
  await press(kind === "retry" ? "Retry saved recordings" : kind === "export" ? "Export encrypted recording 1" : "Remove saved recording 1");
  if (kind === "remove") await button("Remove recording");
  await vi.waitFor(() => expect(old.entered()).toBe(true));
  const next = Buffer.alloc(32, 77);
  await act(async () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/recovery")) await fresh.run(); };
  await press("Create recovery kit"); await confirm(false); await vi.waitFor(() => expect(fresh.entered()).toBe(true));
  vi.mocked(Alert.alert).mockClear(); old.release(); await flush();
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]); expect(text()).toContain("Verifying…");
  expect(await storage.getItem(slot)).toBe(original); expect(files.__hasFile(descriptor.uri)).toBe(true);
  expect(decryptAudio({ dataKey: DATA }, USER, id, await files.readAsStringAsync(descriptor.uri))).toEqual(words);
  fresh.release(); await flush();
});
it("a retired Native recording confirmation preserves ciphertext and leaves current controls usable",async()=>{
 const id="native-retired-recording-dialog",words=Buffer.from("the current Native recording must remain recoverable"),blob=encryptAudio({dataKey:DATA},USER,id,words);await enqueueAudio({userId:USER,clientEntryId:id,...blob,mime:"audio/m4a",durationSeconds:4},captureLocalWritePermit(USER,vault.get().dataKey));const slot=`${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:${id}`,original=(await storage.getItem(slot))!,descriptor=JSON.parse(original);await mount();await vi.waitFor(()=>expect(text()).toContain("Export encrypted recording 1"));await press("Remove saved recording 1");const remove=alert()?.[2]?.find(n=>n.text==="Remove recording");expect(remove).toBeDefined();await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:Buffer.alloc(32,78)},USER);installLocalDataKey(USER,vault.get().dataKey);});vi.mocked(Alert.alert).mockClear();await act(async()=>remove!.onPress?.());await flush();expect(await storage.getItem(slot)).toBe(original);expect(decryptAudio({dataKey:DATA},USER,id,await files.readAsStringAsync(descriptor.uri))).toEqual(words);expect(root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Retry saved recordings")!.props.disabled).toBe(false);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("a current rekeyed Native recording remains manageable from the mounted Settings screen",async()=>{
 const id="native-current-rekey-recording",words=Buffer.from("my retained recording after a real local key replacement"),blob=encryptAudio({dataKey:DATA},USER,id,words);await enqueueAudio({userId:USER,clientEntryId:id,...blob,mime:"audio/m4a",durationSeconds:4},captureLocalWritePermit(USER,vault.get().dataKey));const slot=`${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:${id}`;await mount();await vi.waitFor(()=>expect(text()).toContain("Export encrypted recording 1"));const next=Buffer.alloc(32,79),changes=await prepareAudioRekey(USER,DATA,next);for(const change of changes)await storage.setItem(change.key,change.after);await cleanupAudioRekey(changes,"before");const current=JSON.parse((await storage.getItem(slot))!);expect(decryptAudio({dataKey:next},USER,id,await files.readAsStringAsync(current.uri))).toEqual(words);await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});await flush();await press("Remove saved recording 1");await button("Remove recording");await flush();expect(await storage.getItem(slot)).toBeNull();expect(files.__hasFile(current.uri)).toBe(false);expect(text()).not.toContain("Export encrypted recording 1");
});
it("a retired Native password rotation cannot clear a newer recovery proof's busy state",async()=>{
 await mount();await press("Change password");await act(async()=>{root!.root.findAllByType(TextInput).find(n=>n.props.accessibilityLabel==="Password confirmation")!.props.onChangeText(PASSWORD);root!.root.findAllByType(TextInput).find(n=>n.props.accessibilityLabel==="New password")!.props.onChangeText("New Native secret42!");});const old=pause(),fresh=pause(),get=secureStore.getItem.bind(secureStore);let first=true;vi.spyOn(secureStore,"getItem").mockImplementation(async key=>{const answer=await get(key);if(key==="@mindpattern/user_id"&&first){first=false;await old.run();}return answer;});await press("Rotate keys and sign in again");await vi.waitFor(()=>expect(old.entered()).toBe(true));await act(async()=>{const next=Buffer.alloc(32,81);vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});boundary=async(path,method)=>{if(method==="PUT"&&path.endsWith("/account/recovery"))await fresh.run();};await press("Create recovery kit");await confirm(false);await vi.waitFor(()=>expect(fresh.entered()).toBe(true));vi.mocked(Alert.alert).mockClear();old.release();await flush();expect(text()).toContain("Verifying…");expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);fresh.release();await flush();
});

it("an old Native biometric-off account lookup cannot erase a newly installed replacement-key wrap",async()=>{
 keychain.__setBiometryType("FaceID");await enableBiometricUnlock(USER,vault.get().dataKey);await mount();expect(control("Biometric unlock").props.value).toBe(true);const held=pause(),get=secureStore.getItem.bind(secureStore);let first=true;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot==="@mindpattern/user_id"){first=false;await held.run();}return value;});let old:Promise<void>|undefined;await act(async()=>{old=control("Biometric unlock").props.onValueChange(false);});await vi.waitFor(()=>expect(held.entered()).toBe(true));const next=Buffer.alloc(32,82);await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});await enableBiometricUnlock(USER,next);const service="com.mindpattern.biometric-unlock.v1."+USER,wrapped=await keychain.getGenericPassword({service});expect(wrapped).toMatchObject({username:USER,password:next.toString("base64")});held.release();await act(async()=>old);await flush();expect(await keychain.getGenericPassword({service})).toEqual(wrapped);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("an authentic stale Native account-id receipt cannot turn off another owner's biometric wrap",async()=>{
 keychain.__setBiometryType("FaceID");await enableBiometricUnlock(USER,vault.get().dataKey);await mount();const other="b".repeat(32),service="com.mindpattern.biometric-unlock.v1."+other,oldKey=Buffer.alloc(32,83);await keychain.setGenericPassword(other,oldKey.toString("base64"),{service,accessControl:keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,accessible:keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY});const before=await keychain.getGenericPassword({service});await secureStore.setItem("@mindpattern/user_id",other);await act(async()=>control("Biometric unlock").props.onValueChange(false));await flush();expect(await keychain.getGenericPassword({service})).toEqual(before);expect(control("Biometric unlock").props.value).toBe(true);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("a retired Native biometric enable lookup cannot publish a new password prompt",async()=>{
 keychain.__setBiometryType("FaceID");await mount();const held=pause(),get=secureStore.getItem.bind(secureStore);let first=true;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot==="@mindpattern/user_id"){first=false;await held.run();}return value;});let old:Promise<void>|undefined;await act(async()=>{old=control("Biometric unlock").props.onValueChange(true);});await vi.waitFor(()=>expect(held.entered()).toBe(true));await act(async()=>emitAppState("background"));vi.mocked(Alert.alert).mockClear();held.release();await act(async()=>old);await flush();expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);expect(text()).not.toContain("Confirm with password");expect(await keychain.hasGenericPassword({service:"com.mindpattern.biometric-unlock.v1."+USER})).toBe(false);
});


it("two actual Native confirmation releases before commit keep the displayed kit matched to the server envelope", async () => {
  await mount(); await press("Create recovery kit");
  await act(async () => root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD));
  const held = pause(); let writes = 0;
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/recovery")) { writes++; if (writes === 1) await held.run(); } };
  await act(async () => {
    for (let i = 0; i < 2; i++) {
      const host = root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Confirm with password")!;
      const tap = nativeGrantedPress(host.props as { disabled?: boolean; onPress: () => void });
      try { tap.configure(host.props as { disabled?: boolean; onPress: () => void }); tap.release(); } finally { tap.dispose(); }
    }
  });
  await vi.waitFor(() => expect(held.entered()).toBe(true)); await flush(); held.release(); await flush(); await flush();
  await vi.waitFor(() => expect(text()).toContain("mindpattern-recovery:v2:"));
  const encoded = text().match(/mindpattern-recovery:v2:([A-Za-z0-9+/]{43}=)/)![1];
  const key = Buffer.from(encoded, "base64"), kek = Buffer.from(crypto.hkdfSync("sha256", key, Buffer.alloc(32), "mindpattern/recovery-seal/v2", 32));
  expect(recoverySealed).toBeDefined();
  const sealed = Buffer.from(recoverySealed!, "base64"), decipher = crypto.createDecipheriv("aes-256-gcm", kek, sealed.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["recovery", USER, "data-key"]))); decipher.setAuthTag(sealed.subarray(-16));
  expect(Buffer.concat([decipher.update(sealed.subarray(12, -16)), decipher.final()])).toEqual(DATA);
});

it("same-origin credential retirement releases the still-mounted Settings confirmation for a fresh proof", async () => {
  await mount(); const held = pause();
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/llm-consent")) await held.run(); };
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(false);
  await vi.waitFor(() => expect(held.entered()).toBe(true)); await act(async () => { await setBaseUrl(DEFAULT_BASE_URL); });
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(vault.isUnlocked()).toBe(true); expect(control("Allow third-party transcript translation").props.disabled).toBe(false);
  expect(text()).not.toContain("Confirm with password"); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  expect(root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.value).toBe("");
});


it.each(["daily", "time", "measure", "interval", "health"] as const)("a current Native %s preference write refusal reports failure without changing the selected value", async kind => {
  const key = kind === "daily" || kind === "time" ? accountStorageKey.reminders(USER) : kind === "health" ? accountStorageKey.healthMirror(USER) : accountStorageKey.measureReminders(USER);
  if (kind === "time" || kind === "interval") await storage.setItem(key, JSON.stringify(kind === "time" ? { enabled: true, hour: 20, minute: 0 } : { enabled: true, intervalWeeks: 4 }));
  await mount(); const before = await storage.getItem(key), write = storage.setItem.bind(storage);
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === key) throw new Error("Native preference write refused"); return write(slot, value); });
  vi.mocked(Alert.alert).mockClear();
  if (kind === "health") await act(async () => control("Mirror mood check-ins to the Health app").props.onValueChange(true));
  else await act(async () => { await reminderChoice(kind, true); });
  await flush(); expect(await storage.getItem(key)).toBe(before); expect(alert()?.[0]).toBe("Could not save");
  if (kind === "health") expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false); else unchangedReminderChoice(kind);
});

async function seedCurrentRecording(id: string) {
  const words = Buffer.from("this original Native recording remains in ciphertext custody"), blob = encryptAudio({ dataKey: DATA }, USER, id, words);
  await enqueueAudio({ userId: USER, clientEntryId: id, ...blob, mime: "audio/m4a", durationSeconds: 4 }, captureLocalWritePermit(USER, vault.get().dataKey));
  const slot = `${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:${id}`, raw = (await storage.getItem(slot))!, descriptor = JSON.parse(raw);
  return { words, slot, raw, descriptor };
}
it.each(["retry", "export", "remove"] as const)("a current Native saved-audio %s refusal reports its public failure and retains ciphertext", async kind => {
  const record = await seedCurrentRecording("native-failed-" + kind); await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  if (kind === "retry") vi.spyOn(storage, "getAllKeys").mockRejectedValue(new Error("Native directory temporarily unavailable"));
  else if (kind === "export") sharing.shareAsync.mockRejectedValueOnce(new Error("Native share sheet unavailable"));
  else files.deleteAsync.mockRejectedValueOnce(new Error("Native file deletion refused"));
  vi.mocked(Alert.alert).mockClear(); await press(kind === "retry" ? "Retry saved recordings" : kind === "export" ? "Export encrypted recording 1" : "Remove saved recording 1");
  if (kind === "remove") await button("Remove recording"); await vi.waitFor(() => expect(alert()?.[0]).toBe(kind === "export" ? "Export failed" : "Could not retry"));
  if (kind === "retry") expect(alert()?.[1]).toBe("The saved entries are still safe on this device.");
  expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  expect(decryptAudio({ dataKey: DATA }, USER, "native-failed-" + kind, await files.readAsStringAsync(record.descriptor.uri))).toEqual(record.words);
  expect(root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Retry saved recordings")!.props.disabled).toBe(false);
});


it("an admitted recovery username receipt cannot install a kit after its actual route unmounts and a new login unlocks", async () => {
  await mount(); const held = pause(), read = secureStore.getItem.bind(secureStore); let usernames = 0;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (slot === "@mindpattern/username" && ++usernames === 2) await held.run(); return answer; });
  await press("Create recovery kit"); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => { root!.unmount(); root = undefined; vault.lock(); });
  await api.setSession("replacement native login", USER, "alice");
  const next = Buffer.from(DATA); vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next);
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(recovery).toBe(false); expect(recoverySealed).toBeUndefined(); expect(vault.get().dataKey).toBe(next); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("a Native recovery username receipt for a replacement physical key cannot latch the current controls busy",async()=>{
 await mount();const held=pause(),read=secureStore.getItem.bind(secureStore);let usernames=0;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const answer=await read(slot);if(slot==="@mindpattern/username"&&++usernames===2)await held.run();return answer;});
 await press("Create recovery kit");await confirm(false);await vi.waitFor(()=>expect(held.entered()).toBe(true));
 const next=Buffer.from(DATA);await act(async()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});
 held.release();await flush();await flush();
 expect(recovery).toBe(false);expect(recoverySealed).toBeUndefined();expect(vault.get().dataKey).toBe(next);expect(control("Allow third-party transcript translation").props.disabled).toBe(false);expect(text()).not.toContain("Confirm with password");
});
it("a current Native credential disappearance after password verification refuses recovery creation", async () => {
  await mount(); const read = secureStore.getItem.bind(secureStore); let usernames = 0;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { if (slot === "@mindpattern/username" && ++usernames === 2) await secureStore.removeItem(slot); return read(slot); });
  await press("Create recovery kit"); await confirm(); await flush();
  expect(recovery).toBe(false); expect(recoverySealed).toBeUndefined(); expect(text()).not.toContain("mindpattern-recovery:v2:"); expect(alert()?.[1]).toBe("The kit could not be created — check your connection and try again.");
});
it("a Native account-id receipt for a different owner cannot enable that owner's biometric key", async () => {
  keychain.__setBiometryType("FaceID"); await mount(); await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable");
  await secureStore.setItem("@mindpattern/user_id", "b".repeat(32)); await confirm(); await flush();
  expect(await keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1." + "b".repeat(32) })).toBe(false);
  expect(control("Biometric unlock").props.value).toBe(false); expect(alert()?.[0]).toBe("Could not complete");
});
it("held Native biometric capability discovery does not expose an unsupported control early", async () => {
  keychain.__setBiometryType("FaceID"); const held = pause(), probe = keychain.getSupportedBiometryType;
  vi.spyOn(keychain, "getSupportedBiometryType").mockImplementation(async () => { const value = await probe(); await held.run(); return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true)); expect(root!.root.findAllByType(Switch).some(n => n.props.accessibilityLabel === "Biometric unlock")).toBe(false);
  held.release(); await flush(); expect(control("Biometric unlock")).toBeDefined();
});


it("a rejected-entry retry admitted on the old route cannot move retained ciphertext after a replacement login", async () => {
  const id = "native-rejected-entry", blob = encryptEntry({ dataKey: DATA }, USER, id, "my physically retained rejected journal", "2026-10-07T04:00:00Z", null);
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), rejected = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`, queue = `${ACCOUNT_STORAGE_PREFIX.queue}.items.${scope}`;
  const record = JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]); await storage.setItem(rejected, record);
  await mount(); await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  const held = pause(), read = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (first && slot === "@mindpattern/user_id") { first = false; await held.run(); } return answer; });
  await press("Try syncing the recovered entries again", false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => { root!.unmount(); root = undefined; vault.lock(); }); await api.setSession("a fresh native login", USER, "alice");
  const next = Buffer.from(DATA); vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next);
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(await storage.getItem(rejected)).toBe(record); expect(await storage.getItem(queue)).toBeNull(); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});


function InstalledSettingsNavigator() {
  const events = useEventEmitter(); nativeRouteEvents = events;
  const navigation = React.useMemo(() => ({ ...events.create("native-settings-route"), navigate: () => events.emit({ type: "blur", target: "native-settings-route" }) }), [events]);
  return <SettingsScreen navigation={navigation}/>;
}
async function mountInstalledNavigator() { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><InstalledSettingsNavigator/></ThemeProvider>); }); await flush(); }
it("native navigator blur clears the password before a new live confirmation opens", async () => {
  await mountInstalledNavigator(); await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  await act(async () => root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD));
  await act(async () => nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" })); expect(text()).not.toContain("Confirm with password");
  await act(async () => nativeRouteEvents!.emit({ type: "focus", target: "native-settings-route" }));
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  expect(root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.value).toBe("");
});
it("blur followed by actual route unmount never revives an old Native consent failure", async () => {
  await mountInstalledNavigator(); const held = pause(); consentWriteStatus = 500;
  boundary = async (path, method) => { if (method === "PUT" && path.endsWith("/account/llm-consent")) await held.run(); };
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" })); await act(async () => { root!.unmount(); root = undefined; });
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush(); expect(vault.isUnlocked()).toBe(true); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});
it("corrupt retained Native recording metadata shows its unavailable date and repair note", async () => {
  const slot = `${ACCOUNT_STORAGE_PREFIX.audioQueue}${canonicalOrigin(DEFAULT_BASE_URL)}:${USER}:native-repair-recording`;
  await storage.setItem(slot, JSON.stringify({ v: "corrupt retained descriptor" })); await mount();
  await vi.waitFor(() => expect(text()).toContain("Recording 1 · date unavailable")); expect(text()).toContain("needs attention"); expect(await storage.getItem(slot)).not.toBeNull();
});
it("enabling during a held initial Native reminder read retains the default evening choice until the saved preference arrives", async () => {
  const key = accountStorageKey.reminders(USER), held = pause(), read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const value = await read(slot); if (first && slot === key) { first = false; await held.run(); } return value; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true)); await act(async () => control("Daily reminder").props.onValueChange(true)); await flush();
  expect(control("Daily reminder").props.value).toBe(true); expect(root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Reminder time: Evening 20:00")!.props.accessibilityState.selected).toBe(true);
  held.release(); await flush();
});
it("a recreated recovery kit with an unavailable new status never shows the removed kit's date", async () => {
  recovery = true; await mount(); await press("Remove kit"); await confirm(); expect(text()).toContain("No recovery kit.");
  recoveryReadStatus = 500; await press("Create recovery kit"); await confirm(); await flush(); expect(text()).toContain("mindpattern-recovery:v2:"); expect(text()).not.toContain("2026-10-07");
});


it("native navigator blur clears both visible rotation passwords before the route returns", async () => {
  await mountInstalledNavigator(); await press("Change password");
  await act(async () => { root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD); root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "New password")!.props.onChangeText("New Native secret42!"); });
  await act(async () => nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" }));
  await act(async () => nativeRouteEvents!.emit({ type: "focus", target: "native-settings-route" }));
  for (const label of ["Password confirmation", "New password"]) expect(root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === label)!.props.value).toBe("");
});

it.each([...reminderActions, "health"] as const)("a mismatched Native identity receipt leaves the current %s preference untouched and quiet", async kind => {
  const key = kind === "health" ? accountStorageKey.healthMirror(USER) : kind === "daily" || kind === "time" ? accountStorageKey.reminders(USER) : accountStorageKey.measureReminders(USER);
  if (kind === "time" || kind === "interval") await storage.setItem(key, JSON.stringify(kind === "time" ? { enabled: true, hour: 20, minute: 0 } : { enabled: true, intervalWeeks: 4 }));
  await mount(); const before = await storage.getItem(key);
  // The device can return a durable stale credential slot while the RAM
  // vault still belongs to the authenticated owner; use the real slot read.
  await secureStore.setItem("@mindpattern/user_id", "b".repeat(32)); vi.mocked(Alert.alert).mockClear();
  await act(async () => { if (kind === "health") await control("Mirror mood check-ins to the Health app").props.onValueChange(true); else await reminderChoice(kind, true); }); await flush();
  expect(await storage.getItem(key)).toBe(before);
  expect(await storage.getItem(kind === "health" ? accountStorageKey.healthMirror("b".repeat(32)) : kind === "daily" || kind === "time" ? accountStorageKey.reminders("b".repeat(32)) : accountStorageKey.measureReminders("b".repeat(32)))).toBeNull();
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  if (kind === "health") expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false); else unchangedReminderChoice(kind);
});

it.each([...reminderActions, "health"] as const)("a Native %s control cannot start a preference write while an actual local rotation checkpoint owns admission", async kind => {
  const key = kind === "health" ? accountStorageKey.healthMirror(USER) : kind === "daily" || kind === "time" ? accountStorageKey.reminders(USER) : accountStorageKey.measureReminders(USER);
  if (kind === "time" || kind === "interval") await storage.setItem(key, JSON.stringify(kind === "time" ? { enabled: true, hour: 20, minute: 0 } : { enabled: true, intervalWeeks: 4 }));
  await mount(); const before = await storage.getItem(key);
  await prepareLocalRekey(USER, DATA, Buffer.alloc(32, 42), { oldSaltB64: SALT.toString("base64") });
  vi.mocked(Alert.alert).mockClear();
  const failures: unknown[] = [], observeNativeFailure = (error: unknown) => { failures.push(error); };
  process.on("unhandledRejection", observeNativeFailure);
  try {
    await act(async () => { if (kind === "health") await control("Mirror mood check-ins to the Health app").props.onValueChange(true); else await reminderChoice(kind, true); }); await flush();
    await new Promise<void>(resolve => setImmediate(resolve));
    // A visible Native control must remain a finite, quiet refusal. An
    // uncaught asynchronous callback failure is a real runtime outcome,
    // independently observed rather than treated as a runner failure.
    expect(failures).toEqual([]);
    expect(await storage.getItem(key)).toBe(before); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
    if (kind === "health") expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false); else unchangedReminderChoice(kind);
  } finally { process.off("unhandledRejection", observeNativeFailure); }
});

it("unmount releases the rendered Native password input callback from process custody", async () => {
  // Use a physical subscription provider. The ordinary event spy keeps
  // historical observer arguments even after a successful remove; those
  // diagnostic records are not the Native emitter's actual custody.
  const nativeState = new EventEmitter();
  const observedSubscription = vi.spyOn(AppState, "addEventListener").mockImplementation((event, listener) => {
    nativeState.on(event, listener); return { remove: () => { nativeState.removeListener(event, listener); } };
  });
  await mountInstalledNavigator(); await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  await act(async () => root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD));
  // Observe the actual rendered public Native input callback's physical
  // reachability. The guarded wrapper is not a direct hook dispatcher;
  // this assertion makes no separate private password-state custody claim.
  const dispatcher = new WeakRef(root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText as object);
  await act(async () => { root!.unmount(); root = undefined; }); nativeRouteEvents = undefined;
  observedSubscription.mockClear();
  setFlagsFromString("--expose_gc"); const collect = runInNewContext("gc") as () => void;
  for (let attempt = 0; attempt < 8; attempt++) { await new Promise<void>(resolve => setImmediate(resolve)); collect(); }
  expect(dispatcher.deref()).toBeUndefined();
});

it("a late initial Native wrap-presence receipt cannot undo a completed biometric opt-out", async () => {
  keychain.__setBiometryType("FaceID"); await enableBiometricUnlock(USER, vault.get().dataKey);
  const held = pause(), has = keychain.hasGenericPassword; let first = true;
  vi.spyOn(keychain, "hasGenericPassword").mockImplementation(async options => { const answer = await has(options); if (first && options?.service === "com.mindpattern.biometric-unlock.v1." + USER) { first = false; await held.run(); } return answer; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => { await control("Biometric unlock").props.onValueChange(false); }); held.release(); await flush();
  expect(control("Biometric unlock").props.value).toBe(false);
  expect(await has({ service: "com.mindpattern.biometric-unlock.v1." + USER })).toBe(false);
});

it.each([false, true])("a retired Native biometric removal failure=%s cannot change or warn over a replacement wrap publication", async failure => {
  keychain.__setBiometryType("FaceID"); await enableBiometricUnlock(USER, vault.get().dataKey); await mount();
  expect(control("Biometric unlock").props.value).toBe(true);
  const old = pause(), fresh = pause(), reset = keychain.resetGenericPassword, write = keychain.setGenericPassword; let first = true;
  vi.spyOn(keychain, "resetGenericPassword").mockImplementation(async options => {
    if (first && options?.service === "com.mindpattern.biometric-unlock.v1." + USER) { first = false; await old.run(); if (failure) throw new Error("The old native Keychain removal was refused"); }
    return reset(options);
  });
  let oldCompletion: Promise<void> | undefined;
  await act(async () => { oldCompletion = control("Biometric unlock").props.onValueChange(false); }); await vi.waitFor(() => expect(old.entered()).toBe(true));
  const next = Buffer.alloc(32, 94); await act(async () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
  vi.spyOn(keychain, "setGenericPassword").mockImplementation(async (...args) => { const answer = await write(...args); if (args[2]?.service === "com.mindpattern.biometric-unlock.v1." + USER) await fresh.run(); return answer; });
  await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable"); await confirm(false);
  vi.mocked(Alert.alert).mockClear(); old.release(); await vi.waitFor(() => expect(fresh.entered()).toBe(true)); await flush();
  expect((await keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1." + USER })) || {}).toMatchObject({ password: next.toString("base64") });
  expect(control("Biometric unlock").props.value).toBe(true); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  fresh.release(); await act(async () => { await oldCompletion; }); await flush(); expect(control("Biometric unlock").props.value).toBe(true);
});

it.each([false, true])("a superseded Native Health write failure=%s remains quiet while the newer choice is still being persisted", async failure => {
  await mount(); const slot = accountStorageKey.healthMirror(USER), prior = pause(), next = pause(), write = storage.setItem.bind(storage); let first = true;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { if (key !== slot) return write(key, value); if (first) { first = false; await prior.run(); if (failure) throw new Error("The old native Health preference write failed"); return write(key, value); } await next.run(); return write(key, value); });
  let oldCompletion: Promise<void> | undefined, nextCompletion: Promise<void> | undefined;
  await act(async () => { oldCompletion = control("Mirror mood check-ins to the Health app").props.onValueChange(true); }); await vi.waitFor(() => expect(prior.entered()).toBe(true));
  await act(async () => { nextCompletion = control("Mirror mood check-ins to the Health app").props.onValueChange(false); }); vi.mocked(Alert.alert).mockClear(); prior.release();
  await vi.waitFor(() => expect(next.entered()).toBe(true)); await flush();
  expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  next.release(); await act(async () => { await Promise.all([oldCompletion, nextCompletion]); }); await flush();
  expect(control("Mirror mood check-ins to the Health app").props.value).toBe(false); expect(JSON.parse((await storage.getItem(slot))!).enabled).toBe(false);
});

it("an admitted Native recovery request cannot publish its wrapped data key after navigator blur during a credential receipt", async () => {
  await mountInstalledNavigator(); const held = pause(), read = secureStore.getItem.bind(secureStore); let userReads = 0;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (slot === "@mindpattern/user_id" && ++userReads === 2) await held.run(); return answer; });
  await press("Create recovery kit"); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" })); vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(recoverySealed).toBeUndefined(); expect(recovery).toBe(false); expect(vault.get().dataKey).toEqual(DATA); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("a completed server deletion reports a retained physical cleanup checkpoint when the Native origin provider refuses cleanup", async () => {
  await mount(); const slot = accountStorageKey.feedback(USER); await storage.setItem(slot, "retained native ciphertext awaiting erasure");
  const read = storage.getItem.bind(storage); let deleted = false;
  boundary = async (path, method) => { if (method === "DELETE" && path.endsWith("/account")) deleted = true; };
  vi.spyOn(storage, "getItem").mockImplementation(async key => { if (deleted && key === "@mindpattern/base_url") throw new Error("Native origin storage unavailable after server deletion"); return read(key); });
  await deletePrompt(); await confirm(); await flush();
  expect(await read(slot)).toBe("retained native ciphertext awaiting erasure");
  expect((await storage.getAllKeys()).some(key => key.startsWith(ACCOUNT_STORAGE_PREFIX.erasure))).toBe(true);
  expect(await api.getUserId()).toBeNull(); expect(alert()?.[0]).toBe("Deleted");
  expect(alert()?.[1]).toContain("Some device cleanup remains");
});

it("a replacement login after physical deletion cleanup owns its bearer and cannot be signed out by the old Settings continuation", async () => {
  await mount(); const held = pause(), read = secureStore.getItem.bind(secureStore); let deleted = false, first = true;
  boundary = async (path, method) => { if (method === "DELETE" && path.endsWith("/account")) deleted = true; };
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (first && deleted && slot === "@mindpattern/user_id" && answer === null) { first = false; await held.run(); } return answer; });
  await deletePrompt(); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const nextOwner = "b".repeat(32), next = Buffer.alloc(32, 95);
  await api.setSession("replacement native bearer after deletion", nextOwner, "bob");
  await act(async () => { vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 96), dataKey: next }, nextOwner); installLocalDataKey(nextOwner, next); });
  vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement native bearer after deletion"); expect(await api.getUserId()).toBe(nextOwner);
  expect(vault.get().dataKey).toBe(next); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it.each(["llm", "voice", "recovery-create", "recovery-remove", "delete"] as const)("an admitted Native %s request keeps the server unchanged when its credential receipt follows navigation retirement", async kind => {
  recovery = kind === "recovery-remove"; await mountInstalledNavigator();
  const held = pause(), read = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (first && slot === "@mindpattern/token") { first = false; await held.run(); } return answer; });
  if (kind === "llm" || kind === "voice") await act(async () => control(kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling").props.onValueChange(true));
  else if (kind === "delete") await deletePrompt(); else await press(kind === "recovery-create" ? "Create recovery kit" : "Remove kit");
  await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  await act(async () => nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" })); vi.mocked(Alert.alert).mockClear(); held.release(); await flush(); await flush();
  expect(consent).toBe(false); expect(voice).toBe(false); expect(recovery).toBe(kind === "recovery-remove"); expect(serverAccountPresent).toBe(true);
  expect(vault.get().dataKey).toEqual(DATA); expect(await api.getUserId()).toBe(USER); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("a refused Native password proof cannot report against a replacement key delivered between the timer receipt and caller continuation", async () => {
  await mount(); await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  await act(async () => root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD + " wrong"));
  const timer = globalThis.setTimeout, next = Buffer.alloc(32, 97);
  vi.spyOn(globalThis, "setTimeout").mockImplementation((callback, delay, ...args) => timer(() => {
    callback(...args);
    if (delay === 500) queueMicrotask(() => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
  }, delay));
  vi.mocked(Alert.alert).mockClear(); await press("Confirm with password"); await flush();
  expect(vault.get().dataKey).toBe(next); expect(consent).toBe(false); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("the still-enabled confirmation cannot start a consent change while the Native recording share sheet owns Settings busy state", async () => {
  const record = await seedCurrentRecording("native-confirmation-during-share"); await mount();
  await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  await act(async () => root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD));
  const held = pause(); sharing.shareAsync.mockImplementationOnce(async () => { await held.run(); });
  await press("Export encrypted recording 1"); await vi.waitFor(() => expect(held.entered()).toBe(true));
  const confirmation = root!.root.findAllByType(TouchableOpacity).find(n => n.props.accessibilityLabel === "Confirm with password")!;
  expect(confirmation.props.disabled).toBe(false);
  await act(async () => { const tap = nativeGrantedPress(confirmation.props); try { tap.configure(confirmation.props); tap.release(); } finally { tap.dispose(); } }); await flush();
  expect(consent).toBe(false); expect(control("Allow third-party transcript translation").props.value).toBe(false);
  expect(root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.value).toBe(PASSWORD);
  expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  held.release(); await flush(); await press("Confirm with password"); await flush();
  expect(consent).toBe(true); expect(control("Allow third-party transcript translation").props.value).toBe(true);
});

it("Native saved-recording removal explains retained journal custody before its single destructive choice", async () => {
  const record = await seedCurrentRecording("native-removal-disclosure"); await mount();
  await vi.waitFor(() => expect(text()).toContain("Remove saved recording 1")); await press("Remove saved recording 1");
  expect(alert()?.[0]).toBe("Remove this saved recording?");
  expect(alert()?.[1]).toBe("This removes the device's saved copy. Export an encrypted copy first if you want to keep it. Your journal entry stays saved.");
  expect(alert()?.[2]?.map(choice => [choice.text, choice.style])).toEqual([["Cancel", "cancel"], ["Remove recording", "destructive"]]);
  expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
});

it("Native recovery replacement warns that the existing physical kit will be invalidated before admission", async () => {
  recovery = true; await mount(); await press("Replace kit key");
  expect(alert()?.[0]).toBe("Recovery kit");
  expect(alert()?.[1]).toBe("Replacing your kit immediately invalidates the old recovery key. Keep this screen open until you save the new kit.");
  expect(recovery).toBe(true); expect(recoverySealed).toBeUndefined();
});

it("the Native voice opt-out password card states the requested direction before any server change", async () => {
  voice = true; await mount(); await act(async () => control("Allow voice journaling").props.onValueChange(false));
  expect(text()).toContain("Enter your password to disable voice journaling"); expect(voice).toBe(true);
});

it("an empty Native theme preference preserves the advertised System selection", async () => {
  await storage.setItem("@mindpattern/theme.mode", ""); await mount();
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Theme: System")!.props.accessibilityState.selected).toBe(true);
});

function nativeDelivery(turns: number, event: () => void): void { if (turns === 0) event(); else queueMicrotask(() => nativeDelivery(turns - 1, event)); }
it.each([0, 1, 2, 3, 4, 5, 6])("a Native haptics receipt at phase %s cannot overwrite an acknowledged live opt-in", async turns => {
  await storage.setItem("@mindpattern/haptics.enabled", "off");
  const read = storage.getItem.bind(storage); let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const answer = await read(key);
    if (first && key === "@mindpattern/haptics.enabled") { first = false; nativeDelivery(turns, () => { void control("Haptics").props.onValueChange(true); }); }
    return answer;
  });
  await mount(); await flush(); expect(control("Haptics").props.value).toBe(true);
  expect(await read("@mindpattern/haptics.enabled")).toBe("on");
});

it("adopting the real password proof after Native biometric unlock preserves the current confirmation", async () => {
  keychain.__setBiometryType("FaceID"); await enableBiometricUnlock(USER, DATA); vault.lock();
  const unwrapped = await unwrapBiometricDataKey(USER); expect(unwrapped).toEqual(DATA);
  // These are the shipped Unlock biometric producer's exact key facts:
  // the authenticated owner and unwrapped key are real, auth is unknown.
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey: unwrapped! }, USER, { authKeyKnown: false }); installLocalDataKey(USER, vault.get().dataKey);
  await mount(); await act(async () => control("Allow third-party transcript translation").props.onValueChange(true)); await confirm(); await flush();
  expect(vault.get().authKeyKnown).toBe(true); expect(vault.get().authKey).toEqual(AUTH); expect(vault.get().dataKey).toEqual(DATA);
  expect(consent).toBe(true); expect(control("Allow third-party transcript translation").props.value).toBe(true);
});

it("held Native biometric presence cannot advertise an enabled wrap before its actual receipt", async () => {
  keychain.__setBiometryType("FaceID"); const held = pause(), has = keychain.hasGenericPassword; let first = true;
  vi.spyOn(keychain, "hasGenericPassword").mockImplementation(async options => { const answer = await has(options); if (first && options?.service === "com.mindpattern.biometric-unlock.v1." + USER) { first = false; await held.run(); } return answer; });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true));
  expect(control("Biometric unlock").props.value).toBe(false); expect(await has({ service: "com.mindpattern.biometric-unlock.v1." + USER })).toBe(false);
  held.release(); await flush(); expect(control("Biometric unlock").props.value).toBe(false);
});

it.each([0, 15])("the Native reminder chips select exactly the durable minute %s rather than all offered choices", async minute => {
  await storage.setItem(accountStorageKey.reminders(USER), JSON.stringify({ enabled: true, hour: 20, minute })); await mount();
  const labels = ["Reminder time: Morning 9:00", "Reminder time: Midday 12:00", "Reminder time: Evening 20:00"];
  const selected = () => labels.map(label => root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label)!.props.accessibilityState.selected);
  expect(selected()).toEqual([false, false, minute === 0]);
  if (minute !== 0) expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Reminder time: 20:15")!.props.accessibilityState.selected).toBe(true);
  await press(labels[0]); await flush(); expect(selected()).toEqual([true, false, false]);
});

it("a current Native recovery removal refusal keeps the actual kit and explains its failure", async () => {
  recovery = true; await mount(); recoveryRemoveStatus = 500; await press("Remove kit"); await confirm(); await flush();
  expect(recovery).toBe(true); expect(text()).toContain("Remove kit"); expect(alert()?.[0]).toBe("Recovery kit"); expect(alert()?.[1]).toBe("The kit could not be removed — try again.");
});

it("a held Native recovery removal keeps other sensitive controls unavailable until its physical receipt", async () => {
  recovery = true; await mount(); const held = pause(); boundary = async (path, method) => { if (path.endsWith("/account/recovery") && method === "DELETE") await held.run(); };
  await press("Remove kit"); await confirm(false); await vi.waitFor(() => expect(held.entered()).toBe(true));
  expect(control("Allow third-party transcript translation").props.disabled).toBe(true); expect(text()).toContain("Verifying…");
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Delete my account and data")!.props.disabled).toBe(true);
  held.release(); await flush(); expect(control("Allow third-party transcript translation").props.disabled).toBe(false); expect(recovery).toBe(false);
});

it.each(["retry", "remove"] as const)("a held Native recording %s keeps sensitive controls unavailable until durable completion", async kind => {
  const record = await seedCurrentRecording("native-busy-" + kind); await mount(); await vi.waitFor(() => expect(text()).toContain("Remove saved recording 1"));
  const held = pause();
  if (kind === "retry") { const list = storage.getAllKeys.bind(storage); let first = true; vi.spyOn(storage, "getAllKeys").mockImplementation(async () => { const keys = await list(); if (first) { first = false; await held.run(); } return keys; }); }
  else { const remove = files.deleteAsync.getMockImplementation()!; let first = true; files.deleteAsync.mockImplementation(async (...args) => { if (first && args[0] === record.descriptor.uri) { first = false; await held.run(); } return remove(...args); }); }
  await press(kind === "retry" ? "Retry saved recordings" : "Remove saved recording 1"); if (kind === "remove") await button("Remove recording");
  await vi.waitFor(() => expect(held.entered()).toBe(true)); expect(control("Allow third-party transcript translation").props.disabled).toBe(true);
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Delete my account and data")!.props.disabled).toBe(true);
  held.release(); await flush(); await vi.waitFor(() => expect(control("Allow third-party transcript translation").props.disabled).toBe(false));
});

it.each(["retry", "export"] as const)("a queued Native recording %s release before key-replacement commit cannot latch busy or reject asynchronously", async kind => {
  const record = await seedCurrentRecording("native-before-commit-" + kind); await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  const failures: unknown[] = [], observe = (error: unknown) => { failures.push(error); }; process.on("unhandledRejection", observe);
  try {
    await act(async () => {
      const next = Buffer.alloc(32, 101); vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next);
      // Native event delivery still uses this actual uncommitted host frame;
      // no callback from an already replaced React frame is retained.
      const host = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === (kind === "retry" ? "Retry saved recordings" : "Export encrypted recording 1"))!;
      expect(host).toBeDefined(); expect(host.props.disabled).toBe(false);
      const tap = nativeGrantedPress(host.props); try { tap.configure(host.props); tap.release(); } finally { tap.dispose(); }
    });
    await flush(); await new Promise<void>(resolve => setImmediate(resolve));
    expect(failures).toEqual([]); expect(control("Allow third-party transcript translation").props.disabled).toBe(false);
    expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
    expect(decryptAudio({ dataKey: DATA }, USER, "native-before-commit-" + kind, await files.readAsStringAsync(record.descriptor.uri))).toEqual(record.words);
  } finally { process.off("unhandledRejection", observe); }
});

it("a retired Native rejected-entry retry cannot release a replacement recovery confirmation's busy admission", async () => {
  const id = "native-rejected-busy", blob = encryptEntry({ dataKey: DATA }, USER, id, "my retained rejected ciphertext", "2026-10-07T04:00:00Z", null);
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), rejected = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`;
  const raw = JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]); await storage.setItem(rejected, raw);
  await mount(); await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  const old = pause(), fresh = pause(), read = secureStore.getItem.bind(secureStore); let first = true;
  vi.spyOn(secureStore, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (first && slot === "@mindpattern/user_id") { first = false; await old.run(); } return answer; });
  await press("Try syncing the recovered entries again", false); await vi.waitFor(() => expect(old.entered()).toBe(true));
  const next = Buffer.alloc(32, 102); await act(async () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
  boundary = async (path, method) => { if (path.endsWith("/account/recovery") && method === "PUT") await fresh.run(); };
  await press("Create recovery kit"); await confirm(false); await vi.waitFor(() => expect(fresh.entered()).toBe(true)); vi.mocked(Alert.alert).mockClear();
  old.release(); await flush(); expect(control("Allow third-party transcript translation").props.disabled).toBe(true); expect(text()).toContain("Verifying…");
  expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!.props.value).toBe(PASSWORD);
  expect(await storage.getItem(rejected)).toBe(raw); expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  fresh.release(); await flush();
});

it("a retired deletion origin receipt cannot start a legacy credential rewrite that overwrites a replacement Native login", async () => {
  await mountInstalledNavigator(); const slot = "@mindpattern/user_id", stored = JSON.parse((await storage.getItem(slot))!);
  // The secure store explicitly supports old bare-base64 ciphertext and
  // rewrites it through the same physical Native provider when read.
  await storage.setItem(slot, stored.c); const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage);
  const legacy = pause(); let baseReads = 0, replacementStarted = false, legacyRewriteHeld = false;
  let finish!: () => void; const replacementDone = new Promise<void>(resolve => { finish = resolve; });
  let clockFinish!: () => void; const nativeClockDone = new Promise<void>(resolve => { clockFinish = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (!replacementStarted && key === slot && !legacyRewriteHeld) { legacyRewriteHeld = true; await legacy.run(); }
    return write(key, value);
  });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const answer = await read(key);
    if (key === "@mindpattern/base_url" && ++baseReads === 2) {
      nativeRouteEvents!.emit({ type: "blur", target: "native-settings-route" });
      setImmediate(() => { void (async () => {
        replacementStarted = true; setTimeout(() => { legacy.release(); setImmediate(clockFinish); }, 25); const owner = "b".repeat(32), next = Buffer.alloc(32, 103);
        try { await api.setSession("replacement native login after blur", owner, "bob"); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 104), dataKey: next }, owner); installLocalDataKey(owner, next); }
        finally { finish(); }
      })(); });
    }
    return answer;
  });
  await deletePrompt(); await confirm(false); await replacementDone; await nativeClockDone; await flush(); await flush();
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement native login after blur");
  expect(await api.getUserId()).toBe("b".repeat(32)); expect(vault.ownerUserId()).toBe("b".repeat(32)); expect(serverAccountPresent).toBe(true);
});

it("an already granted Native confirmation release before replacement-login commit cannot reuse the retired password card", async () => {
  await mount(); await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  const field = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!;
  await act(async () => field.props.onChangeText(PASSWORD));
  const host = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Confirm with password")!, tap = nativeGrantedPress(host.props);
  await api.setSession("replacement same-account Native bearer", USER, "alice");
  try {
    act(() => {
      // A successful password login owns fresh buffers even when the same
      // account and password yield identical authenticated key bytes.
      vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
      expect(field.props.value).toBe(PASSWORD);
      expect(host.props.disabled).toBe(false);
      tap.configure(host.props); tap.release();
    });
  } finally { tap.dispose(); }
  await flush(); await vi.waitFor(() => expect(control("Allow third-party transcript translation").props.disabled).toBe(false), { timeout: 1500 });
  expect(consent).toBe(false); expect(text()).not.toContain("Confirm with password");
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement same-account Native bearer");
});

it.each(["confirmation", "rotation current", "rotation new"] as const)("a queued Native %s text event before replacement commit cannot repopulate a retired password", async fieldKind => {
  await mount();
  if (fieldKind === "confirmation") await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  else await press("Change password");
  const label = fieldKind === "rotation new" ? "New password" : "Password confirmation";
  const field = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label)!;
  await api.setSession("replacement keyboard Native bearer", USER, "alice");
  act(() => {
    vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
    // The Native host still displays the prior committed frame. Execute the
    // installed TextInput change publisher against its current public props.
    expect(field.props.value).toBe("");
    nativeInputChange(field.props, "retired Native keyboard secret");
  });
  await flush();
  if (fieldKind === "confirmation") await act(async () => control("Allow third-party transcript translation").props.onValueChange(true));
  expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label)!.props.value).toBe("");
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement keyboard Native bearer");
});

it("a Native biometric opt-out from the still-committed old frame cannot delete a replacement login's usable wrap", async () => {
  keychain.__setBiometryType("FaceID"); await enableBiometricUnlock(USER, vault.get().dataKey); await mount();
  const host = control("Biometric unlock"); expect(host.props.value).toBe(true);
  await api.setSession("replacement biometric Native bearer", USER, "alice"); let completion: Promise<void> | undefined;
  act(() => {
    vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
    expect(host.props.value).toBe(true); completion = host.props.onValueChange(false);
  });
  await completion; await flush();
  expect(await keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1." + USER })).toBe(true);
  const restored = await unwrapBiometricDataKey(USER); try { expect(restored).toEqual(DATA); } finally { restored?.fill(0); }
});

it("an already granted Native rejected-entry retry before replacement-login commit retains the current rejected ciphertext", async () => {
  const id = "native-rendered-rejected", blob = encryptEntry({ dataKey: DATA }, USER, id, "retained after replacement login", "2026-10-07T04:00:00Z", null);
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), rejected = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`, queue = `${ACCOUNT_STORAGE_PREFIX.queue}.items.${scope}`;
  const raw = JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]); await storage.setItem(rejected, raw); await mount();
  await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  const host = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Try syncing the recovered entries again")!, tap = nativeGrantedPress(host.props);
  await api.setSession("replacement rejected-queue Native bearer", USER, "alice");
  try { act(() => {
    vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
    expect(host.props.disabled).toBe(false); tap.configure(host.props); tap.release();
  }); } finally { tap.dispose(); }
  await flush(); await vi.waitFor(() => expect(control("Allow third-party transcript translation").props.disabled).toBe(false));
  expect(await storage.getItem(rejected)).toBe(raw); expect(await storage.getItem(queue)).toBeNull();
});

it("an already granted Native rotation release before replacement-login commit cannot lock the replacement vault", async () => {
  await mount(); await press("Change password");
  await act(async () => { root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD); root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "New password")!.props.onChangeText("New Native secret42!"); });
  const oldField = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!, host = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Rotate keys and sign in again")!, tap = nativeGrantedPress(host.props);
  await api.setSession("replacement rotation Native bearer", USER, "alice");
  try { act(() => {
    vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
    expect(oldField.props.value).toBe(PASSWORD); expect(host.props.disabled).toBe(false); tap.configure(host.props); tap.release();
  }); } finally { tap.dispose(); }
  await flush(); await vi.waitFor(() => expect(control("Allow third-party transcript translation").props.disabled).toBe(false), { timeout: 1500 });
  expect(vault.isUnlocked()).toBe(true); expect(vault.get().dataKey).toEqual(DATA); expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement rotation Native bearer");
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("an already granted Native retry release while a share sheet owns busy preserves rejected ciphertext and busy admission", async () => {
  const record = await seedCurrentRecording("native-share-rejected-busy"), id = "native-busy-rejected", blob = encryptEntry({ dataKey: DATA }, USER, id, "private rejected journal during share", "2026-10-07T04:00:00Z", null);
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), rejected = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`, queue = `${ACCOUNT_STORAGE_PREFIX.queue}.items.${scope}`;
  const raw = JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]); await storage.setItem(rejected, raw); await mount();
  await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  const host = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Try syncing the recovered entries again")!, tap = nativeGrantedPress(host.props), held = pause();
  sharing.shareAsync.mockImplementationOnce(async () => { await held.run(); });
  await press("Export encrypted recording 1"); await vi.waitFor(() => expect(held.entered()).toBe(true));
  try { await act(async () => { expect(host.props.disabled).toBe(true); tap.configure(host.props); tap.release(); }); await flush(); await flush();
    expect(await storage.getItem(rejected)).toBe(raw); expect(await storage.getItem(queue)).toBeNull(); expect(control("Allow third-party transcript translation").props.disabled).toBe(true);
    expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  } finally { tap.dispose(); held.release(); await flush(); }
});

it("a native identity mismatch during rejected retry keeps the foreign account's retained ciphertext", async () => {
  const id = "native-retry-owner-mismatch", blob = encryptEntry({ dataKey: DATA }, USER, id, "current rejected journal", "2026-10-07T04:00:00Z", null), other = "b".repeat(32);
  const scoped = (owner: string) => Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${owner}`).toString("base64url"), current = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scoped(USER)}`, foreign = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scoped(other)}`, foreignQueue = `${ACCOUNT_STORAGE_PREFIX.queue}.items.${scoped(other)}`;
  await storage.setItem(current, JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]));
  const foreignBlob = encryptEntry({ dataKey: DATA }, other, "foreign-native-retained", "foreign private retained journal", "2026-10-07T04:00:00Z", null), raw = JSON.stringify([{ userId: other, clientEntryId: "foreign-native-retained", blobB64: foreignBlob.blobB64, entryDate: "2026-10-07" }]);
  await storage.setItem(foreign, raw); await mount(); await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  // A physically restored, valid device-key encrypted account slot does
  // not prove it belongs to the current vault's authenticated owner.
  await secureStore.setItem("@mindpattern/user_id", other);
  await press("Try syncing the recovered entries again"); await flush();
  expect(await storage.getItem(foreign)).toBe(raw); expect(await storage.getItem(foreignQueue)).toBeNull(); expect(alert()?.[0]).toBe("Could not retry");
});

it.each([false, true])("the current Native quarantine notice matches durable retained custody=%s", async present => {
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), slot = `${ACCOUNT_STORAGE_PREFIX.queue}.quarantine.${scope}`;
  if (present) await storage.setItem(slot, JSON.stringify({ v: 1, records: ["a damaged retained Native queue record"] }));
  await mount(); await flush();
  const notice = "A damaged piece of the offline queue was set aside instead of deleted. New entries sync normally.";
  expect(text().includes(notice)).toBe(present);
  expect(await storage.getItem(slot)).toBe(present ? JSON.stringify({ v: 1, records: ["a damaged retained Native queue record"] }) : null);
});

it("the current Native recovery card displays only the acknowledged calendar date", async () => {
  recovery = true; await mount(); await flush();
  expect(text()).toContain("Recovery kit active since 2026-10-07.");
  expect(text()).not.toContain("T04:00:00Z");
});

it.each([false, true])("the current Native legacy queue disclosure matches physically preserved old records=%s", async present => {
  const raw = "opaque retained legacy encrypted Native queue bytes";
  if (present) await storage.setItem("@mindpattern/queue", raw);
  await mount(); await flush();
  expect(text().includes("Older offline entries need recovery")).toBe(present);
  const retained = await storage.getItem("@mindpattern/queue.legacy-unscoped.v1");
  if (present) {
    expect(text()).toContain("They remain on this device but cannot be safely assigned automatically; contact support before clearing app data.");
    expect(JSON.parse(retained!).records).toContainEqual({ key: "@mindpattern/queue", raw });
    expect(await storage.getItem("@mindpattern/queue")).toBeNull();
  } else expect(retained).toBeNull();
});

it("a finite Native session cleanup refusal after account erasure keeps the honest retry disclosure", async () => {
  await mount(); const remove = storage.removeItem.bind(storage), checkpoint = accountStorageKey.erasure(canonicalOrigin(DEFAULT_BASE_URL), USER);
  let erased = false, refused = false;
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => {
    if (erased && !refused && slot === "@mindpattern/token") { refused = true; throw new Error("Native credential storage is temporarily unavailable"); }
    await remove(slot); if (slot === checkpoint) erased = true;
  });
  await deletePrompt(); await confirm(); await flush();
  expect(erased).toBe(true); expect(refused).toBe(true); expect(serverAccountPresent).toBe(false);
  expect(alert()?.[0]).toBe("Deleted");
  expect(alert()?.[1]).toContain("Your server account is deleted. Some device cleanup remains; Fathom will retry it on the next start.");
  expect(await secureStore.getItem("@mindpattern/token")).toBeNull(); expect(await api.getUserId()).toBeNull(); expect(vault.isUnlocked()).toBe(false);
});

it("a finite Native identity read refusal after erasure still publishes the completed deletion", async () => {
  await mount(); const remove = storage.removeItem.bind(storage), read = storage.getItem.bind(storage), checkpoint = accountStorageKey.erasure(canonicalOrigin(DEFAULT_BASE_URL), USER);
  let erased = false, refused = false;
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => { await remove(slot); if (slot === checkpoint) erased = true; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    if (erased && !refused && slot === "@mindpattern/user_id") { refused = true; throw new Error("Native credential read temporarily unavailable"); }
    return read(slot);
  });
  await deletePrompt(); await confirm(); await flush();
  expect(erased).toBe(true); expect(refused).toBe(true); expect(serverAccountPresent).toBe(false);
  expect(alert()?.[0]).toBe("Deleted");
  expect(await secureStore.getItem("@mindpattern/token")).toBeNull(); expect(await api.getUserId()).toBeNull(); expect(vault.isUnlocked()).toBe(false);
});

it.each(["recovery", "delete", "upgrade"] as const)("a valid foreign Native identity cannot attribute a current %s proof to that account", async kind => {
  await mount();
  if (kind === "recovery") await press("Create recovery kit");
  else if (kind === "delete") await deletePrompt();
  else await press("Upgrade now");
  await secureStore.setItem("@mindpattern/user_id", "b".repeat(32));
  await confirm(); await flush();
  expect(serverAccountPresent).toBe(true); expect(recovery).toBe(false); expect(recoverySealed).toBeUndefined();
  expect(vault.get().dataKey).toEqual(DATA);
  if (kind === "recovery") expect(alert()?.[1]).toBe("The kit could not be created — check your connection and try again.");
  else {
    expect(alert()?.[0]).toBe(kind === "delete" ? "Delete failed" : "Could not complete");
    expect(alert()?.[1]).toBe("Something went wrong — try again.");
  }
});

it("a valid foreign Native identity refuses password rotation with the current screen's public copy", async () => {
  await mount(); await press("Change password");
  await act(async () => {
    root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD);
    root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "New password")!.props.onChangeText("New Native secret42!");
  });
  await secureStore.setItem("@mindpattern/user_id", "b".repeat(32));
  await press("Rotate keys and sign in again"); await flush();
  expect(alert()?.[1]).toBe("Something went wrong — try again.");
  expect(vault.get().dataKey).toEqual(DATA); expect(await secureStore.getItem("@mindpattern/token")).toBe("native bearer");
});
it.each([4,5,6,7,8,9])("a Native foreign rotation identity followed by replacement phase %s gives the completed refusal before retiring the frame",async phase=>{
 await mount();await press("Change password");await act(async()=>{root!.root.findAllByType(TextInput).find(n=>n.props.accessibilityLabel==="Password confirmation")!.props.onChangeText(PASSWORD);root!.root.findAllByType(TextInput).find(n=>n.props.accessibilityLabel==="New password")!.props.onChangeText("New Native secret42!");});await secureStore.setItem("@mindpattern/user_id","b".repeat(32));
 const read=secureStore.getItem.bind(secureStore),next=Buffer.from(DATA);let delivered=false;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const answer=await read(slot);if(!delivered&&slot==="@mindpattern/username"){delivered=true;nativeDelivery(phase,()=>{vault.unlock({masterKey:Buffer.from(MASTER),authKey:Buffer.from(AUTH),dataKey:next},USER);installLocalDataKey(USER,next);});}return answer;});
 await press("Rotate keys and sign in again",false);await flush();expect(delivered).toBe(true);expect(vault.get().dataKey).toBe(next);expect(vi.mocked(Alert.alert).mock.calls).toEqual([["Could not change password","Something went wrong — try again."]]);
});

it.each(["delete-origin", "delete-uid", "recovery-uid", "upgrade-uid", "rotation-uid"] as const)("a retired Native %s receipt cannot monopolize replacement credential publication through legacy migration", async edge => {
  await mount(); const slot = edge === "delete-origin" ? "@mindpattern/user_id" : "@mindpattern/username", stored = JSON.parse((await storage.getItem(slot))!);
  if (edge === "delete-origin") await storage.setItem(slot, stored.c);
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), legacy = pause();
  let baseReads = 0, retired = false, replacementStarted = false, loginReady = false, migrationHeld = false;
  let replacement!: Promise<void>, nativeTimer: ReturnType<typeof setTimeout> | undefined;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (retired && !replacementStarted && key === slot && !migrationHeld) { migrationHeld = true; await legacy.run(); }
    return write(key, value);
  });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    const receipt = edge === "delete-origin" ? key === "@mindpattern/base_url" && ++baseReads === 2 : key === "@mindpattern/user_id";
    if (!retired && receipt) {
      // Recovery/upgrade already read the username during password proof.
      // Restore supported old bytes at this actual UID receipt so a later
      // old continuation, rather than that earlier proof, would migrate it.
      if (edge !== "delete-origin") await write(slot, stored.c);
      retired = true; vault.lock();
      setImmediate(() => {
        replacementStarted = true;
        // A finite slow Native migration occupies the real serialized slot
        // only if the old continuation admitted it after key retirement.
        nativeTimer = setTimeout(legacy.release, 800);
        replacement = (async () => {
          await api.setSession("replacement Native login during slow legacy provider", USER, "alice");
          vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey);
          loginReady = true;
        })();
      });
    }
    return value;
  });
  if (edge === "delete-origin" || edge === "delete-uid") await deletePrompt(); else if (edge === "rotation-uid") { await press("Change password"); await act(async () => { root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD); root!.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "New password")!.props.onChangeText("New Native secret42!"); }); } else await press(edge === "recovery-uid" ? "Create recovery kit" : "Upgrade now");
  if (edge === "rotation-uid") await press("Rotate keys and sign in again", false); else await confirm(false);
  try {
    await vi.waitFor(() => expect(replacementStarted).toBe(true), { timeout: 1500 });
    await vi.waitFor(() => expect(loginReady).toBe(true), { timeout: 250 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement Native login during slow legacy provider"); expect(await api.getUserId()).toBe(USER);
    expect(serverAccountPresent).toBe(true); expect(recovery).toBe(false);
  } finally {
    legacy.release(); if (nativeTimer) clearTimeout(nativeTimer); if (replacement) await replacement;
  }
});

it.each(["llm", "voice"].flatMap(kind => Array.from({ length: 5 }, (_, phase) => [kind, phase] as const)))("a Native %s consent receipt phase %s cannot publish after its physical key retires", async (kind, phase) => {
  await mount(); const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling", next = Buffer.from(DATA);
  let replaced = false;
  boundary = async (path, method) => {
    if (method === "PUT" && path.endsWith("/account/" + kind + "-consent")) nativeDelivery(phase, () => {
      replaced = true;
      vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next);
    });
  };
  await act(async () => control(label).props.onValueChange(true)); await confirm(); await flush();
  expect(replaced).toBe(true); expect(vault.get().dataKey).toBe(next);
  expect(control(label).props.value).toBe(false); expect(text()).not.toContain("Confirm with password");
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("a disappeared Native identity receipt after recording removal explains the still-owned refresh failure", async () => {
  const record = await seedCurrentRecording("native-removal-identity-disappeared"); await mount();
  await vi.waitFor(() => expect(text()).toContain("Remove saved recording 1"));
  const remove = files.deleteAsync.getMockImplementation()!; let disappeared = false;
  files.deleteAsync.mockImplementation(async (...args) => {
    const result = await remove(...args);
    if (!disappeared && args[0].endsWith("exports/" + Buffer.from("native-removal-identity-disappeared").toString("base64url") + ".json")) {
      disappeared = true; await secureStore.removeItem("@mindpattern/user_id");
    }
    return result;
  });
  await press("Remove saved recording 1"); await button("Remove recording");
  await vi.waitFor(() => expect(alert()?.[0]).toBe("Could not retry"));
  expect(alert()?.[1]).toBe("Session damaged");
  expect(await storage.getItem(record.slot)).toBeNull(); expect(files.__hasFile(record.descriptor.uri)).toBe(false);
  expect(vault.get().dataKey).toEqual(DATA);
});

it.each(["requeue-write", "final-count-read"].flatMap(edge => Array.from({ length: 19 }, (_, phase) => [edge, phase] as const)))("a Native rejected retry %s receipt phase %s respects admission and keeps retired notices quiet", async (edge, phase) => {
  const id = "native-retry-caller-handoff", blob = encryptEntry({ dataKey: DATA }, USER, id, "my retained Native retry handoff journal", "2026-10-07T04:00:00Z", null);
  const scope = Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"), rejected = `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`;
  await storage.setItem(rejected, JSON.stringify([{ userId: USER, clientEntryId: id, blobB64: blob.blobB64, entryDate: "2026-10-07" }]));
  await mount(); await vi.waitFor(() => expect(text()).toContain("Try syncing them again"));
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage), request = globalThis.fetch;
  let completedRequeue = false, delivered = false, replaced = false;
  const lateAlerts: unknown[][] = [], lateEntries: unknown[] = [], next = Buffer.from(DATA);
  const deliver = () => {
    if (delivered) return; delivered = true;
    nativeDelivery(phase, () => {
      replaced = true;
      vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER);
      installLocalDataKey(USER, next);
    });
  };
  vi.mocked(Alert.alert).mockImplementation((...args) => { if (replaced) lateAlerts.push(args); });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    if (new URL(url).pathname.endsWith("/entries") && init.method === "POST") {
      const body = JSON.parse(String(init.body));
      expect(body.client_entry_id).toBe(id); expect(body.blob).toBe(blob.blobB64);
      if (replaced) lateEntries.push(body);
      const response = new Response(JSON.stringify({ id: "native-acknowledged-row" }), { status: 200 });
      Object.defineProperty(response, "url", { value: url }); return response;
    }
    return request(url, init);
  });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    await write(slot, value);
    if (slot === rejected) { completedRequeue = true; if (edge === "requeue-write") deliver(); }
  });
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => {
    await remove(slot);
    if (slot === rejected) { completedRequeue = true; if (edge === "requeue-write") deliver(); }
  });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await read(slot);
    if (completedRequeue && slot === rejected && edge === "final-count-read") deliver();
    return value;
  });
  await press("Try syncing the recovered entries again"); await flush();
  expect(delivered).toBe(true); expect(replaced).toBe(true); expect(vault.get().dataKey).toBe(next);
  // Later phases can complete an already admitted opaque-ciphertext upload;
  // same-key buffer renewal does not retire its local generation permit.
  // The first six phases deliver before Settings admits the flush helper.
  if (edge === "requeue-write" && phase <= 5) expect(lateEntries).toEqual([]);
  expect(lateAlerts).toEqual([]);
});

it.each(Array.from({length:7},(_,phase)=>phase))("a retired Native final empty queue receipt phase %s leaves the physical credential worker available",async phase=>{
 const id="native-final-flush-worker",blob=encryptEntry({dataKey:DATA},USER,id,"retained physical queue receipt","2026-10-07T04:00:00Z",null),scope=Buffer.from(`${canonicalOrigin(DEFAULT_BASE_URL)}\0${USER}`).toString("base64url"),rejected=`${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope}`,queue=`${ACCOUNT_STORAGE_PREFIX.queue}.items.${scope}`;
 await storage.setItem(rejected,JSON.stringify([{userId:USER,clientEntryId:id,blobB64:blob.blobB64,entryDate:"2026-10-07"}]));await mount();await vi.waitFor(()=>expect(text()).toContain("Try syncing them again"));
 const read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),remove=storage.removeItem.bind(storage),request=globalThis.fetch,held=pause();let worker:Promise<unknown>=Promise.resolve(),uploaded=false,delivered=false,retired=false,loginReady=false,replacement:Promise<void>|undefined,timer:ReturnType<typeof setTimeout>|undefined;
 const nativeJob=<T,>(operation:()=>Promise<T>):Promise<T>=>{const pending=worker.then(operation,operation);worker=pending.catch(()=>{});return pending;};
 vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{if(new URL(url).pathname.endsWith("/entries")&&init.method==="POST"){uploaded=true;const response=new Response(JSON.stringify({id:"native-final-flush-server-row"}),{status:200});Object.defineProperty(response,"url",{value:url});return response;}return request(url,init);});
 vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
  const answer=await nativeJob(async()=>{if(retired&&slot==="@mindpattern/queue"){timer??=setTimeout(held.release,800);await held.run();}return read(slot);});
  if(!delivered&&uploaded&&slot===queue&&(answer===null||answer==="[]")){delivered=true;nativeDelivery(phase,()=>{retired=true;vault.lock();setImmediate(()=>{replacement=api.setSession("new Native final-flush bearer",USER,"alice");void replacement.then(()=>{loginReady=true;});});});}
  return answer;
 });
 vi.spyOn(storage,"setItem").mockImplementation((slot,value)=>nativeJob(()=>write(slot,value)));vi.spyOn(storage,"removeItem").mockImplementation(slot=>nativeJob(()=>remove(slot)));
 try{await press("Try syncing the recovered entries again",false);await vi.waitFor(()=>expect(retired).toBe(true));await vi.waitFor(()=>expect(loginReady).toBe(true),{timeout:250,interval:5});expect(await secureStore.getItem("@mindpattern/token")).toBe("new Native final-flush bearer");expect(await read(queue)).toBeNull();}
 finally{held.release();if(timer)clearTimeout(timer);await replacement;await worker;}
});

it.each(Array.from({ length: 9 }, (_, phase) => phase))("a Native saved-recording list receipt at phase %s cannot restore old controls while the replacement refresh is still held", async phase => {
  const record = await seedCurrentRecording("native-list-replacement-custody"), readFile = files.readAsStringAsync.getMockImplementation()!, list = storage.getAllKeys.bind(storage), held = pause();
  let reads = 0, delivered = false, replaced = false; const next = Buffer.from(DATA);
  vi.spyOn(storage, "getAllKeys").mockImplementation(async () => { const answer = await list(); if (replaced) await held.run(); return answer; });
  files.readAsStringAsync.mockImplementation(async (...args) => {
    const answer = await readFile(...args);
    if (args[0] === record.descriptor.uri && ++reads === 2) {
      delivered = true;
      nativeDelivery(phase, () => { replaced = true; vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
    }
    return answer;
  });
  await mount(); await vi.waitFor(() => expect(held.entered()).toBe(true)); await flush();
  expect(delivered).toBe(true); expect(vault.get().dataKey).toBe(next);
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Export encrypted recording 1")).toBeUndefined();
  expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  expect(decryptAudio({ dataKey: DATA }, USER, "native-list-replacement-custody", await readFile(record.descriptor.uri))).toEqual(record.words);
  held.release(); await flush(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
});

it.each(Array.from({ length: 5 }, (_, phase) => phase))("a Native recovery creation response at phase %s cannot publish a retired acknowledgement", async phase => {
  await mount(); const next = Buffer.from(DATA); let delivered = false;
  boundary = async (path, method) => {
    if (!delivered && method === "PUT" && path.endsWith("/account/recovery")) {
      delivered = true; nativeDelivery(phase, () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
    }
  };
  await press("Create recovery kit"); await confirm(); await flush();
  expect(delivered).toBe(true); expect(recovery).toBe(true); expect(vault.get().dataKey).toBe(next);
  expect(text()).toContain("No recovery kit."); expect(text()).not.toContain("Remove kit"); expect(text()).not.toContain("mindpattern-recovery:v2:");
});

it.each(["identity", "status"] as const)("a retired Native saved-recording %s receipt cannot monopolize the installed Android storage worker ahead of a new login", async edge => {
  const record = await seedCurrentRecording("native-serial-refresh-admission"); await mount(); await vi.waitFor(() => expect(text()).toContain("Export encrypted recording 1"));
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage), list = storage.getAllKeys.bind(storage), held = pause();
  let worker: Promise<unknown> = Promise.resolve();
  const nativeJob = <T,>(operation: () => Promise<T>): Promise<T> => { const job = worker.then(operation, operation); worker = job.catch(() => {}); return job; };
  let retired = false, delivered = false, replacement: Promise<void> | undefined, replacementFinished = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const retire = () => { delivered = true; retired = true; vault.lock(); setTimeout(() => { replacement = api.setSession("new Native serialized-worker bearer", USER, "alice"); void replacement.then(() => { replacementFinished = true; }); }, 0); };
  if (edge === "status") { const readFile = files.readAsStringAsync.getMockImplementation()!; files.readAsStringAsync.mockImplementation(async (...args) => { const answer = await readFile(...args); if (!delivered && args[0] === record.descriptor.uri) retire(); return answer; }); }
  // AsyncStorageModule's installed Android SerialExecutor releases the
  // physical worker before the Native callback is delivered into JS.
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const answer = await nativeJob(() => read(slot));
    if (edge === "identity" && !delivered && slot === "@mindpattern/user_id") retire();
    return answer;
  });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => nativeJob(() => write(slot, value)));
  vi.spyOn(storage, "removeItem").mockImplementation(slot => nativeJob(() => remove(slot)));
  vi.spyOn(storage, "getAllKeys").mockImplementation(() => nativeJob(async () => {
    if (retired) { timer ??= setTimeout(held.release, 800); await held.run(); }
    return list();
  }));
  try {
    await act(async () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey); });
    await vi.waitFor(() => expect(delivered).toBe(true));
    await vi.waitFor(() => expect(replacementFinished).toBe(true), { timeout: 250, interval: 5 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("new Native serialized-worker bearer"); expect(await read(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  } finally { held.release(); if (timer) clearTimeout(timer); await replacement; await worker; }
});

it.each(Array.from({ length: 5 }, (_, phase) => phase))("a Native account deletion response at phase %s cannot erase a replacement key and its retained recording", async phase => {
  const record = await seedCurrentRecording("native-delete-replacement-custody"); await mount(); const next = Buffer.from(DATA); let delivered = false;
  boundary = async (path, method) => {
    if (!delivered && method === "DELETE" && path.endsWith("/account")) {
      delivered = true; nativeDelivery(phase, () => { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); });
    }
  };
  await deletePrompt(); await confirm(); await flush();
  expect(delivered).toBe(true); expect(serverAccountPresent).toBe(false); expect(vault.canReauthenticate()).toBe(true); expect(vault.get().dataKey).toBe(next);
  expect(await storage.getItem(record.slot)).toBe(record.raw); expect(files.__hasFile(record.descriptor.uri)).toBe(true);
  expect(await secureStore.getItem("@mindpattern/user_id")).toBe(USER); expect(alert()?.[0]).not.toBe("Deleted");
});

it("a Native biometric confirmation identity receipt cannot install a replacement vault key under the retired password proof", async () => {
  keychain.__setBiometryType("FaceID"); await mount(); await act(async () => control("Biometric unlock").props.onValueChange(true)); await button("Enable");
  const read = storage.getItem.bind(storage), next = Buffer.from(DATA); let delivered = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const answer = await read(slot);
    if (!delivered && slot === "@mindpattern/user_id") { delivered = true; vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); }
    return answer;
  });
  await confirm(); await flush(); expect(delivered).toBe(true); expect(vault.get().dataKey).toBe(next);
  expect(await keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1." + USER })).toBe(false);
  expect(await storage.getItem(accountStorageKey.biometricOwner(USER))).toBeNull(); expect(control("Biometric unlock").props.value).toBe(false);
});

it.each([false, true])("a Native upgrade username receipt retirement=%s preserves the actual owned server format", async retirement => {
  const id = "native-upgrade-owned-corpus", words = "my actual server journal keeps its verified encryption format", saved = encryptEntry({ dataKey: DATA }, USER, id, words, "2026-10-07T04:00:00Z", null);
  await mount(); const request = globalThis.fetch, next = Buffer.from(DATA); let serverScheme: "v1" | "v2" = "v1", possession = false;
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    if (!path.endsWith("/processing/sessions") && !path.endsWith("/account/key-envelope/upgrade")) return request(url, init);
    const body = JSON.parse(String(init.body)); let value: unknown = {};
    if (path.endsWith("/processing/sessions")) {
      const key = Buffer.from(body.data_key, "base64"), blob = Buffer.from(saved.blobB64, "base64"), cipher = crypto.createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
      cipher.setAAD(Buffer.from(JSON.stringify(["entry", USER, id]))); cipher.setAuthTag(blob.subarray(-16));
      expect(JSON.parse(Buffer.concat([cipher.update(blob.subarray(12, -16)), cipher.final()]).toString("utf8")).text).toBe(words);
      possession = true; value = { session_token: "native actual corpus possession" };
    } else {
      expect(possession).toBe(true); expect(new Headers(init.headers).get("X-Account-Verifier")).toBe(AUTH.toString("base64"));
      const master = crypto.pbkdf2Sync(PASSWORD, SALT, body.kdf_params.iterations, 32, "sha256"), kek = Buffer.from(crypto.hkdfSync("sha256", master, SALT, "mindpattern/envelope/v2", 32)), wrapped = Buffer.from(body.wrapped_data_key, "base64"), cipher = crypto.createDecipheriv("aes-256-gcm", kek, wrapped.subarray(0, 12));
      cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: body.kdf_params, username: "alice" }))); cipher.setAuthTag(wrapped.subarray(-16));
      expect(Buffer.concat([cipher.update(wrapped.subarray(12, -16)), cipher.final()])).toEqual(DATA); master.fill(0); kek.fill(0); serverScheme = "v2";
    }
    const response = new Response(JSON.stringify(value), { status: 200 }); Object.defineProperty(response, "url", { value: url }); return response;
  });
  const read = storage.getItem.bind(storage); let usernames = 0, delivered = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (slot === "@mindpattern/username" && ++usernames === 2) { delivered = true; if (retirement) { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); } } return answer; });
  await press("Upgrade now"); await confirm(); await flush(); expect(delivered).toBe(true); if (retirement) expect(vault.get().dataKey).toBe(next); else expect(vault.get().dataKey).toEqual(DATA); expect(serverScheme).toBe(retirement ? "v1" : "v2");
  expect(await secureStore.getItem("@mindpattern/token")).toBe("native bearer");
});

it.each([false, true])("a Native rotation username receipt retirement=%s preserves the verified server credential", async retirement => {
  const NEW = "Cedar ridge!73 Oak", params = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, request = globalThis.fetch;
  let serverSalt = Buffer.from(SALT), serverVerifier = AUTH.toString("base64"), possession = false;
  const wrap = (key: Buffer, master: Buffer, salt: Buffer) => { const kek = Buffer.from(crypto.hkdfSync("sha256", master, salt, "mindpattern/envelope/v2", 32)), nonce = Buffer.alloc(12, 7), cipher = crypto.createCipheriv("aes-256-gcm", kek, nonce); cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: "alice" }))); const answer = Buffer.concat([nonce, cipher.update(key), cipher.final(), cipher.getAuthTag()]).toString("base64"); kek.fill(0); return answer; };
  let wrapped = wrap(DATA, MASTER, SALT);
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname; let value: unknown;
    if (path.endsWith("/auth/key-envelope")) value = { key_scheme: "v2", salt: serverSalt.toString("base64"), kdf_params: params, wrapped_data_key: wrapped };
    else if (path.endsWith("/processing/sessions")) { const body = JSON.parse(String(init.body)); expect(Buffer.from(body.data_key, "base64")).toEqual(DATA); possession = true; value = { session_token: "native unchanged data possession" }; }
    else if (path.endsWith("/account/password")) {
      const body = JSON.parse(String(init.body)); expect(possession).toBe(true); expect(body.verifier).toBe(serverVerifier); serverSalt = Buffer.from(body.new_salt, "base64");
      const nextMaster = crypto.pbkdf2Sync(NEW, serverSalt, 600000, 32, "sha256"), nextAuth = Buffer.from(crypto.hkdfSync("sha256", nextMaster, Buffer.alloc(32), "mindpattern/auth/v1", 32)); expect(body.new_verifier).toBe(nextAuth.toString("base64"));
      const kek = Buffer.from(crypto.hkdfSync("sha256", nextMaster, serverSalt, "mindpattern/envelope/v2", 32)), envelope = Buffer.from(body.wrapped_data_key, "base64"), decipher = crypto.createDecipheriv("aes-256-gcm", kek, envelope.subarray(0, 12)); decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: "alice" }))); decipher.setAuthTag(envelope.subarray(-16)); expect(Buffer.concat([decipher.update(envelope.subarray(12, -16)), decipher.final()])).toEqual(DATA);
      serverVerifier = body.new_verifier; wrapped = body.wrapped_data_key; nextMaster.fill(0); nextAuth.fill(0); kek.fill(0); value = {};
    } else if (path.endsWith("/auth/login")) { const body = JSON.parse(String(init.body)); expect(body.verifier).toBe(serverVerifier); value = { token: "native committed rotated bearer", user_id: USER }; }
    else return request(url, init);
    const response = new Response(JSON.stringify(value), { status: 200 }); Object.defineProperty(response, "url", { value: url }); return response;
  });
  await mount(); await act(async () => { await new Promise(resolve => setTimeout(resolve, 50)); }); await press("Change password"); await act(async () => { root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Password confirmation")!.props.onChangeText(PASSWORD); root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "New password")!.props.onChangeText(NEW); });
  const read = storage.getItem.bind(storage), next = Buffer.from(DATA); let delivered = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => { const answer = await read(slot); if (!delivered && slot === "@mindpattern/username") { delivered = true; if (retirement) { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: next }, USER); installLocalDataKey(USER, next); } } return answer; });
  await press("Change password and sign in again"); await vi.waitFor(() => expect(delivered).toBe(true)); if (retirement) await act(async () => { await new Promise(resolve => setTimeout(resolve, 1000)); }); else await vi.waitFor(() => expect(serverVerifier).not.toBe(AUTH.toString("base64")), { timeout: 4000 }); await flush();
  if (retirement) { expect(serverVerifier).toBe(AUTH.toString("base64")); expect(serverSalt).toEqual(SALT); expect(vault.get().dataKey).toBe(next); expect(await secureStore.getItem("@mindpattern/token")).toBe("native bearer"); }
  else { expect(serverVerifier).not.toBe(AUTH.toString("base64")); expect(vault.get().dataKey).toEqual(DATA); expect(await secureStore.getItem("@mindpattern/token")).toBe("native committed rotated bearer"); expect(alert()?.[0]).toBe("Password changed"); }
});

it.each(["AppState", "vault"] as const)("an unmounted Native Settings %s subscription leaves the credential worker available", async producer => {
  // The shipped ErrorBoundary can dispose its whole SessionProvider scene
  // while preserving the vault. A later device event or genuine key adoption
  // must not let the disposed Settings controller start new Native IO.
  const nativeState = new EventEmitter();
  vi.spyOn(AppState, "addEventListener").mockImplementation((event, listener) => {
    nativeState.on(event, listener); return { remove: () => nativeState.removeListener(event, listener) };
  });
  await mountInstalledNavigator(); await flush();
  await act(async () => { root!.unmount(); root = undefined; }); nativeRouteEvents = undefined;
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage), remove = storage.removeItem.bind(storage), held = pause();
  let worker: Promise<unknown> = Promise.resolve(), replacementStarted = false, ready = false, timer: ReturnType<typeof setTimeout> | undefined;
  const nativeJob = <T,>(operation: () => Promise<T>): Promise<T> => { const pending = worker.then(operation, operation); worker = pending.catch(() => {}); return pending; };
  // Android AsyncStorage's physical FIFO worker is free before JS receipts.
  // A read admitted before the next credential event takes finite slow IO;
  // that event recovers the provider for subsequent newly admitted jobs.
  vi.spyOn(storage, "getItem").mockImplementation(slot => {
    const slow = !replacementStarted && slot === "@mindpattern/user_id";
    return nativeJob(async () => { if (slow) { timer ??= setTimeout(held.release, 800); await held.run(); } return read(slot); });
  });
  vi.spyOn(storage, "setItem").mockImplementation((slot, value) => nativeJob(() => write(slot, value)));
  vi.spyOn(storage, "removeItem").mockImplementation(slot => nativeJob(() => remove(slot)));
  if (producer === "AppState") nativeState.emit("change", "inactive");
  else { vault.unlock({ masterKey: Buffer.from(MASTER), authKey: Buffer.from(AUTH), dataKey: Buffer.from(DATA) }, USER); installLocalDataKey(USER, vault.get().dataKey); }
  replacementStarted = true;
  const replacement = api.setSession("replacement Native disposed Settings bearer", USER, "alice"); void replacement.then(() => { ready = true; });
  try {
    await vi.waitFor(() => expect(ready).toBe(true), { timeout: 250, interval: 5 });
    expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement Native disposed Settings bearer");
  } finally { held.release(); if (timer) clearTimeout(timer); await replacement; await worker; }
});
