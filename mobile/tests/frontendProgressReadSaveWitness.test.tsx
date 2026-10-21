/** public producer witness for store413. HTTP and native storage
 * are independent; every AsyncStorage operation retains one FIFO lane. */
import crypto from "node:crypto";

import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { Alert, Text, TextInput, TouchableOpacity } from "react-native";
import { LoginScreen } from "../src/screens/LoginScreen";
import { EntryScreen } from "../src/screens/EntryScreen";
import { InsightsScreen } from "../src/screens/InsightsScreen";
import { MainShell } from "../src/components/BottomNav";
import { SessionProvider, useSession } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { verifyUnlockProof } from "../src/unlockProof";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests, localWriteScopeEpoch } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import * as files from "./helpers/expoFsMock";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "a".repeat(32), NAME = "alice", PASSWORD = "Native strong Passphrase 2026!";
const SALT = Buffer.alloc(16, 3), DATA = Buffer.alloc(32, 7);
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
const MASTER = crypto.pbkdf2Sync(PASSWORD, SALT, PARAMS.iterations, 32, "sha256");
const hkdf = (salt: Buffer, label: string) => Buffer.from(crypto.hkdfSync("sha256", MASTER, salt, label, 32));
const AUTH = hkdf(Buffer.alloc(32), "mindpattern/auth/v1");
const cipher = crypto.createCipheriv("aes-256-gcm", hkdf(SALT, "mindpattern/envelope/v2"), Buffer.alloc(12, 9));
cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: PARAMS, username: NAME })));
const WRAP = Buffer.concat([Buffer.alloc(12, 9), cipher.update(DATA), cipher.final(), cipher.getAuthTag()]).toString("base64");
const nativeDelete = files.deleteAsync.getMockImplementation()!;
const native = { ...storage };
type Event = { index: number; event: string; operation?: string; key?: string; route?: string; scope: number };
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let session: ReturnType<typeof useSession>;
let route = "boot", events: Event[] = [];
let restoreStorage = () => undefined;
function record(event: string, values: Partial<Event> = {}) { events.push({ index: events.length, event, scope: localWriteScopeEpoch(), ...values }); }
function Screen() {
  session = useSession();
  const [current, setCurrent] = React.useState("Entry");
  const navigation = React.useMemo(() => ({ navigate: (destination: string) => {  setCurrent(destination); } }), []);
  route = session.authStatus === "loggedIn" ? current : session.authStatus;
  if (session.authStatus === "loading") return <Text>Booting public session</Text>;
  if (session.authStatus === "loggedOut") return <LoginScreen navigation={navigation} />;
  return current === "Insights"
    ? <MainShell current="Insights" navigation={navigation}><InsightsScreen navigation={navigation} /></MainShell>
    : <EntryScreen navigation={navigation} />;
}
function response(url: string, body: unknown, status = 200) { const value = new Response(JSON.stringify(body), { status }); Object.defineProperty(value, "url", { value: url }); return value; }
function button(label: string) { const found = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label); if (!found) throw new Error(`SetupError: ProgressSaveWitness missing public action ${label}`); return found; }
async function fill(label: string, value: string) { const node = root!.root.findAllByType(TextInput).find(item => item.props.accessibilityLabel === label); if (!node) throw new Error(`SetupError: ProgressSaveWitness missing public input ${label}`); await act(async () => node.props.onChangeText(value)); }
async function until(label: string, ready: () => boolean) {
  const end = Date.now() + 15_000;
  while (!ready()) { if (Date.now() >= end) {  throw new Error(`SetupError: ProgressSaveWitness producer completion deadline ${label}`); } await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); }
}
async function finite<T>(label: string, work: Promise<T>) { let timer: ReturnType<typeof setTimeout>; try { return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`SetupError: ProgressSaveWitness producer completion deadline ${label}`)), 15_000); })]); } finally { clearTimeout(timer!); } }
function text() { return root!.root.findAllByType(Text).flatMap(node => node.children.filter(child => typeof child === "string")).join(" "); }
afterEach(async () => {

  if (root) { await act(async () => root!.unmount()); root = undefined; }
  restoreStorage(); vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

it("an older Insights owner receipt cannot clear Entry's pending save-triggered progress refresh", async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles(); files.deleteAsync.mockImplementation(nativeDelete);
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock(); await api.clearSession(); await setBaseUrl("http://localhost:8000"); vi.mocked(Alert.alert).mockClear();
  events = [];
  let releaseSave!: () => void, releaseOwner!: () => void, releaseFresh!: () => void;
  const saveGate = new Promise<void>(resolve => { releaseSave = resolve; }), ownerGate = new Promise<void>(resolve => { releaseOwner = resolve; }), freshGate = new Promise<void>(resolve => { releaseFresh = resolve; });
  let saveAdmitted = false, olderOwnerHeld = false, freshInsightsAdmitted = false, armOwner = false, afterSave = false;
  let lane: Promise<unknown> = Promise.resolve();
  const operations = ["getItem", "setItem", "removeItem", "multiSet", "multiRemove", "getAllKeys"] as const;
  for (const operation of operations) {
    (storage as any)[operation] = (...args: any[]) => {
      const key = typeof args[0] === "string" ? args[0] : undefined;
      record("native-admitted", { operation, key });
      const pending = lane.then(async () => {
        if (operation === "getItem" && key === "@mindpattern/user_id" && armOwner) {
          armOwner = false; olderOwnerHeld = true; record("older-insights-owner-head-held", { route }); await ownerGate;
        }
        await new Promise(resolve => setTimeout(resolve, 1));
        const result = await (native[operation] as any)(...args);
         return result;
      });
      lane = pending.catch(() => undefined); return pending;
    };
  }
  restoreStorage = () => { for (const operation of operations) (storage as any)[operation] = native[operation]; };
  let save: Promise<void> | undefined;
  try {
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      const path = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) : {};
      if (path.endsWith("/auth/salt")) return response(url, { salt: SALT.toString("base64") });
      if (path.endsWith("/auth/login")) return body.username === NAME && body.verifier === AUTH.toString("base64") ? response(url, { token: "independent progress bearer", user_id: USER, role: "user" }) : response(url, { code: "invalid_credentials" }, 401);
      if (path.endsWith("/auth/key-envelope")) return response(url, { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: WRAP });
      if (path.endsWith("/meta")) return response(url, { unlock_days: 30, llm_available: false, sharing_available: false, audio_available: false });
      if (path.endsWith("/consent/voice")) return response(url, { enabled: false, active_for_current_policy: false });
      if (path.endsWith("/entries") && init.method === "POST") {
        if (new Headers(init.headers).get("Authorization") !== "Bearer independent progress bearer" || typeof body.blob !== "string" || body.content_version !== 1) throw new Error("SetupError: ProgressSaveWitness actual save transport/owner contract did not hold");
        saveAdmitted = true;  await saveGate; afterSave = true;  return response(url, { client_entry_id: body.client_entry_id }, 201);
      }
      if (path.endsWith("/insights")) {
        if (!afterSave) return response(url, { code: "temporarily_unavailable" }, 503);
        freshInsightsAdmitted = true;  await freshGate; return response(url, { phase: "baseline", active_days: 7, days_remaining: 23, blob: null });
      }
      throw new Error(`SetupError: ProgressSaveWitness unexpected HTTP route ${path}`);
    });
    await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><Screen /></SessionProvider></ThemeProvider>); });
    await until("actual logged-out boot", () => route === "loggedOut");
    await fill("Username", NAME); await fill("Password", PASSWORD);
    await act(async () => { await finite("actual Login Promise", button("Sign in").props.onPress()); });
    await until("initial progress refusal and Entry readiness", () => route === "Entry" && !session.activeDaysKnown && !session.activeDaysLoading);
    expect(vault.get().dataKey).toEqual(DATA); expect(await verifyUnlockProof(DATA, USER)).toBe("ok");
    const scope = localWriteScopeEpoch();
    await fill("Journal entry", "A short authentic public writing entry whose acknowledged save overlaps a Patterns owner read.");
    await act(async () => { const pending = button("Save entry").props.onPress(); if (!pending || typeof pending.then !== "function") throw new Error("SetupError: ProgressSaveWitness actual save Promise unavailable"); save = pending; });
    await until("actual createEntry HTTP admitted", () => saveAdmitted);
    await finite("prior native operations drain", lane.then(() => undefined));
    armOwner = true;
    await act(async () => button("Patterns").props.onPress());
    await until("actual Insights owner read at FIFO head", () => olderOwnerHeld);
    const heldAt = events.find(event => event.event === "older-insights-owner-head-held")!.index;
    releaseSave();
    await until("acknowledged Save queued its later real native owner read", () => events.some(event => event.index > heldAt && event.event === "native-admitted" && event.operation === "getItem" && event.key === "@mindpattern/user_id"));
    await act(async () => button("Today").props.onPress());
    releaseOwner();
    await until("actual newer save-triggered HTTP refresh pending", () => freshInsightsAdmitted);
    await act(async () => { await finite("acknowledged actual Save handler completes", save!); });
    if (route !== "Entry" || localWriteScopeEpoch() !== scope || session.authStatus !== "loggedIn" || !vault.isUnlocked()) throw new Error("SetupError: ProgressSaveWitness route/account ownership producer changed before behavior stage");

    expect(session.activeDaysKnown).toBe(false);
    expect(text()).toContain("Checking your writing days…");
    expect(root!.root.findAllByType(TouchableOpacity).some(node => node.props.accessibilityLabel === "Refresh writing days")).toBe(false);
    releaseFresh();
    await until("actual authoritative progress publication", () => session.activeDaysKnown && !session.activeDaysLoading);
    expect(session.activeDays).toBe(7);
  } finally {
    releaseSave(); releaseOwner(); releaseFresh();
    if (save) await finite("owned Save cleanup", save).catch(() => undefined);
  }
}, 30000);
