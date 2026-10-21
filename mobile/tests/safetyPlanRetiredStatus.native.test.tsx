/** Registered AppNavigator and installed React Navigation route ownership.
 * AsyncStorage, native stack frames/insets and Native Timing device transport
 * are seams; ciphertext production, physical forwarding, controller lifetime,
 * SafetyPlan 300ms draft/2600ms status JSTimers allocation/cancellation and
 * Pressability release are installed code. Other timers retain Node host transport.
 */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { createServer, type ServerResponse } from "node:http";
import { createDecipheriv } from "node:crypto";
import { setTimeout as hostSetTimeout, clearTimeout as hostClearTimeout } from "node:timers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Text, TextInput, TouchableOpacity } from "react-native";
import { BaseNavigationContainer } from "@react-navigation/core";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { SessionProvider, useSession } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { AppNavigator } from "../src/navigation";
import { recordOnboardingSeen, takePendingOnboarding } from "../src/onboarding";
import { accountStorageKey } from "../src/accountStorage";
import { buildAad } from "../src/crypto/aad";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests, waitLocalWriteCommits } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import { nativeGrantedPress } from "./helpers/nativePressability";
import { installedNativeTiming } from "./helpers/nativeTiming";
import { setLocale, t as tr } from "../src/strings";
import * as keychain from "./helpers/keychainMock";
import storage from "./helpers/storageMock";

vi.mock("@react-navigation/native-stack", async () => {
  const { createNavigatorFactory, useNavigationBuilder } = await import("@react-navigation/core");
  const { StackRouter } = await import("@react-navigation/routers");
  function NativeDescriptorStack({ children }: { children: React.ReactNode }) {
    const { state, descriptors, NavigationContent } = useNavigationBuilder(StackRouter, { children });
    const route = state.routes[state.index];
    if (!route || !descriptors[route.key]) throw new Error("SetupError: registered native route descriptor missing");
    return <NavigationContent>{descriptors[route.key]!.render()}</NavigationContent>;
  }
  return { createNativeStackNavigator: createNavigatorFactory(NativeDescriptorStack) };
});
vi.mock("react-native-safe-area-context", () => ({
  SafeAreaProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useSafeAreaInsets: () => ({ top: 0, right: 0, bottom: 0, left: 0 }),
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const OWNER = "a".repeat(32), BEARER = "owned-safety-plan-status-bearer";
const KEY = Buffer.alloc(32, 3), NOTE = "A private note from this installed safety-plan editor";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let session: ReturnType<typeof useSession> | undefined;
let server: ReturnType<typeof createServer> | undefined, origin = "";
let faults: unknown[] = [], releases: Array<() => void> = [];
let ownedPromises: Promise<unknown>[] = [];
let originalFetch: typeof fetch;
const setup = (message: string) => new Error(`SetupError: installed safety-plan status lifecycle: ${message}`);
function SessionConsumer() { session = useSession(); return null; }
function words() {
  return root?.root.findAllByType(Text).map(node => node.props.children).flat(Infinity)
    .filter(value => typeof value === "string" || typeof value === "number").join(" ") ?? "";
}
async function finite<T>(label: string, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof hostSetTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => {
    timer = hostSetTimeout(() => reject(setup(`${label} did not settle`)), 15000);
  })]); } finally { if (timer !== undefined) hostClearTimeout(timer); }
}
async function flush() { await act(async () => { for (let i = 0; i < 100; i++) await Promise.resolve(); }); }
async function ready(label: string, test: () => boolean) {
  const deadline = Date.now() + 8000;
  while (!test()) {
    if (Date.now() >= deadline) throw setup(`${label} missing: ${words()}`);
    await act(async () => { await new Promise<void>(resolve => hostSetTimeout(resolve, 5)); });
  }
}
async function press(label: string) {
  const button = root?.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  if (!button || typeof button.props.onPress !== "function") throw setup(`registered public ${label} button missing`);
  const touch = nativeGrantedPress(button.props);
  try { await act(async () => { touch.release(); }); } finally { touch.dispose(); }
  await flush();
}
function retain<T>(promise: Promise<T>): Promise<T> {
  ownedPromises.push(promise);
  void promise.catch(error => { faults.push(error); });
  return promise;
}
async function drain() {
  let stable = 0;
  while (stable < 2) {
    const version = ownedPromises.length;
    await finite("owned physical writes", Promise.allSettled(ownedPromises));
    await finite("public native commit drain", waitLocalWriteCommits());
    await flush(); await new Promise<void>(resolve => setImmediate(resolve)); await flush();
    stable = ownedPromises.length === version ? stable + 1 : 0;
  }
}
function send(response: ServerResponse, value: unknown, status = 200) {
  response.writeHead(status, { "content-type": "application/json" }); response.end(JSON.stringify(value));
}
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); setLocale("en"); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); takePendingOnboarding(); faults = []; releases = []; ownedPromises = []; session = undefined; originalFetch = globalThis.fetch;
  server = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "", origin);
      if (request.headers.authorization !== `Bearer ${BEARER}`) throw setup("unexpected native bearer");
      if (request.method === "POST" && url.pathname === "/api/v1/auth/logout") { send(response, {}); return; }
      if (request.method !== "GET") throw setup("unexpected native method");
      if (url.pathname === "/api/v1/progress") { send(response, { active_days: 0 }); return; }
      if (url.pathname === "/api/v1/meta") { send(response, { unlock_days: 30, llm_available: false, sharing_available: false, audio_available: false }); return; }
      if (url.pathname === "/api/v1/entries" || url.pathname === "/api/v1/measures" || url.pathname === "/api/v1/consents") { send(response, []); return; }
      if (url.pathname === "/api/v1/insights") { send(response, { phase: "baseline", active_days: 0, days_remaining: 30 }); return; }
      if (url.pathname === "/api/v1/account/llm-consent" || url.pathname === "/api/v1/account/voice-consent") { send(response, { enabled: false, active_for_current_policy: true }); return; }
      if (url.pathname === "/api/v1/auth/key-envelope") { send(response, { key_scheme: "v1", salt: Buffer.alloc(16, 5).toString("base64"), kdf_params: null, wrapped_data_key: null }); return; }
      if (url.pathname.startsWith("/api/v1/questions/")) { send(response, { detail: "question not available" }, 404); return; }
      throw setup(`unexpected native route ${url.pathname}`);
    } catch (error) { faults.push(error); send(response, { detail: "Owned native fixture fault" }, 500); }
  });
  await finite("native HTTP listen", new Promise<void>((resolve, reject) => {
    server!.once("error", reject); server!.listen(0, "127.0.0.1", () => { server!.removeListener("error", reject); resolve(); });
  }));
  const address = server.address(); if (!address || typeof address === "string") throw setup("native HTTP address missing");
  origin = `http://127.0.0.1:${address.port}`;
  if (await setBaseUrl(origin) !== null) throw setup("owned loopback origin was refused");
  await finite("public session publication", api.setSession(BEARER, OWNER, "original-safety-plan"));
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(KEY) }, OWNER);
  await finite("ordinary completed onboarding", recordOnboardingSeen(OWNER));
});
afterEach(async () => {
  for (const release of releases) release(); await drain();
  if (root) await act(async () => { root!.unmount(); root = undefined; });
  await drain(); vi.unstubAllGlobals(); vault.lock(); await finite("public session cleanup", api.clearSession());
  server?.closeAllConnections();
  if (server?.listening) await finite("native HTTP close", new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())));
  server = undefined; session = undefined; vi.restoreAllMocks(); vi.unstubAllGlobals(); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); takePendingOnboarding(); setLocale("en");
  if (faults.length) throw setup(`retained native fault: ${String(faults[0])}`);
  if (globalThis.fetch !== originalFetch) throw setup("native fetch identity changed");
});

describe("Installed safety-plan status ownership", () => {
  it.each(["live route", "retired locked route"] as const)("binds a physically pending save status to its %s", async mode => {
    const device = installedNativeTiming();
    await act(async () => { root = ReactTestRenderer.create(<BaseNavigationContainer><ThemeProvider><SessionProvider><SessionConsumer /><AppNavigator /></SessionProvider></ThemeProvider></BaseNavigationContainer>); });
    await ready("registered ordinary journal", () => words().includes("Save entry"));
    await ready("settled original public progress", () => session?.activeDaysKnown === true && session.activeDaysLoading === false);
    await finite("original native metadata completion", api.meta()); await flush();
    await press(tr("nav.getHelpA11y"));
    await ready("registered static crisis resources", () => words().includes(tr("common.makeSafetyPlan")));
    await press(tr("crisis.makePlanA11y"));
    const field = () => root?.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === tr("safetyplan.field.warningSigns"));
    await ready("registered decrypted plan editor", () => field() !== undefined);
    // Exact current production delays: SafetyPlan draft debounce300/status2600.
    // Genuine Node HTTP/Undici and all other timers keep native host handles.
    const deviceHandles = new Set<ReturnType<typeof setTimeout>>();
    vi.stubGlobal("setTimeout", (handler: (...args: any[]) => void, delay = 0, ...args: any[]) => {
      if (delay === 300 || delay === 2600) {
        const handle = device.setTimeout(handler, delay, ...args); deviceHandles.add(handle); return handle;
      }
      return Reflect.apply(hostSetTimeout, globalThis, [handler, delay, ...args]) as ReturnType<typeof hostSetTimeout>;
    });
    vi.stubGlobal("clearTimeout", (handle: ReturnType<typeof setTimeout>) => {
      if (deviceHandles.delete(handle)) device.clearTimeout(handle);
      else hostClearTimeout.call(globalThis, handle);
    });
    for (const delay of [undefined, 17]) {
      let delivered!: () => void;
      const delivery = new Promise<void>(resolve => { delivered = resolve; });
      const handle = delay === undefined ? setTimeout(delivered) : setTimeout(delivered, delay);
      expect(typeof handle).toBe("object");
      expect(typeof (handle as { unref?: unknown }).unref).toBe("function");
      await finite("native forwarded default/unknown host timer", delivery); clearTimeout(handle);
    }
    await act(async () => { field()!.props.onChangeText(NOTE); });
    expect(device.hasActiveTimersInRange(400)).toBe(true);
    const savedSlot = accountStorageKey.safetyPlan(OWNER), draftSlot = accountStorageKey.safetyPlanDraft(OWNER);
    const write = storage.setItem; let admitted = 0, ciphertext: string | null = null;
    let entered!: () => void, release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; }); releases.push(release);
    const events: string[] = [];
    vi.spyOn(storage, "setItem").mockImplementation((slot, value) => retain((async () => {
      if (slot === savedSlot) {
        admitted++; if (admitted !== 1 || typeof value !== "string" || value.includes(NOTE)) throw setup("owned saved ciphertext admission differs");
        ciphertext = value; events.push("physical saved ciphertext held before forwarding"); entered(); await gate;
      }
      const native = retain(write.call(storage, slot, value)); await native;
      if (slot === savedSlot) events.push("physical saved ciphertext forwarded");
    })()));
    await press(tr("safetyplan.save")); await finite("physical encrypted save admission", started);
    expect(await storage.getItem(savedSlot)).toBeNull();
    if (mode === "retired locked route") {
      await act(async () => { vault.lock(); });
      await ready("registered Crisis replacement with locked vault", () => words().includes(tr("crisis.title")) && field() === undefined && !vault.isUnlocked() && vault.ownerUserId() === null);
      events.push("registered plan route retired before save completion");
      expect(device.hasActiveTimersInRange(2601)).toBe(false);
    }
    release(); await drain();
    expect(admitted).toBe(1); expect(await storage.getItem(savedSlot)).toBe(ciphertext);
    if (!ciphertext) throw setup("forwarded owned saved ciphertext absent");
    const blob = Buffer.from(ciphertext, "base64"), oracle = createDecipheriv("aes-256-gcm", KEY, blob.subarray(0, 12));
    oracle.setAAD(buildAad("safety-plan", OWNER)); oracle.setAuthTag(blob.subarray(blob.length - 16));
    const plaintext = Buffer.concat([oracle.update(blob.subarray(12, blob.length - 16)), oracle.final()]);
    try { expect(JSON.parse(plaintext.toString("utf8")).warningSigns).toBe(NOTE); } finally { plaintext.fill(0); }
    expect(await storage.getItem(draftSlot)).toBeNull();
    if (mode === "live route") {
      expect(words()).toContain(tr("safetyplan.saved")); expect(device.hasActiveTimersInRange(2601)).toBe(true);
      await act(async () => { root!.unmount(); root = undefined; }); await drain();
      expect(device.hasActiveTimersInRange(2601)).toBe(false);
    } else {
      expect(words()).toContain(tr("crisis.title")); expect(field()).toBeUndefined(); expect(vault.isUnlocked()).toBe(false); expect(vault.ownerUserId()).toBeNull();
    }
    const leaked = device.hasActiveTimersInRange(2601);
    console.info("SAFETY_PLAN_RETIRED_STATUS_CUSTODY", JSON.stringify({ mode, admitted, events, plaintextAuthenticated: true, savedForwarded: true, draftAcknowledged: true, leaked }));
    expect(leaked, "retired safety-plan completion cannot allocate a native status timer").toBe(false);
  });
});
