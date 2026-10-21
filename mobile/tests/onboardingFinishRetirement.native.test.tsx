/** Installed React Navigation core/StackRouter, registered AppNavigator and
 * session controllers. Native stack rendering and frame insets are seams;
 * routing, route keys, navigation dispatch and controller lifetime are real.
 * Registration completion uses its public session/queue APIs, not a Login form.
 */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { createServer, type ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Text, TouchableOpacity } from "react-native";
import { BaseNavigationContainer } from "@react-navigation/core";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { SessionProvider, useSession } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { AppNavigator } from "../src/navigation";
import { queueOnboarding, takePendingOnboarding } from "../src/onboarding";
import { accountStorageKey } from "../src/accountStorage";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import { nativeGrantedPress } from "./helpers/nativePressability";
import { setLocale } from "../src/strings";
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
const ORIGINAL = "a".repeat(32), REPLACEMENT = "b".repeat(32);
const ORIGINAL_BEARER = "owned-original-onboarding-bearer", REPLACEMENT_BEARER = "owned-replacement-onboarding-bearer";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let session: ReturnType<typeof useSession> | undefined;
let server: ReturnType<typeof createServer> | undefined, origin = "";
let faults: unknown[] = [], releases: Array<() => void> = [];
let originalFetch: typeof fetch;
const setup = (message: string) => new Error(`SetupError: installed onboarding lifecycle: ${message}`);
function SessionConsumer() { session = useSession(); return null; }
function words() {
  return root?.root.findAllByType(Text).map(node => node.props.children).flat(Infinity)
    .filter(value => typeof value === "string" || typeof value === "number").join(" ") ?? "";
}
async function finite<T>(label: string, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(setup(`${label} did not settle`)), 15000);
  })]); } finally { if (timer !== undefined) clearTimeout(timer); }
}
async function flush() { await act(async () => { for (let i = 0; i < 100; i++) await Promise.resolve(); }); }
async function ready(label: string, test: () => boolean) {
  const deadline = Date.now() + 8000;
  while (!test()) {
    if (Date.now() >= deadline) throw setup(`${label} missing: ${words()}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
}
async function press(label: string) {
  const button = root?.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  if (!button || typeof button.props.onPress !== "function") throw setup(`registered public ${label} button missing`);
  const touch = nativeGrantedPress(button.props);
  try { await act(async () => { touch.release(); }); } finally { touch.dispose(); }
  await flush();
}
async function publish(owner: string, bearer: string) {
  await finite("public session publication", api.setSession(bearer, owner, owner === ORIGINAL ? "original-onboarding" : "replacement-onboarding"));
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, owner === ORIGINAL ? 3 : 4) }, owner);
}
function send(response: ServerResponse, value: unknown, status = 200) {
  response.writeHead(status, { "content-type": "application/json" }); response.end(JSON.stringify(value));
}
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); setLocale("en"); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); takePendingOnboarding(); faults = []; releases = []; session = undefined; originalFetch = globalThis.fetch;
  server = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "", origin);
      const bearer = request.headers.authorization;
      if (bearer !== `Bearer ${ORIGINAL_BEARER}` && bearer !== `Bearer ${REPLACEMENT_BEARER}`) throw setup("unexpected native bearer");
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
  await publish(ORIGINAL, ORIGINAL_BEARER); queueOnboarding();
});
afterEach(async () => {
  for (const release of releases) release(); await flush();
  if (root) await act(async () => { root!.unmount(); root = undefined; });
  vault.lock(); await finite("public session cleanup", api.clearSession());
  server?.closeAllConnections();
  if (server?.listening) await finite("native HTTP close", new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())));
  server = undefined; session = undefined; vi.restoreAllMocks(); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); takePendingOnboarding(); setLocale("en");
  if (faults.length) throw setup(`native HTTP fault: ${String(faults[0])}`);
  if (globalThis.fetch !== originalFetch) throw setup("native fetch identity changed");
});

describe("Installed onboarding completion ownership", () => {
  it.each(["live route", "retired replacement route"] as const)("keeps the physical final owner receipt bound to its %s", async mode => {
    await act(async () => { root = ReactTestRenderer.create(<BaseNavigationContainer><ThemeProvider><SessionProvider><SessionConsumer /><AppNavigator /></SessionProvider></ThemeProvider></BaseNavigationContainer>); });
    await ready("registered original first panel", () => words().includes("Write each day"));
    await ready("settled original public progress", () => session?.activeDaysKnown === true && session.activeDaysLoading === false);
    await finite("original native metadata completion", api.meta()); await flush();
    await press("Continue to panel 2 of 3"); await press("Continue to panel 3 of 3");
    const read = storage.getItem; let armed = true, entered!: () => void, release!: () => void, settled!: () => void;
    let captured: string | null = null;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    const released = new Promise<void>(resolve => { settled = resolve; }); releases.push(release);
    vi.spyOn(storage, "getItem").mockImplementation(async slot => {
      const value = await read(slot);
      if (armed && slot === "@mindpattern/user_id") {
        armed = false; captured = value;
        if (!value || JSON.parse(value).v !== 1 || typeof JSON.parse(value).c !== "string") throw setup("held owner ciphertext absent");
        entered(); await held; settled();
      }
      return value;
    });
    await press("I understand — start writing"); await finite("physical final credential entry", started);
    expect(captured).not.toContain(ORIGINAL);
    if (mode === "retired replacement route") {
      await act(async () => { vault.lock(); });
      await ready("registered locked route", () => words().includes("Locked"));
      if (!session) throw setup("registered session consumer missing");
      await act(async () => { await finite("public original session sign-out", session!.signOut()); });
      await ready("registered signed-out route", () => words().includes("Sign in"));
      await act(async () => { await publish(REPLACEMENT, REPLACEMENT_BEARER); queueOnboarding(); session!.markLoggedIn(); });
      await ready("registered replacement first panel", () => words().includes("Write each day") && words().includes("1 of 3"));
      expect(await storage.getItem(accountStorageKey.onboardingSeen(REPLACEMENT))).toBeNull();
    }
    release(); await finite("original encrypted owner release", released);
    await flush(); await new Promise<void>(resolve => setImmediate(resolve)); await flush();
    if (mode === "live route") {
      await ready("registered ordinary journal after live completion", () => words().includes("Save entry"));
      expect(await storage.getItem(accountStorageKey.onboardingSeen(ORIGINAL))).toBe("1");
    } else {
      expect(words(), "a retired final completion must preserve the replacement account's required onboarding").toContain("Write each day");
      expect(words()).toContain("1 of 3");
      expect(words()).not.toContain("Save entry");
      expect(await storage.getItem(accountStorageKey.onboardingSeen(REPLACEMENT))).toBeNull();
      await press("Continue to panel 2 of 3"); await press("Continue to panel 3 of 3"); await press("I understand — start writing");
      await ready("replacement's own admitted completion", () => words().includes("Save entry"));
      expect(await storage.getItem(accountStorageKey.onboardingSeen(REPLACEMENT))).toBe("1");
    }
    expect(await api.getUserId()).toBe(mode === "live route" ? ORIGINAL : REPLACEMENT);
  });
});
