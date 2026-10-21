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
import { Alert, Text, TextInput, TouchableOpacity, View } from "react-native";
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
import { installedNativeAlert } from "./helpers/nativeAlert";
import { emptySafetyPlan, saveSafetyPlanDraft } from "../src/safetyPlan";
import { localWriteScopeEpoch } from "../src/localWriteGuard";
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
const LATER = "A later edit remains independently recoverable";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let windowRoot: ReturnType<typeof ReactTestRenderer.create> | undefined;
let nativeWindow: ReturnType<typeof installedNativeAlert> | undefined;
let alertDeliveries = 0;
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
async function bootSession() {
  vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); setLocale("en"); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); takePendingOnboarding(); faults = []; releases = []; ownedPromises = []; session = undefined; alertDeliveries = 0; originalFetch = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation((...args) => retain(Reflect.apply(originalFetch, globalThis, args) as ReturnType<typeof fetch>));
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
  nativeWindow = installedNativeAlert();
  vi.spyOn(Alert, "alert").mockImplementation((...args) => { alertDeliveries++; Reflect.apply(nativeWindow!.alert, nativeWindow, args); });
}
async function closeSession() {
  for (const release of releases) release(); await drain();
  if (root) await act(async () => { root!.unmount(); root = undefined; });
  await drain();
  if (windowRoot) await act(async () => { windowRoot!.unmount(); windowRoot = undefined; });
  vi.unstubAllGlobals(); vault.lock(); await finite("public session cleanup", api.clearSession());
  server?.closeAllConnections();
  if (server?.listening) await finite("native HTTP close", new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())));
  server = undefined; session = undefined; vi.restoreAllMocks(); vi.unstubAllGlobals(); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); takePendingOnboarding(); setLocale("en");
  if (faults.length) throw setup(`retained native fault: ${String(faults[0])}`);
  if (globalThis.fetch !== originalFetch) throw setup("native fetch identity changed");
  nativeWindow = undefined;
}
beforeEach(bootSession);
afterEach(closeSession);

type Case = "identity read" | "save ACK refusal" | "discard refusal" | "successful discard";
const CASES = ["identity read", "save ACK refusal", "discard refusal", "successful discard"] as const;
function editor() {
  return root?.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === tr("safetyplan.field.warningSigns"));
}
async function refreshWindow() {
  const Window = nativeWindow!.Window; await act(async () => {
    if (windowRoot) windowRoot.update(<Window />);
    else windowRoot = ReactTestRenderer.create(<Window />);
  });
}
function windowWords() {
  return windowRoot?.root.findAllByType(Text).map(node => node.props.children).flat(Infinity).join(" ") ?? "";
}
function hasNativeWindow() {
  return (windowRoot?.root.findAllByType(View).filter(node => node.props.accessibilityRole === "alert").length ?? 0) > 0;
}
async function chooseDiscard() {
  await refreshWindow();
  expect(windowWords()).toContain(tr("safetyplan.discardTitle"));
  const button = windowRoot?.root.findAllByType(TouchableOpacity)
    .find(node => node.props.accessibilityLabel === tr("safetyplan.discardConfirm"));
  if (!button) throw setup("installed native destructive Alert button missing");
  const touch = nativeGrantedPress(button.props);
  try { await act(async () => { touch.release(); }); } finally { touch.dispose(); }
  await flush(); await refreshWindow();
}
function authenticate(raw: string | null, purpose: "safety-plan" | "safety-plan-draft") {
  if (!raw || raw.includes(NOTE)) throw setup("actual encrypted owned record absent or plaintext");
  const blob = Buffer.from(raw, "base64"), oracle = createDecipheriv("aes-256-gcm", KEY, blob.subarray(0, 12));
  oracle.setAAD(buildAad(purpose, OWNER)); oracle.setAuthTag(blob.subarray(blob.length - 16));
  const plain = Buffer.concat([oracle.update(blob.subarray(12, blob.length - 16)), oracle.final()]);
  try { return JSON.parse(plain.toString("utf8")).warningSigns as string; } finally { plain.fill(0); }
}
async function openEditor(kind: Case) {
  if (kind.startsWith("discard") || kind === "successful discard") {
    await finite("genuine seeded encrypted draft", saveSafetyPlanDraft(KEY, OWNER, { ...emptySafetyPlan(), warningSigns: "Prior recoverable note" }));
  }
  await act(async () => { root = ReactTestRenderer.create(<BaseNavigationContainer><ThemeProvider><SessionProvider><SessionConsumer /><AppNavigator /></SessionProvider></ThemeProvider></BaseNavigationContainer>); });
  await ready("registered ordinary journal", () => words().includes("Save entry"));
  await ready("settled original public progress", () => session?.activeDaysKnown === true && session.activeDaysLoading === false);
  await finite("original native metadata completion", api.meta()); await drain();
  await press(tr("nav.getHelpA11y"));
  await ready("registered static crisis resources", () => words().includes(tr("common.makeSafetyPlan")));
  await press(tr("crisis.makePlanA11y"));
  await ready("registered decrypted plan editor", () => editor() !== undefined); await drain();
  // As in the accepted timer proof, only the production300/2600 timers use
  // installed JSTimers. Every other timer retains real Node host transport.
  const device = installedNativeTiming(), deviceHandles = new Set<ReturnType<typeof setTimeout>>();
  vi.stubGlobal("setTimeout", (handler: (...args: any[]) => void, delay = 0, ...args: any[]) => {
    if (delay === 300 || delay === 2600) {
      const handle = device.setTimeout(handler, delay, ...args); deviceHandles.add(handle); return handle;
    }
    return Reflect.apply(hostSetTimeout, globalThis, [handler, delay, ...args]) as ReturnType<typeof hostSetTimeout>;
  });
  vi.stubGlobal("clearTimeout", (handle: ReturnType<typeof setTimeout>) => {
    if (deviceHandles.delete(handle)) device.clearTimeout(handle); else hostClearTimeout.call(globalThis, handle);
  });
  return device;
}
async function retireEditor() {
  await act(async () => { vault.lock(); });
  await ready("registered retained Crisis with locked vault", () => words().includes(tr("crisis.title"))
    && editor() === undefined && !vault.isUnlocked() && vault.ownerUserId() === null);
}

describe("Installed safety-plan late publication and discard ownership", () => {
  it.each(CASES)("owns %s across a public route retirement", async kind => {
    for (const identityReceipt of kind === "identity read" ? ["present", "missing"] as const : ["present"] as const) {
    for (const mode of ["live", "retired"] as const) {
      if (mode === "retired" || identityReceipt === "missing") { await closeSession(); await bootSession(); }
      const device = await openEditor(kind), beforeEpoch = localWriteScopeEpoch();
      const savedSlot = accountStorageKey.safetyPlan(OWNER), draftSlot = accountStorageKey.safetyPlanDraft(OWNER);
      const nativeRead = storage.getItem, nativeWrite = storage.setItem, nativeRemove = storage.removeItem;
      let admitted = 0, forwarded = 0, captures: Array<string | null> = [], removals = 0;
      let entered!: () => void, release!: () => void;
      const started = new Promise<void>(resolve => { entered = resolve; });
      const gate = new Promise<void>(resolve => { release = resolve; }); releases.push(release);
      const events: string[] = [];
      if (kind === "identity read") {
        vi.spyOn(storage, "getItem").mockImplementation(slot => retain((async () => {
          const actual = retain(nativeRead.call(storage, slot)), raw = await actual;
          if (slot === "@mindpattern/user_id" && admitted === 0) {
            admitted++; captures.push(raw);
            if (identityReceipt === "missing") {
              if (raw !== null) throw setup("actual removed native identity receipt was not absent");
            } else if (!raw || raw.includes(OWNER) || !raw.startsWith("{")) throw setup("owned device-key encrypted identity read differs");
            events.push("native encrypted identity result held"); entered(); await gate;
            forwarded++; events.push("same native encrypted identity result released");
          }
          return raw;
        })()));
      } else if (kind === "save ACK refusal" || kind === "discard refusal") {
        const target = kind === "save ACK refusal" ? savedSlot : draftSlot;
        vi.spyOn(storage, "setItem").mockImplementation((slot, value) => retain((async () => {
          if (slot === target) {
            admitted++; captures.push(value);
            if (admitted !== 1 || value.includes(NOTE)) throw setup("owned encrypted physical write admission differs");
            events.push("native encrypted write held before forwarding"); entered(); await gate;
          }
          await retain(nativeWrite.call(storage, slot, value));
          if (slot === target) { forwarded++; events.push("same native encrypted write forwarded"); }
        })()));
      } else {
        vi.spyOn(storage, "removeItem").mockImplementation(slot => retain((async () => {
          if (slot === draftSlot) {
            admitted++; captures.push(await retain(nativeRead.call(storage, slot)));
            if (admitted !== 1) throw setup("owned draft deletion admission differs");
            events.push("native draft delete held before forwarding"); entered(); await gate;
          }
          await retain(nativeRemove.call(storage, slot));
          if (slot === draftSlot) { forwarded++; events.push("same native draft delete forwarded"); }
        })()));
      }
      if (kind !== "successful discard") {
        vi.spyOn(storage, "removeItem").mockImplementation(slot => {
          if (slot === draftSlot) removals++;
          return retain(nativeRemove.call(storage, slot));
        });
      }
      if (identityReceipt === "missing") {
        // Model an externally missing physical credential receipt. The original
        // native backend removes its real encrypted bytes; no API return value,
        // vault owner, scope generation or getUserId Promise is fabricated.
        await finite("actual native user-id receipt removal", retain(nativeRemove.call(storage, "@mindpattern/user_id")));
        if (localWriteScopeEpoch() !== beforeEpoch || vault.ownerUserId() !== OWNER) throw setup("external receipt loss unexpectedly changed the live owner scope");
      }
      await act(async () => { editor()!.props.onChangeText(NOTE); });
      if (kind === "identity read" || kind === "save ACK refusal") {
        await press(tr("safetyplan.save")); await finite("owned public save admission", started);
      } else {
        await act(async () => { device.advance(1000); });
        if (kind === "successful discard") {
          await drain(); expect(authenticate(await nativeRead.call(storage, draftSlot), "safety-plan-draft")).toBe(NOTE);
        } else await finite("owned pending encrypted draft admission", started);
        await press(tr("common.back")); await chooseDiscard();
        if (kind === "successful discard") await finite("owned public discard deletion admission", started);
        else expect(removals).toBe(0);
      }
      if (mode === "retired") { await retireEditor(); events.push("registered editor retired before native completion"); }
      if (kind === "save ACK refusal" || kind === "discard refusal") {
        // Exported actual credential retirement is also the store's final
        // sign-out operation. It changes scope synchronously, then awaits
        // actual admitted commits. Never await it before releasing the gate.
        retain(api.clearSession());
        expect(localWriteScopeEpoch()).toBeGreaterThan(beforeEpoch); events.push("public credential retirement invalidated pending permit");
        expect(await nativeRead.call(storage, "@mindpattern/user_id")).not.toBeNull();
      } else expect(localWriteScopeEpoch()).toBe(beforeEpoch);
      if (kind === "identity read" && identityReceipt === "present" && mode === "live") await act(async () => { editor()!.props.onChangeText(LATER); });
      release(); await drain(); await refreshWindow();
      expect(admitted).toBe(1); expect(forwarded).toBe(1); expect(captures).toHaveLength(1);
      const saved = await nativeRead.call(storage, savedSlot), draft = await nativeRead.call(storage, draftSlot);
      const physical = kind === "successful discard" ? "delete" : kind === "identity read" ? "identity" : "write";
      let authenticated = false;
      if (kind === "identity read" && identityReceipt === "missing") {
        expect(await api.getUserId()).toBeNull(); expect(saved).toBeNull(); expect(captures).toEqual([null]);
        if (mode === "live") {
          expect(windowWords()).toContain(tr("common.sessionDamagedTitle"));
          expect(hasNativeWindow(), "The still-current save explains a genuinely missing native account receipt").toBe(true);
          expect(alertDeliveries).toBe(1); expect(editor()?.props.value).toBe(NOTE);
        }
        authenticated = true;
      } else if (kind === "identity read") {
        expect(await api.getUserId()).toBe(OWNER);
        if (mode === "live") {
          expect(authenticate(saved, "safety-plan")).toBe(NOTE); expect(authenticate(draft, "safety-plan-draft")).toBe(LATER);
          expect(editor()?.props.value).toBe(LATER);
          expect(words()).toContain(tr("safetyplan.saved")); expect(hasNativeWindow()).toBe(false);
        } else { expect(saved).toBeNull(); expect(authenticate(draft, "safety-plan-draft")).toBe(NOTE); }
        authenticated = true;
      } else if (kind === "save ACK refusal") {
        expect(await api.getUserId()).toBeNull(); expect(authenticate(saved, "safety-plan")).toBe(NOTE);
        expect(removals).toBe(0); authenticated = true;
      } else if (kind === "discard refusal") {
        expect(await api.getUserId()).toBeNull(); expect(saved).toBeNull();
        expect(authenticate(draft, "safety-plan-draft")).toBe(NOTE); expect(removals).toBe(0); authenticated = true;
      } else {
        expect(await api.getUserId()).toBe(OWNER); expect(saved).toBeNull();
        expect(authenticate(captures[0]!, "safety-plan-draft")).toBe(NOTE); authenticated = true;
        if (draft !== null) expect(authenticate(draft, "safety-plan-draft")).toBe(NOTE);
        if (mode === "live") { expect(draft).toBeNull(); expect(words()).toContain(tr("crisis.title")); }
      }
      if (mode === "live" && (kind === "save ACK refusal" || kind === "discard refusal")) {
        expect(windowWords()).toContain(tr("safetyplan.saveFailedTitle")); expect(editor()?.props.value).toBe(NOTE);
      }
      if (mode === "retired") {
        expect(words()).toContain(tr("crisis.title")); expect(editor()).toBeUndefined();
        expect(vault.isUnlocked()).toBe(false); expect(vault.ownerUserId()).toBeNull();
      }
      const leaked = mode === "retired" && (hasNativeWindow() || (kind === "successful discard" && draft !== null));
      console.info("SAFETY_PLAN_RETIRED_PUBLICATION_CUSTODY", JSON.stringify({ kind, identityReceipt, mode, admitted, forwarded, events,
        physical, authenticated, epochChanged: localWriteScopeEpoch() !== beforeEpoch, nativeAlert: hasNativeWindow(),
        alertDeliveries, discardedDraftPresent: kind === "successful discard" && draft !== null, leaked }));
      expect(leaked, "retired safety-plan completion cannot publish an alert or recreate its acknowledged discarded draft").toBe(false);
    }
    }
    if (kind === "successful discard") {
      await closeSession(); await bootSession();
      const device = await openEditor("successful discard");
      const draftSlot = accountStorageKey.safetyPlanDraft(OWNER);
      const nativeRead = storage.getItem, nativeRemove = storage.removeItem;
      let firstEntered!: () => void, secondEntered!: () => void;
      let releaseFirst!: () => void, releaseSecond!: () => void;
      const firstStarted = new Promise<void>(resolve => { firstEntered = resolve; });
      const secondStarted = new Promise<void>(resolve => { secondEntered = resolve; });
      const firstGate = new Promise<void>(resolve => { releaseFirst = resolve; });
      const secondGate = new Promise<void>(resolve => { releaseSecond = resolve; });
      releases.push(releaseFirst, releaseSecond);
      let firstRemoval = true;
      vi.spyOn(storage, "removeItem").mockImplementation(slot => retain((async () => {
        if (slot === draftSlot) {
          const isFirst = firstRemoval; firstRemoval = false;
          if (isFirst) { firstEntered(); await firstGate; }
          else { secondEntered(); await secondGate; }
        }
        await retain(nativeRemove.call(storage, slot));
      })()));
      try {
        await act(async () => { editor()!.props.onChangeText(NOTE); device.advance(1000); });
        await drain();
        expect(authenticate(await nativeRead.call(storage, draftSlot), "safety-plan-draft")).toBe(NOTE);
        await press(tr("common.back")); await chooseDiscard();
        await finite("first current destructive choice entered native draft deletion", firstStarted);
        expect(editor()?.props.value).toBe(NOTE);
        await press(tr("common.back")); await chooseDiscard();
        releaseFirst();
        await finite("second admitted destructive choice entered native draft deletion", secondStarted);
        await ready("first acknowledged discard returned to current Crisis resources", () =>
          words().includes(tr("crisis.title")) && editor() === undefined);
        expect(words()).toContain(tr("common.makeSafetyPlan"));
        releaseSecond(); await drain(); await refreshWindow();
        expect(await nativeRead.call(storage, draftSlot)).toBeNull();
        expect(words(), "A second admitted discard cannot leave the current Crisis resources after its editor retires").toContain(tr("crisis.title"));
        expect(editor()).toBeUndefined(); expect(hasNativeWindow()).toBe(false);
      } finally {
        releaseFirst(); releaseSecond();
        await drain();
      }
    }
  });
});
