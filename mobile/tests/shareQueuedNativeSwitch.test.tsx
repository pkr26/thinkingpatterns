/** Actual installed Switch JS + actual public sharing route; lowest host/event
 * transport only is substituted. No private sharing callback/state is invoked.
 */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";


import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("react-native", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-native")>();
  const installed = await import("./helpers/installedNativeSwitch");
  return { ...actual, Switch: installed.installedNativeSwitch() };
});

import { Alert, Text, TextInput, TouchableOpacity } from "react-native";
import { TherapistShareScreen } from "../src/screens/TherapistShareScreen";
import { LoginScreen } from "../src/screens/LoginScreen";
import { api, ApiError, SHARING_DISCLOSURE_VERSION } from "../src/api/client";
import { SessionProvider, useSession } from "../src/store";
import { vault } from "../src/vault";
import { admitQueuedSwitchPayload, SWITCH_NATIVE_HOST } from "./helpers/installedNativeSwitch";
import { nativeGrantedPress } from "./helpers/nativePressability";
import storage from "./helpers/storageMock";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const OWNER = "c".repeat(32), THERAPIST = "d".repeat(32), CONSENT = "a".repeat(32);
const USERNAME = "synthetic-sharing-patient", PASSWORD = "A genuine native sharing passphrase!", TOKEN = "synthetic-current-sharing-owner", SALT = Buffer.alloc(16, 5);
let root: ReactTestRenderer.ReactTestRenderer | undefined;
let releaseLookup: (() => void) | undefined, lookupEntered = false;
let originalLookup: Promise<unknown> | undefined;
type PublicDialog = { title: string | null | undefined; body?: string | null; choices?: Array<{ text?: string }> };
let visibleDialog: PublicDialog | null = null;


function response(url: string, value: unknown, status = 200) {
  const result = new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
  Object.defineProperty(result, "url", { value: url }); return result;
}
async function finite<T>(name: string, pending: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([pending, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("ExecutionError: sharing public producer deadline: " + name)), 15_000); })]); }
  finally { if (timer) clearTimeout(timer); }
}
async function flush() { await act(async () => { for (let turn = 0; turn < 80; turn++) await Promise.resolve(); }); }
function text() { return root!.root.findAllByType(Text).map(node => React.Children.toArray(node.props.children).filter(value => typeof value === "string").join(" ")).join(" "); }
function currentDialog(): PublicDialog | null { return visibleDialog; }
function PublicAuthenticatedRoute() {
  const session = useSession();
  return session.authStatus === "loggedIn" && session.unlocked
    ? <TherapistShareScreen navigation={{ navigate: () => {}, goBack: () => {} }} />
    : session.authStatus === "loggedOut" ? <LoginScreen navigation={{ navigate: () => {} }} /> : <Text>Waiting for the actual authenticated route</Text>;
}


beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); vault.lock(); await api.clearSession(); visibleDialog = null; releaseLookup = undefined; lookupEntered = false; originalLookup = undefined;
  const master = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const data = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/data/v1", 32)); master.fill(0);
  vi.spyOn(Alert, "alert").mockImplementation((title, body, choices) => { visibleDialog = { title, body, choices }; });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (String(init.body ?? "").includes(PASSWORD)) throw new Error("SetupError: plaintext public Login password reached transport");
    if (path.endsWith("/auth/salt")) return response(url, { salt: SALT.toString("base64") });
    if (path.endsWith("/auth/key-envelope")) return response(url, { detail: "legacy key envelope not found", code: "not_found" }, 404);
    if (path.endsWith("/auth/login")) {
      if (body.username !== USERNAME || body.verifier !== auth.toString("base64")) throw new Error("SetupError: actual public Login verifier differs from independent600k account");
      return response(url, { token: TOKEN, user_id: OWNER });
    }
    if (new Headers(init.headers).get("Authorization") !== "Bearer " + TOKEN && !path.endsWith("/meta")) throw new Error("SetupError: sharing transport lacks actual adopted public Login bearer");
    if (path.endsWith("/meta")) return response(url, { sharing_available: true, sharing_disclosure_version: SHARING_DISCLOSURE_VERSION, unlock_days: 30 });
    if (path.endsWith("/insights")) return response(url, { phase: "baseline", active_days: 0, days_remaining: 30 });
    if (path.endsWith("/consents") && (init.method ?? "GET") === "GET") return response(url, [{ id: CONSENT, therapist_id: THERAPIST, display_name: "Dr. queued native", username: "synthetic-therapist", status: "active", granted_at: "2026-09-01T10:00:00Z", revoked_at: null, share_voice: false }]);
    if (path.endsWith("/pairing/lookup")) { lookupEntered = true; await new Promise<void>(resolve => { releaseLookup = resolve; }); return response(url, { detail: "pairing code not found", code: "not_found" }, 404); }
    throw new Error("SetupError: unexpected public sharing request " + path);
  });
  const lookup = api.pairingLookup.bind(api);
  vi.spyOn(api, "pairingLookup").mockImplementation(code => { const promise = lookup(code); originalLookup = promise; return promise; });
  await act(async () => { root = ReactTestRenderer.create(<SessionProvider><PublicAuthenticatedRoute /></SessionProvider>, { createNodeMock: node => node.type === "input" ? { setNativeProps: () => {} } : null }); });
  await flush();
  const username = root!.root.findAllByType(TextInput).find(node => node.props.placeholder === "username");
  const password = root!.root.findAllByType(TextInput).find(node => node.props.placeholder === "password");
  if (!username || !password) throw new Error("SetupError: public Login producer fields were not reached");
  await act(async () => { username.props.onChangeText(USERNAME); password.props.onChangeText(PASSWORD); });
  const login = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Sign in");
  if (!login || login.props.disabled) throw new Error("SetupError: actual public Login was not admitted");
  await act(async () => { await finite("actual public Login", login.props.onPress()); });
  const deadline = Date.now() + 15_000;
  while (!text().includes("Dr. queued native")) {
    if (Date.now() >= deadline) throw new Error("ExecutionError: actual public Login sharing route did not complete");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  if (!vault.isUnlocked() || vault.ownerUserId() !== OWNER || !(await api.isLoggedIn()) || !vault.get().authKey.equals(auth) || !vault.get().dataKey.equals(data)) throw new Error("SetupError: actual Login/session/vault owner differs from independently derived account");
  auth.fill(0); data.fill(0);
});
afterEach(async () => {
  releaseLookup?.();
  try {
    if (originalLookup) {
      try { await finite("cleanup actual lookup", originalLookup); }
      catch (error) {
        if (!(error instanceof ApiError && error.status === 404 && error.code === "not_found" && error.message === "pairing code not found")) {
          throw new Error("SetupError: unexpected native/public lookup cleanup outcome", { cause: error });
        }
      }
    }
  } finally {
    try { if (root) { await act(async () => { root!.unmount(); root = undefined; }); } }
    finally {
      try { vault.lock(); await api.clearSession(); }
      finally { vi.restoreAllMocks(); vi.unstubAllGlobals(); }
    }
  }
});

it("an enabled actual installed Native Switch exposes the public sharing-voice disclosure", async () => {
  const queued = admitQueuedSwitchPayload(root!, true);
  await act(async () => { queued.deliverToCurrentHost(); });
  expect(currentDialog()?.title).toBe("Let your therapist hear your recordings");
  expect(currentDialog()?.body).toContain("recordings");
  expect(currentDialog()?.choices?.map(choice => choice.text)).toEqual(["Cancel", "Continue"]);
  expect(text()).toContain("Dr. queued native");

});

it("a queued actual Native Switch payload cannot open a voice disclosure during the current public lookup", async () => {
  const queued = admitQueuedSwitchPayload(root!, true);
  const input = root!.root.findAllByType(TextInput).find(node => node.props.placeholder === "e.g. 7X2KQM4N");
  if (!input) throw new Error("SetupError: actual sharing pairing field missing");
  await act(async () => input.props.onChangeText("7X2KQM4N"));
  const button = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Find my therapist");
  if (!button || button.props.disabled) throw new Error("SetupError: public lookup was not admitted while enabled");
  let actualHandler: Promise<unknown> | undefined;
  await act(async () => {
    const touch = nativeGrantedPress({ disabled: button.props.disabled, onPress: () => { actualHandler = button.props.onPress(); } });
    try { touch.release(); } finally { touch.dispose(); }
  });
  await flush();
  if (!lookupEntered || !releaseLookup || !originalLookup || !(actualHandler instanceof Promise)) throw new Error("SetupError: actual held public lookup not reached");
  expect(root!.root.find(node => node.type === SWITCH_NATIVE_HOST).props.enabled).toBe(false);
  expect(text()).toContain("Looking up");
  await act(async () => { queued.deliverToCurrentHost(); });
  expect(currentDialog()).toBeNull();
  releaseLookup();
  await finite("original public lookup handler", actualHandler);
  await flush();
  expect(currentDialog()?.title).toBe("Code not found");
  expect(root!.root.find(node => node.type === SWITCH_NATIVE_HOST).props.enabled).toBe(true);
  expect(text()).not.toContain("Looking up");

});
