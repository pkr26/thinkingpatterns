/** public RecoveryScreen completion witness. Real recoveryFlow
 * Promises are returned unchanged and observed to finite settlement. No
 * positive vault poll, model recovery result or private screen setter. */
import crypto from "node:crypto";
import { Activity } from "react";


import RTR, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Alert, Text, TextInput, TouchableOpacity } from "react-native";
import { RecoveryScreen } from "../../src/screens/RecoveryScreen";
import * as recoveryFlow from "../../src/recoveryFlow";
import { api, ApiError, setBaseUrl } from "../../src/api/client";
import { vault } from "../../src/vault";
import { SessionProvider, useSession } from "../../src/store";
import { ThemeProvider } from "../../src/theme";
import { takePendingOnboarding } from "../../src/onboarding";
import { setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import * as files from "../helpers/expoFsMock";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "c".repeat(32), NAME = "synthetic_recovery_finite";
const PASSWORD = "Native strong Passphrase 2026!", DATA = Buffer.alloc(32, 7), KIT = Buffer.alloc(32, 4);
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 };
type Scheme = "v1" | "v2";
type Root = ReturnType<typeof RTR.create>;
type Outcome = Awaited<ReturnType<typeof recoveryFlow.recoverAccountWithKey>>;
type Settlement = { ok: true; outcome: Outcome } | { ok: false; error: unknown };
let root: Root | undefined, serverScheme: Scheme, wire: { salt: string; wrapped: string; verifier: string } | undefined;
let state: { auth: string; unlocked: boolean } | undefined, witness: Record<string, unknown>;
let current: { originalPromise: Promise<Outcome>; settlement: Promise<Settlement> } | undefined;
let releases: Array<() => void> = [], holdResponse: Promise<void>, releaseResponse: () => void;
let fixtureFault: Error | undefined;
let recoverRequested: Promise<void>, markRecoverRequested: () => void;
const nativeDelete = files.deleteAsync.getMockImplementation()!;
const hkdf = (key: Buffer, salt: Buffer, label: string) => Buffer.from(crypto.hkdfSync("sha256", key, salt, label, 32));

function gate() { holdResponse = new Promise<void>(resolve => { releaseResponse = resolve; releases.push(resolve); }); recoverRequested = new Promise<void>(resolve => { markRecoverRequested = resolve; }); }
async function finite<T>(pending: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([pending, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`SetupError: Recovery actual producer deadline ${label}`)), 15_000); })]); }
  finally { if (timer) clearTimeout(timer); }
}
function seal(key: Buffer, data: Buffer): string {
  const nonce = Buffer.alloc(12, 9), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["recovery", USER, "data-key"])));
  return Buffer.concat([nonce, cipher.update(data), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
function openWire(value: { salt: string; wrapped: string; verifier: string }): Buffer {
  const salt = Buffer.from(value.salt, "base64"), master = crypto.pbkdf2Sync(PASSWORD, salt, 600_000, 32, "sha256");
  const auth = hkdf(master, Buffer.alloc(32), "mindpattern/auth/v1"), kek = hkdf(master, salt, "mindpattern/envelope/v2");
  try {
    if (value.verifier !== auth.toString("base64")) throw new Error("SetupError: Independent recovery verifier did not authenticate");
    const blob = Buffer.from(value.wrapped, "base64"), decipher = crypto.createDecipheriv("aes-256-gcm", kek, blob.subarray(0, 12));
    decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: PARAMS, username: NAME }))); decipher.setAuthTag(blob.subarray(-16));
    return Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]);
  } finally { master.fill(0); auth.fill(0); kek.fill(0); }
}
function answer(url: string, data: unknown, status = 200): Response {
  const value = status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
  Object.defineProperty(value, "url", { value: url }); return value;
}
function State() { const session = useSession(); state = { auth: session.authStatus, unlocked: session.unlocked }; return <Text>{`Finite recovery ${session.authStatus} unlocked=${session.unlocked}`}</Text>; }
function button(label: string) { const node = root!.root.findAllByType(TouchableOpacity).find(item => item.props.accessibilityLabel === label); if (!node) throw new Error(`SetupError: Recovery public button unavailable ${label}`); return node; }
function input(label: string) { const node = root!.root.findAllByType(TextInput).find(item => item.props.accessibilityLabel === label); if (!node) throw new Error(`SetupError: Recovery public input unavailable ${label}`); return node; }
const text = () => root!.root.findAllByType(Text).map(item => item.props.children).flat(Infinity).filter(item => typeof item === "string" || typeof item === "number").join(" ");
async function flush() { await act(async () => { for (let turn = 0; turn < 64; turn++) await Promise.resolve(); }); }
async function fill(label: string, value: string) { await act(async () => input(label).props.onChangeText(value)); }
async function press(label: string) { const action = button(label); if (action.props.disabled || typeof action.props.onPress !== "function") throw new Error(`SetupError: Recovery public action disabled ${label}`); await act(async () => { action.props.onPress(); }); }
async function mount() {
  await act(async () => { root = RTR.create(view("visible")); });
  await flush(); await fill("Username", NAME); await fill("Recovery key", KIT.toString("base64")); await fill("New password (12+ characters)", PASSWORD); await fill("Confirm new password", PASSWORD);
}




beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles(); files.deleteAsync.mockImplementation(nativeDelete);
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock(); await api.clearSession(); await setBaseUrl("http://localhost:8000"); takePendingOnboarding(); vi.mocked(Alert.alert).mockClear();
  root = undefined; state = undefined; wire = undefined; serverScheme = "v2"; releases = []; current = undefined; fixtureFault = undefined;  witness = { protocol: [] }; gate();
  const native = recoveryFlow.recoverAccountWithKey;
  vi.spyOn(recoveryFlow, "recoverAccountWithKey").mockImplementation((...args) => {
    const originalPromise = native(...args);
    const settlement: Promise<Settlement> = originalPromise.then(outcome => ({ ok: true as const, outcome }), error => ({ ok: false as const, error }));
    current = { originalPromise, settlement };
    return originalPromise;
  });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    try {
    const route = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    witness.protocol = [...(witness.protocol as unknown[]), { route, method: init.method }];
    if (String(init.body ?? "").includes(PASSWORD)) throw new Error("SetupError: Plaintext password crossed actual recovery transport");
    const proof = serverScheme === "v1" ? KIT : hkdf(KIT, Buffer.alloc(32), "mindpattern/recovery-verifier/v2");
    if (route.endsWith("/auth/recover")) {
      markRecoverRequested();
      await holdResponse;
      // Shipped RecoveryLoginRequest admits only literal v1/v2. Malformed
      // selector values receive the same finite422 envelope as FastAPI's
      // validation_no_echo handler, before recovery route authentication.
      if (body.scheme !== "v1" && body.scheme !== "v2") return answer(url, { detail: "scheme: Input should be 'v1' or 'v2'", code: "validation_error" }, 422);
      if (body.username !== NAME || body.scheme !== serverScheme || body.verifier !== proof.toString("base64")) return answer(url, { detail: "Synthetic real server rejected recovery scheme/proof", code: "invalid_credentials" }, 401);
      const kek = hkdf(KIT, Buffer.alloc(32), serverScheme === "v1" ? "mindpattern/recovery/v1" : "mindpattern/recovery-seal/v2");
      try { return answer(url, { token: "synthetic-finite-recovered-bearer", user_id: USER, role: "user", key_scheme: "v2", recovery_scheme: serverScheme, username: NAME, recovery_wrapped_data_key: seal(kek, DATA) }); }
      finally { kek.fill(0); }
    }
    if (route.endsWith("/processing/sessions")) {
      if (body.data_key !== DATA.toString("base64")) throw new Error("SetupError: Genuine recovered key differs from authenticated server ciphertext");
      return answer(url, { session_token: "synthetic-finite-processing", expires_in: 300 });
    }
    if (route.endsWith("/account/recovery/password")) {
      if (body.proof !== proof.toString("base64") || new Headers(init.headers).get("X-Processing-Token") !== "synthetic-finite-processing" || JSON.stringify(body.new_kdf_params) !== JSON.stringify(PARAMS)) throw new Error("SetupError: Independent recovery reset proof/params fixture refused");
      wire = { salt: String(body.new_salt), wrapped: String(body.wrapped_data_key), verifier: String(body.new_verifier) };
      const opened = openWire(wire); try { if (!opened.equals(DATA)) throw new Error("SetupError: Independent reset changed journal key"); } finally { opened.fill(0); }
      return answer(url, null, 204);
    }
    if (route.endsWith("/insights")) return answer(url, { active_days: 12 });
    if (route.endsWith("/meta")) return answer(url, { unlock_days: 30 });
    if (route.endsWith("/auth/logout")) return answer(url, null, 204);
    throw new Error(`SetupError: Unexpected genuine Recovery producer route ${route}`);
    } catch (error) {
      fixtureFault = error instanceof Error ? error : new Error(`SetupError: Native recovery fixture failed ${String(error)}`);
      if (!fixtureFault.message.startsWith("SetupError:")) fixtureFault = new Error(`SetupError: Native recovery fixture failed ${fixtureFault.message}`);
      throw fixtureFault;
    }
  });
});
afterEach(async () => {
  const pending = current?.settlement;
  releases.forEach(release => release());
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  // Even an early finite admission assertion must retire the actual started
  // flow before a later case restores or replaces its transport/native seams.
  if (pending) await finite(pending, "cleanup original recoveryFlow settlement after actual unmount");
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

// Activity is the real public React host. Updates retain the same keyed screen;
// no screen refs, effect callbacks, setters or event handlers are replayed.
function view(mode: "visible" | "hidden") {
  return <ThemeProvider><SessionProvider><Activity mode={mode}><RecoveryScreen navigation={{ navigate: () => undefined }} /></Activity><State /></SessionProvider></ThemeProvider>;
}
async function changeVisibility(mode: "visible" | "hidden") {
  await act(async () => { root!.update(view(mode)); });
  await flush();
}
async function retireAndRevealHeldPublicAttempt() {
  current = undefined;
  await press("Recover and set new password");
  expect(button("Verifying…").props.disabled).toBe(true);
  const admitted = current as { originalPromise: Promise<Outcome>; settlement: Promise<Settlement> } | undefined;
  if (!admitted) throw new Error("SetupError: Public Activity attempt has no original recoveryFlow Promise");
  await act(async () => { await finite(recoverRequested, "real auth/recover request held at external transport"); });
  await changeVisibility("hidden");
  await changeVisibility("visible");
  // Public state persistence distinguishes Activity retention from a remount.
  expect(input("Username").props.value).toBe(NAME);
  expect(input("Recovery key").props.value).toBe(KIT.toString("base64"));
  expect(input("New password (12+ characters)").props.value).toBe(PASSWORD);
  expect(button("Verifying…").props.disabled).toBe(true);
  releaseResponse();
  let completed!: Settlement;
  await act(async () => { completed = await finite(admitted.settlement, "retired original producer settles after real response"); });
  await flush();
  if (fixtureFault) throw fixtureFault;
  if (!completed.ok && completed.error instanceof Error && /SetupError|ExecutionError/.test(completed.error.message)) throw completed.error;
  return completed;
}

// React Activity hosts the real screen; native services and transport are controlled.
it("a public Activity hide and reveal keeps a retired recovery from adopting credentials", async () => {
  await mount();
  const completed = await retireAndRevealHeldPublicAttempt();
  expect(completed.ok, "the retired public producer must reject after Activity reconnect").toBe(false);
  expect(vault.isUnlocked()).toBe(false);
  expect(await api.isLoggedIn()).toBe(false);
  expect(text()).not.toContain("Recovered. Your journal is unlocked");
}, 30_000);

it("a retired refusal after public Activity reconnect cannot write a stale error or reenable its pending action", async () => {
  serverScheme = "v1"; // Same genuine 401 refusal as the existing public fixture.
  await mount();
  const completed = await retireAndRevealHeldPublicAttempt();
  expect(completed.ok).toBe(false);
  expect(text(), "a retired request cannot display a new failure on the reconnected view").not.toContain("Recovery did not complete.");
  expect(text(), "retired finally cannot clear the retained pending public presentation").toContain("Verifying…");
  expect(button("Verifying…").props.disabled).toBe(true);
}, 30_000);

// Model one native tap callback captured while its visible button was enabled.
// The actual public screen is retained by React Activity; recoveryFlow remains real.
it("a retained tap cannot start a new recovery after an Activity-retired completion", async () => {
  await mount();
  const capturedTap = button("Recover and set new password").props.onPress;
  if (typeof capturedTap !== "function") throw new Error("SetupError: native recovery tap is unavailable");
  const completed = await retireAndRevealHeldPublicAttempt();
  expect(completed.ok, "the first held producer was retired").toBe(false);
  expect(vi.mocked(recoveryFlow.recoverAccountWithKey)).toHaveBeenCalledTimes(1);
  expect(button("Verifying…").props.disabled).toBe(true);
  // A previously captured event can be delivered after the rendered action
  // disables. Hold any unexpected second request so cleanup owns its producer.
  gate();
  await act(async () => { capturedTap(); await Promise.resolve(); });
  expect(vi.mocked(recoveryFlow.recoverAccountWithKey), "a retired tap cannot start another real recovery").toHaveBeenCalledTimes(1);
  expect(vault.isUnlocked()).toBe(false);
  expect(await api.isLoggedIn()).toBe(false);
}, 30_000);
