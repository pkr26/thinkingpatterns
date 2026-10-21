/** pristine producer draft. Actual Login creates the v2 offline
 * material; actual Settings finishes sign-out before custody assertions. */
import crypto from "node:crypto";

import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { Alert, TextInput, TouchableOpacity } from "react-native";
import { LoginScreen } from "../src/screens/LoginScreen";
import { SettingsScreen } from "../src/screens/SettingsScreen";
import { SessionProvider, useSession } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { verifyUnlockProof } from "../src/unlockProof";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
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
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let observedSession: { auth: string; unlocked: boolean } | undefined;

function Screen() {
  const session = useSession();
  observedSession = { auth: session.authStatus, unlocked: session.unlocked };
  return session.authStatus === "loggedIn"
    ? <SettingsScreen navigation={{ popToTop: () => undefined }} />
    : <LoginScreen navigation={{ navigate: () => undefined }} />;
}
function answer(url: string, body: unknown, status = 200) {
  const response = new Response(JSON.stringify(body), { status });
  Object.defineProperty(response, "url", { value: url }); return response;
}
function action(label: string) {
  const node = root!.root.findAllByType(TouchableOpacity).find(item => item.props.accessibilityLabel === label);
  if (!node) throw new Error(`SetupError: missing public native action ${label}`);
  return node;
}
async function fill(label: string, value: string) {
  const node = root!.root.findAllByType(TextInput).find(item => item.props.accessibilityLabel === label);
  if (!node) throw new Error(`SetupError: missing public native input ${label}`);
  await act(async () => node.props.onChangeText(value));
}
async function pressAndComplete(label: string) {
  const node = action(label);
  expect(node.props.disabled).not.toBe(true);
  await act(async () => {
    const pending = node.props.onPress();
    if (!pending || typeof pending.then !== "function") throw new Error(`SetupError: ${label} has no genuine handler completion Promise`);
    await pending;
  });
}
afterEach(async () => {



  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});
it("retires actual v2 Login offline material after the completed public Settings sign-out", async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles();
  files.deleteAsync.mockImplementation(nativeDelete);
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); await api.clearSession(); await setBaseUrl("http://localhost:8000"); vi.mocked(Alert.alert).mockClear();

  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    const route = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) : {};
    if (route.endsWith("/auth/salt")) return answer(url, { salt: SALT.toString("base64") });
    if (route.endsWith("/auth/login")) return body.username === NAME && body.verifier === AUTH.toString("base64")
      ? answer(url, { token: "independently verified native signout bearer", user_id: USER, role: "user" })
      : answer(url, { code: "invalid_credentials" }, 401);
    if (route.endsWith("/auth/key-envelope")) return answer(url, { key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: PARAMS, wrapped_data_key: WRAP });
    if (route.endsWith("/insights")) return answer(url, { active_days: 12 });
    if (route.endsWith("/meta")) return answer(url, { unlock_days: 30, llm_available: false, sharing_available: false, audio_available: false });
    if (route.endsWith("/account/recovery")) return answer(url, { enabled: false, set_at: null, scheme: "v2" });
    if (route.endsWith("/consent/llm") || route.endsWith("/consent/voice")) return answer(url, { enabled: false, active_for_current_policy: false });
    if (route.endsWith("/auth/logout")) return answer(url, {});
    throw new Error(`SetupError: unexpected public native HTTP route ${route}`);
  });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><Screen /></SessionProvider></ThemeProvider>); });
  await act(async () => { for (let i = 0; i < 64; i++) await Promise.resolve(); });
  await fill("Username", NAME); await fill("Password", PASSWORD); await pressAndComplete("Sign in");
  expect(observedSession).toEqual({ auth: "loggedIn", unlocked: true });
  expect(vault.get().dataKey).toEqual(DATA); expect(await verifyUnlockProof(DATA, USER)).toBe("ok");
  expect(await api.getCachedSalt(NAME)).toBe(SALT.toString("base64"));
  expect(await api.getCachedKeyEnvelope(NAME)).toMatchObject({ scheme: "v2", saltB64: SALT.toString("base64"), wrappedB64: WRAP });

  await pressAndComplete("Sign out");

  expect(observedSession).toEqual({ auth: "loggedOut", unlocked: false });
  expect(vault.isUnlocked()).toBe(false); expect(await api.getUserId()).toBeNull();
  expect(await api.getCachedSalt(NAME)).toBeNull(); expect(await api.getCachedKeyEnvelope(NAME)).toBeNull();
  expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);

}, 30000);
