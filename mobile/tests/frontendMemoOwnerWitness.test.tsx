/** Pristine public producer exploration only. All AsyncStorage operations use
 * one FIFO physical queue; the only held native operation is independent Expo
 * file deletion already admitted by production resumeLocalRekey. */
import "react";
import crypto from "node:crypto";
import fs from "node:fs";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { Text, TextInput, TouchableOpacity, Switch } from "./helpers/rnMock";
import { ThemeProvider } from "../src/theme";
import { SessionProvider, useSession } from "../src/store";
import { api, getBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { secureStore } from "../src/secureStore";
import { accountStorageKey } from "../src/accountStorage";
import { localWriteScopeEpoch } from "../src/localWriteGuard";
import { rotatePassword } from "../src/rotation";
import { flushQueue, rejectedEntryCount, queueLength, MAX_QUEUE_BYTES, MAX_QUEUE_LENGTH, MAX_REJECTED_LENGTH } from "../src/offlineQueue";
import { onboardingSeenCached } from "../src/onboarding";
import { emitAppState } from "./helpers/rnMock";
import storage from "./helpers/storageMock";
import * as files from "./helpers/expoFsMock";
import { fakeRecorderStatus, __resetAudioMock } from "./helpers/expoAudioMock";

const stack = vi.hoisted(() => ({ navigate: undefined as undefined | ((name: string) => void) }));
vi.mock("@react-navigation/native-stack", async () => {
  const React = await import("react");
  const collect = (children: any): any[] => React.Children.toArray(children).flatMap(child =>
    React.isValidElement(child) ? child.type === React.Fragment ? collect((child.props as any).children) : [child] : []);
  function Navigator({ children }: any) {
    const routes = collect(children), [chosen, setChosen] = React.useState<string | null>(null);
    const names = routes.map(route => route.props.name);
    const current = routes.find(route => route.props.name === chosen) ?? routes[0];
    const navigation = React.useMemo(() => ({
      navigate: (name: string) => setChosen(name), replace: (name: string) => setChosen(name), popToTop: () => setChosen(null),
    }), []);
    React.useLayoutEffect(() => { stack.navigate = name => { if (names.includes(name)) setChosen(name); }; });
    if (!current) return null;
    const Screen = current.props.component;
    return <Screen key={current.props.name} navigation={navigation} />;
  }
  return { createNativeStackNavigator: () => ({ Navigator, Screen: () => null }) };
});
vi.mock("@react-navigation/native", () => ({ NavigationContainer: ({ children }: any) => children }));
const { AppNavigator } = await import("../src/navigation");
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const A = "a".repeat(32), B = "b".repeat(32), SALT_A = Buffer.alloc(16, 3);
const PASSWORD_A = "A retained strong Passphrase 2026!";
const MASTER_A = crypto.pbkdf2Sync(PASSWORD_A, SALT_A, 600000, 32, "sha256");
const AUTH_A = Buffer.from(crypto.hkdfSync("sha256", MASTER_A, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const OLD = Buffer.from(crypto.hkdfSync("sha256", MASTER_A, Buffer.alloc(32), "mindpattern/data/v1", 32));
const PASSWORD = "Native strong Passphrase 2026!", NAME = "bob";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let releaseFile = () => {};
let serial: Promise<unknown> = Promise.resolve();
let state: { auth: string; unlocked: boolean } | undefined;
let registration: any;
let registeredData: Buffer | undefined;
let events: Array<Record<string, unknown> & { order: number }> = [];
let phase = "fixture";
const receipt = process.env.MEMO_OWNER_RECEIPT_FILE;
function event(name: string, more: Record<string, unknown> = {}) {
  events.push({ order: events.length, name, phase, scope: localWriteScopeEpoch(), ...more });
}
function save(result: string) { if (receipt) fs.writeFileSync(receipt, JSON.stringify({ result, events }, null, 2) + "\n"); }
function deferred() { let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; }); return { pending, release }; }
function State() { const s = useSession(); state = { auth: s.authStatus, unlocked: s.unlocked }; return null; }
function words() { return root!.root.findAllByType(Text).map(node => node.props.children).flat(Infinity).filter(value => typeof value === "string" || typeof value === "number").join(" "); }
async function until(check: () => void) {
  try { await vi.waitFor(async () => { await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); check(); }, { timeout: 15000, interval: 5 }); }
  catch (cause) {
    // vi.waitFor may rethrow its last AssertionError on deadline. An absent
    // producer receipt or missed schedule is setup evidence, not a kill.
    event("producer-barrier-deadline", { cause: String(cause) });
    const error = new Error("MemoWitnessScheduleFault: a required public producer barrier did not complete");
    error.name = "MemoWitnessScheduleFault"; throw error;
  }
}
async function fill(label: string, value: string) { const node = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === label); expect(node, label).toBeDefined(); await act(async () => node!.props.onChangeText(value)); }
async function press(label: string) { const node = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label); expect(node, `${label}: ${words()}`).toBeDefined(); expect(node!.props.disabled).not.toBe(true); await act(async () => { void node!.props.onPress(); }); }
function response(url: string, body: unknown, status = 200) { const res = new Response(JSON.stringify(body), { status }); Object.defineProperty(res, "url", { value: url }); return res; }
function independentRegistration(body: any) {
  const salt = Buffer.from(body.salt, "base64"), master = crypto.pbkdf2Sync(PASSWORD, salt, body.kdf_params.iterations, 32, "sha256");
  const hkdf = (label: string, bytes: Buffer) => Buffer.from(crypto.hkdfSync("sha256", master, bytes, label, 32));
  expect(body.username).toBe(NAME); expect(body.verifier).toBe(hkdf("mindpattern/auth/v1", Buffer.alloc(32)).toString("base64"));
  expect(body.age_attestation).toBe("minimum_age_confirmed_v1");
  const blob = Buffer.from(body.wrapped_data_key, "base64"), cipher = crypto.createDecipheriv("aes-256-gcm", hkdf("mindpattern/envelope/v2", salt), blob.subarray(0, 12));
  cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: body.kdf_params, username: NAME }))); cipher.setAuthTag(blob.subarray(-16));
  return Buffer.concat([cipher.update(blob.subarray(12, -16)), cipher.final()]);
}
function fifoStorage() {
  for (const name of ["getItem", "setItem", "removeItem", "multiSet", "multiRemove", "getAllKeys"] as const) {
    const operation = storage[name].bind(storage);
    vi.spyOn(storage, name).mockImplementation(((...args: any[]) => {
      const entered = events.length;
      const pending = serial.then(async () => {
        await new Promise(resolve => setTimeout(resolve, 1));
        const value = await (operation as any)(...args);
        event(`native-${name}`, { key: args[0], admittedOrder: entered });
        return value;
      });
      serial = pending.catch(() => {});
      return pending;
    }) as never);
  }
}

afterEach(async () => {
  releaseFile(); await serial;
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vault.lock();
  if (receipt && !fs.existsSync(receipt)) save("PristinePublicWitnessIncomplete");
});

it("a retiring account cannot erase the replacement registration's unseen memo under FIFO native storage", async () => {
  events = []; serial = Promise.resolve(); fifoStorage(); __resetAudioMock();
  let deleted = false, processingCount = 0, index: any, offlineSaves = true, offlineAttempts = 0, rejectedAttempts = 0;
  const fileHeld = deferred(); releaseFile = fileHeld.release;
  const nativeDelete = files.deleteAsync.getMockImplementation()!;
  let holdFile: string | undefined, fileEntered = false, fileReleased = false;
  files.deleteAsync.mockImplementation(async (...args) => {
    if (holdFile && args[0] === holdFile && !fileEntered) {
      fileEntered = true; event("A-rekey-native-file-deletion-admitted"); await fileHeld.pending;
      fileReleased = true; event("A-rekey-native-file-deletion-released");
    }
    return nativeDelete(...args);
  });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    const path = new URL(url).pathname, body = init.body ? JSON.parse(init.body as string) : {};
    if (path.endsWith("/auth/register")) {
      registeredData = independentRegistration(body); registration = body; event("B-public-registration-HTTP-accepted");
      return response(url, { token: "B verified bearer", user_id: B, role: "user" });
    }
    if (path.endsWith("/auth/salt")) return response(url, { salt: body.username === "alice" ? SALT_A.toString("base64") : registration.salt });
    if (path.endsWith("/auth/login")) {
      if (body.username === "alice") { expect(body.verifier).toBe(AUTH_A.toString("base64")); return response(url, { token: "A verified fixture bearer", user_id: A, role: "user" }); }
      expect(body.username).toBe(NAME); expect(body.verifier).toBe(registration.verifier); return response(url, { token: "B unlocked bearer", user_id: B, role: "user" });
    }
    if (path.endsWith("/auth/key-envelope")) return response(url, registration ? { key_scheme: "v2", salt: registration.salt, kdf_params: registration.kdf_params, wrapped_data_key: registration.wrapped_data_key } : { key_scheme: "v1", salt: SALT_A.toString("base64"), kdf_params: null, wrapped_data_key: null });
    if (path.endsWith("/processing/sessions")) { expect(Buffer.from(body.data_key, "base64")).toHaveLength(32); return response(url, { session_token: `A-processing-${++processingCount}` }); }
    if (path.endsWith("/processing/rekey")) { event("A-actual-atomic-rotation-HTTP-committed", { operationId: body.operation_id }); return response(url, { credential_rotated: true, operation_id: body.operation_id, entries: 0, insights: 0, measures: 0, consents_rewrapped: 0 }); }
    if (path.endsWith("/audio/transcriptions")) {
      expect(body.mime).toBe("audio/m4a"); expect(body.duration_seconds).toBe(4);
      expect(Buffer.from(body.audio_b64, "base64")).toEqual(Buffer.from("retained authenticated native audio"));
      event("A-shipped-voice-producer-transcription", { nativePlaintextBytes: Buffer.from(body.audio_b64, "base64").length, mime: body.mime, durationSeconds: body.duration_seconds });
      return response(url, { language: "en", language_raw: "en", original_text: "Retain this recorded entry.", english_text: null });
    }
    if (path.endsWith("/entries") && init.method === "POST") {
      if (offlineSaves) {
        offlineAttempts++; event("A-public-entry-save-native-transport-unavailable", { contentVersion: body.content_version });
        throw new Error("The injected native network transport is offline");
      }
      rejectedAttempts++; event("A-real-outbox-upload-permanently-rejected");
      return response(url, { detail: "permanent entry upload refusal" }, 403);
    }
    if (path.endsWith("/meta")) return deleted ? response(url, { detail: "A authoritatively deleted", code: "account_deleted" }, 410) : response(url, { unlock_days: 30 });
    if (path.endsWith("/insights")) return response(url, { phase: "baseline", active_days: 0, days_remaining: 30 });
    if (path.endsWith("/progress")) return response(url, { active_days: 0 });
    return response(url, []);
  });
  await api.setSession("A verified fixture bearer", A, "alice");
  await api.cacheSalt("alice", SALT_A.toString("base64"));
  vault.unlock({ masterKey: Buffer.from(MASTER_A), authKey: Buffer.from(AUTH_A), dataKey: Buffer.from(OLD) }, A);
  await storage.setItem(accountStorageKey.onboardingSeen(A), "1");
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><AppNavigator /><State /></SessionProvider></ThemeProvider>); });
  await until(() => expect(words()).toContain("Save entry"));
  // These are submitted by the shipped EntryScreen Save handler, including
  // its 100,000-character check, v2 AAD/contentVersion=1 encryption, durable
  // draft and actual offline fallback. Multiple legitimate retained rows,
  // rather than an oversized lower-level injected row, create this index.
  phase = "A-public-entry-fixture";
  for (let i = 0; i < 7; i++) {
    await fill("Journal entry", "x".repeat(99000));
    await until(() => expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save entry")!.props.disabled).not.toBe(true));
    await press("Save entry");
    await until(() => {
      expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Journal entry")!.props.value).toBe("");
    });
    expect(await queueLength(A)).toBe(i + 1);
  }
  // The independent file is also produced by the shipped Record/Stop/Save
  // flow. The adapter supplies native recorder bytes, not queue descriptors.
  const takeUri = files.cacheDirectory + "memo-owner-real-voice-take.m4a";
  files.__seedFile(takeUri, Buffer.from("retained authenticated native audio").toString("base64"));
  fakeRecorderStatus.url = takeUri; fakeRecorderStatus.durationMillis = 4200;
  await press("Record instead"); await until(() => expect(words()).toContain("Stop recording")); await press("Stop recording");
  await until(() => expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Journal entry")!.props.value).toBe("Retain this recorded entry."));
  await press("Save entry");
  await until(() => expect(root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Journal entry")!.props.value).toBe(""));
  expect(offlineAttempts).toBe(8); offlineSaves = false;
  await flushQueue(A); expect(await rejectedEntryCount(A)).toBe(8); expect(await queueLength(A)).toBe(0);
  expect(rejectedAttempts).toBe(8);
  event("A-shipped-entry-producer-bounds", { typedSaves: 7, charactersPerTypedSave: 99000, voiceSaves: 1, voiceCharacters: 26, entryScreenMaxCharacters: 100000, contentVersion: 1, offlineNativeAttempts: offlineAttempts, realOutboxRejectedAttempts: rejectedAttempts, rejectedEntries: 8, queuedEntries: 0, maxQueueBytes: MAX_QUEUE_BYTES, maxQueueLength: MAX_QUEUE_LENGTH, maxRejectedLength: MAX_REJECTED_LENGTH });
  const audioKey = (await storage.getAllKeys()).find(key => key.startsWith("@mindpattern/audioqueue.v1:"))!;
  holdFile = JSON.parse((await storage.getItem(audioKey))!).uri;
  event("A-shipped-audio-custody-bounds", { producer: "EntryScreen Record instead, Stop recording, automatic transcription, Save entry", nativePlaintextBytes: 35, encryptedBlobCharacters: (await files.readAsStringAsync(holdFile!)).length, audioQueueMaxBlobCharacters: 6000000, mime: "audio/m4a", durationSeconds: 4 });
  const checkpoint = accountStorageKey.localRekey(new URL(await getBaseUrl()).origin, A);
  phase = "A-resume";
  const resuming = rotatePassword({ username: "alice", userId: A, oldPassword: PASSWORD_A, newPassword: "A changed strong Passphrase 2026!" });
  await until(() => expect(fileEntered).toBe(true));
  index = JSON.parse((await secureStore.getItem(checkpoint))!);
  expect(index.parts).toBeGreaterThan(20); event("A-actual-rotation-retained-index", { parts: index.parts });
  expect(processingCount).toBe(2);
  phase = "A-death"; const beforeRetirement = localWriteScopeEpoch(); deleted = true;
  await expect(api.meta()).rejects.toMatchObject({ status: 410, code: "account_deleted" }); deleted = false;
  await until(() => expect(words()).toContain("Sign in"));
  // A's retirement must already publish its null owner scope and wait for the
  // admitted file write before B's real registration captures that scope.
  await until(() => expect(localWriteScopeEpoch()).toBeGreaterThan(beforeRetirement));
  event("A-retirement-null-owner-scope-observed");
  await press("New here? Create an account"); await fill("Username", NAME); await fill("Password", PASSWORD); await fill("Confirm password", PASSWORD);
  await act(async () => root!.root.findByType(Switch).props.onValueChange(true));
  const retiredScope = localWriteScopeEpoch(); phase = "B-register"; await press("Create account");
  await until(() => { expect(registration).toBeDefined(); expect(localWriteScopeEpoch()).toBeGreaterThan(retiredScope); });
  const scopeB = localWriteScopeEpoch(); event("B-public-setSession-scope-admitted", { scopeB });
  phase = "FIFO-interleaving"; await act(async () => releaseFile());
  expect(await resuming).toMatchObject({ ok: false }); expect(fileReleased).toBe(true);
  await until(() => { expect(state).toEqual({ auth: "loggedIn", unlocked: true }); expect(vault.ownerUserId()).toBe(B); expect(words()).toContain("Write each day"); expect(onboardingSeenCached(B)).toBe(false); });
  expect(vault.get().dataKey).toEqual(registeredData); expect(onboardingSeenCached(B)).toBe(false);
  const publication = events.length; event("B-real-navigator-unseen-memo-published", { scopeB });
  // A's physical third deletion must happen AFTER the actual B navigator's
  // first unpublished-to-published unseen read, not just after api.setSession.
  const legacy = "@mindpattern/onboarding_panel";
  if (events.slice(0, publication).some(e => e.name === "native-removeItem" && e.key === legacy && e.phase === "FIFO-interleaving")) {
    event("producer-barrier-schedule-missed"); throw new Error("MemoWitnessScheduleFault: A cleanup preceded B navigator publication");
  }
  await until(() => expect(events.some(e => e.name === "native-removeItem" && e.key === legacy && e.order > publication)).toBe(true));
  if (localWriteScopeEpoch() !== scopeB) throw new Error("MemoWitnessScheduleFault: B ownership changed before A cleanup completed");
  event("A-late-cleanup-observable-replacement-memo", { replacementMemo: onboardingSeenCached(B), scopeB });
  phase = "B-background"; await act(async () => emitAppState("background")); await until(() => expect(words()).toContain("Locked"));
  expect(state!.auth).toBe("loggedIn");
  await fill("Password", PASSWORD); phase = "B-public-unlock"; await press("Unlock");
  await until(() => { expect(state).toEqual({ auth: "loggedIn", unlocked: true }); expect(vault.isUnlocked()).toBe(true); expect(words().includes("Write each day") || words().includes("Save entry")).toBe(true); });
  expect(vault.ownerUserId()).toBe(B); expect(vault.get().dataKey).toEqual(registeredData);
  event("B-verified-unlock-public-completion", { route: words().includes("Write each day") ? "Onboarding" : "Entry" });
  expect(words()).toContain("Write each day");
  expect(onboardingSeenCached(B)).toBe(false);
  expect(state!.auth).toBe("loggedIn"); event("B-verified-unlock-restores-required-onboarding"); save("PristinePublicWitnessPassed");
}, 60000);
