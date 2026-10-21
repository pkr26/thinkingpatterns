/** Public App account death followed by a real second Login whose local
 * rotation read fails. Real credential/vault/API/storage functions remain;
 * the injected lowest KV backend authors one native AbortError and the
 * synthetic server returns genuine native Response objects. */
import { hkdfSync, pbkdf2Sync } from "node:crypto";

import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionUserId, sessionUsername } from "../src/api/client";
import * as localRotation from "../src/localRotation";
import * as erasure from "../src/localErasure";
import { kv, setKvBackendForTests, StorageReadError, writeGenerationKey } from "../src/kvstore";
import { applyLanguagePref } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const A = "a".repeat(32), B = "b".repeat(32);
const A_NAME = "deleted_public_account", B_NAME = "current_public_account";
const PASSWORD = "A genuine recovery sign in passphrase!";
const SALT = Buffer.alloc(16, 41);
const MASTER = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
const AUTH = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const DATA = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/data/v1", 32)); MASTER.fill(0);
const STORAGE_COPY = "Local encrypted records could not be read. Keep this view open and retry before changing stored data.";
type Wire = { path: string; bearer: string | null; status: number; username?: unknown; verifier?: unknown };
type State = { case: string; stage: string; root?: ReactTestRenderer; wires: Wire[]; responses: Promise<Response>[]; originals: Promise<unknown>[]; firstOwnerKey?: Uint8Array; emit410: boolean; sent410: boolean; rejectRotation: boolean; rotationFaults: number; nativeFault: DOMException; actualReadFailure?: StorageReadError; remoteErasureCompleted: boolean; unknown?: unknown };
let current: State | undefined;
function setup(message: string, cause?: unknown): Error { return new Error("SetupError: public410 recovery producer: " + message, { cause }); }
function signedInNotes(root: ReactTestRenderer): string[] { return root.root.findAllByType("p").map(textOfNode).filter(value => value.startsWith("Signed in as ")); }
async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(label + " did not complete")), 20_000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function published(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 20_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw setup(label + " was not published");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  await flush(12);
}
function install(state: State): void {
  const backend = memoryKvBackend();
  setKvBackendForTests({ ...backend, getItem(key) {
    if (state.rejectRotation && key === `mindpattern.localRotation.${B}`) {
      state.rejectRotation = false; state.rotationFaults += 1;
      return Promise.reject(state.nativeFault);
    }
    return backend.getItem(key);
  } });
  const rotation = localRotation.hasLocalRotation;
  vi.spyOn(localRotation, "hasLocalRotation").mockImplementation(owner => {
    const original = rotation(owner); state.originals.push(original);
    // Observer reaction only; the caller receives the identical production
    // Promise and the actual kv StorageReadError, not a copied implementation.
    void original.then(() => undefined, error => {
      if (owner === B && error instanceof StorageReadError && error.constructor === StorageReadError && error.message === STORAGE_COPY && error.cause === state.nativeFault) state.actualReadFailure = error;
      else state.unknown = error;
    });
    return original;
  });
  const confirm = erasure.confirmRemoteLocalErasure;
  vi.spyOn(erasure, "confirmRemoteLocalErasure").mockImplementation(owner => {
    const original = confirm(owner); state.originals.push(original);
    void original.then(() => { if (owner === A) state.remoteErasureCompleted = true; }, error => { state.unknown = error; });
    return original;
  });
  const chains = new Map<string, Promise<unknown>>();
  vi.stubGlobal("navigator", { onLine: true, locks: { request<T>(name: string, work: () => Promise<T>): Promise<T> { const original = (chains.get(name) ?? Promise.resolve()).then(work); state.originals.push(original); chains.set(name, original.catch(() => undefined)); return original; } } });
  stubFetch((url, init) => {
    try {
      const path = new URL(url).pathname, bearer = new Headers(init.headers).get("Authorization");
      const body = init.body === undefined ? undefined : JSON.parse(String(init.body)) as Record<string, unknown>;
      let response: Response;
      if (path === "/api/v1/auth/salt") response = jsonResponse({ salt: SALT.toString("base64") });
      else if (path === "/api/v1/auth/login") {
        if (![A_NAME, B_NAME].includes(String(body?.username)) || body?.verifier !== AUTH.toString("base64") || String(init.body).includes(PASSWORD)) throw setup("actual Login credential wire was not independently verified");
        const owner = body!.username === A_NAME ? A : B;
        response = jsonResponse({ token: `real-public-${owner}`, user_id: owner, expires_in: 3600, role: "user", key_scheme: "v1" });
      } else if (path === "/api/v1/auth/key-envelope") response = jsonResponse({ key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null });
      else if (path === "/api/v1/meta") response = jsonResponse({ version: "synthetic", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: false, audio_available: false });
      else if (path === "/api/v1/entries") {
        if (state.emit410) {
          if (bearer !== `Bearer real-public-${A}`) throw setup("account-death response lacked the authentic first owner request");
          state.emit410 = false; state.sent410 = true;
          response = jsonResponse({ code: "account_deleted", detail: "Synthetic authoritative account death" }, { status: 410 });
        } else response = jsonResponse([]);
      } else if (path === "/api/v1/account/access-log" || path === "/api/v1/consents") response = jsonResponse([]);
      else if (path === "/api/v1/account/llm-consent") response = jsonResponse({ enabled: false, active_for_current_policy: false, llm_consent_at: null, llm_consent_disclosure: null, llm_consent_policy: null });
      else if (path === "/api/v1/account/voice-consent") response = jsonResponse({ enabled: false, active_for_current_policy: false, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
      else if (path === "/api/v1/auth/logout") response = new Response(null, { status: 204 });
      else throw setup("unexpected actual HTTP route " + path);
      state.wires.push({ path, bearer, status: response.status, username: body?.username, verifier: body?.verifier });
      const original = Promise.resolve(response); state.responses.push(original); return original;
    } catch (error) { state.unknown = error; throw error; }
  });
}
async function signIn(root: ReactTestRenderer, username: string): Promise<void> {
  if (!buttonByLabel(root, "Sign in") || isDisabled(root, "Sign in")) throw setup("public sign-in was not enabled");
  await typeInto(root, "Username", username); await typeInto(root, "Password", PASSWORD);
  await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
}
async function firstOwnerThenDeath(label: string): Promise<{ state: State; root: ReactTestRenderer }> {
  const state: State = { case: label, stage: "first-login", wires: [], responses: [], originals: [], emit410: false, sent410: false, rejectRotation: false, rotationFaults: 0, nativeFault: new DOMException("Synthetic owned read transaction unavailable", "AbortError"), remoteErasureCompleted: false };
  current = state; install(state); const root = await render(<App />); state.root = root;
  await published("actual App Login", () => buttonByLabel(root, "Sign in")); await signIn(root, A_NAME);
  await published("actual first Login onboarding", () => buttonByLabel(root, "Next"));
  if (!vault.isUnlocked() || vault.ownerUserId() !== A || !hasSession() || sessionUserId() !== A || !Buffer.from(vault.get().dataKey).equals(DATA)) throw setup("first public Login did not adopt independently derived owner keys");
  state.firstOwnerKey = vault.get().dataKey;
  await press(root, "Next"); await press(root, "Next"); await press(root, "Start journaling");
  await published("first actual signed-in shell", () => buttonByLabel(root, "History") && signedInNotes(root).includes(`Signed in as ${A_NAME}`));
  await finite(Promise.all(state.responses), "first native responses");
  state.emit410 = true; await press(root, "History");
  await published("authoritative410 App Login funnel", () => state.sent410 && buttonByLabel(root, "Sign in"));
  await published("actual owned remote-erasure completion", () => state.remoteErasureCompleted);
  if (state.unknown || vault.isUnlocked() || hasSession()) throw setup("account-death producer had an unknown fault or retained its session", state.unknown);
  state.stage = "authoritative-death-and-owned-erasure-completed";
  return { state, root };
}
beforeEach(() => { vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); });
afterEach(async () => {
  const state = current;
  try {
    if (state?.root) await act(async () => { state.root!.unmount(); });
    if (state) {
      await finite(Promise.all(state.responses), "original native response retirement");
      for (const result of await finite(Promise.allSettled(state.originals), "original App storage/erasure Promise retirement")) {
        if (result.status === "rejected" && !(result.reason instanceof StorageReadError && result.reason.constructor === StorageReadError && result.reason.message === STORAGE_COPY && result.reason.cause === state.nativeFault)) throw setup("unknown original production Promise rejected", result.reason);
      }
      if (state.unknown) throw setup("unknown native/API provider fault", state.unknown);
    }
  } finally {


    current = undefined; resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals();
  }
});


it("an authoritative deleted account followed by a healthy public Login publishes only the new account label", async () => {
  const { state, root } = await firstOwnerThenDeath("healthy-successor");
  expect(state.firstOwnerKey).toEqual(new Uint8Array(32));
  expect(JSON.parse((await kv.getItem(writeGenerationKey(A)))!).deleted).toBe(true);
  expect(textOf(root)).toContain("This account was deleted.");
  await signIn(root, B_NAME); await published("actual second Login onboarding", () => buttonByLabel(root, "Next"));
  await press(root, "Next"); await press(root, "Next"); await press(root, "Start journaling");
  await published("second genuine signed-in shell", () => signedInNotes(root).includes(`Signed in as ${B_NAME}`));
  expect(signedInNotes(root)).toEqual([`Signed in as ${B_NAME}`]);
  expect(vault.ownerUserId()).toBe(B); expect(sessionUserId()).toBe(B); expect(sessionUsername()).toBe(B_NAME);
  expect(vault.get().authKey).toEqual(new Uint8Array(AUTH)); expect(vault.get().dataKey).toEqual(new Uint8Array(DATA));
  state.stage = "public-current-owner-label-and-key-oracles-completed";
});

it("a genuine next-owner local rotation read failure shows Settings recovery without an old account label after410", async () => {
  const { state, root } = await firstOwnerThenDeath("storage-refused-successor");
  expect(state.firstOwnerKey).toEqual(new Uint8Array(32)); expect(textOf(root)).toContain("This account was deleted.");
  state.rejectRotation = true; await signIn(root, B_NAME);
  await published("actual second-owner storage refusal and public Settings recovery", () => state.actualReadFailure !== undefined && textOf(root).includes(STORAGE_COPY) && textOf(root).includes("Appearance"));
  if (state.rotationFaults !== 1 || !state.actualReadFailure || state.actualReadFailure.cause !== state.nativeFault) throw setup("authored one-use lowest-backend failure was not the actual kv StorageReadError");
  expect(signedInNotes(root)).toEqual([]);
  expect(textOf(root)).toContain(STORAGE_COPY); expect(textOf(root)).toContain("Appearance");
  expect(vault.isUnlocked()).toBe(true); expect(vault.ownerUserId()).toBe(B);
  expect(hasSession()).toBe(true); expect(sessionUserId()).toBe(B); expect(sessionUsername()).toBe(B_NAME);
  expect(vault.get().authKey).toEqual(new Uint8Array(AUTH)); expect(vault.get().dataKey).toEqual(new Uint8Array(DATA));
  state.stage = "public-empty-recovery-label-and-current-owner-key-oracles-completed";
});
