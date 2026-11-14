/** Prospective isolated regressions; actual App/Login/API/crypto, controlled
 * ordinary storage and native Response delivery. No frozen campaign edit. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { LoginView } from "../src/views/LoginView";
import { api, auth, clearSession, hasSession, sessionAbortSignal, sessionUserId, setSession } from "../src/api/client";
import { buildAad } from "../src/crypto/aad";
import { deriveMasterKey, encrypt, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import * as loginCrypto from "../src/crypto/core";
import * as loginKeys from "../src/crypto/keys";
import { setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { withLock } from "../src/platform";
import { applyLanguagePref, loadFullCatalogs, t } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, press, render, setCheckbox, textOf, typeInto } from "./helpers/rtr";
const A = "0123456789abcdef0123456789abcdef", B = "fedcba9876543210fedcba9876543210";
const SALT = "AAECAwQFBgcICQoLDA0ODw==", PASSWORD = "quiet-morning-lantern-42", DATE = "2026-10-07";
const A_TEXT = "Private reflection for account A", B_TEXT = "Private reflection for account B";
type Mode = "signin" | "register";
function deferred() { let resolve!: () => void, reject!: (error: Error) => void; const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; }); void promise.catch(() => undefined); return { promise, resolve, reject }; }
async function bounded<T>(label: string, work: Promise<T>): Promise<T> {
 let timer!: ReturnType<typeof setTimeout>;
 try { return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`SetupError: bounded producer did not settle: ${label}`)), 15000); })]); }
 finally { clearTimeout(timer); }
}
async function completion(label: string, ready: () => boolean): Promise<void> {
 const end = Date.now() + 15000;
 while (!ready()) { if (Date.now() >= end) throw new Error(`SetupError: public prerequisite did not complete: ${label}`); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); }); }
 await flush();
}
function streamed(data: unknown, signal?: AbortSignal | null) {
 let controller!: ReadableStreamDefaultController<Uint8Array>, ended = false;
 const abort = () => { if (!ended) { ended = true; controller.error(new DOMException("The operation was aborted", "AbortError")); } };
 const body = new ReadableStream<Uint8Array>({ start(next) { controller = next; if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true }); }, cancel() { ended = true; signal?.removeEventListener("abort", abort); } });
 return { response: new Response(body, { status: 200, headers: { "Content-Type": "application/json" } }), deliver() { if (ended) return; ended = true; signal?.removeEventListener("abort", abort); controller.enqueue(new TextEncoder().encode(JSON.stringify(data))); controller.close(); } };
}
async function fill(root: ReactTestRenderer, mode: Mode, username: string) {
 if (mode === "register") await press(root, "Create an account");
 await typeInto(root, "Username", username); await typeInto(root, "Password", PASSWORD);
 if (mode === "register") { await typeInto(root, "Confirm password", PASSWORD); await setCheckbox(root, "I am 18 or older", true); }
 const label = mode === "signin" ? "Sign in" : "Create journal";
 expect(isDisabled(root, label)).toBe(false); await press(root, label);
}
afterEach(() => { resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function harness(mode: Mode, options: { holdA?: boolean; failAdoption?: boolean; direct?: (success: { userId: string; username: string }) => void | Promise<void> } = {}) {
 vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); await loadFullCatalogs("en");
 let keysA: Awaited<ReturnType<typeof derivePatientKeys>> | null = mode === "signin" ? await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(SALT))) : null;
 const keysB = await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(SALT)));
 const pending: Promise<unknown>[] = [], observers: { mockRestore(): void }[] = [];
 const own = <T,>(promise: Promise<T>): Promise<T> => { pending.push(promise); void promise.catch(() => undefined); return promise; };
 for (const [object, name] of [[auth,"saltFor"],[auth,"login"],[auth,"register"],[loginCrypto,"deriveMasterKey"],[loginKeys,"derivePatientKeys"],[api,"openProcessingSession"],[api,"questionToday"],[api,"recompute"]] as const) {
  const actual = (object as any)[name]; observers.push(vi.spyOn(object as any, name).mockImplementation((...args: unknown[]) => own(actual(...args))) as any);
 }
 const onboarding = deferred(), backend = memoryKvBackend();
 await backend.setItem(`mindpattern.onboarding.v1.${A}`, "done"); await backend.setItem(`mindpattern.onboarding.v1.${B}`, "done");
 let held = false, fail = options.failAdoption === true, holdOldProcessing = false, oldProcessing: ReturnType<typeof streamed> | undefined;
 let loginA = 0, loginB = 0, processingA = 0, processingB = 0, questionA = 0, questionB = 0, unauthorized = false;
 setKvBackendForTests({ ...backend, async getItem(key) {
  if (fail && key === writeGenerationKey(A)) { fail = false; throw new Error("Local adoption storage temporarily unavailable."); }
  if (options.holdA && !held && key === `mindpattern.onboarding.v1.${A}`) { held = true; await onboarding.promise; }
  return backend.getItem(key);
 } });
 const bLogin = streamed({ token: "account-b", user_id: B, expires_in: 86400, role: "user", key_scheme: "v1" }); let gateB = false;
 const token = (owner: string) => ({ token: owner === A ? "account-a" : "account-b", user_id: owner, expires_in: 86400, role: "user", key_scheme: "v1" });
 stubFetch(async (url, init) => {
  if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT });
  if (url.endsWith("/auth/register")) { const body = JSON.parse(String(init.body)); keysA = await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(body.salt))); if (body.verifier !== toBase64(keysA.authKey)) throw new Error("SetupError: registration fixture verifier mismatch"); loginA++; return jsonResponse(token(A)); }
  if (url.endsWith("/auth/login")) { const body = JSON.parse(String(init.body)); const owner = body.username === "account_a" ? A : B; if (body.verifier !== toBase64((owner === A ? keysA! : keysB).authKey)) throw new Error("SetupError: actual login verifier mismatch"); if (owner === A) { loginA++; return jsonResponse(token(A)); } loginB++; return gateB ? bLogin.response : jsonResponse(token(B)); }
  if (url.endsWith("/auth/logout")) return new Response(null, { status: 204 });
  if (url.endsWith("/meta")) return jsonResponse(unauthorized ? { code: "unauthorized" } : { user_id: A }, { status: unauthorized ? 401 : 200 });
  const owner = new Headers(init.headers).get("Authorization") === "Bearer account-a" ? A : B;
  if (url.endsWith("/questions/today")) { owner === A ? questionA++ : questionB++; const dataKey = (owner === A ? keysA! : keysB).dataKey; const blob = await encrypt(dataKey, new TextEncoder().encode(JSON.stringify({ for_date: DATE, question: owner === A ? A_TEXT : B_TEXT, pattern_pid: "topic:owned" })), buildAad("question", owner, DATE)); return jsonResponse({ for_date: DATE, blob: toBase64(blob) }); }
  if (url.endsWith("/processing/sessions")) { if (owner === A) { processingA++; if (holdOldProcessing) { oldProcessing = streamed({ session_token: "retired-processing", expires_in: 300 }, init.signal); return oldProcessing.response; } } else processingB++; return jsonResponse({ session_token: "active-processing", expires_in: 300 }); }
  if (url.endsWith("/insights/recompute")) return jsonResponse({ phase: "insight" });
  if (url.endsWith("/insights")) return jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null });
  if (url.includes("/entries?")) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
  return jsonResponse({ code: "not_found" }, { status: 404 });
 });
 const originalHash = window.location.hash; window.location.hash = "#/question";
 const root = await render(options.direct ? <LoginView onSuccess={options.direct} /> : <App />);
 return { root, own, onboarding, bLogin, keysB,
  snapshot: () => ({ held, loginA, loginB, processingA, processingB, questionA, questionB }),
  holdProcessing: () => { holdOldProcessing = true; }, holdBLogin: () => { gateB = true; }, expire: () => { unauthorized = true; },
  start: async () => { if (!options.direct) await completion("initial public Login", () => buttonByLabel(root, "Sign in")); await fill(root, mode, "account_a"); },
  settleAdoption: async () => { onboarding.resolve(); await act(async () => { await bounded("actual App adoption FIFO", withLock("account-transition", async () => undefined)); }); await flush(); },
  cleanup: async () => { onboarding.resolve(); bLogin.deliver(); oldProcessing?.deliver(); await act(async () => { root.unmount(); }); for (;;) { const count = pending.length; await act(async () => { await bounded("all real public producers", Promise.allSettled([...pending])); }); if (count === pending.length) break; } await bounded("final App FIFO", withLock("account-transition", async () => undefined)); for (const observer of observers.reverse()) observer.mockRestore(); window.location.hash = originalHash; if (keysA) zeroize(keysA.masterKey, keysA.authKey, keysA.dataKey); zeroize(keysB.masterKey, keysB.authKey, keysB.dataKey); },
 };
}
for (const mode of ["signin", "register"] as const) for (const goal of ["content", "refresh"] as const) it(`${mode} adoption prevents overlap or safely retires prior-account ${goal}`, async () => {
 const h = await harness(mode, { holdA: true });
 try {
  await h.start(); await completion("real A adoption is waiting on ordinary onboarding read", () => h.snapshot().held);
  const action = mode === "signin" ? "Sign in" : "Create journal";
  const admitted = buttonByLabel(h.root, action) && !isDisabled(h.root, action);
  if (admitted) {
   h.holdBLogin(); if (mode === "register") await press(h.root, "I have an account");
   await fill(h.root, "signin", "account_b"); await completion("genuine B login awaits its response body", () => h.snapshot().loginB === 1);
   await h.settleAdoption(); await completion("real decrypted A question", () => textOf(h.root).includes(A_TEXT));
   h.holdProcessing(); await press(h.root, "Refresh patterns"); await completion("A refresh is pending native body", () => h.snapshot().processingA === 1);
   await act(async () => { h.bLogin.deliver(); }); await completion("B owns real session and vault", () => sessionUserId() === B && vault.ownerUserId() === B); await h.settleAdoption();
   if (goal === "content") expect(textOf(h.root)).not.toContain(A_TEXT);
   else expect(buttonByLabel(h.root, "Refresh patterns")).toBe(true);
   expect(isDisabled(h.root, "Refresh patterns")).toBe(false); await press(h.root, "Refresh patterns"); await completion("B public refresh acknowledgement", () => textOf(h.root).includes("Patterns refreshed.")); await completion("B decrypted question", () => textOf(h.root).includes(B_TEXT)); expect(textOf(h.root)).not.toContain(A_TEXT);
  } else {
   // A correct fix may prevent the second admission entirely. Do not call a
   // disabled/retired handler or require the historical retained view.
   expect(isDisabled(h.root, "Working…")).toBe(true); await h.settleAdoption(); await completion("A question after completed adoption", () => textOf(h.root).includes(A_TEXT));
   expect(isDisabled(h.root, "Refresh patterns")).toBe(false); await press(h.root, "Refresh patterns"); await completion("A public refresh acknowledgement", () => textOf(h.root).includes("Patterns refreshed.")); expect(sessionUserId()).toBe(A); expect(h.snapshot().loginB).toBe(0);
  }
 } finally { await h.cleanup(); }
}, 60000);
it("ordinary sign-out then B sign-in preserves the Question route and only B content", async () => {
 const h = await harness("signin");
 try { await h.start(); await completion("A encrypted question", () => textOf(h.root).includes(A_TEXT)); await press(h.root, t("nav.more")); await press(h.root, t("nav.signOut")); await completion("signed-out public Login", () => buttonByLabel(h.root, "Sign in")); expect(textOf(h.root)).not.toContain(A_TEXT); await fill(h.root, "signin", "account_b"); await completion("B encrypted Question route", () => textOf(h.root).includes(B_TEXT)); expect(textOf(h.root)).not.toContain(A_TEXT); expect(isDisabled(h.root, "Refresh patterns")).toBe(false); await press(h.root, "Refresh patterns"); await completion("B refresh acknowledged", () => textOf(h.root).includes("Patterns refreshed.")); }
 finally { await h.cleanup(); }
}, 60000);
it("a local App adoption storage refusal reaches recoverable Settings instead of a stuck transition", async () => {
 const h = await harness("signin", { failAdoption: true });
 try { await h.start(); await completion("public local-adoption recovery error", () => textOf(h.root).includes("Local encrypted records could not be read.")); expect(buttonByLabel(h.root, "Working…")).toBe(false); expect(buttonByLabel(h.root, "Sign in")).toBe(false); expect(hasSession()).toBe(true); expect(vault.ownerUserId()).toBe(A); await press(h.root, t("nav.more")); await press(h.root, t("nav.signOut")); await completion("recovery can sign out", () => buttonByLabel(h.root, "Sign in")); expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false); }
 finally { await h.cleanup(); }
}, 60000);
for (const mode of ["signin", "register"] as const) it(`${mode} supports a synchronous successful public adoption callback`, async () => {
 let accepted = false; const h = await harness(mode, { direct: () => { accepted = true; } });
 try { await h.start(); await completion("synchronous public adoption", () => accepted); expect(hasSession()).toBe(true); expect(vault.ownerUserId()).toBe(A); await completion("working cleared after synchronous callback", () => !buttonByLabel(h.root, "Working…")); }
 finally { await h.cleanup(); }
}, 60000);
for (const mode of ["signin", "register"] as const) for (const kind of ["throw", "reject"] as const) it(`${mode} rolls back its owned failed ${kind} adoption without a stuck action`, async () => {
 const gate = deferred(); let entered = false;
 const h = await harness(mode, { direct: () => { entered = true; if (kind === "throw") throw new Error("application adoption refused"); return gate.promise; } });
 try {
  await h.start(); await completion("actual public callback entered", () => entered);
  if (kind === "reject") { expect(buttonByLabel(h.root, "Working…")).toBe(true); gate.reject(new Error("application adoption refused")); }
  await completion("failed public adoption releases busy", () => !buttonByLabel(h.root, "Working…"));
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false); expect(textOf(h.root)).toContain(t("login.genericWeb"));
 } finally { gate.resolve(); await h.cleanup(); }
}, 60000);
for (const mode of ["signin", "register"] as const) it(`${mode} refuses adoption when a real vault observer already retired the session`, async () => {
 let accepted = false; const h = await harness(mode, { direct: () => { accepted = true; } });
 const off = vault.subscribe(() => { if (vault.isUnlocked() && vault.ownerUserId() === A) clearSession(); });
 try { await h.start(); await completion("retired public action settles", () => !buttonByLabel(h.root, "Working…") && (accepted || textOf(h.root).includes(t("errors.offline")))); expect(accepted).toBe(false); expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false); }
 finally { off(); await h.cleanup(); }
}, 60000);
for (const notification of ["abort", "vault-lock"] as const) it(`failed adoption preserves a successor installed during ${notification} notification`, async () => {
 const h = await harness("signin", { direct: () => { throw new Error("application adoption refused"); } });
 const successor = { authKey: new Uint8Array(h.keysB.authKey), dataKey: new Uint8Array(h.keysB.dataKey) }; let armed = false, installed = false;
 const install = () => { if (installed) return; installed = true; setSession("reentrant-successor-b", B, "account_b"); vault.unlock(successor, B); };
 const observed: { oldSignal: AbortSignal | null } = { oldSignal: null };
 const off = vault.subscribe(() => {
  if (vault.isUnlocked() && vault.ownerUserId() === A) {
   armed = true; observed.oldSignal = sessionAbortSignal(); if (notification === "abort") observed.oldSignal?.addEventListener("abort", install, { once: true });
  } else if (notification === "vault-lock" && armed && !vault.isUnlocked()) { armed = false; install(); }
 });
 try { await h.start(); await completion("failed action settled", () => !buttonByLabel(h.root, "Working…") && textOf(h.root).includes(t("login.genericWeb"))); expect(installed).toBe(true); expect(sessionUserId()).toBe(B); expect(vault.ownerUserId()).toBe(B); expect(vault.get().authKey).toBe(successor.authKey); expect(vault.get().dataKey).toBe(successor.dataKey); expect(successor.dataKey.some(value => value !== 0)).toBe(true); }
 finally { off(); observed.oldSignal?.removeEventListener("abort", install); await h.cleanup(); zeroize(successor.authKey, successor.dataKey); }
}, 60000);
it("real API 401 supersession releases old adoption and permits a genuine B login before old storage finishes", async () => {
 const h = await harness("signin", { holdA: true });
 try {
  await h.start(); await completion("actual A adoption waits on storage", () => h.snapshot().held);
  h.expire(); await act(async () => { await h.own(api.meta()).catch(() => undefined); });
  await completion("real expiry funnel makes Login usable", () => buttonByLabel(h.root, "Sign in") && !isDisabled(h.root, "Sign in"));
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false);
  await fill(h.root, "signin", "account_b"); await completion("B authenticates before releasing old A storage", () => h.snapshot().loginB === 1 && sessionUserId() === B && vault.ownerUserId() === B);
  await h.settleAdoption(); await completion("B Question after old adoption drains", () => textOf(h.root).includes(B_TEXT));
  expect(textOf(h.root)).not.toContain(A_TEXT); expect(isDisabled(h.root, "Refresh patterns")).toBe(false); await press(h.root, "Refresh patterns"); await completion("B refresh remains usable", () => textOf(h.root).includes("Patterns refreshed."));
 } finally { await h.cleanup(); }
}, 60000);
