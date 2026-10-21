/** genuine native CryptoKey lifetime witness after actual portal
 * login/MFA and renderer unmount. No private React queue or callback registry
 * is inspected or changed. Every native import Promise is forwarded intact. */
import { createCipheriv, createDecipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import { flush, press, textOf, typeInto } from "./helpers/rtr";

const USERNAME = "synthetic_portal_key_lifetime";
const PASSWORD = "correct horse battery staple";
const OWNER = "1234567890abcdef1234567890abcdef";
const TOKEN = "synthetic-private-key-lifetime-token";
const SALT = Buffer.from("AAECAwQFBgcICQoLDA0ODw==", "base64");
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
const controls = new Map<string, CryptoKey>();
const imported: WeakRef<CryptoKey>[] = [];
let witness: Record<string, unknown> = {};
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const save = () => { if (process.env.FRONTEND_PORTAL_KEY_COLLECTION_RECEIPT) writeFileSync(process.env.FRONTEND_PORTAL_KEY_COLLECTION_RECEIPT, JSON.stringify(witness, null, 2) + "\n"); };

async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`SetupError: native key lifetime producer deadline ${label}`)), 15_000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

function privateDer(): Buffer {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ format: "der", type: "pkcs8" });
}

async function controlKey(): Promise<CryptoKey> {
  const der = privateDer(), bytes = new Uint8Array(der);
  try { return await finite(crypto.subtle.importKey("pkcs8", bytes, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]), "control import"); }
  finally { der.fill(0); bytes.fill(0); }
}

async function negativeKey(): Promise<WeakRef<CryptoKey>> { return new WeakRef(await controlKey()); }
async function positiveKey(stage: string): Promise<WeakRef<CryptoKey>> {
  const key = await controlKey(); controls.set(stage, key); return new WeakRef(key);
}

async function collect(): Promise<void> {
  if (typeof gc !== "function") throw new Error("SetupError: native CryptoKey collector requires Node --expose-gc");
  await turn(); gc(); await turn();
}

async function validateCollector(stage: string): Promise<void> {
  const positive = await positiveKey(stage), negative = await negativeKey();
  try {
    for (let attempt = 0; attempt < 20; attempt++) {
      await collect();
      if (negative.deref() === undefined && positive.deref() === controls.get(stage)) {
        witness.collectorControls = [...(witness.collectorControls as unknown[] ?? []), { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true, algorithm: "ECDH/P-256", extractable: false }];
        return;
      }
    }
    throw new Error("SetupError: native positive/negative CryptoKey collector controls did not complete");
  } finally { controls.delete(stage); save(); }
}

function fixture(): { verifier: string; publicKeyB64: string; envelope: string } {
  const master = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/portal-wrap/v1", 32));
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const nonce = randomBytes(12), aad = Buffer.from(JSON.stringify(["therapist-key", USERNAME]));
  try {
    const cipher = createCipheriv("aes-256-gcm", wrap, nonce); cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(der), cipher.final()]), tag = cipher.getAuthTag();
    const decipher = createDecipheriv("aes-256-gcm", wrap, nonce); decipher.setAAD(aad); decipher.setAuthTag(tag);
    const opened = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    try { if (!opened.equals(der)) throw new Error("SetupError: independent therapist envelope authentication failed"); }
    finally { opened.fill(0); }
    return { verifier: auth.toString("base64"), publicKeyB64: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"), envelope: Buffer.concat([nonce, encrypted, tag]).toString("base64") };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); der.fill(0); }
}

const response = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
async function complete(root: ReactTestRenderer, label: string, ready: () => boolean): Promise<void> {
  const end = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= end) throw new Error(`SetupError: actual portal producer deadline ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  await flush();
  // Keep this parameter useful without retaining the renderer after return.
  if (!root.root) throw new Error("SetupError: actual portal renderer disappeared");
}

async function publicLoginAndUnmount(): Promise<void> {
  const account = fixture();
  let root: ReactTestRenderer | undefined;
  const original = crypto.subtle.importKey;
  const forward = ((...args: unknown[]) => {
    const promise = Reflect.apply(original, crypto.subtle, args) as Promise<CryptoKey>;
    if (args[0] === "pkcs8") promise.then(key => {
      if (key.type === "private" && key.algorithm.name === "ECDH") imported.push(new WeakRef(key));
    }, () => undefined);
    return promise;
  }) as SubtleCrypto["importKey"];
  const spy = vi.spyOn(crypto.subtle, "importKey").mockImplementation(forward);
  let observerRestored = false;
  const restoreObserver = () => { if (!observerRestored) { spy.mockRestore(); observerRestored = true; } };
  let passwordChallenge = false, acceptedMfa = false, authenticatedProfile = false, caseloadLoaded = false;
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(url).pathname, body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: password crossed the actual server seam");
    if (path === "/api/v1/meta") return response({ sharing_available: true });
    if (path === "/api/v1/auth/salt") return response({ salt: SALT.toString("base64") });
    if (path === "/api/v1/auth/login") {
      if (body.username !== USERNAME || body.verifier !== account.verifier) throw new Error("SetupError: actual 600k verifier differs from independent fixture");
      if (body.totp_code === undefined) { passwordChallenge = true; return response({ code: "totp_required", detail: "MFA is required" }, 401); }
      if (body.totp_code !== "123456") throw new Error("SetupError: public MFA code was not supplied");
      acceptedMfa = true; return response({ token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86_400 });
    }
    if (path === "/api/v1/therapist/me") {
      if (!acceptedMfa || new Headers(init?.headers).get("Authorization") !== `Bearer ${TOKEN}`) throw new Error("SetupError: unauthenticated therapist identity producer");
      authenticatedProfile = true; return response({ username: USERNAME, display_name: "Dr. Synthetic Lifetime", wrap_pub_key: account.publicKeyB64, wrap_key_blob: account.envelope, totp_enabled: true });
    }
    if (path === "/api/v1/therapist/patients") { caseloadLoaded = true; return response([]); }
    if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
    throw new Error(`SetupError: unexpected actual portal request ${path}`);
  });
  try {
    await act(async () => { root = RTR.create(<App />); });
    await typeInto(root!, "Username", USERNAME); await typeInto(root!, "Password", PASSWORD); await press(root!, "Sign in");
    await complete(root!, "password completed into MFA", () => textOf(root!).includes("Verify code"));
    if (!passwordChallenge || authenticatedProfile || hasSession()) throw new Error("SetupError: password-only gate did not preserve mandatory MFA");
    await typeInto(root!, "Authenticator code (or recovery code)", "123456"); await press(root!, "Verify code");
    await complete(root!, "actual authenticated caseload", () => caseloadLoaded && textOf(root!).includes("No patients are sharing with you yet"));
    if (!acceptedMfa || !authenticatedProfile || !hasSession() || imported.length === 0 || !textOf(root!).includes("Patients — Dr. Synthetic Lifetime")) throw new Error("SetupError: actual authenticated private-key owner did not complete");
    witness.publicProducer = { complete: true, password600kVerifierMatched: true, passwordOnlyProfileBlocked: true, acceptedPublicMfa: true, authenticatedIdentityEnvelopeOpened: true, actualCaseloadLoaded: true };
    // Release the spy's stored fulfilled original import Promises immediately
    // after the completed public adoption, before the real unmount.
    restoreObserver(); await Promise.resolve();
    witness.observerRestoredBeforeUnmount = true;
  } finally {
    if (root) { await act(async () => root!.unmount()); root = undefined; }
    // mockRestore clears the spy's stored fulfilled Promises as well as
    // restoring the function; those Promises must not retain observed keys.
    restoreObserver(); vi.unstubAllGlobals(); await flush();
  }
  if (hasSession()) throw new Error("SetupError: actual App unmount did not retire its API bearer");
  witness.realUnmountCompleted = true;
}

afterEach(() => { controls.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); clearSession(); save(); });

it("collects the imported nonextractable private key after actual portal unmount", async () => {
  vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = "";
  imported.length = 0;
  witness = { stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", limits: ["Genuine Node ECDH/P-256 CryptoKey weak lifetime, not browser/device hardware or attacker compromise.", "Actual portal Login/MFA/session/caseload/unmount with synthetic independently authenticated server fixtures and existing Node storage/event seams.", "One retained global callback at most until next registration; no unbounded per-key growth claim.", "Only WeakRef observes imported handles; no private React queue/registry writes or source-call count oracle."] };
  await validateCollector("before-public-producer");
  witness.stage = "public-producer";
  await publicLoginAndUnmount();
  await validateCollector("after-public-producer");
  let attempts = 0;
  for (; attempts < 20; attempts++) { await collect(); if (imported.every(weak => weak.deref() === undefined)) break; }
  const retained = imported.filter(weak => weak.deref() !== undefined).length;
  witness.stage = "behavior-resource-assertion"; witness.collectionAttempts = attempts + 1;
  witness.observedNativePrivateKeys = imported.length; witness.retainedPrivateKeyCount = retained; save();
  expect(retained).toBe(0);
  witness.stage = "passed"; save();
}, 60000);
