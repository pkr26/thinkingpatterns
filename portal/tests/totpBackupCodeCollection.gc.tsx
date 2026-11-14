/** Node22 collection contract for the real TOTP API response allocation.
 * Observe its public Promise without replacing it or inspecting React state. */
import { generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { PatientsView } from "../src/views/PatientsView";
import { api, clearSession, setSession } from "../src/api";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const controls = new Map<string, string[]>();
let root: ReactTestRenderer | undefined;
let restoreObserver: (() => void) | undefined;
let witness: Record<string, unknown> = {};
const save = () => { if (process.env.FRONTEND_PORTAL_TOTP_COLLECTION_RECEIPT) writeFileSync(process.env.FRONTEND_PORTAL_TOTP_COLLECTION_RECEIPT, JSON.stringify(witness, null, 2) + "\n"); };
async function collect(): Promise<void> {
  if (typeof gc !== "function") throw new Error("SetupError: TOTP response collector requires exposed Node GC");
  await turn(); gc(); await turn();
}
async function releasedControl(): Promise<WeakRef<string[]>> { return new WeakRef(["native-control-a", "native-control-b"]); }
async function retainedControl(stage: string): Promise<WeakRef<string[]>> { const value = ["native-control-a", "native-control-b"]; controls.set(stage, value); return new WeakRef(value); }
async function validateCollector(stage: string): Promise<void> {
  const retained = await retainedControl(stage), released = await releasedControl();
  try {
    for (let attempt = 0; attempt < 20; attempt++) {
      await collect();
      if (released.deref() === undefined && retained.deref() === controls.get(stage)) {
        witness.collectorControls = [...(witness.collectorControls as unknown[] ?? []), { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true, resource: "public-backup-code-array" }]; save(); return;
      }
    }
    throw new Error("SetupError: backup code collection controls did not settle");
  } finally { controls.delete(stage); }
}
async function completed(label: string, ready: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt++) {
    if (ready()) { await flush(); return; }
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  throw new Error(`SetupError: public TOTP completion absent: ${label}`);
}
afterEach(async () => { restoreObserver?.(); restoreObserver = undefined; await act(async () => root?.unmount()); root = undefined; clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals(); save(); });

it("releases the accepted one-time recovery code array after public two-factor disable", async () => {
  witness = { nodeVersion: process.version, gcCapability: typeof gc === "function", stage: "started", collectorControls: [], limits: ["Node22 array lifetime after public TOTP actions on the production PatientsView with genuine independently derived session keys and synthetic accepted API responses.", "The original production API Promise is forwarded unchanged; only its public recovery-code array is observed through a WeakRef. No React state or private queue access.", "This does not measure browser/device physical memory erasure or string allocation copies."] };
  try {
    await validateCollector("before-public-producer");
    const username = "native_totp_collection", owner = "0123456789abcdef0123456789abcdef", password = "correct horse battery staple";
    const salt = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"), master = pbkdf2Sync(password, salt, 600_000, 32, "sha256");
    const derive = (label: string) => new Uint8Array(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from(label), 32));
    const verifierBytes = derive("mindpattern/auth/v1"), verifier = Buffer.from(verifierBytes).toString("base64"), noteKey = derive("mindpattern/portal-notes/v1");
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), der = pair.privateKey.export({ format: "der", type: "pkcs8" });
    const noteKeyV2 = new Uint8Array(hkdfSync("sha256", der, Buffer.alloc(32), "mindpattern/portal-notes/v2", 32));
    const privateKey = await crypto.subtle.importKey("pkcs8", new Uint8Array(der), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const publicKeyB64 = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
    master.fill(0); verifierBytes.fill(0); der.fill(0);
    let enabled = false, acceptedEnable = 0, acceptedDisable = 0, passwordProofs = 0;
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
      if (path === "/api/v1/therapist/patients") return Response.json([]);
      if (path === "/api/v1/therapist/me") return Response.json({ username, display_name: "Dr. Native TOTP", wrap_pub_key: publicKeyB64, wrap_key_blob: "unused-current-profile", totp_enabled: enabled });
      if (path === "/api/v1/auth/salt") return Response.json({ salt: salt.toString("base64") });
      const body = JSON.parse(String(init?.body));
      if (body.verifier !== verifier || new Headers(init?.headers).get("Authorization") !== "Bearer native-totp-collection") throw new Error("SetupError: real TOTP request lacks independently derived proof/owner");
      passwordProofs++;
      if (path === "/api/v1/account/totp/setup") return Response.json({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:native?secret=JBSWY3DPEHPK3PXP" });
      if (body.code !== "123456") throw new Error("SetupError: native TOTP confirmation code differs");
      if (path === "/api/v1/account/totp/enable") { enabled = true; acceptedEnable++; return new Response('{"backup_codes":["native-accepted-backup-a","native-accepted-backup-b"]}', { headers: { "Content-Type": "application/json" } }); }
      if (path === "/api/v1/account/totp/disable") { enabled = false; acceptedDisable++; return Response.json({}); }
      throw new Error(`SetupError: unexpected TOTP route ${path}`);
    });
    let allocation: WeakRef<string[]> | undefined, observed = 0;
    const descriptor = Object.getOwnPropertyDescriptor(api, "totpEnable"), original = api.totpEnable;
    Object.defineProperty(api, "totpEnable", { ...descriptor, value: function (this: unknown, ...args: Parameters<typeof api.totpEnable>) {
      const promise = Reflect.apply(original, this, args) as ReturnType<typeof api.totpEnable>;
      void promise.then(value => { if (Array.isArray(value.backup_codes)) { allocation = new WeakRef(value.backup_codes); observed++; } }, () => undefined);
      return promise;
    } });
    restoreObserver = () => { Object.defineProperty(api, "totpEnable", descriptor!); };
    clearSession(); window.localStorage.clear(); window.sessionStorage.clear();
    setSession("native-totp-collection", "http://localhost:5173");
    root = await render(<PatientsView displayName="Dr. Native TOTP" session={{ username, userId: owner, noteKey, noteKeyV2, privateKey, publicKeyB64 }} onOpen={() => {}} onSignOut={() => {}} />);
    await flush(); await press(root, "Show account security"); await completed("setup available", () => textOf(root!).includes("Set up authenticator"));
    await typeInto(root, "Current password (to authorize setup)", password); await press(root, "Set up authenticator"); await completed("enable available", () => textOf(root!).includes("Enable two-factor"));
    await typeInto(root, "Current password (to authorize setup)", password); await typeInto(root, "6-digit code from the app", "123456"); await press(root, "Enable two-factor");
    await completed("accepted recovery codes visible", () => textOf(root!).includes("native-accepted-backup-a"));
    restoreObserver(); restoreObserver = undefined;
    if (observed !== 1 || allocation?.deref() === undefined) throw new Error("SetupError: accepted public API array was not positively observed");
    await typeInto(root, "Current password (to disable two-factor)", password); await typeInto(root, "6-digit code (to disable two-factor)", "123456"); await press(root, "Disable two-factor");
    await completed("disable acknowledged", () => textOf(root!).includes("Two-factor authentication is off."));
    // These are ordinary current form edits, retiring previous React commits.
    for (const text of ["next", "next current", "next current password"]) await typeInto(root, "Current password (to authorize setup)", text);
    witness.publicProducer = { complete: true, authenticatedSession: true, genuine600kPasswordProofs: passwordProofs === 3, acceptedEnable: acceptedEnable === 1, acceptedDisable: acceptedDisable === 1, codeArrayWasPubliclyVisible: true, disabledCodesAbsent: !textOf(root).includes("native-accepted-backup-a"), currentWritingCompleted: true };
    witness.observedBackupCodeArrays = observed; witness.observerRestoredBeforeCollection = true; witness.originalProductionPromiseForwarded = true;
    await validateCollector("after-public-producer");
    let attempts = 0;
    for (; attempts < 20; attempts++) { await collect(); if (allocation!.deref() === undefined) break; }
    witness.collectionAttempts = attempts + 1;
    witness.retainedBackupCodeArrayCount = allocation!.deref() === undefined ? 0 : 1; witness.stage = "asserting"; save();
    expect(witness.retainedBackupCodeArrayCount).toBe(0);
    witness.stage = "passed"; save();
  } catch (error) { witness.stage = "failed"; witness.failure = String(error); save(); throw error; }
}, 30_000);
