/** native host lifetime witness. Actual public App/Login/MFA,
 * authenticated charts, writing and navigation produce encrypted draft saves.
 * Native async_hooks observes only weak Promise references; no Map is read. */
import { createHook } from "node:async_hooks";
import { createCipheriv, createDecipheriv, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import { setKvBackendForTests } from "../src/kvstore";

const PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
type Allocation = { weak: WeakRef<Promise<unknown>>; scope: string; origin: string; settled: boolean };
const observed = new Map<number, Allocation>();
const controls = new Map<string, Promise<void>>();
let currentScope: string | null = null;
let witness: Record<string, unknown> = {};
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const save = () => { if (process.env.FRONTEND_PORTAL_DRAFT_COLLECTION_RECEIPT) writeFileSync(process.env.FRONTEND_PORTAL_DRAFT_COLLECTION_RECEIPT, JSON.stringify(witness, null, 2) + "\n"); };
const observer = createHook({
  init(id, type, _triggerId, resource: unknown) {
    if (type !== "PROMISE" || currentScope === null) return;
    const origin = (new Error().stack ?? "").split("\n").find(frame => /\bsavePortalDraft\b/.test(frame) && frame.includes("/src/noteDrafts.ts"));
    if (origin) observed.set(id, { weak: new WeakRef(resource as Promise<unknown>), scope: currentScope, origin: origin.trim(), settled: false });
  },
  promiseResolve(id) { const allocation = observed.get(id); if (allocation) allocation.settled = true; },
});

const text = (node: unknown): string => {
  const children = (node as { children?: unknown[] } | null)?.children;
  return Array.isArray(children) ? children.map(child => typeof child === "string" || typeof child === "number" ? String(child) : text(child)).join("") : "";
};
const rendered = (root: ReactTestRenderer) => text(root.root);
async function flush() { for (let i = 0; i < 8; i++) await act(async () => { await Promise.resolve(); }); }
async function complete(label: string, ready: () => boolean) {
  const end = Date.now() + 15_000;
  while (!ready()) { if (Date.now() >= end) throw new Error(`SetupError: draft producer completion deadline ${label}`); await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); }); }
  await flush();
}
async function press(root: ReactTestRenderer, label: string, index = 0) {
  const button = root.root.findAllByType("button").filter(node => text(node) === label)[index];
  if (!button || button.props.disabled) throw new Error(`SetupError: enabled public button unavailable ${label}/${index}`);
  await act(async () => { const event = { preventDefault() {} }; if (button.props.type === "submit") {
    let parent = button.parent; while (parent && parent.type !== "form") parent = parent.parent;
    if (!parent) throw new Error("SetupError: public submit has no owning form"); parent.props.onSubmit(event);
  } else button.props.onClick(event); });
}
async function input(root: ReactTestRenderer, label: string, value: string) {
  const field = root.root.findAllByType("input").find(node => {
    const explicit = root.root.findAllByType("label").find(owner => owner.props.htmlFor === node.props.id && text(owner).includes(label));
    if (explicit) return true;
    let owner = node.parent; while (owner && owner.type !== "label") owner = owner.parent;
    return owner !== null && text(owner).includes(label);
  });
  if (!field || field.props.disabled) throw new Error(`SetupError: enabled public input unavailable ${label}`);
  await act(async () => field.props.onChange({ target: { value } }));
}
function sealed(key: Buffer, aad: string[], plain: Buffer): string {
  const nonce = randomBytes(12), associated = Buffer.from(JSON.stringify(aad)), cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(associated); const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]), tag = cipher.getAuthTag();
  const verify = createDecipheriv("aes-256-gcm", key, nonce); verify.setAAD(associated); verify.setAuthTag(tag);
  const opened = Buffer.concat([verify.update(encrypted), verify.final()]);
  try { if (!opened.equals(plain)) throw new Error("SetupError: independent fixture wire authentication failed"); }
  finally { opened.fill(0); }
  return Buffer.concat([nonce, encrypted, tag]).toString("base64");
}
function openedDraft(key: Buffer, blob: string, owner: string, patient: string) {
  const bytes = Buffer.from(blob, "base64"), decryptor = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
  decryptor.setAAD(Buffer.from(JSON.stringify(["portal-draft", owner, patient]))); decryptor.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decryptor.update(bytes.subarray(12, -16)), decryptor.final()]);
  try { return JSON.parse(plain.toString("utf8")) as { v: number; state: { text: { general?: string } } }; }
  finally { plain.fill(0); }
}
function account(index: number) {
  const username = `synthetic_draft_owner_${index}`, owner = `${index}`.padStart(32, "0"), token = `synthetic-draft-owner-token-${index}`;
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/portal-wrap/v1", 32));
  const identity = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = identity.privateKey.export({ format: "der", type: "pkcs8" });
  const publicDer = identity.publicKey.export({ format: "der", type: "spki" });
  const noteKey = Buffer.from(hkdfSync("sha256", privateDer, Buffer.alloc(32), "mindpattern/portal-notes/v2", 32));
  try {
    const patients = Array.from({ length: 6 }, (_, at) => {
      const patient = `${index}${at + 1}`.padStart(32, "0"), label = `Synthetic draft patient ${index}/${at + 1}`, key = randomBytes(32);
      const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), ephemeralPublic = ephemeral.publicKey.export({ format: "der", type: "spki" });
      const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: identity.publicKey });
      const consentKey = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeralPublic, publicDer]), "mindpattern/wrap/v1", 32));
      try { return { key, patient, label, row: { user_id: patient, username: label, status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null, share_voice: false,
        ephemeral_pub: ephemeralPublic.toString("base64"), wrapped_key: sealed(consentKey, ["consent-wrap", patient, owner], key) },
        insights: { phase: "insight", active_days: 4, streak: 1, days_remaining: 0, state_seq: 7,
          blob: sealed(key, ["insights", patient, "patterns"], Buffer.from(JSON.stringify({ v: 2, state_seq: 7, stats: { avg_sentiment: 0, total_entries: 4, active_days: 4, patterns: [] } }))) } }; }
      finally { shared.fill(0); consentKey.fill(0); }
    });
    return { username, owner, token, verifier: auth.toString("base64"), publicKeyB64: publicDer.toString("base64"),
      envelope: sealed(wrap, ["therapist-key", username], privateDer), noteKey, patients };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0); }
}
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function collect() {
  if (typeof gc !== "function") throw new Error("SetupError: native Promise lifetime requires fork Node --expose-gc");
  await turn(); gc(); await turn();
}
function collectible() { return new WeakRef(Promise.resolve()); }
function retained(stage: string) { const promise = Promise.resolve(); controls.set(stage, promise); return new WeakRef(promise); }
async function verifyCollector(stage: string) {
  const positive = retained(stage), negative = collectible();
  try { for (let attempt = 0; attempt < 20; attempt++) { await collect(); if (negative.deref() === undefined && positive.deref() === controls.get(stage)) {
    witness.collectorControls = [...(witness.collectorControls as unknown[] ?? []), { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true, resource: "fulfilled-native-Promise" }]; return;
  } } throw new Error("SetupError: native Promise positive/negative controls did not complete"); }
  finally { controls.delete(stage); save(); }
}

async function publicDraftProducers() {
  const accounts = [account(1), account(2)], storage = new Map<string, string>(), commits = new Map<string, number>();
  let root: ReactTestRenderer | undefined, current = accounts[0]!, mfa = false;
  const publicStages: unknown[] = [], retiredOwners: string[] = [];
  setKvBackendForTests({ getItem: async id => storage.get(id) ?? null, removeItem: async id => { storage.delete(id); },
    setItem: (id, blob) => { const original = Promise.resolve().then(() => { storage.set(id, blob); commits.set(id, (commits.get(id) ?? 0) + 1); }); return original; } });
  vi.stubGlobal("fetch", async (request: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof request === "string" ? request : request instanceof URL ? request.href : request.url), path = url.pathname;
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: plaintext password crossed synthetic backend");
    if (path === "/api/v1/meta") return response({ sharing_available: true });
    if (path === "/api/v1/auth/salt") return response({ salt: SALT });
    if (path === "/api/v1/auth/login") {
      if (body.username !== current.username || body.verifier !== current.verifier) throw new Error("SetupError: genuine600k public verifier mismatch");
      if (body.totp_code === undefined) return response({ code: "totp_required", detail: "MFA is required" }, 401);
      if (body.totp_code !== "123456") throw new Error("SetupError: public MFA mismatch"); mfa = true;
      return response({ token: current.token, user_id: current.owner, role: "therapist", expires_in: 86400, mfa_enrollment_required: false });
    }
    if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
    if (!mfa || new Headers(init?.headers).get("Authorization") !== `Bearer ${current.token}`) throw new Error("SetupError: current therapist bearer/MFA missing");
    if (path === "/api/v1/therapist/me") return response({ username: current.username, display_name: `Dr. Draft ${current.owner}`, wrap_pub_key: current.publicKeyB64, wrap_key_blob: current.envelope, totp_enabled: true });
    if (path === "/api/v1/therapist/patients") return response(current.patients.map(patient => patient.row));
    const patient = current.patients.find(patient => path.includes(`/patients/${patient.patient}/`));
    if (patient && path.endsWith("/insights")) return response(patient.insights);
    if (patient && (path.endsWith("/notes") || path.endsWith("/measures"))) return response([]);
    throw new Error(`SetupError: unsupported actual producer ${path}`);
  });
  try {
    observer.enable(); await act(async () => { root = RTR.create(<App />); });
    for (const next of accounts) {
      current = next; mfa = false;
      await input(root!, "Username", current.username); await input(root!, "Password", PASSWORD); await press(root!, "Sign in");
      await complete("mandatory MFA challenge", () => rendered(root!).includes("Verify code"));
      if (hasSession()) throw new Error("SetupError: password-only session bypassed public MFA");
      await input(root!, "Authenticator code (or recovery code)", "123456"); await press(root!, "Verify code");
      await complete("authenticated caseload", () => rendered(root!).includes(current.patients[0]!.label) && hasSession());
      for (let at = 0; at < current.patients.length; at++) {
        const patient = current.patients[at]!, id = `portal.draft.${current.owner}.${patient.patient}`, writing = `Owned acknowledged draft ${current.username}/${patient.patient}`;
        currentScope = `${current.owner}:${patient.patient}`;
        await press(root!, "Open patterns", at);
        await complete("authenticated chart and restored local draft", () => rendered(root!).includes("General notes about this patient") && rendered(root!).includes("Drafts are encrypted on this device."));
        const field = root!.root.findAllByType("textarea").find(node => node.props.placeholder === "Note about this patient…");
        if (!field || field.props.disabled) throw new Error("SetupError: restored public draft composer unavailable");
        await act(async () => field.props.onChange({ target: { value: writing } }));
        await press(root!, "Back to patients");
        await complete("actual last draft write commit on chart retirement", () => storage.has(id) && rendered(root!).includes(current.patients[0]!.label));
        const saved = openedDraft(current.noteKey, storage.get(id)!, current.owner, patient.patient);
        if (saved.v !== 1 || saved.state.text.general !== writing) throw new Error("SetupError: public writing did not independently authenticate under its actual owner/patient AAD");
        publicStages.push({ owner: current.owner, patient: patient.patient, password600kAndMfa: true, actualChartWriting: true, actualBackNavigation: true, encryptedCommit: true, independentDraftAuthenticated: true, commitCount: commits.get(id) });
        currentScope = null;
      }
      await press(root!, "Sign out"); await complete("completed public owner retirement", () => !hasSession() && rendered(root!).includes("Sign in"));
      retiredOwners.push(current.owner);
    }
    await complete("all attributed native draft Promises settled", () => observed.size > 0 && [...observed.values()].every(allocation => allocation.settled));
    witness.publicProducerStages = publicStages; witness.actualPublicOwnerCount = accounts.length; witness.actualPublicDraftScopeCount = publicStages.length;
    witness.completedPublicOwnerRetirements = retiredOwners;
  } finally {
    currentScope = null; if (root) { await act(async () => root!.unmount()); root = undefined; }
    observer.disable(); vi.clearAllMocks(); vi.restoreAllMocks(); vi.unstubAllGlobals(); setKvBackendForTests(null);
    for (const owner of accounts) { owner.noteKey.fill(0); for (const patient of owner.patients) patient.key.fill(0); }
    await flush();
  }
  witness.originalProductionPromisesUnmodified = true; witness.observerDisabledBeforeGc = true;
  witness.actualAppUnmountCompleted = true; witness.ownedRendererAndNativeMocksReleased = true;
}

afterEach(() => { observer.disable(); currentScope = null; controls.clear(); vi.clearAllMocks(); vi.restoreAllMocks(); vi.unstubAllGlobals(); setKvBackendForTests(null); clearSession(); save(); });
it("releases fulfilled native draft-write Promises after legitimate clinician chart navigation", async () => {
  vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; observed.clear();
  witness = { stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", collectorControls: [],
    limits: ["Native Node fulfilled Promise lifetime only; no plaintext-retention, browser/device GC, attacker access or physical OOM claim.",
      "Two legitimate synthetic clinician accounts and six independently authenticated patients each; actual public Login/MFA/chart-writing/navigation/signout consumers.",
      "Only WeakRef plus primitive native allocation/settlement metadata are retained; no private draft Map or source-equality oracle.",
      "Existing helper test-only drain is not imported, so an omitted cleanup cannot manufacture a teardown watchdog kill."] };
  await verifyCollector("before-public-producers"); witness.stage = "public-producers";
  await publicDraftProducers(); await verifyCollector("after-public-producers");
  const allocations = [...observed.values()];
  if (allocations.length < 12 || new Set(allocations.map(value => value.scope)).size !== 12 || allocations.some(value => !value.settled)) throw new Error("SetupError: native allocation attribution did not cover all completed public draft scopes");
  let attempts = 0; for (; attempts < 20; attempts++) { await collect(); if (allocations.every(value => value.weak.deref() === undefined)) break; }
  const retained = allocations.filter(value => value.weak.deref() !== undefined).length;
  witness.stage = "behavior-resource-assertion"; witness.collectionAttempts = attempts + 1;
  witness.observedNativePromiseCount = allocations.length; witness.retainedNativePromiseCount = retained;
  witness.allocations = allocations.map(value => ({ scope: value.scope, origin: value.origin, settled: value.settled })); save();
  expect(retained).toBe(0); witness.stage = "passed"; save();
}, 60000);
