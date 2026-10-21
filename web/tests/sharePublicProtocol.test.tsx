/** public workflow supplement. Real App/Login/Share, vault, API,
 * password verification and native P-256/PBKDF2/HKDF/AES are unchanged.
 * Only the loopback server transport, persistent KV and origin Web Locks use
 * the existing Node renderer seams. This is not backend/device coverage.
 */
import { createCipheriv, createDecipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, hasSession, type ListedConsent, type StepUpAction } from "../src/api/client";
import * as reauth from "../src/reauth";
import * as sharing from "../src/crypto/sharing";
import { applyLanguagePref, t } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, press, pressSwitch, render, setCheckbox, textOf, typeInto } from "./helpers/rtr";

const OWNER = "0123456789abcdef0123456789abcdef";
const THERAPIST = "fedcba9876543210fedcba9876543210";
const CONSENT = "a".repeat(32);
const USERNAME = "synthetic_share_protocol";
const PASSWORD = "public share protocol password";
const SALT = Buffer.from("00112233445566778899aabbccddeeff", "hex");
const MASTER = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
const EXPECTED_AUTH = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
const EXPECTED_DATA = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), Buffer.from("mindpattern/data/v1"), 32));
MASTER.fill(0);
const therapist = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const SPKI = therapist.publicKey.export({ type: "spki", format: "der" });
const FINGERPRINT = createHash("sha256").update(SPKI).digest("hex").slice(0, 32).toUpperCase().match(/.{4}/g)!.join(" ");
type Wire = { path: string; method: string; body: Record<string, unknown> | null; proof: string | null; bearer: string | null; accepted?: boolean; action?: string };
type Transfer = { key: Uint8Array; before: Uint8Array; settled: Promise<void> };
type NativeErrorSignature = { name: string; message: string; constructorName: string; code: undefined };
type NativeAuthenticationControl = { algorithm: "aes-256-gcm"; positiveRoundtrip: true; nonceBytes: 12; plaintextBytes: 32; tagBytes: 16; positivePlaintext: number[]; rejectionSignature: NativeErrorSignature };
type State = { case: string; stage: string; wires: Wire[]; unexpected: string[]; rows: ListedConsent[]; proofs: Map<string, StepUpAction>; issued: string[]; consumed: string[]; transfers: Transfer[]; settled: Promise<void>[]; root?: ReactTestRenderer; rejectDisclosure: boolean; nativeAuthenticationControl: NativeAuthenticationControl };
let current: State | undefined;

function nativeAuthenticationSignature(error: unknown): NativeErrorSignature | undefined {
  if (!(error instanceof Error) || error.constructor !== Error || error.name !== "Error" || error.message !== "Unsupported state or unable to authenticate data" || (error as Error & { code?: unknown }).code !== undefined) return undefined;
  return { name: error.name, message: error.message, constructorName: error.constructor.name, code: undefined };
}
function independentAuthenticationControl(): NativeAuthenticationControl {
  // Genuine independent encoder/decoder control, including a deliberately
  // damaged private control tag. No production wire or implementation changes.
  const key = Buffer.alloc(32, 0x42), nonce = Buffer.alloc(12, 0x24), plain = Buffer.alloc(32, 0x65), aad = Buffer.from("synthetic-independent-share-decoder-control");
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(aad);
    const encoded = Buffer.concat([cipher.update(plain), cipher.final()]), tag = cipher.getAuthTag();
    const positive = createDecipheriv("aes-256-gcm", key, nonce); positive.setAAD(aad); positive.setAuthTag(tag);
    const opened = Buffer.concat([positive.update(encoded), positive.final()]);
    if (!opened.equals(plain) || tag.length !== 16) throw new Error("ExecutionError: independent native AES control did not complete its positive roundtrip");
    const badTag = Buffer.from(tag); badTag[0] = badTag[0]! ^ 1;
    const negative = createDecipheriv("aes-256-gcm", key, nonce); negative.setAAD(aad); negative.setAuthTag(badTag); negative.update(encoded);
    let rejectionSignature: NativeErrorSignature | undefined;
    try { negative.final(); } catch (error) { rejectionSignature = nativeAuthenticationSignature(error); if (!rejectionSignature) throw error; }
    if (!rejectionSignature) throw new Error("ExecutionError: independent native AES control did not reject its damaged tag");
    return { algorithm: "aes-256-gcm", positiveRoundtrip: true, nonceBytes: 12, plaintextBytes: 32, tagBytes: 16, positivePlaintext: [...opened], rejectionSignature };
  } catch (error) {
    throw new Error("ExecutionError: independent native AES authentication control unavailable", { cause: error });
  } finally { key.fill(0); plain.fill(0); }
}
class AuthenticatedWrapRejection extends Error {
  readonly kind = "supported-native-aes-gcm-authentication-rejection";
  constructor(readonly nativeSignature: NativeErrorSignature) { super("Completed Share wire failed independently controlled native AES-GCM authentication"); }
}

function publicProducer<T>(promise: Promise<T>, state: State): Promise<T> {
  // Observe the identical production Promise. Never replace its value,
  // rejection, callbacks or schedule with an async wrapper.
  state.settled.push(promise.then(() => undefined, () => undefined));
  return promise;
}
async function completion(label: string, ready: () => boolean): Promise<void> {
  const end = Date.now() + 20_000;
  while (!ready()) {
    if (Date.now() >= end) throw new Error(`ExecutionError: public producer completion unavailable: ${label}`);
    await act(async () => { await new Promise<void>(done => setTimeout(done, 5)); });
  }
  await flush(16);
}
function installTransport(state: State): void {
  const chains = new Map<string, Promise<unknown>>();
  vi.stubGlobal("navigator", { onLine: true, locks: { request<T>(name: string, run: () => Promise<T>): Promise<T> { const result = (chains.get(name) ?? Promise.resolve()).then(run); chains.set(name, result.catch(() => undefined)); return result; } } });
  stubFetch((url, init) => {
    const path = new URL(url).pathname;
    const body = init.body === undefined ? null : JSON.parse(String(init.body)) as Record<string, unknown>;
    const headers = new Headers(init.headers);
    const wire: Wire = { path, method: init.method ?? "GET", body, proof: headers.get("X-Step-Up-Proof"), bearer: headers.get("Authorization") };
    state.wires.push(wire);
    if (path === "/api/v1/auth/salt") return jsonResponse({ salt: SALT.toString("base64") });
    if (path === "/api/v1/auth/login") {
      wire.accepted = body?.username === USERNAME && body?.verifier === EXPECTED_AUTH.toString("base64");
      return wire.accepted ? jsonResponse({ token: "synthetic-share-token", user_id: OWNER, expires_in: 3600, role: "user", key_scheme: "v1" }) : jsonResponse({ code: "wrong_password" }, { status: 401 });
    }
    if (path === "/api/v1/auth/key-envelope") return jsonResponse({ key_scheme: "v1", salt: SALT.toString("base64"), kdf_params: null, wrapped_data_key: null });
    if (path === "/api/v1/meta") return jsonResponse({ version: "synthetic", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v3", audio_available: false });
    if (path === "/api/v1/entries" || path === "/api/v1/consents" && wire.method === "GET") return jsonResponse(path.endsWith("entries") ? [] : state.rows);
    if (path === "/api/v1/account/step-up") {
      wire.action = String(body?.action);
      wire.accepted = body?.verifier === EXPECTED_AUTH.toString("base64") && ["sharing_grant", "sharing_voice", "sharing_revoke"].includes(wire.action);
      if (!wire.accepted) return jsonResponse({ code: "wrong_password" }, { status: 401 });
      const proof = `synthetic-once-${state.issued.length}-${wire.action}`;
      state.proofs.set(proof, wire.action as StepUpAction); state.issued.push(proof);
      return jsonResponse({ proof, action: wire.action, expires_in: 120 });
    }
    if (path === "/api/v1/consents/pairing/lookup") return jsonResponse({ therapist_id: THERAPIST, display_name: "Dr. Public Protocol", wrap_pub_key: SPKI.toString("base64"), sas: "123 456", wrap_key_fingerprint: FINGERPRINT });
    const action = path === "/api/v1/consents" && wire.method === "POST" ? "sharing_grant" : path === `/api/v1/consents/${CONSENT}/share-voice` && wire.method === "PUT" ? "sharing_voice" : path === `/api/v1/consents/${CONSENT}` && wire.method === "DELETE" ? "sharing_revoke" : null;
    if (action) {
      wire.action = action; wire.accepted = wire.bearer === "Bearer synthetic-share-token" && wire.proof !== null && state.proofs.get(wire.proof) === action;
      if (!wire.accepted) return jsonResponse({ code: "invalid_step_up" }, { status: 409 });
      state.proofs.delete(wire.proof!); state.consumed.push(wire.proof!);
      if (action === "sharing_grant") {
        if (state.rejectDisclosure) { wire.accepted = false; return jsonResponse({ code: "disclosure_outdated" }, { status: 409 }); }
        state.rows = [{ id: CONSENT, therapist_id: THERAPIST, display_name: "Dr. Public Protocol", username: "synthetic_clinician", status: "active", granted_at: "2026-10-07T12:00:00Z", revoked_at: null, share_voice: false, therapist_wrap_pub_key: SPKI.toString("base64") }];
        return jsonResponse(state.rows[0], { status: 201 });
      }
      if (action === "sharing_voice") { state.rows = state.rows.map(row => ({ ...row, share_voice: body?.enabled === true })); return jsonResponse({ id: CONSENT, share_voice: state.rows[0]?.share_voice }); }
      state.rows = state.rows.map(row => ({ ...row, status: "revoked", revoked_at: "2026-10-07T13:00:00Z", share_voice: false }));
      return new Response(null, { status: 204 });
    }
    if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
    state.unexpected.push(`${wire.method} ${path}`);
    return jsonResponse({ code: "unexpected_fixture_route" }, { status: 404 });
  });
  const wrap = sharing.wrapDataKeyForTherapist;
  vi.spyOn(sharing, "wrapDataKeyForTherapist").mockImplementation((...args) => { const promise = wrap(...args); state.transfers.push({ key: args[0], before: args[0].slice(), settled: promise.then(() => undefined, () => undefined) }); return publicProducer(promise, state); });
  const step = reauth.freshStepUp;
  vi.spyOn(reauth, "freshStepUp").mockImplementation((...args) => publicProducer(step(...args), state));
  const grant = api.grantConsent, voice = api.setShareVoice, revoke = api.revokeConsent;
  vi.spyOn(api, "grantConsent").mockImplementation((...args) => publicProducer(grant(...args), state));
  vi.spyOn(api, "setShareVoice").mockImplementation((...args) => publicProducer(voice(...args), state));
  vi.spyOn(api, "revokeConsent").mockImplementation((...args) => publicProducer(revoke(...args), state));
}
async function setup(name: string): Promise<{ state: State; root: ReactTestRenderer; adopted: { authKey: Uint8Array; dataKey: Uint8Array } }> {
  const state: State = { case: name, stage: "setup", wires: [], unexpected: [], rows: [], proofs: new Map(), issued: [], consumed: [], transfers: [], settled: [], rejectDisclosure: false, nativeAuthenticationControl: independentAuthenticationControl() };
  current = state; installTransport(state);
  const root = await render(<App />); state.root = root;
  await completion("actual App boot", () => buttonByLabel(root, "Sign in"));
  await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD);
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  await completion("actual Login and App onboarding adoption", () => buttonByLabel(root, "Next"));
  const adopted = vault.get();
  await press(root, "Next"); await press(root, "Next"); await press(root, "Start journaling");
  await completion("actual App authenticated navigation", () => buttonByLabel(root, "More"));
  await press(root, "More"); await press(root, "Share");
  await completion("actual lazy Share mounts and finishes its initial list", () => buttonByLabel(root, "Look up") && !textOf(root).includes("Loading…"));
  return { state, root, adopted };
}
async function requestGrant(root: ReactTestRenderer): Promise<void> {
  await typeInto(root, "Pairing code", "  PUBLIC123  "); await press(root, "Look up");
  await completion("native key fingerprint lookup completes", () => buttonByLabel(root, "Confirm and share"));
  await setCheckbox(root, t("share.webFingerprintConfirm"), true); await setCheckbox(root, t("share.webDisclosureConfirm"), true);
  await press(root, "Confirm and share");
}
async function submit(root: ReactTestRenderer, password = PASSWORD): Promise<void> {
  await typeInto(root, "Current password", password); await press(root, "Verify and continue");
}
async function finish(state: State, root: ReactTestRenderer): Promise<void> {
  await completion("public sensitive action busy-finally", () => !buttonByLabel(root, "Working…"));
  await Promise.all([...state.settled, ...state.transfers.map(transfer => transfer.settled)]);
  await flush(16); state.stage = "behavior-oracle";
}
function openActualWrap(body: Record<string, unknown>, control: NativeAuthenticationControl): Buffer {
  const ephemeral = Buffer.from(String(body.ephemeral_pub), "base64");
  const shared = diffieHellman({ privateKey: therapist.privateKey, publicKey: createPublicKey({ key: ephemeral, type: "spki", format: "der" }) });
  const kek = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeral, SPKI]), Buffer.from("mindpattern/wrap/v1"), 32));
  const wire = Buffer.from(String(body.wrapped_key), "base64"), decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["consent-wrap", OWNER, THERAPIST]))); decipher.setAuthTag(wire.subarray(-16));
  const partial = decipher.update(wire.subarray(12, -16));
  try {
    try { return Buffer.concat([partial, decipher.final()]); }
    catch (error) {
      const signature = nativeAuthenticationSignature(error);
      if (signature && signature.message === control.rejectionSignature.message && signature.name === control.rejectionSignature.name && signature.constructorName === control.rejectionSignature.constructorName) throw new AuthenticatedWrapRejection(signature);
      throw error;
    }
  }
  finally { partial.fill(0); shared.fill(0); kek.fill(0); }
}
beforeEach(() => { vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); });
afterEach(async () => {
  if (current?.root) await act(async () => current!.root!.unmount());
  if (current) {
    await Promise.all([...current.settled, ...current.transfers.map(transfer => transfer.settled)]);


  }
  current = undefined; resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});

it("real App login grants an independently authenticated key, changes voice scope twice and revokes with fresh action proofs", async () => {
  const { state, root, adopted } = await setup("grant-voice-revoke");
  expect(adopted.authKey).toEqual(new Uint8Array(EXPECTED_AUTH)); expect(adopted.dataKey).toEqual(new Uint8Array(EXPECTED_DATA));
  await requestGrant(root); expect(textOf(root)).toContain(FINGERPRINT); expect(isDisabled(root, "Verify and continue")).toBe(true);
  await submit(root); await finish(state, root);
  const grant = state.wires.find(wire => wire.action === "sharing_grant" && wire.path === "/api/v1/consents");
  expect(grant?.accepted).toBe(true); expect(grant?.body?.code).toBe("PUBLIC123"); expect(grant?.body?.disclosure).toBe("v3");
  expect(typeof grant!.body!.ephemeral_pub).toBe("string"); expect(typeof grant!.body!.wrapped_key).toBe("string");
  const ephemeralWire = Buffer.from(String(grant!.body!.ephemeral_pub), "base64"), wrappedWire = Buffer.from(String(grant!.body!.wrapped_key), "base64");
  expect(ephemeralWire.length).toBe(91); expect(ephemeralWire.toString("base64")).toBe(grant!.body!.ephemeral_pub);
  expect(wrappedWire.length).toBe(60); expect(wrappedWire.toString("base64")).toBe(grant!.body!.wrapped_key);
  let opened: Buffer | undefined, authenticationRejected = false;
  try { opened = openActualWrap(grant!.body!, state.nativeAuthenticationControl); } catch (error) { if (!(error instanceof AuthenticatedWrapRejection)) throw error; authenticationRejected = true; }
  expect(authenticationRejected).toBe(false); expect(opened).toEqual(EXPECTED_DATA);
  expect(state.transfers.map(transfer => [...transfer.key])).toEqual(state.transfers.map(transfer => new Array(transfer.key.length).fill(0)));
  expect(state.transfers.map(transfer => Buffer.from(transfer.before))).toEqual([EXPECTED_DATA]);
  expect(textOf(root)).toContain(t("share.webGrantedStatus", { name: "Dr. Public Protocol" }));
  expect(root.root.findAllByType("input").filter(node => node.props.type === "password" || node.props.type === "checkbox")).toHaveLength(0);
  expect(state.rows[0]?.share_voice).toBe(false);
  await pressSwitch(root); await submit(root); await finish(state, root);
  expect(state.rows[0]?.share_voice).toBe(true); expect(root.root.findAllByType("button").find(node => node.props.role === "switch")?.props["aria-checked"]).toBe(true); expect(textOf(root)).toContain(t("share.voiceOn"));
  await pressSwitch(root); await submit(root); await finish(state, root);
  expect(state.rows[0]?.share_voice).toBe(false); expect(root.root.findAllByType("button").find(node => node.props.role === "switch")?.props["aria-checked"]).toBe(false); expect(textOf(root)).toContain(t("share.voiceOff"));
  await press(root, "Revoke access"); await press(root, "Revoke access"); await submit(root); await finish(state, root);
  expect(state.rows.map(row => ({ id: row.id, status: row.status, shareVoice: row.share_voice }))).toEqual([{ id: CONSENT, status: "revoked", shareVoice: false }]);
  expect(textOf(root)).toContain(t("share.webRevokedStatus", { name: "Dr. Public Protocol" })); expect(textOf(root)).toContain(t("share.webNoGrants"));
  expect(state.wires.filter(wire => wire.path === "/api/v1/account/step-up").map(wire => ({ verifier: wire.body?.verifier, action: wire.body?.action }))).toEqual(["sharing_grant", "sharing_voice", "sharing_voice", "sharing_revoke"].map(action => ({ verifier: EXPECTED_AUTH.toString("base64"), action })));
  expect(state.wires.filter(wire => wire.action && wire.path !== "/api/v1/account/step-up").map(wire => ({ action: wire.action, proof: wire.proof, accepted: wire.accepted, enabled: wire.body?.enabled }))).toEqual([{ action: "sharing_grant", proof: state.issued[0], accepted: true, enabled: undefined }, { action: "sharing_voice", proof: state.issued[1], accepted: true, enabled: true }, { action: "sharing_voice", proof: state.issued[2], accepted: true, enabled: false }, { action: "sharing_revoke", proof: state.issued[3], accepted: true, enabled: undefined }]);
  expect(state.consumed).toEqual(state.issued); expect(state.proofs.size).toBe(0);
  expect(adopted.authKey).toEqual(new Uint8Array(EXPECTED_AUTH)); expect(adopted.dataKey).toEqual(new Uint8Array(EXPECTED_DATA)); expect(vault.ownerUserId()).toBe(OWNER); expect(hasSession()).toBe(true); expect(state.unexpected).toEqual([]);
  state.stage = "passed";
});

it("real Share password refusal completes locally without a remote proof or grant and keeps the pairing available", async () => {
  const { state, root, adopted } = await setup("wrong-password"); await requestGrant(root); await submit(root, "incorrect public password"); await finish(state, root);
  expect(state.rows).toEqual([]); expect(state.issued).toEqual([]); expect(state.wires.filter(wire => wire.path === "/api/v1/consents" && wire.method === "POST")).toEqual([]);
  expect(textOf(root)).toContain(t("common.wrongPassword")); expect(textOf(root)).toContain("Dr. Public Protocol"); expect(textOf(root)).not.toContain(t("share.webGrantedStatus", { name: "Dr. Public Protocol" }));
  expect(root.root.findAllByType("input").find(node => node.props.type === "password")?.props.value).toBe(""); expect(isDisabled(root, "Verify and continue")).toBe(true);
  expect(state.transfers.map(transfer => [...transfer.key])).toEqual(state.transfers.map(transfer => new Array(transfer.key.length).fill(0))); expect(adopted.authKey).toEqual(new Uint8Array(EXPECTED_AUTH)); expect(adopted.dataKey).toEqual(new Uint8Array(EXPECTED_DATA)); expect(state.unexpected).toEqual([]); state.stage = "passed";
});

it("real Share action proof reaches a disclosure refusal without claiming a grant or losing native key custody", async () => {
  const { state, root, adopted } = await setup("disclosure-outdated"); state.rejectDisclosure = true; await requestGrant(root); await submit(root); await finish(state, root);
  const grant = state.wires.find(wire => wire.path === "/api/v1/consents" && wire.method === "POST");
  expect(grant?.action).toBe("sharing_grant"); expect(grant?.proof).toBe(state.issued[0]);
  expect(typeof grant!.body!.ephemeral_pub).toBe("string"); expect(typeof grant!.body!.wrapped_key).toBe("string");
  const ephemeralWire = Buffer.from(String(grant!.body!.ephemeral_pub), "base64"), wrappedWire = Buffer.from(String(grant!.body!.wrapped_key), "base64");
  expect(ephemeralWire.length).toBe(91); expect(ephemeralWire.toString("base64")).toBe(grant!.body!.ephemeral_pub);
  expect(wrappedWire.length).toBe(60); expect(wrappedWire.toString("base64")).toBe(grant!.body!.wrapped_key);
  let opened: Buffer | undefined, authenticationRejected = false;
  try { opened = openActualWrap(grant!.body!, state.nativeAuthenticationControl); } catch (error) { if (!(error instanceof AuthenticatedWrapRejection)) throw error; authenticationRejected = true; }
  expect(authenticationRejected).toBe(false); expect(opened).toEqual(EXPECTED_DATA);
  expect(state.rows).toEqual([]); expect(textOf(root)).toContain(t("share.webTermsChanged")); expect(textOf(root)).toContain("Dr. Public Protocol"); expect(textOf(root)).not.toContain(t("share.webGrantedStatus", { name: "Dr. Public Protocol" }));
  expect(root.root.findAllByType("input").find(node => node.props.type === "password")?.props.value).toBe(""); expect(state.transfers.map(transfer => [...transfer.key])).toEqual(state.transfers.map(transfer => new Array(transfer.key.length).fill(0))); expect(adopted.authKey).toEqual(new Uint8Array(EXPECTED_AUTH)); expect(adopted.dataKey).toEqual(new Uint8Array(EXPECTED_DATA)); expect(state.unexpected).toEqual([]); state.stage = "passed";
});
