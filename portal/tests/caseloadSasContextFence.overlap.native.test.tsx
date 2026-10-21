/** public SAS context regression. Genuine owned Node
 * HTTP/native fetch and production Promises; synthetic independent auth/MFA. */
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { createServer, type Server, type ServerResponse } from "node:http";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import * as api from "../src/api";
import * as cryptography from "../src/crypto";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const USERNAME = "synthetic_sas_context", PASSWORD = "correct horse battery staple", SALT = "AAECAwQFBgcICQoLDA0ODw==";
const OWNER = "0123456789abcdef0123456789abcdef", PATIENT_A = "fedcba9876543210fedcba9876543210", PATIENT_B = "11111111111111111111111111111111";
const TOKEN = "synthetic-native-sas-context-token", CODE_A = "7X2KQM4N", CODE_B = "8W3LRN5P", SAS_A = "123456", SAS_B = "654321";
const nativeFetch = globalThis.fetch;
const CASES = ["unchanged-positive-control", "old-success-after-new-code", "old-404-after-new-code", "old-success-after-patient-edit", "completed-success-after-patient-edit", "overlapping-current-request-keeps-busy"] as const;
type Scenario = typeof CASES[number];
type Witness = { requests: { path: string; method: string; pairingCode?: string; patient?: string }[]; transportFaults: string[]; nativeFetchCreated: number; nativeFetchCompleted: number; responseBodiesCompleted: number; apiSettlements: { status: "fulfilled" | "known404" }[] };
function fixture() {
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const identity = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = identity.privateKey.export({ type: "pkcs8", format: "der" }), publicDer = identity.publicKey.export({ type: "spki", format: "der" });
  try {
    const nonce = randomBytes(12), aad = Buffer.from(JSON.stringify(["therapist-key", USERNAME]));
    const seal = createCipheriv("aes-256-gcm", wrap, nonce); seal.setAAD(aad);
    const encrypted = Buffer.concat([seal.update(privateDer), seal.final()]), tag = seal.getAuthTag();
    const open = createDecipheriv("aes-256-gcm", wrap, nonce); open.setAAD(aad); open.setAuthTag(tag);
    const verified = Buffer.concat([open.update(encrypted), open.final()]);
    if (!verified.equals(privateDer)) throw new Error("SetupError: independent native identity envelope failed authentication");
    verified.fill(0);
    return { verifier: auth.toString("base64"), publicKey: publicDer.toString("base64"), envelope: Buffer.concat([nonce, encrypted, tag]).toString("base64"), fingerprint: createHash("sha256").update(publicDer).digest("hex").slice(0, 16) };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0); }
}
async function finite<T>(name: string, original: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([original, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`ExecutionError: owned producer did not complete: ${name}`)), 15_000); })]); }
  finally { if (timer) clearTimeout(timer); }
}
async function completed(name: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: public completion not observed: ${name}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}

type Transport = { server: Server; originals: Promise<Response>[]; pending: ServerResponse[]; release: (onlyIndex?: number) => void; retire: () => Promise<void> };
let root: ReactTestRenderer | undefined, owned: Transport | undefined;
async function transport(account: ReturnType<typeof fixture>, scenario: Scenario, witness: Witness): Promise<Transport> {
  let origin = "", generations = 0; const pending: ServerResponse[] = [];
  const server = createServer((request, response) => {
    void (async () => {
      let body = ""; for await (const chunk of request) body += String(chunk);
      const url = new URL(request.url ?? "", origin), path = url.pathname;
      witness.requests.push({ path, method: request.method ?? "GET", ...(path.endsWith("/sas") ? { pairingCode: String(request.headers["x-pairing-code"]), patient: url.searchParams.get("patient_user_id") ?? "" } : {}) });
      if (body.includes(PASSWORD)) throw new Error("SetupError: password plaintext reached native receiver");
      const parsed = body ? JSON.parse(body) as Record<string, unknown> : {};
      let value: unknown, status = 200;
      if (path === "/api/v1/meta") value = { sharing_available: true };
      else if (path === "/api/v1/auth/salt") value = { salt: SALT };
      else if (path === "/api/v1/auth/login") {
        if (parsed.username !== USERNAME || parsed.verifier !== account.verifier) throw new Error("SetupError: native login differs from independent600k verifier");
        if (parsed.totp_code === undefined) { status = 401; value = { detail: "MFA is required", code: "totp_required" }; }
        else { if (parsed.totp_code !== "123456") throw new Error("SetupError: unknown synthetic MFA input"); value = { token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86_400, mfa_enrollment_required: false }; }
      } else {
        if (request.headers.authorization !== `Bearer ${TOKEN}`) throw new Error("SetupError: protected native receiver lacks current bearer");
        if (path === "/api/v1/therapist/me") value = { username: USERNAME, display_name: "Dr. Native SAS", wrap_pub_key: account.publicKey, wrap_key_blob: account.envelope, totp_enabled: true };
        else if (path === "/api/v1/therapist/patients") value = [];
        else if (path === "/api/v1/auth/logout") { status = 204; value = undefined; }
        else if (path === "/api/v1/therapist/pairing-codes") {
          if (request.method !== "POST" || generations >= 2) throw new Error("SetupError: unexpected code-generation producer");
          generations += 1; value = { code: generations === 1 ? CODE_A : CODE_B, expires_in: 900 };
        } else if (path === "/api/v1/therapist/pairing/sas") {
          if (request.method !== "GET" || request.headers["x-pairing-code"] !== (pending.length === 0 ? CODE_A : CODE_B) || url.searchParams.get("patient_user_id") !== PATIENT_A || pending.length > (scenario === "overlapping-current-request-keeps-busy" ? 1 : 0)) throw new Error("SetupError: unexpected native SAS tuple producer");
          response.once("finish", () => { witness.responseBodiesCompleted += 1; }); pending.push(response); return;
        } else throw new Error(`SetupError: unexpected native HTTP route ${path}`);
      }
      response.once("finish", () => { witness.responseBodiesCompleted += 1; });
      response.writeHead(status, { "Content-Type": "application/json" }); response.end(value === undefined ? undefined : JSON.stringify(value));
    })().catch(error => { witness.transportFaults.push(`SetupError: owned HTTP receiver failure: ${String(error)}`); if (!response.headersSent) response.writeHead(500, { "Content-Type": "application/json" }); response.end(JSON.stringify({ detail: "owned fixture failure", code: "witness_setup_fault" })); });
  });
  server.on("error", error => { witness.transportFaults.push(`SetupError: native HTTP server failure: ${String(error)}`); });
  await finite("native HTTP bind", new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }));
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: native HTTP address absent"); origin = `http://127.0.0.1:${address.port}`;
  vi.stubGlobal("window", { ...window, location: { ...window.location, origin } });
  const originals: Promise<Response>[] = [];
  vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin) throw new Error("SetupError: native fetch observer received an unowned public origin");
    const original = nativeFetch(input, init); originals.push(original); witness.nativeFetchCreated += 1;
    void original.then(() => { witness.nativeFetchCompleted += 1; }, error => { witness.transportFaults.push(`SetupError: genuine native fetch failure: ${String(error)}`); });
    return original;
  });
  const release = (onlyIndex?: number) => {
    for (const [index, response] of pending.entries()) if ((onlyIndex === undefined || onlyIndex === index) && !response.writableEnded && !response.destroyed) {
      const known404 = scenario === "old-404-after-new-code";
      response.writeHead(known404 ? 404 : 200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(known404 ? { detail: "pairing code not found", code: "not_found" } : { sas: index === 0 ? SAS_A : SAS_B, wrap_key_fingerprint: account.fingerprint, expires_in: 900 }));
    }
  };
  const current: Transport = { server, originals, pending, release, retire: async () => {
    release(); await finite("all native fetch settlement", Promise.allSettled(originals));
    vi.unstubAllGlobals();
    server.closeAllConnections(); await finite("native HTTP close", new Promise<void>((resolve, reject) => server.close(error => error ? reject(new Error(`SetupError: owned HTTP close failed: ${String(error)}`)) : resolve())));
     if (owned === current) owned = undefined;
  } }; owned = current; return current;
}
beforeEach(() => { vi.useRealTimers(); api.clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; });
afterEach(async () => { await act(async () => { root?.unmount(); }); root = undefined; const current = owned; owned = undefined; if (current) await current.retire(); api.clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it.each(CASES)("actual authenticated SAS tuple %s retires only the current comparison", async scenario => {
  const witness: Witness = { requests: [], transportFaults: [], nativeFetchCreated: 0, nativeFetchCompleted: 0, responseBodiesCompleted: 0, apiSettlements: [] };
  const originalSas: Promise<Awaited<ReturnType<typeof api.api.pairingSas>>>[] = [], originalFingerprints: Promise<string>[] = [];
  let current: Transport | undefined;
  try {
    const account = fixture(); current = await transport(account, scenario, witness);
    const realSas = api.api.pairingSas, realFingerprint = cryptography.serverWrapKeyFingerprint;
    vi.spyOn(api.api, "pairingSas").mockImplementation((...args) => {
      const original = realSas(...args); originalSas.push(original);
      void original.then(() => { witness.apiSettlements.push({ status: "fulfilled" }); }, error => {
        if (scenario === "old-404-after-new-code" && error instanceof api.ApiError && error.status === 404) witness.apiSettlements.push({ status: "known404" });
        else witness.transportFaults.push(`SetupError: unowned SAS API failure: ${String(error)}`);
      }); return original;
    });
    vi.spyOn(cryptography, "serverWrapKeyFingerprint").mockImplementation((...args) => {
      const original = realFingerprint(...args); originalFingerprints.push(original);  return original;
    });
    root = await render(<App />); await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD); await press(root, "Sign in");
    await completed("password-only refusal and required MFA", () => root!.root.findAllByType("button").some(node => textOfNode(node) === "Verify code"));
    if (api.hasSession() || witness.requests.some(row => row.path === "/api/v1/therapist/me")) throw new Error("SetupError: password-only request adopted identity before MFA");
    await typeInto(root, "Authenticator code (or recovery code)", "123456"); await press(root, "Verify code");
    await completed("native protected caseload and actual pairing controls", () => witness.requests.some(row => row.path === "/api/v1/therapist/patients") && root!.root.findAllByType("button").some(node => textOfNode(node) === "Generate pairing code"));
    await press(root, "Generate pairing code"); await completed("first public code", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-code").some(node => textOfNode(node) === CODE_A));
    await typeInto(root, "Patient's account id (shown in their app)", PATIENT_A); await press(root, "Show verification code");
    await completed("first native SAS request held", () => current!.pending.length === 1 && originalSas.length === 1);
    if (scenario === "old-success-after-new-code" || scenario === "old-404-after-new-code" || scenario === "overlapping-current-request-keeps-busy") {
      await press(root, "Generate pairing code"); await completed("new code producer complete before old SAS response", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-code").some(node => textOfNode(node) === CODE_B));
    } else if (scenario === "old-success-after-patient-edit") { await typeInto(root, "Patient's account id (shown in their app)", PATIENT_B);  }
    if (scenario === "overlapping-current-request-keeps-busy") {
      // New code has completed publicly; original may fail this finite
      // readiness assertion before any disabled native button is invoked.

      expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Show verification code" && node.props.disabled !== true)).toHaveLength(1);

      await press(root, "Show verification code");
      await completed("second current native SAS request held", () => current!.pending.length === 2 && originalSas.length === 2);
      current.release(0);
      await act(async () => { await finite("old public SAS settles while current request remains held", Promise.allSettled(originalSas.slice(0, 1))); }); await flush(8);
      const heldCurrentResponse = current.pending[1];
      if (!heldCurrentResponse || witness.transportFaults.length || witness.apiSettlements.length !== 1 || heldCurrentResponse.writableEnded) throw new Error("SetupError: held current request/old completion custody differs");

      expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Checking…" && node.props.disabled === true)).toHaveLength(1);
      expect(root.root.findAll(node => node.props["data-testid"] === "pairing-sas")).toHaveLength(0);
        current.release(1);
    } else current.release();
    await act(async () => { await finite("unchanged public SAS API Promise", Promise.allSettled(originalSas)); }); await flush(8);
    await act(async () => { try { await finite("unchanged native local fingerprint", Promise.all(originalFingerprints)); } catch (error) { throw new Error(`SetupError: local fingerprint producer failed: ${String(error)}`); } }); await flush(8);
    if (scenario === "completed-success-after-patient-edit" || scenario === "unchanged-positive-control" || scenario === "overlapping-current-request-keeps-busy") {
      await completed("positive current SAS and native local fingerprint completion", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-sas").some(node => textOfNode(node) === (scenario === "overlapping-current-request-keeps-busy" ? SAS_B : SAS_A)) && originalFingerprints.length === 1 && !textOf(root!).includes("could not compute the fingerprint"));
      if (scenario === "completed-success-after-patient-edit") { await typeInto(root, "Patient's account id (shown in their app)", PATIENT_B);  }
    }
    await finite("native fetch producers settled", Promise.allSettled(current.originals)); await flush(8);
    if (witness.transportFaults.length || witness.apiSettlements.length !== (scenario === "overlapping-current-request-keeps-busy" ? 2 : 1) || witness.nativeFetchCreated !== witness.nativeFetchCompleted || witness.responseBodiesCompleted !== witness.nativeFetchCreated || !api.hasSession()) throw new Error(`SetupError: native producer/session custody differs: ${JSON.stringify(witness.transportFaults)}`);


    if (scenario === "unchanged-positive-control") {
      await typeInto(root, "Patient's account id (shown in their app)", `  ${PATIENT_A}  `);
    }
    if (scenario === "unchanged-positive-control" || scenario === "overlapping-current-request-keeps-busy") {
      expect(root.root.findAll(node => node.props["data-testid"] === "pairing-sas").map(textOfNode)).toEqual([scenario === "overlapping-current-request-keeps-busy" ? SAS_B : SAS_A]);
      expect(textOf(root)).toContain(`key id ${account.fingerprint}`);
      expect(textOf(root)).not.toContain("could not compute the fingerprint");
    } else {
      expect(root.root.findAll(node => node.props["data-testid"] === "pairing-sas")).toHaveLength(0);
      expect(textOf(root)).not.toContain("pairing code not found or expired");
      expect(textOf(root)).not.toContain("Verification code for this pairing");
    }
    expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Show verification code" && node.props.disabled !== true)).toHaveLength(1);
    expect(root.root.findAll(node => node.props.role === "alert")).toHaveLength(0);
    expect(api.hasSession()).toBe(true);
  }  finally {
    current?.release();
    // Retire held real producers before App session/unmount invalidates them;
    // even an early readiness failure gets an independent finite cleanup.
    await act(async () => { await finite("owned original SAS producer retirement", Promise.allSettled(originalSas)); }); await flush(8);
    await finite("owned original fingerprint producer retirement", Promise.allSettled(originalFingerprints)); await flush(8);
    await act(async () => { root?.unmount(); }); root = undefined;

    vi.restoreAllMocks(); if (current) await current.retire(); api.clearSession();
  }
});
