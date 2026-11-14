/** Controlled fingerprint-provider schedule. Login/MFA, native HTTP and retired SHA256 computation are genuine; delivery of the old digest is held, and the current provider refusal is an explicit test double. */
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { createServer, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";


import { act } from "react";

import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import * as api from "../src/api";
import * as cryptography from "../src/crypto";
const { JSDOM } = createRequire(import.meta.url)("jsdom");
let nativeDom: any, container: HTMLDivElement | undefined;
async function flush(times=3) { for(let i=0;i<times;i++) await act(async()=>{await Promise.resolve();}); }
const textOf=()=>container?.textContent??"";
const hasButton=(text:string)=>[...container!.querySelectorAll("button")].some(node=>node.textContent===text);
const byTestId=(id:string)=>[...container!.querySelectorAll(`[data-testid="${id}"]`)];
async function typeInto(_root:unknown,labelText:string,value:string) {
 const input=[...container!.querySelectorAll("input")].find(node=>[...container!.querySelectorAll("label")].some(label=>label.htmlFor===node.id&&(label.textContent??"").includes(labelText)));
 if(!input)throw new Error("SetupError: current native DOM input absent: "+labelText);
 await act(async()=>{ const setter=Object.getOwnPropertyDescriptor(nativeDom.window.HTMLInputElement.prototype,"value")!.set!; setter.call(input,value); input.dispatchEvent(new nativeDom.window.Event("input",{bubbles:true})); });
}
async function press(_root:unknown,label:string) {
 const button=[...container!.querySelectorAll("button")].find(node=>node.textContent===label);
 if(!button||button.disabled)throw new Error("SetupError: current native DOM button absent/disabled: "+label);
 await act(async()=>{button.click();});
}
async function render(element:React.ReactElement) {
 const {createRoot}=await import("react-dom/client"); const current=createRoot(container!); await act(async()=>{current.render(element);});return current;
}

const USERNAME = "synthetic_sas_context", PASSWORD = "correct horse battery staple", SALT = "AAECAwQFBgcICQoLDA0ODw==";
const OWNER = "0123456789abcdef0123456789abcdef", PATIENT_A = "fedcba9876543210fedcba9876543210";
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
let root: { unmount:()=>void } | undefined, owned: Transport | undefined;
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
  nativeDom=new JSDOM("<!doctype html><html><body></body></html>",{url:origin});
  vi.stubGlobal("window",nativeDom.window);vi.stubGlobal("document",nativeDom.window.document);vi.stubGlobal("navigator",nativeDom.window.navigator);vi.stubGlobal("HTMLElement",nativeDom.window.HTMLElement);
  container=document.createElement("div");document.body.append(container);
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
afterEach(async () => { await act(async () => { root?.unmount(); }); root = undefined; const current = owned; owned = undefined; if (current) await current.retire(); api.clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals(); nativeDom?.window.close(); nativeDom=undefined;container=undefined; });


it("keeps the unavailable warning when a retired digest arrives after the current provider refuses", async () => {
  const witness: Witness = { requests: [], transportFaults: [], nativeFetchCreated: 0, nativeFetchCompleted: 0, responseBodiesCompleted: 0, apiSettlements: [] };
  const retiredNative: Promise<string>[] = [], deliveredPromises: Promise<string>[] = [], originalSas: Promise<unknown>[] = [];
  const controlledRefusal = new Error("Controlled current fingerprint provider refusal");
  let releaseRetired!: () => void, providerCalls = 0, currentRefused = false, delivered = false;
  const gate = new Promise<void>(resolve => { releaseRetired = resolve; });
  const nativePress = (label: string) => new Promise<void>((resolve, reject) => setImmediate(() => { void press(root!, label).then(resolve, reject); }));
  let current: Transport | undefined;
  const flags = globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }, oldAct = flags.IS_REACT_ACT_ENVIRONMENT;
  flags.IS_REACT_ACT_ENVIRONMENT = true;
  try {
    const account = fixture(); current = await transport(account, "overlapping-current-request-keeps-busy", witness);
    const realSas = api.api.pairingSas, realFingerprint = cryptography.serverWrapKeyFingerprint;
    vi.spyOn(api.api, "pairingSas").mockImplementation((...args) => { const original = realSas(...args); originalSas.push(original); return original; });
    vi.spyOn(cryptography, "serverWrapKeyFingerprint").mockImplementation((...args) => {
      providerCalls += 1;
      if (providerCalls === 1) {
        const original = realFingerprint(...args); retiredNative.push(original);
        const delayed = original.then(async value => { await gate; delivered = true; return value; }); deliveredPromises.push(delayed); return delayed;
      }
      if (providerCalls !== 2) throw new Error("SetupError: unexpected controlled provider invocation");
      currentRefused = true; return Promise.reject(controlledRefusal);
    });
    root = await render(<App />);
    await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD); await press(root, "Sign in");
    await completed("mandatory native MFA", () => hasButton("Verify code"));
    if (api.hasSession() || witness.requests.some(row => row.path === "/api/v1/therapist/me")) throw new Error("SetupError: password-only login adopted an identity before MFA");
    await typeInto(root, "Authenticator code (or recovery code)", "123456"); await press(root, "Verify code");
    await completed("real authenticated public caseload", () => witness.requests.some(row => row.path === "/api/v1/therapist/patients") && hasButton("Generate pairing code"));
    await nativePress("Generate pairing code"); await completed("first public pairing code", () => byTestId("pairing-code").some(node => node.textContent === CODE_A));
    await typeInto(root, "Patient's account id (shown in their app)", PATIENT_A); await nativePress("Show verification code");
    await completed("first genuine SAS HTTP response held", () => current!.pending.length === 1);
    current.release(0); await completed("retired SHA256 admitted", () => retiredNative.length === 1 && byTestId("pairing-sas").some(node => node.textContent === SAS_A));
    expect(await finite("genuine old SHA256 completed before retirement", retiredNative[0]!)).toBe(account.fingerprint);
    expect(delivered).toBe(false);
    await nativePress("Generate pairing code"); await completed("replacement public pairing code", () => byTestId("pairing-code").some(node => node.textContent === CODE_B));
    await nativePress("Show verification code"); await completed("replacement genuine SAS HTTP response held", () => current!.pending.length === 2);
    current.release(1); await completed("controlled current refusal and warning", () => currentRefused && byTestId("pairing-sas").some(node => node.textContent === SAS_B) && textOf().includes("could not compute the fingerprint"));
    expect(delivered).toBe(false);
    await act(async () => { releaseRetired(); await new Promise<void>(resolve => setImmediate(resolve)); }); await flush(8);
    expect(delivered).toBe(true);
    expect(byTestId("pairing-sas").map(node => node.textContent)).toEqual([SAS_B]);
    expect(textOf(), "a retired digest must not conceal the current provider refusal").toContain("could not compute the fingerprint");
    expect(witness.transportFaults).toEqual([]); expect(api.hasSession()).toBe(true);
    await finite("native fetch completion", Promise.allSettled(current.originals));
    expect(witness.nativeFetchCompleted).toBe(witness.nativeFetchCreated);
  } finally {
    releaseRetired(); current?.release();
    await finite("owned native fingerprint and API producers retire", Promise.allSettled([...retiredNative, ...deliveredPromises, ...originalSas])); await act(async () => { root?.unmount(); }); root = undefined;
    vi.restoreAllMocks(); if (current) await current.retire(); api.clearSession();
    nativeDom?.window.close(); nativeDom = undefined; container = undefined; flags.IS_REACT_ACT_ENVIRONMENT = oldAct;
  }
}, 60_000);
