/** Excluded ordinary Node DOM busy-provider contract. Native worker contention
 * keeps the current original SHA256 Promise pending while an obsolete tuple's
 * original digest settles. Real HTTP/App/MFA and current-DOM input Tasks remain
 * intact. This is a Node provider profile, not physical-browser timing proof. */
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes, pbkdf2, getFips } from "node:crypto";
import { createServer, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { isMainThread } from "node:worker_threads";


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


// The native worker pool is deliberately busy. Its original cryptographic
// Promises and public HTTP producers remain unchanged throughout the profile.
it("keeps a current SAS comparison unverified while its own native digest is pending", async () => {
  const receiptPath = process.env.FRONTEND_NATIVE_SAS_BUSY_RECEIPT;
  if (!receiptPath || !/^v22\./.test(process.version) || process.env.UV_THREADPOOL_SIZE !== "1" || !isMainThread || getFips() !== 0) throw new Error("SetupError: explicit owned Node22/fork1/UV1 busy profile required");
  const receipt: Record<string, unknown> = { stage: "started", nodeVersion: process.version, actorPid: process.pid, actualNativeMainThread: isMainThread, workerPool: process.env.UV_THREADPOOL_SIZE, startingFips: getFips(), nativeInputTasks: [], events: [], originalProductionPromisesForwardedUnchanged: true };
  const events = receipt.events as { event: string; at: number }[];
  const event = (name: string) => { events.push({ event: name, at: Date.now() }); };
  const publish = () => writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n");
  publish();
  const witness: Witness = { requests: [], transportFaults: [], nativeFetchCreated: 0, nativeFetchCompleted: 0, responseBodiesCompleted: 0, apiSettlements: [] };
  const originalFingerprints: Promise<string>[] = [], originalSas: Promise<unknown>[] = [];
  const fingerprintSettled: boolean[] = []; const tasks: { name: string; promise: Promise<void>; settled: boolean; zeroized: boolean }[] = [];
  let current: Transport | undefined;
  const ownNativeBusyTask = (name: string, iterations: number) => {
    const task = { name, promise: Promise.resolve(), settled: false, zeroized: false };
    task.promise = new Promise<void>((resolve, reject) => pbkdf2("owned-worker-queue", "owned-native-salt", iterations, 32, "sha256", (error, bytes) => {
      task.settled = true; event(name + "-settled"); if (error) reject(error); else { bytes.fill(0); task.zeroized = true; resolve(); }
    })); tasks.push(task); return task;
  };
  const nativePress = (label: string) => new Promise<void>((resolve, reject) => setImmediate(() => {
    // Lookup and delivery occur in this separate current native task. press()
    // also checks the current host button exists and is enabled.
    const currentButton=[...container!.querySelectorAll("button")].find(node=>node.textContent===label);
    if (!currentButton || currentButton.disabled) { reject(new Error("SetupError: current native task button absent/disabled: " + label)); return; }
    (receipt.nativeInputTasks as {label:string;currentDom:boolean;enabled:boolean;separateNativeTask:boolean}[]).push({label,currentDom:true,enabled:true,separateNativeTask:true});
    event("native-input:" + label);
    void press(root!, label).then(resolve, reject);
  }));
  try {
    const account = fixture(); current = await transport(account, "overlapping-current-request-keeps-busy", witness);
    const realSas = api.api.pairingSas, realFingerprint = cryptography.serverWrapKeyFingerprint;
    vi.spyOn(api.api, "pairingSas").mockImplementation((...args) => { const original=realSas(...args); originalSas.push(original); receipt.originalSasPromiseCount=originalSas.length; return original; });
    vi.spyOn(cryptography, "serverWrapKeyFingerprint").mockImplementation((...args) => {
      const index=originalFingerprints.length, original=realFingerprint(...args); originalFingerprints.push(original); fingerprintSettled.push(false);
      void original.then(() => { fingerprintSettled[index]=true;event("original-native-fingerprint-"+index+"-fulfilled"); }, () => { fingerprintSettled[index]=true;event("original-native-fingerprint-"+index+"-rejected"); }); receipt.originalFingerprintPromiseCount=originalFingerprints.length;return original;
    });
    root=await render(<App />); await typeInto(root,"Username",USERNAME); await typeInto(root,"Password",PASSWORD); await press(root,"Sign in");
    await completed("required native MFA",()=>hasButton("Verify code"));
    if (api.hasSession() || witness.requests.some(row=>row.path==="/api/v1/therapist/me")) throw new Error("SetupError: password-only path adopted an authenticated identity before MFA");
    receipt.passwordOnlyRefusedBeforeMfa=true;
    await typeInto(root,"Authenticator code (or recovery code)","123456"); await press(root,"Verify code");
    await completed("actual authenticated caseload",()=>witness.requests.some(row=>row.path==="/api/v1/therapist/patients")&&hasButton("Generate pairing code"));
    await nativePress("Generate pairing code"); await completed("first public code",()=>byTestId("pairing-code").some(node=>node.textContent===CODE_A));
    await typeInto(root,"Patient's account id (shown in their app)",PATIENT_A); await nativePress("Show verification code"); await completed("first SAS native request held",()=>current!.pending.length===1);
    receipt.authenticatedPublicCaseload=true;
    const beforeOld=ownNativeBusyTask("before-old-native-digest",20_000_000);
    current.release(0); await completed("first unchanged native fingerprint created",()=>originalFingerprints.length===1);
    const beforeCurrent=ownNativeBusyTask("between-old-and-current-native-digests",5_000_000);
    await nativePress("Generate pairing code"); await completed("new public code",()=>byTestId("pairing-code").some(node=>node.textContent===CODE_B));
    await nativePress("Show verification code"); await completed("second SAS native request held",()=>current!.pending.length===2);
    current.release(1); await completed("current SAS visible and original current digest pending",()=>originalFingerprints.length===2&&byTestId("pairing-sas").some(node=>node.textContent===SAS_B));
    if(beforeOld.settled||fingerprintSettled[0]||fingerprintSettled[1])throw new Error("SetupError: native queue did not admit current public SAS before old digest completion");
    await finite("old native digest settles",originalFingerprints[0]!); await flush(8);
    if(beforeCurrent.settled||fingerprintSettled[1])throw new Error("SetupError: current native digest completed before pending comparison assertion");
    receipt.stage="assertion-ready";
    receipt.beforeAssertion={oldFingerprintSettled:Boolean(fingerprintSettled.at(0)),currentFingerprintPending:fingerprintSettled[1]===false,betweenNativeBusyTaskPending:beforeCurrent.settled===false,currentSas:byTestId("pairing-sas").map(node=>node.textContent)};
    event("current-warning-assertion-ready");publish();
    process.stdout.write(`Native SAS digest queue ${JSON.stringify({workerPool:process.env.UV_THREADPOOL_SIZE,fingerprintSettled,tasks:tasks.map(({name,settled})=>({name,settled})),oldAndCurrentPromiseIdentityPreserved:true,nativeInputTask:true})}\n`);
    expect(byTestId("pairing-sas").map(node=>node.textContent)).toEqual([SAS_B]);
    expect(textOf(),"A pending current key comparison cannot inherit verification from the retired tuple").toContain("could not compute the fingerprint");
    const nativeValues=await finite("both original native digests settle",Promise.all(originalFingerprints));
    await finite("all finite native busy tasks settle",Promise.all(tasks.map(row=>row.promise)));await flush(8);
    expect(nativeValues).toEqual([account.fingerprint,account.fingerprint]);receipt.correctNativeDigestPositiveControls=true;
    expect(textOf()).not.toContain("could not compute the fingerprint"); expect(witness.transportFaults).toEqual([]); expect(api.hasSession()).toBe(true);
    if(witness.nativeFetchCreated!==witness.nativeFetchCompleted||witness.nativeFetchCreated!==witness.responseBodiesCompleted)throw new Error("SetupError: original native HTTP producer census incomplete");
    receipt.publicProducer={complete:true,password600kVerifierMatched:true,passwordOnlyRefusedBeforeMfa:receipt.passwordOnlyRefusedBeforeMfa===true,acceptedMfa:true,authenticatedIdentityEnvelopeOpened:true,currentSasVisible:true,currentComparisonEventuallyVerified:true};
    receipt.stage="passed";
  } finally {
    try {
      current?.release();const settled=await finite("owned original producers retire",Promise.allSettled([...originalFingerprints,...originalSas,...tasks.map(row=>row.promise)]));
      receipt.allOwnedOriginalProducersFulfilled=settled.every(row=>row.status==="fulfilled");
      receipt.finiteNativeBusyTasks=tasks.map(({name,settled,zeroized})=>({name,settled,zeroized}));
      await act(async()=>{root?.unmount();});root=undefined;vi.restoreAllMocks();if(current)await current.retire();api.clearSession();
      nativeDom?.window.close();nativeDom=undefined;container=undefined;
      receipt.cleanupCompleted=true;receipt.finalFips=getFips();
    } finally { publish(); }
  }
},60_000);
