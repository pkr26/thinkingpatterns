/** Public account-security ownership with genuine Node HTTP/fetch/WebCrypto.
 * RTR exercises rendered forms/buttons. This is an owned synthetic same-account
 * protocol fixture, not a physical browser or backend integration claim. */
import { createCipheriv, createDecipheriv, generateKeyPairSync, createPrivateKey, createPublicKey, hkdfSync, pbkdf2Sync, randomBytes, diffieHellman } from "node:crypto";
import { createServer, type ServerResponse } from "node:http";
import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, auth, clearSession, hasSession } from "../src/api";
import * as portalCrypto from "../src/crypto";
import { drainPortalDraftWritesForTests } from "./helpers/testControl";

const USER = "native_retirement_clinician", OWNER = "0123456789abcdef0123456789abcdef";
const PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const setup = (label: string, cause?: unknown) => new Error(`SetupError: ${label}`, cause === undefined ? undefined : { cause });
function keys(password: string, salt: string) {
  const master = pbkdf2Sync(password, Buffer.from(salt, "base64"), 600000, 32, "sha256");
  const key = (info: string) => Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), info, 32));
  try { return { auth: key("mindpattern/auth/v1"), wrap: key("mindpattern/portal-wrap/v1"), note: key("mindpattern/portal-notes/v1") }; }
  finally { master.fill(0); }
}
function seal(key: Buffer, aad: string[], plain: Buffer) {
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(aad)));
  return Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString("base64");
}
function open(key: Buffer, aad: string[], encoded: string) {
  const wire = Buffer.from(encoded, "base64"), decipher = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(aad))); decipher.setAuthTag(wire.subarray(-16));
  return Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
}
const text = (node: unknown): string => typeof node === "string" || typeof node === "number" ? String(node) : Array.isArray(node) ? node.map(text).join("") : node && typeof node === "object" && "children" in node ? text((node as { children: unknown }).children) : "";
function deferred() { let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; }); return { promise, resolve }; }
async function finite<T>(label: string, promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_yes, no) => { timer = setTimeout(() => no(setup(`owned completion deadline: ${label}`)), 15000); })]); }
  finally { if (timer) clearTimeout(timer); }
}

it.each([["rotation", "live completion"], ["rotation", "retired salt completion"], ["TOTP disable", "live completion"], ["TOTP disable", "retired salt completion"]] as const)("preserves %s security ownership through %s", async (action, scenario) => {
  // Keep all four original cases; add view retirement with the same API owner.
  const continuations = scenario === "live completion"
    ? action === "rotation" ? ["original", "recovery", "recovery fallback"] as const : ["original"] as const
    : action === "rotation" ? ["original", "retired rotation salt", "retired recovery salt", "retired recovery KDF", "279", "280", "281", "289", "295", "300", "302", "305", "306", "317", "371", "379", "380", "384", "386", "389", "390", "402"] as const : ["original", "retired view"] as const;
  for (const continuation of continuations) {
  const producerBoundary = /^\d+$/.test(continuation) ? continuation : undefined;
  const recoveryTargets = ["279", "280", "281", "289", "295", "300", "302", "305", "306", "317"];
  const fallback = continuation === "recovery fallback" || producerBoundary === "295";
  const kdfBoundary = continuation === "retired recovery KDF";
  const recovery = continuation === "recovery" || fallback || continuation === "retired recovery salt" || kdfBoundary || !!producerBoundary && recoveryTargets.includes(producerBoundary);
  const viewBoundary = continuation === "retired view" || continuation === "retired rotation salt" || continuation === "retired recovery salt" || kdfBoundary || !!producerBoundary;
  vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = "";
  const accountKeys = keys(PASSWORD, SALT), pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateBytes = pair.privateKey.export({ format: "der", type: "pkcs8" }), publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const identityNote = Buffer.from(hkdfSync("sha256", privateBytes, Buffer.alloc(32), "mindpattern/portal-notes/v2", 32));
  const intendedSalt = "EBESExQVFhcYGRobHB0eHw==", intendedPassword = "intended correct horse battery staple";
  const intendedKeys = recovery ? keys(intendedPassword, intendedSalt) : undefined;
  const verifier = accountKeys.auth.toString("base64");
  let envelope = seal(accountKeys.wrap, ["therapist-key", USER], privateBytes);
  const patientId = producerBoundary ? producerBoundary.padStart(32, "0") : fallback ? "ffffffffffffffffffffffffffffffff" : continuation === "retired recovery salt" ? "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" : recovery ? "cccccccccccccccccccccccccccccccc" : action === "rotation" ? "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" : "dddddddddddddddddddddddddddddddd";
  const patientName = "Current authenticated chart";
  const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), dataKey = randomBytes(32);
  const ephemeralDer = ephemeral.publicKey.export({ format: "der", type: "spki" });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: pair.publicKey });
  const consentKey = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeralDer, Buffer.from(publicKey, "base64")]), "mindpattern/wrap/v1", 32));
  const patient = { user_id: patientId, username: patientName, status: "active", granted_at: "2026-10-01T12:00:00Z", revoked_at: null,
    wrapped_key: seal(consentKey, ["consent-wrap", patientId, OWNER], dataKey), ephemeral_pub: ephemeralDer.toString("base64") };
  shared.fill(0); consentKey.fill(0); dataKey.fill(0);
  if (recovery) window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${OWNER}`, intendedSalt);
  let serverPublicKey = publicKey, custodyBlob: string | undefined, totpEnabled = true;
  const installedRing = !!producerBoundary || fallback;
  if (installedRing) custodyBlob = seal(accountKeys.wrap, ["portal-notes-keyring", OWNER, "v1"], Buffer.from(JSON.stringify({ v: 1, active: accountKeys.note.toString("base64"), historical: [accountKeys.note.toString("base64"), identityNote.toString("base64")] })));
  const originalRingBlob = fallback ? seal(intendedKeys!.wrap, ["portal-notes-keyring", OWNER, "v1"], Buffer.from(JSON.stringify({ v: 1, active: accountKeys.note.toString("base64"), historical: [accountKeys.note.toString("base64"), identityNote.toString("base64")] }))) : custodyBlob;
  const noteId = "1234567890abcdef1234567890abcdef", notePlain = "Authenticated independent security custody note";
  const note = { id: noteId, client_note_id: noteId, pattern_pid: null,
    blob: seal(accountKeys.note, ["note", OWNER, patientId, noteId], Buffer.from(JSON.stringify({ v: 1, text: notePlain }))), created_at: "2026-10-01T12:00:00Z", updated_at: "2026-10-01T12:00:00Z", version: 1 };
  let custodyVersion = 0, successfulLogins = 0, saltRequests = 0, rotationCommits = 0, disableCommits = 0, logoutRequests = 0;
  const tokens = new Set<string>(), requests: Array<{ path: string; bearer: string | null }> = [], faults: unknown[] = [], unhandled: unknown[] = [];
  const created: Promise<unknown>[] = [], producers = new Set<Promise<unknown>>(), nativeBodies: Promise<unknown>[] = [], handlers: Promise<void>[] = [];
  const secretArrays: Uint8Array[] = [], saltArrays: Uint8Array[] = [], heldSalt = deferred(), admittedKdf = deferred();
  let heldResponse: ServerResponse | undefined, root: ReactTestRenderer | undefined, phase = "initial login", origin = "";
  let viewRetired = false, finishing = false, failed = false, submitActOpen = false, boundaryReached = false;
  const retiredBoundary = deferred(), finalRevisionArrived = deferred();
  let finalRevisionResponse: ServerResponse | undefined, finalRevisionOriginal: ReturnType<typeof api.noteRevisions> | undefined;
  const admissionEvents: Array<{ kind: string; retired: boolean }> = [];
  let securityPortalKeyCalls = 0, securityProfileCalls = 0, ringOpenCalls = 0, expectedNativeRingFailures = 0, successfulNativeRingDecrypts = 0;
  const nativeRingWire = originalRingBlob ? Buffer.from(originalRingBlob, "base64") : undefined;
  const equalBytes = (value: BufferSource | undefined, expected: Uint8Array): boolean => {
    if (value === undefined) return false;
    const bytes = ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : new Uint8Array(value);
    return bytes.length === expected.length && bytes.every((byte, index) => byte === expected[index]);
  };
  let originalFailure: unknown;
  const securityOriginals: Promise<unknown>[] = [], chartOriginals: Promise<unknown>[] = [];
  const passwordAdmissions: Array<{ retired: boolean; phase: string; salt: string; original: Promise<ArrayBuffer>; settled: boolean }> = [];
  const oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), nativeFetch = globalThis.fetch;
  const subtle = globalThis.crypto.subtle, originalBits = subtle.deriveBits, originalDecrypt = subtle.decrypt, originalExport = subtle.exportKey, originalRandom = crypto.getRandomValues;
  const oldBits = Object.getOwnPropertyDescriptor(subtle, "deriveBits"), oldDecrypt = Object.getOwnPropertyDescriptor(subtle, "decrypt"), oldExport = Object.getOwnPropertyDescriptor(subtle, "exportKey"), oldRandom = Object.getOwnPropertyDescriptor(crypto, "getRandomValues");
  const originalJson = Response.prototype.json, oldJson = Object.getOwnPropertyDescriptor(Response.prototype, "json");
  const nativeRestores: Array<() => void> = [];
  const observeUnhandled = (error: unknown) => { unhandled.push(error); };
  process.on("unhandledRejection", observeUnhandled);
  function track<T>(original: Promise<T>, expectedRejection = false) {
    created.push(original); producers.add(original);
    void original.then(() => { producers.delete(original); }, error => { producers.delete(original); if (!expectedRejection) faults.push(error); });
    return original;
  }
  function clean() { if (faults.length) throw setup("unknown owned producer/server fault", faults[0]); }
  async function complete(label: string, predicate: () => boolean) {
    const until = Date.now() + 15000;
    while (!predicate()) { clean(); if (Date.now() >= until) throw setup(`public completion missing: ${label}`); await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); }); }
    clean();
  }
  async function settleSecurityOriginals() {
    for (;;) {
      const originals = [...securityOriginals];
      await finite("same original public salt, full crypto and API producers", Promise.allSettled(originals));
      if (originals.length === securityOriginals.length) break;
    }
    clean();
  }
  async function drain() {
    let stable = 0, prior = -1;
    await complete("all owned producers and public continuations settle", () => {
      stable = producers.size === 0 && prior === created.length ? stable + 1 : 0; prior = created.length;
      return stable >= 4;
    });
  }
  const rendered = () => root ? text(root.root) : "";
  const button = (label: string) => {
    const matches = root!.root.findAllByType("button").filter(node => text(node) === label);
    if (matches.length !== 1 || matches[0]!.props.disabled) throw setup(`enabled public button missing: ${label}`);
    return matches[0]!;
  };
  async function press(label: string) {
    const node = button(label);
    await act(async () => {
      if (node.props.type === "submit") root!.root.findByType("form").props.onSubmit({ preventDefault() {} });
      else node.props.onClick({ preventDefault() {} });
    });
  }
  async function input(label: string, value: string) {
    const field = root!.root.findAllByType("input").find(node => node.props["aria-label"] === label || root!.root.findAllByType("label").some(owner => owner.props.htmlFor === node.props.id && text(owner) === label));
    if (!field || field.props.disabled) throw setup(`enabled public input missing: ${label}`);
    await act(async () => field.props.onChange({ target: { value } }));
  }
  async function login(waitForDrain = true) {
    await input("Username", USER); await input("Password", PASSWORD); await press("Sign in");
    await complete("real mandatory MFA challenge", () => rendered().includes("Verify code"));
    if (hasSession()) throw setup("password-only login adopted a session");
    await input("Authenticator code (or recovery code)", "123456"); await press("Verify code");
    await complete("same clinician authenticated caseload", () => hasSession() && rendered().includes("Patients — Dr. Native Retirement") && ((viewBoundary || fallback) ? rendered().includes(patientName) : rendered().includes("No patients are sharing")));
    if (waitForDrain) await drain();
  }
  function retireAtOriginalBoundary() {
    if (finishing) return;
    if (viewRetired || submitActOpen) throw setup("original producer retirement repeated or submit act still open");
    const open = button("Open patterns");
    viewRetired = true; phase = "retired action"; boundaryReached = true;
    act(() => { open.props.onClick({ preventDefault() {} }); });
    if (!hasSession()) throw setup("public view retirement ended the genuine API owner");
    retiredBoundary.resolve();
  }
  function beforeNextProducer<T>(original: Promise<T>, target: string, validate?: (value: T) => void) {
    if (producerBoundary === target && phase === "security action") void original.then(value => {
      try { validate?.(value); retireAtOriginalBoundary(); } catch (error) { faults.push(error); }
    }, error => { faults.push(error); });
    return original;
  }
  function send(response: ServerResponse, value: unknown, status = 200) {
    response.writeHead(status, { "content-type": "application/json" }); response.end(status === 204 ? undefined : JSON.stringify(value));
  }
  const server = createServer((request, response) => {
    const original = (async () => {
      let wire = ""; for await (const part of request) wire += String(part);
      const body = wire ? JSON.parse(wire) as Record<string, unknown> : {}, path = new URL(request.url ?? "", origin).pathname;
      const bearer = request.headers.authorization ?? null; requests.push({ path, bearer });
      if (wire.includes(PASSWORD)) throw setup("plaintext password crossed native HTTP");
      if (path === "/api/v1/meta") return send(response, { sharing_available: true });
      if (path === "/api/v1/auth/salt") {
        saltRequests += 1;
        if (scenario === "retired salt completion" && !kdfBoundary && saltRequests === 3) { heldResponse = response; heldSalt.resolve(); if (finishing) send(response, { salt: SALT }); return; }
        return send(response, { salt: SALT });
      }
      if (path === "/api/v1/auth/login") {
        if (body.username !== USER || body.verifier !== verifier) throw setup("independent 600k verifier mismatch");
        if (body.totp_code === undefined) return send(response, { code: "totp_required", detail: "MFA required" }, 401);
        if (body.totp_code !== "123456") throw setup("public MFA code mismatch");
        const token = `owned-retirement-bearer-${++successfulLogins}`; tokens.add(token);
        return send(response, { token, user_id: OWNER, role: "therapist", expires_in: 86400, mfa_enrollment_required: false });
      }
      if (path === "/api/v1/auth/logout") { logoutRequests += 1; tokens.clear(); return send(response, null, 204); }
      if (!bearer || !tokens.has(bearer.replace(/^Bearer /, ""))) throw setup("protected native request lacks live bearer");
      if (path === "/api/v1/therapist/me") return send(response, { username: USER, display_name: "Dr. Native Retirement", wrap_pub_key: serverPublicKey, wrap_key_blob: envelope, notes_keyring_blob: custodyBlob, custody_version: custodyVersion, totp_enabled: totpEnabled });
      if (path === "/api/v1/therapist/patients") return send(response, viewBoundary || fallback ? [patient] : []);
      if ((viewBoundary || fallback) && path === `/api/v1/therapist/patients/${patientId}/notes`) return send(response, installedRing && !viewRetired ? [note] : []);
      if (installedRing && path === `/api/v1/therapist/notes/${noteId}/revisions`) {
        if ((producerBoundary === "300" || producerBoundary === "384") && !viewRetired) { finalRevisionResponse = response; finalRevisionArrived.resolve(); if (finishing) send(response, []); return; }
        return send(response, []);
      }
      if (viewBoundary && path === `/api/v1/therapist/patients/${patientId}/measures`) return send(response, []);
      if (viewBoundary && path === `/api/v1/therapist/patients/${patientId}/insights`) return send(response, { phase: "baseline", active_days: 1, streak: 1, days_remaining: 3, state_seq: 0, blob: null });
      if (path === "/api/v1/therapist/custody") {
        if (body.verifier !== verifier || body.expected_custody_version !== custodyVersion || body.custody_version !== custodyVersion + 1) throw setup("native custody proof/version mismatch");
        const plain = open(accountKeys.wrap, ["portal-notes-keyring", OWNER, "v1"], String(body.notes_keyring_blob));
        try {
          const ring = JSON.parse(plain.toString("utf8")) as { v: number; active: string; historical: string[] };
          if (ring.v !== 1 || Buffer.from(ring.active, "base64").length !== 32 || !ring.historical.includes(accountKeys.note.toString("base64")) || !ring.historical.includes(identityNote.toString("base64"))) throw setup("independent notes custody differs");
          custodyBlob = String(body.notes_keyring_blob); custodyVersion += 1; return send(response, null, 204);
        } finally { plain.fill(0); }
      }
      if (path === "/api/v1/therapist/wrap-key") {
        if (request.headers["x-account-verifier"] !== verifier || body.expected_custody_version !== custodyVersion || custodyVersion !== 1 || (recovery ? body.wrap_pub_key !== publicKey : body.wrap_pub_key === publicKey)) throw setup("native rotation proof/custody mismatch");
        const plain = open(accountKeys.wrap, ["therapist-key", USER], String(body.wrap_key_blob));
        try {
          const fresh = createPrivateKey({ key: plain, format: "der", type: "pkcs8" });
          if (createPublicKey(fresh).export({ format: "der", type: "spki" }).toString("base64") !== body.wrap_pub_key) throw setup("independent rotated identity does not match public key");
          serverPublicKey = String(body.wrap_pub_key); envelope = String(body.wrap_key_blob); rotationCommits += 1; if (!recovery) tokens.clear(); return send(response, null, 204);
        } finally { plain.fill(0); }
      }
      if (path === "/api/v1/account/totp/disable") {
        if (!totpEnabled || body.verifier !== verifier || body.code !== "654321") throw setup("fresh authenticator/verifier proof mismatch");
        totpEnabled = false; disableCommits += 1; return send(response, null, 204);
      }
      throw setup(`unexpected owned route ${path}`);
    })();
    handlers.push(original); void original.catch(error => { faults.push(error); if (!response.writableEnded) send(response, { detail: "Owned fixture failure" }, 500); });
  });
  function restore(target: object, key: PropertyKey, descriptor: PropertyDescriptor | undefined) { if (descriptor) Object.defineProperty(target, key, descriptor); else Reflect.deleteProperty(target, key); }
  try {
    await finite("owned HTTP listen", new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }));
    const address = server.address(); if (!address || typeof address === "string") throw setup("owned loopback address missing"); origin = `http://127.0.0.1:${address.port}`;
    Object.defineProperty(window.location, "origin", { configurable: true, value: origin });
    vi.spyOn(globalThis, "fetch").mockImplementation((...args) => {
      const url = new URL(typeof args[0] === "string" ? args[0] : args[0] instanceof URL ? args[0].href : args[0].url);
      if (url.origin !== origin) throw setup("native fetch escaped owned origin");
      if (producerBoundary && ["/api/v1/therapist/me", "/api/v1/therapist/custody", "/api/v1/therapist/wrap-key"].includes(url.pathname) && (phase === "security action" || phase === "retired action")) admissionEvents.push({ kind: `HTTP ${url.pathname}`, retired: viewRetired });
      const original = nativeFetch(...args); return track(original);
    });
    Object.defineProperty(Response.prototype, "json", { ...oldJson, value: function (this: Response) { const original = originalJson.call(this); nativeBodies.push(track(original)); return original; } });
    Object.defineProperty(subtle, "deriveBits", { ...oldBits, configurable: true, value: (...args: Parameters<SubtleCrypto["deriveBits"]>) => {
      const owned = (phase === "security action" || phase === "retired action") && (!producerBoundary || typeof args[0] === "object" && (args[0].name === "PBKDF2" || args[0].name === "HKDF" && ["mindpattern/auth/v1", "mindpattern/portal-wrap/v1", "mindpattern/portal-notes/v1", "mindpattern/portal-notes/v2"].some(info => equalBytes((args[0] as HkdfParams).info, Buffer.from(info))))), original = originalBits.apply(subtle, args);
      if (typeof args[0] === "object" && args[0].name === "PBKDF2") {
        const parameters = args[0] as Pbkdf2Params;
        const salt = ArrayBuffer.isView(parameters.salt) ? new Uint8Array(parameters.salt.buffer, parameters.salt.byteOffset, parameters.salt.byteLength) : new Uint8Array(parameters.salt);
        const hash = typeof parameters.hash === "string" ? parameters.hash : parameters.hash.name;
        if (hash !== "SHA-256" || parameters.iterations !== 600000 || args[2] !== 256 || salt.length !== 16
          || args[1].algorithm.name !== "PBKDF2" || args[1].type !== "secret" || args[1].extractable !== false
          || args[1].usages.length !== 1 || args[1].usages[0] !== "deriveBits") faults.push(setup("native password KDF parameters or CryptoKey custody differ"));
        const admission = { retired: viewRetired, phase, salt: Buffer.from(salt).toString("base64"), original, settled: false };
        passwordAdmissions.push(admission);
        void original.then(() => { admission.settled = true; }, () => { admission.settled = true; });
        if (kdfBoundary && phase === "security action") admittedKdf.resolve();
      }
      if (producerBoundary && owned && typeof args[0] === "object" && args[0].name === "HKDF" && equalBytes((args[0] as HkdfParams).info, Buffer.from("mindpattern/portal-notes/v2"))) admissionEvents.push({ kind: "native identity HKDF", retired: viewRetired });
      void original.then(bits => { if (owned) secretArrays.push(new Uint8Array(bits)); }, error => { faults.push(error); }); return track(original);
    } });
    Object.defineProperty(subtle, "decrypt", { ...oldDecrypt, configurable: true, value: (...args: Parameters<SubtleCrypto["decrypt"]>) => {
      let owned = phase === "security action" || phase === "retired action"; const original = originalDecrypt.apply(subtle, args);
      const parameters = typeof args[0] === "object" && args[0].name === "AES-GCM" ? args[0] as AesGcmParams : undefined;
      const ringInput = !!parameters && !!nativeRingWire && equalBytes(parameters.iv, nativeRingWire.subarray(0, 12)) && equalBytes(args[2], nativeRingWire.subarray(12)) && equalBytes(parameters.additionalData, Buffer.from(JSON.stringify(["portal-notes-keyring", OWNER, "v1"])));
      const securityInput = !!parameters && [JSON.stringify(["therapist-key", USER]), JSON.stringify(["portal-notes-keyring", OWNER, "v1"])].some(aad => equalBytes(parameters.additionalData, Buffer.from(aad)));
      owned = owned && (!producerBoundary || securityInput);
      if (producerBoundary && owned && securityInput) admissionEvents.push({ kind: "native security AES decrypt", retired: viewRetired });
      // The declared fallback ring is independently sealed under intended KEK.
      // Only its first exact native ciphertext/AAD probe under current KEK can fail.
      const expected = fallback && owned && ringInput && ringOpenCalls === 1;
      void original.then(bytes => { if (owned) secretArrays.push(new Uint8Array(bytes)); if (ringInput) successfulNativeRingDecrypts += 1; }, error => {
        if (expected && error instanceof DOMException && error.name === "OperationError") expectedNativeRingFailures += 1;
        else faults.push(error);
      }); return track(original, expected);
    } });
    Object.defineProperty(subtle, "exportKey", { ...oldExport, configurable: true, value: (format: "spki" | "pkcs8" | "raw", key: CryptoKey) => {
      const owned = phase === "security action" || phase === "retired action", original = originalExport.call(subtle, format, key);
      void original.then(bytes => { if (owned && format === "pkcs8") { if (!(bytes instanceof ArrayBuffer)) { faults.push(setup("native PKCS8 export did not return an ArrayBuffer")); return; } secretArrays.push(new Uint8Array(bytes)); } }, error => { faults.push(error); }); return track(original);
    } });
    Object.defineProperty(crypto, "getRandomValues", { ...oldRandom, configurable: true, value: <T extends ArrayBufferView>(array: T): T => {
      const original = originalRandom.call(crypto, array);
      if ((phase === "security action" || phase === "retired action") && array instanceof Uint8Array && (array.length === 16 || array.length === 32)) saltArrays.push(array);
      return original as T;
    } });
    const originalEncrypt = subtle.encrypt, originalGenerate = subtle.generateKey, oldEncrypt = Object.getOwnPropertyDescriptor(subtle, "encrypt"), oldGenerate = Object.getOwnPropertyDescriptor(subtle, "generateKey");
    Object.defineProperty(subtle, "encrypt", { ...oldEncrypt, configurable: true, value: (...args: Parameters<SubtleCrypto["encrypt"]>) => {
      const parameters = typeof args[0] === "object" && args[0].name === "AES-GCM" ? args[0] as AesGcmParams : undefined;
      if (producerBoundary && parameters && [JSON.stringify(["therapist-key", USER]), JSON.stringify(["portal-notes-keyring", OWNER, "v1"])].some(aad => equalBytes(parameters.additionalData, Buffer.from(aad)))) admissionEvents.push({ kind: "native security AES encrypt", retired: viewRetired });
      return track(originalEncrypt.apply(subtle, args));
    } });
    nativeRestores.push(() => restore(subtle, "encrypt", oldEncrypt));
    Object.defineProperty(subtle, "generateKey", { ...oldGenerate, configurable: true, value: (...args: Parameters<SubtleCrypto["generateKey"]>) => {
      if (producerBoundary && typeof args[0] === "object" && args[0].name === "ECDH") admissionEvents.push({ kind: "native ECDH generateKey", retired: viewRetired });
      return track(originalGenerate.apply(subtle, args));
    } });
    nativeRestores.push(() => restore(subtle, "generateKey", oldGenerate));
    const originalSaltFor = auth.saltFor, originalMaster = portalCrypto.deriveMasterKey, originalPortalKeys = portalCrypto.derivePortalKeys;
    const apiNotes = api.notes, apiInsights = api.patientInsights, apiMeasures = api.patientMeasures;
    vi.spyOn(auth, "saltFor").mockImplementation(function (this: unknown, ...args: Parameters<typeof auth.saltFor>) {
      const original = originalSaltFor.apply(this, args); securityOriginals.push(original); return track(original);
    });
    vi.spyOn(portalCrypto, "deriveMasterKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.deriveMasterKey>) {
      const original = originalMaster.apply(this, args); securityOriginals.push(original); return track(original);
    });
    vi.spyOn(portalCrypto, "derivePortalKeys").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.derivePortalKeys>) {
      const original = originalPortalKeys.apply(this, args); securityOriginals.push(original);
      if (phase === "security action" && ++securityPortalKeyCalls === 2) beforeNextProducer(original, "279");
      return track(original);
    });
    vi.spyOn(api, "notes").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.notes>) {
      const original = apiNotes.apply(this, args); if (!producerBoundary || viewRetired) chartOriginals.push(original); securityOriginals.push(original); return track(original);
    });
    vi.spyOn(api, "patientInsights").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.patientInsights>) {
      const original = apiInsights.apply(this, args); chartOriginals.push(original); return track(original);
    });
    vi.spyOn(api, "patientMeasures").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.patientMeasures>) {
      const original = apiMeasures.apply(this, args); chartOriginals.push(original); return track(original);
    });
    const originalMe = api.me, originalInstall = api.installNotesCustody, originalRotate = api.rotateWrapKey, originalRevisions = api.noteRevisions;
    const originalOpen = portalCrypto.openSealedPrivateKey, originalIdentity = portalCrypto.noteKeyV2FromPrivateKey, originalRing = portalCrypto.openNotesKeyring;
    const originalSealRing = portalCrypto.sealNotesKeyring, originalSealPrivate = portalCrypto.sealPrivateKeyForUpload, originalPair = portalCrypto.generateTherapistKeyPair;
    vi.spyOn(api, "me").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.me>) {
      const original = originalMe.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") {
        const call = ++securityProfileCalls;
        if (call === 1) { beforeNextProducer(original, "280"); beforeNextProducer(original, "371"); }
        if (call === 2) { beforeNextProducer(original, "306"); beforeNextProducer(original, "390"); }
      }
      return track(original);
    });
    vi.spyOn(portalCrypto, "openSealedPrivateKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.openSealedPrivateKey>) {
      const original = originalOpen.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") { beforeNextProducer(original, "281", value => { if (!value || !equalBytes(value, privateBytes)) throw setup("original PKCS8 plaintext differs"); }); beforeNextProducer(original, "379"); }
      return track(original);
    });
    vi.spyOn(portalCrypto, "noteKeyV2FromPrivateKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.noteKeyV2FromPrivateKey>) {
      const original = originalIdentity.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") { beforeNextProducer(original, "289"); beforeNextProducer(original, "380"); }
      return track(original);
    });
    vi.spyOn(portalCrypto, "openNotesKeyring").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.openNotesKeyring>) {
      if (phase === "security action" || phase === "retired action") ringOpenCalls += 1;
      const expected = fallback && ringOpenCalls === 1 && args[2] === originalRingBlob && equalBytes(args[0], accountKeys.wrap);
      const original = originalRing.apply(this, args); securityOriginals.push(original);
      if (expected) void original.then(() => { faults.push(setup("intended-KEK ring unexpectedly opened with current KEK")); }, error => {
        if (!(error instanceof portalCrypto.TamperError) || expectedNativeRingFailures !== 1) faults.push(setup("known original native ring authentication failure differs", error));
        else if (producerBoundary === "295") try { retireAtOriginalBoundary(); } catch (fault) { faults.push(fault); }
      });
      return track(original, expected);
    });
    vi.spyOn(portalCrypto, "sealNotesKeyring").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.sealNotesKeyring>) {
      const original = originalSealRing.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") { beforeNextProducer(original, "302"); beforeNextProducer(original, "386"); }
      return track(original);
    });
    vi.spyOn(api, "installNotesCustody").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.installNotesCustody>) {
      const original = originalInstall.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") { beforeNextProducer(original, "305"); beforeNextProducer(original, "389"); }
      return track(original);
    });
    vi.spyOn(portalCrypto, "sealPrivateKeyForUpload").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.sealPrivateKeyForUpload>) {
      const original = originalSealPrivate.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") beforeNextProducer(original, "317");
      return track(original);
    });
    vi.spyOn(portalCrypto, "generateTherapistKeyPair").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.generateTherapistKeyPair>) {
      const original = originalPair.apply(this, args); securityOriginals.push(original);
      if (phase === "security action") beforeNextProducer(original, "402");
      return track(original);
    });
    vi.spyOn(api, "rotateWrapKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.rotateWrapKey>) {
      const original = originalRotate.apply(this, args); securityOriginals.push(original);
      // A completed wrap PUT has global cleanup/session-ending effects; no stale-view blocker is imposed here.
      return track(original);
    });
    vi.spyOn(api, "noteRevisions").mockImplementation(function (this: unknown, ...args: Parameters<typeof api.noteRevisions>) {
      const original = originalRevisions.apply(this, args); securityOriginals.push(original);
      if ((producerBoundary === "300" || producerBoundary === "384") && !viewRetired) finalRevisionOriginal = original;
      return track(original);
    });
    await act(async () => { root = RTR.create(<App />); }); await login();
    // Model the stored result of an interrupted legacy wrap after this live login.
    if (intendedKeys) envelope = seal(intendedKeys.wrap, ["therapist-key", USER], privateBytes);
    if (fallback) custodyBlob = originalRingBlob;
    await press("Show account security"); await complete("enrolled native account status", () => rendered().includes("Disable two-factor")); await drain();
    if (recovery) {
      await input("Current password (the one you sign in with)", PASSWORD);
      await input("The password you were changing to", intendedPassword);
    } else if (action === "rotation") {
      await input("Current password (to authorize rotation)", PASSWORD);
      const confirm = root!.root.findAllByType("input").find(node => node.props["aria-label"] === "Confirm sharing-key rotation");
      if (!confirm) throw setup("public rotation confirmation missing"); await act(async () => confirm.props.onChange({ target: { checked: true } }));
    } else {
      await input("Current password (to disable two-factor)", PASSWORD); await input("6-digit code (to disable two-factor)", "654321");
    }
    phase = "security action"; submitActOpen = true;
    try { await press(recovery ? "Recover sharing key" : action === "rotation" ? "Rotate sharing key" : "Disable two-factor"); } finally { submitActOpen = false; }
    if (scenario === "live completion") {
      await complete("authenticated live security action", () => recovery ? rotationCommits === 1 && hasSession() && rendered().includes("Sharing key recovered") : action === "rotation" ? rotationCommits === 1 && !hasSession() && rendered().includes("Every session") : disableCommits === 1 && hasSession() && rendered().includes("Set up authenticator")); await drain();
      await settleSecurityOriginals();
      expect(passwordAdmissions.filter(row => row.phase === "security action").map(row => row.salt)).toEqual(recovery ? [SALT, intendedSalt] : [SALT]);
      expect(successfulLogins).toBe(1);
      if (recovery) {
        expect(rotationCommits).toBe(1); expect(custodyVersion).toBe(1); expect(serverPublicKey).toBe(publicKey); expect(hasSession()).toBe(true);
        expect(window.sessionStorage.getItem(`mindpattern.interruptedRotateSalt.${OWNER}`)).toBeNull();
        if (fallback) { expect(expectedNativeRingFailures).toBe(1); expect(successfulNativeRingDecrypts).toBe(1); expect(ringOpenCalls).toBe(2); }
      } else if (action === "rotation") {
        expect(rotationCommits).toBe(1); expect(custodyVersion).toBe(1); expect(serverPublicKey).not.toBe(publicKey); expect(hasSession()).toBe(false);
        expect(secretArrays.length).toBeGreaterThanOrEqual(7); expect(saltArrays.length).toBe(1);
      } else {
        expect(disableCommits).toBe(1); expect(totpEnabled).toBe(false); expect(tokens.has("owned-retirement-bearer-1")).toBe(true); expect(hasSession()).toBe(true);
        expect(secretArrays.length).toBe(4); expect(saltArrays.length).toBe(0);
      }
    } else if (producerBoundary) {
      await finite("original phase salt held until public submit act closes", heldSalt.promise);
      if (!heldResponse || heldResponse.writableEnded || submitActOpen) throw setup("phase original salt or closed submit act missing");
      send(heldResponse, { salt: SALT });
      if (producerBoundary === "300" || producerBoundary === "384") {
        await finite("last genuine revisions HTTP is held", finalRevisionArrived.promise);
        if (!finalRevisionOriginal || !finalRevisionResponse || finalRevisionResponse.writableEnded) throw setup("last original revisions producer missing");
        // This HTTP arrival follows the helper caller registering its own await.
        // Its earlier reaction passes the inner guard and fulfills custody;
        // our queued postreaction retires before the outer caller resumes.
        void finalRevisionOriginal.then(rows => { try { if (rows.length !== 0) throw setup("terminal revisions response differs"); retireAtOriginalBoundary(); } catch (error) { faults.push(error); } }, error => { faults.push(error); });
        send(finalRevisionResponse, []);
      }
      await finite("same original boundary retires current enabled view", retiredBoundary.promise);
      await settleSecurityOriginals(); await drain();
      expect(admissionEvents.filter(event => event.retired), "retired account-security producer cannot admit another genuine crypto job or protected HTTP operation").toEqual([]);
      expect(hasSession(), "retired security completion cannot lock the current chart").toBe(true);
      expect(rendered()).toContain("Still in the baseline phase");
      expect(boundaryReached).toBe(true);
      if (fallback) { expect(expectedNativeRingFailures).toBe(1); expect(ringOpenCalls).toBe(1); }
      expect((await api.me()).username).toBe(USER); await drain();
    } else if (viewBoundary) {
      if (kdfBoundary) await finite("first genuine native security PBKDF2 admitted after submit act closed", admittedKdf.promise);
      else await finite("original native security salt HTTP held after submit act closed", heldSalt.promise);
      const firstKdf = passwordAdmissions.find(row => row.phase === "security action");
      if (!hasSession() || (kdfBoundary ? !firstKdf || firstKdf.settled : !heldResponse || heldResponse.writableEnded)) throw setup("live API owner or genuine pending security boundary missing");
      await press("Open patterns");
      viewRetired = true; phase = "retired action";
      if (kdfBoundary && firstKdf!.settled) throw setup("original native PBKDF2 completed before public view retirement");
      await complete("healthy current chart while old security view is retired", () => rendered().includes(patientName) && rendered().includes("Still in the baseline phase") && rendered().includes("No notes yet."));
      await finite("original current chart notes, measures and insights producers", Promise.all(chartOriginals));
      if (chartOriginals.length !== 3) throw setup("current chart did not issue its three genuine public API producers");
      if (!kdfBoundary) send(heldResponse!, { salt: SALT });
      await settleSecurityOriginals(); await drain();
      // This observes a real WebCrypto job, rather than an internal helper count.
      expect(passwordAdmissions.filter(row => row.retired), "retired account-security salt cannot admit another native 600k PBKDF2-SHA256 job").toEqual([]);
      expect(hasSession()).toBe(true); expect(tokens.has("owned-retirement-bearer-1")).toBe(true);
      expect((await api.me()).username).toBe(USER); await drain();
      expect(rotationCommits).toBe(0); expect(disableCommits).toBe(0); expect(logoutRequests).toBe(0);
      expect(successfulLogins).toBe(1); expect(rendered()).toContain("Still in the baseline phase");
    } else {
      await finite("owned pending old-form salt request", heldSalt.promise);
      // This enabled rendered button is the actual App lockDown path.
      await press("Sign out"); await complete("old bearer revoked and public login shown", () => logoutRequests === 1 && !hasSession() && rendered().includes("Sign in"));
      phase = "replacement login"; await login(false);
      const before = requests.length; phase = "retired action";
      if (!heldResponse || heldResponse.writableEnded) throw setup("owned old salt response unavailable"); send(heldResponse, { salt: SALT }); await drain();
      expect(requests.slice(before).filter(row => row.bearer !== null)).toEqual([]);
      expect(rotationCommits).toBe(0); expect(disableCommits).toBe(0); expect(totpEnabled).toBe(true); expect(successfulLogins).toBe(2); expect(tokens.has("owned-retirement-bearer-2")).toBe(true); expect(hasSession()).toBe(true); expect(rendered()).toContain("Patients — Dr. Native Retirement"); expect(button("Sign out")).toBeDefined();
    }
    for (const bytes of [...secretArrays, ...saltArrays]) expect(bytes.every(value => value === 0)).toBe(true);
    expect(nativeBodies.length).toBeGreaterThanOrEqual(6); expect(unhandled).toEqual([]); clean();
  } catch (error) { failed = true; originalFailure = error; throw error; } finally {
    finishing = true;
    if (heldResponse && !heldResponse.writableEnded) send(heldResponse, { salt: SALT });
    if (finalRevisionResponse && !finalRevisionResponse.writableEnded) send(finalRevisionResponse, []);
    const cleanupFaults: unknown[] = [];
    try { await settleSecurityOriginals(); } catch (error) { cleanupFaults.push(error); }
    try { if (root) await act(async () => root!.unmount()); } catch (error) { cleanupFaults.push(error); }
    try { await drainPortalDraftWritesForTests(); } catch (error) { cleanupFaults.push(error); }
    try { await drain(); } catch (error) { cleanupFaults.push(error); }
    clearSession();
    try { await finite("owned server handlers retired", Promise.all(handlers)); } catch (error) { cleanupFaults.push(error); }
    server.closeAllConnections();
    try { if (server.listening) await finite("owned server closed", new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))); } catch (error) { cleanupFaults.push(error); }
    for (const undo of nativeRestores.reverse()) undo();
    restore(subtle, "deriveBits", oldBits); restore(subtle, "exportKey", oldExport); restore(subtle, "decrypt", oldDecrypt); restore(crypto, "getRandomValues", oldRandom); restore(Response.prototype, "json", oldJson); restore(window.location, "origin", oldOrigin);
    vi.restoreAllMocks(); process.removeListener("unhandledRejection", observeUnhandled); window.location.hash = "";
    for (const bytes of [accountKeys.auth, accountKeys.wrap, accountKeys.note, identityNote, privateBytes]) bytes.fill(0);
    for (const bytes of [intendedKeys?.auth, intendedKeys?.wrap, intendedKeys?.note]) bytes?.fill(0);
    const cleanupFailure = cleanupFaults[0] ?? faults[0] ?? unhandled[0];
    if (cleanupFaults.length || faults.length || unhandled.length) {
      const error = setup("owned cleanup failed", cleanupFailure);
      throw failed ? new AggregateError([originalFailure, error], "original public failure and owned cleanup failure") : error;
    }
  }
  }
}, 120000);
