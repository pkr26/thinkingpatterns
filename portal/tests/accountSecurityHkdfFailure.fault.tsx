/** Dedicated owned Node-fork provider profile, excluded from ordinary tests.
 * Original HTTP/WebCrypto/API Promises are forwarded without replacement. */
import { createCipheriv, generateKeyPairSync, getFips, hkdfSync, pbkdf2Sync, randomBytes, setFips } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import * as portalCrypto from "../src/crypto";
import { drainPortalDraftWritesForTests } from "./helpers/testControl";

const USER = "native_hkdf_failure_clinician", OWNER = "0123456789abcdef0123456789abcdef";
const PASSWORD = "correct horse battery staple", SALT = "AAECAwQFBgcICQoLDA0ODw==";
const setup = (message: string) => new Error(`SetupError: native HKDF profile: ${message}`);
const text = (node: unknown): string => typeof node === "string" || typeof node === "number" ? String(node) : Array.isArray(node) ? node.map(text).join("") : node && typeof node === "object" && "children" in node ? text((node as { children: unknown }).children) : "";
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, index) => value === b[index]);

it("preserves the genuine native HKDF failure explanation and current account retry", async () => {
  vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = "";
  const startingFips = getFips();
  if (startingFips !== 0) throw setup("owned child must begin outside FIPS");
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const derive = (label: string) => Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), label, 32));
  const authKey = derive("mindpattern/auth/v1"), wrapKey = derive("mindpattern/portal-wrap/v1"); master.fill(0);
  const verifier = authKey.toString("base64"), pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateBytes = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", wrapKey, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["therapist-key", USER])));
  const envelope = Buffer.concat([nonce, cipher.update(privateBytes), cipher.final(), cipher.getAuthTag()]).toString("base64");
  let root: ReactTestRenderer | undefined, origin = "", phase = "login", token: string | null = null;
  let passwordProofs = 0, successfulLogins = 0, protectedProfiles = 0, nativeRefusals = 0, helperRefusals = 0;
  let nativeAesVerified = false, activatedFips = false, restoredFips = false, failed = false;
  let nativeFailure: { name: string; message: string; stack: string; fipsAtRefusal: number } | undefined;
  let originalFailure: unknown;
  const events: Array<{ event: string; fips: number }> = [], faults: unknown[] = [], unhandled: unknown[] = [];
  const pending = new Set<Promise<unknown>>(), created: Promise<unknown>[] = [], handlers: Promise<void>[] = [];
  const witness: Record<string, unknown> = { nodeVersion: process.version, startingFips, stage: "started", limits: ["Owned Node22 native OpenSSL FIPS refusal profile; not a browser/device FIPS availability claim.", "Actual mounted App Login/MFA/account form, native HTTP and WebCrypto. Original producer Promises forwarded unchanged. No synthetic rejected Promise/error or private React state."] };
  const rendered = () => root ? text(root.root) : "";
  const save = () => { if (process.env.NATIVE_HKDF_FAULT_RECEIPT) writeFileSync(process.env.NATIVE_HKDF_FAULT_RECEIPT, JSON.stringify(witness, null, 2) + "\n"); };
  const restoreFips = () => { setFips(startingFips !== 0); restoredFips = getFips() === startingFips; events.push({ event: "native-profile-restored", fips: getFips() }); };
  function track<T>(original: Promise<T>, expectedRefusal = false): Promise<T> {
    created.push(original); pending.add(original);
    void original.then(() => pending.delete(original), error => { pending.delete(original); if (!expectedRefusal) faults.push(error); });
    return original;
  }
  const clean = () => { if (faults.length || unhandled.length) throw setup("unknown owned producer/server error"); };
  async function complete(label: string, ready: () => boolean): Promise<void> {
    const until = Date.now() + 15_000;
    while (!ready()) { clean(); if (Date.now() >= until) throw setup(`completion missing: ${label}`); await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); }); }
    clean();
  }
  async function drain(): Promise<void> {
    let stable = 0, last = -1;
    await complete("all original producers and public continuations", () => { stable = pending.size === 0 && last === created.length ? stable + 1 : 0; last = created.length; return stable >= 4; });
  }
  function button(label: string) {
    const candidates = root!.root.findAllByType("button").filter(node => text(node) === label);
    if (candidates.length !== 1 || candidates[0]!.props.disabled) throw setup(`enabled public button missing: ${label}`);
    return candidates[0]!;
  }
  async function press(label: string): Promise<void> {
    const node = button(label);
    await act(async () => { if (node.props.type === "submit") root!.root.findByType("form").props.onSubmit({ preventDefault() {} }); else node.props.onClick({ preventDefault() {} }); });
  }
  async function input(label: string, value: string): Promise<void> {
    const field = root!.root.findAllByType("input").find(node => node.props["aria-label"] === label || root!.root.findAllByType("label").some(owner => owner.props.htmlFor === node.props.id && text(owner) === label));
    if (!field || field.props.disabled) throw setup(`enabled public input missing: ${label}`);
    await act(async () => field.props.onChange({ target: { value } }));
  }
  async function confirmRotation(): Promise<void> {
    const checkbox = root!.root.findAllByType("input").find(node => node.props["aria-label"] === "Confirm sharing-key rotation");
    if (!checkbox) throw setup("current public rotation confirmation missing");
    await act(async () => checkbox.props.onChange({ target: { checked: true } }));
  }
  function send(response: ServerResponse, body: unknown, status = 200): void { response.writeHead(status, { "Content-Type": "application/json" }); response.end(status === 204 ? undefined : JSON.stringify(body)); }
  const server = createServer((request, response) => {
    const original = (async () => {
      let wire = ""; for await (const part of request) wire += String(part);
      const body = wire ? JSON.parse(wire) as Record<string, unknown> : {}, path = new URL(request.url ?? "", origin).pathname;
      if (wire.includes(PASSWORD)) throw setup("plaintext password crossed native HTTP");
      if (path === "/api/v1/meta") return send(response, { sharing_available: true });
      if (path === "/api/v1/auth/salt") return send(response, { salt: SALT });
      if (path === "/api/v1/auth/login") {
        if (body.username !== USER || body.verifier !== verifier) throw setup("independent genuine600k verifier mismatch");
        passwordProofs++;
        if (body.totp_code === undefined) return send(response, { code: "totp_required", detail: "MFA required" }, 401);
        if (body.totp_code !== "123456") throw setup("actual public MFA code mismatch");
        token = `native-hkdf-bearer-${++successfulLogins}`;
        return send(response, { token, user_id: OWNER, role: "therapist", expires_in: 86400, mfa_enrollment_required: false });
      }
      if (path === "/api/v1/auth/logout") { token = null; return send(response, null, 204); }
      if (!token || request.headers.authorization !== `Bearer ${token}`) throw setup("protected request lacks unchanged genuine bearer");
      if (path === "/api/v1/therapist/me") { protectedProfiles++; return send(response, { username: USER, display_name: "Dr. Native HKDF", wrap_pub_key: publicKey, wrap_key_blob: envelope, custody_version: 0, totp_enabled: true }); }
      if (path === "/api/v1/therapist/patients") return send(response, []);
      throw setup(`unexpected protected operation after native refusal: ${path}`);
    })();
    handlers.push(original); void original.catch(error => { faults.push(error); if (!response.writableEnded) send(response, { detail: "Owned profile failure" }, 500); });
  });
  const oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), nativeFetch = globalThis.fetch;
  const subtle = crypto.subtle, nativeBits = subtle.deriveBits, oldBits = Object.getOwnPropertyDescriptor(subtle, "deriveBits");
  const nativeOpen = portalCrypto.openSealedPrivateKey, nativeIdentity = portalCrypto.noteKeyV2FromPrivateKey;
  const onUnhandled = (error: unknown) => { unhandled.push(error); };
  process.on("unhandledRejection", onUnhandled);
  try {
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); });
    const address = server.address(); if (!address || typeof address === "string") throw setup("owned native HTTP address absent");
    origin = `http://127.0.0.1:${address.port}`; Object.defineProperty(window.location, "origin", { configurable: true, value: origin });
    vi.spyOn(globalThis, "fetch").mockImplementation((...args) => {
      const url = new URL(typeof args[0] === "string" ? args[0] : args[0] instanceof URL ? args[0].href : args[0].url);
      if (url.origin !== origin) throw setup("HTTP escaped owned origin");
      return track(nativeFetch(...args));
    });
    Object.defineProperty(subtle, "deriveBits", { ...oldBits, configurable: true, value: (...args: Parameters<SubtleCrypto["deriveBits"]>) => {
      const info = typeof args[0] === "object" && args[0].name === "HKDF" ? (args[0] as HkdfParams).info : undefined;
      const bytes = info ? ArrayBuffer.isView(info) ? new Uint8Array(info.buffer, info.byteOffset, info.byteLength) : new Uint8Array(info) : undefined;
      const expectedRefusal = phase === "account rotation" && activatedFips && getFips() === 1 && !!bytes && equal(bytes, new TextEncoder().encode("mindpattern/portal-notes/v2"));
      const original = nativeBits.apply(subtle, args);
      if (expectedRefusal) void original.then(() => {}, () => { nativeRefusals++; events.push({ event: "original-native-HKDF-Promise-rejected", fips: getFips() }); });
      return track(original, expectedRefusal);
    } });
    vi.spyOn(portalCrypto, "openSealedPrivateKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.openSealedPrivateKey>) {
      const original = nativeOpen.apply(this, args);
      if (phase === "account rotation") void original.then(value => {
        try {
          if (!value || !equal(value, privateBytes)) throw setup("genuine native AES PKCS8 authentication differs");
          nativeAesVerified = true; events.push({ event: "original-AES-open-Promise-fulfilled", fips: getFips() });
          setFips(true); activatedFips = getFips() === 1;
          if (!activatedFips) throw setup("native refusal profile unavailable");
          events.push({ event: "native-FIPS-enabled-before-public-caller-HKDF", fips: getFips() });
        } catch (error) { restoreFips(); faults.push(error); }
      }, error => { faults.push(error); });
      return track(original);
    });
    vi.spyOn(portalCrypto, "noteKeyV2FromPrivateKey").mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.noteKeyV2FromPrivateKey>) {
      const original = nativeIdentity.apply(this, args), expectedRefusal = phase === "account rotation";
      if (expectedRefusal) void original.then(() => { restoreFips(); faults.push(setup("original native HKDF unexpectedly succeeded")); }, error => {
        helperRefusals++; nativeFailure = { name: String(error?.name), message: String(error?.message), stack: String(error?.stack), fipsAtRefusal: getFips() };
        events.push({ event: "original-public-HKDF-helper-Promise-rejected", fips: getFips() }); restoreFips();
      });
      return track(original, expectedRefusal);
    });
    await act(async () => { root = RTR.create(<App />); });
    await input("Username", USER); await input("Password", PASSWORD); await press("Sign in");
    await complete("real MFA challenge", () => rendered().includes("Verify code"));
    if (hasSession()) throw setup("password-only login adopted a session");
    await input("Authenticator code (or recovery code)", "123456"); await press("Verify code");
    await complete("actual authenticated caseload", () => hasSession() && rendered().includes("Patients — Dr. Native HKDF")); await drain();
    await press("Show account security"); await complete("real current account status", () => rendered().includes("Disable two-factor")); await drain();
    await input("Current password (to authorize rotation)", PASSWORD); await confirmRotation();
    phase = "account rotation"; await press("Rotate sharing key"); await drain();
    if (!nativeFailure || nativeFailure.name !== "OperationError" || !nativeFailure.stack.includes("node:internal/crypto/hkdf") || nativeFailure.fipsAtRefusal !== 1 || nativeRefusals !== 1 || helperRefusals !== 1 || !nativeAesVerified || !activatedFips || !restoredFips || getFips() !== 0) throw setup("original finite native refusal/provenance or restored provider absent");
    witness.stage = "asserting"; witness.nativeFailure = nativeFailure; witness.nativeRefusals = nativeRefusals; witness.helperRefusals = helperRefusals;
    witness.nativeAesVerified = nativeAesVerified; witness.activatedFips = activatedFips; witness.restoredFips = restoredFips; witness.fipsBeforeAssertion = getFips(); witness.events = events;
    witness.originalProducerPromisesForwardedUnchanged = true;
    witness.publicProducer = { complete: true, independent600kPasswordProofs: passwordProofs === 2, mandatoryMfaAccepted: successfulLogins === 1, genuineAuthenticatedProfiles: protectedProfiles >= 3, sameSessionActive: hasSession() };
    save();
    expect(rendered(), "current account security must preserve the actual native HKDF failure explanation").toContain(nativeFailure.message);
    expect(rendered()).not.toContain("Cannot read properties of null");
    await input("Current password (to authorize rotation)", PASSWORD); await confirmRotation(); expect(button("Rotate sharing key")).toBeDefined();
    witness.currentPublicRetryAvailable = true; witness.stage = "passed"; save(); clean();
  } catch (error) { restoreFips(); failed = true; originalFailure = error; witness.failure = String(error); save(); throw error; }
  finally {
    restoreFips(); witness.fipsBeforeCleanup = getFips();
    const cleanupFaults: unknown[] = [];
    try { if (root) await act(async () => root!.unmount()); root = undefined; await drainPortalDraftWritesForTests(); await drain(); } catch (error) { cleanupFaults.push(error); }
    clearSession();
    try { await Promise.all(handlers); } catch (error) { cleanupFaults.push(error); }
    server.closeAllConnections();
    try { if (server.listening) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } catch (error) { cleanupFaults.push(error); }
    if (oldBits) Object.defineProperty(subtle, "deriveBits", oldBits); else Reflect.deleteProperty(subtle, "deriveBits");
    if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin); else Reflect.deleteProperty(window.location, "origin");
    vi.restoreAllMocks(); process.removeListener("unhandledRejection", onUnhandled); window.location.hash = "";
    authKey.fill(0); wrapKey.fill(0); privateBytes.fill(0);
    witness.cleanupCompleted = cleanupFaults.length === 0 && faults.length === 0 && unhandled.length === 0; witness.finalFips = getFips(); save();
    if (!witness.cleanupCompleted) throw failed ? new AggregateError([originalFailure, ...cleanupFaults, ...faults, ...unhandled], "original public failure and owned profile cleanup failure") : setup("owned profile cleanup failed");
  }
}, 120_000);
