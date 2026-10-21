/** Public account-security ownership with genuine Node HTTP/fetch/WebCrypto.
 * RTR exercises rendered forms/buttons. This is an owned synthetic same-account
 * protocol fixture, not a physical browser or backend integration claim. */
import { createCipheriv, createDecipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { createServer, type ServerResponse } from "node:http";
import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { expect, it, vi } from "vitest";
import { App } from "../src/App";
import { ApiError, clearSession, hasSession } from "../src/api";
import { api } from "../src/api";
import { auth } from "../src/api";
import * as portalCrypto from "../src/crypto";
import { diffieHellman } from "node:crypto";

const USER = "native_retirement_clinician", OWNER = "0123456789abcdef0123456789abcdef";
const PASSWORD = "correct horse battery staple", NEW_PASSWORD = "another correct horse battery staple";
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

it.each(["live completion", "retired salt completion", "legacy to snapshot custody"] as const)("preserves account-security ownership through %s", async scenario => {
  for (const custodyBoundary of scenario === "live completion" ? ["none", "after notes", "after note", "after revisions", "after revision", "after salt", "after current keys", "after profile", "after private key", "after identity key", "after final custody", "after sealed ring", "after password failure"] as const : ["none"] as const) {
    // Keep the modern success control and also accept a fully headerless legacy listing.
    for (const legacyHeaderless of scenario === "live completion" && custodyBoundary === "none" ? [false, true] : [false]) {
      vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = "";
      const accountKeys = keys(PASSWORD, SALT), pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const privateBytes = pair.privateKey.export({ format: "der", type: "pkcs8" }), publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
      const identityNote = Buffer.from(hkdfSync("sha256", privateBytes, Buffer.alloc(32), "mindpattern/portal-notes/v2", 32));
      const patientId = "abcdef0123456789abcdef0123456789ab";
      const noteRows = ["11111111111111111111111111111111", "22222222222222222222222222222222"].map(id => ({
        id, client_note_id: id, pattern_pid: null,
        blob: seal(identityNote, ["note", OWNER, patientId, id], Buffer.from(JSON.stringify({ v: 1, text: `Owned clinical note ${id}` }))),
        created_at: "2026-10-01T12:00:00Z", updated_at: "2026-10-01T12:00:00Z", version: 1,
      }));
      // Match only these independently sealed note envelopes. The normal custody
      // probe order is active, legacy, repeated historical legacy, then identity.
      const noteProbes = noteRows.map(note => {
        const wire = Buffer.from(note.blob, "base64");
        return { id: note.id, nonce: wire.subarray(0, 12), cipher: wire.subarray(12),
          aad: Buffer.from(JSON.stringify(["note", OWNER, patientId, note.client_note_id])),
          plain: Buffer.from(JSON.stringify({ v: 1, text: `Owned clinical note ${note.id}` })),
          calls: 0, failures: 0, successes: 0 };
      });
      const revisionRequests: string[] = [];
      // A has an installed, independently sealed custody ring so every boundary
      // ciphertext authenticates on its first genuine decrypt. B is a distinct
      // valid current chart: no B path, note id, nonce, cipher or AAD matches A.
      const currentPatientId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", currentPatientName = "Independent current chart B";
      const boundaryNoteId = "33333333333333333333333333333333", currentNoteId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1";
      const boundaryPlain = "Original authenticated custody note A", currentPlain = "Authenticated current chart B note";
      const boundaryRows = [{ id: boundaryNoteId, client_note_id: boundaryNoteId, pattern_pid: null,
        blob: seal(accountKeys.note, ["note", OWNER, patientId, boundaryNoteId], Buffer.from(JSON.stringify({ v: 1, text: boundaryPlain }))),
        created_at: "2026-10-01T12:00:00Z", updated_at: "2026-10-01T12:00:00Z", version: 3 }];
      const boundaryRevisions = [1, 2].map(version => ({ id: `native-custody-revision-${version}`,
        blob: seal(accountKeys.note, ["note", OWNER, patientId, boundaryNoteId], Buffer.from(JSON.stringify({ v: 1, text: `Original authenticated custody revision A ${version}` }))),
        created_at: `2026-10-0${version}T12:00:00Z` }));
      const currentRows = [{ id: currentNoteId, client_note_id: currentNoteId, pattern_pid: null,
        blob: seal(accountKeys.note, ["note", OWNER, currentPatientId, currentNoteId], Buffer.from(JSON.stringify({ v: 1, text: currentPlain }))),
        created_at: "2026-10-01T12:00:00Z", updated_at: "2026-10-01T12:00:00Z", version: 1 }];
      const boundaryNativeProbes = [boundaryRows[0]!.blob, ...boundaryRevisions.map(row => row.blob)].map((blob, index) => {
        const wire = Buffer.from(blob, "base64");
        return { index, blob, nonce: wire.subarray(0, 12), cipher: wire.subarray(12), aad: Buffer.from(JSON.stringify(["note", OWNER, patientId, boundaryNoteId])), calls: 0, retiredCalls: 0, successes: 0 };
      });
      const currentEphemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), currentDataKey = randomBytes(32);
      const currentEphemeralDer = currentEphemeral.publicKey.export({ format: "der", type: "spki" });
      const currentShared = diffieHellman({ privateKey: currentEphemeral.privateKey, publicKey: pair.publicKey });
      const currentConsentKey = Buffer.from(hkdfSync("sha256", currentShared, Buffer.concat([currentEphemeralDer, Buffer.from(publicKey, "base64")]), "mindpattern/wrap/v1", 32));
      const currentPatient = { user_id: currentPatientId, username: currentPatientName, status: "active", granted_at: "2026-10-01T12:00:00Z", revoked_at: null,
        wrapped_key: seal(currentConsentKey, ["consent-wrap", currentPatientId, OWNER], currentDataKey), ephemeral_pub: currentEphemeralDer.toString("base64") };
      currentShared.fill(0); currentConsentKey.fill(0); currentDataKey.fill(0);
      let cleanupReleasesCustody = false, custodyRetired = false, custodyActOpen = false, originalNotesHeld: ServerResponse | undefined, originalRevisionsHeld: ServerResponse | undefined;
      const notesArrived = deferred(), revisionsArrived = deferred(), retirementObserved = deferred();
      const notesOriginals: Array<ReturnType<typeof api.notes>> = [], revisionsOriginals: Array<ReturnType<typeof api.noteRevisions>> = [];
      const custodyDecrypts: Array<{ blob: string; retired: boolean; original: ReturnType<typeof portalCrypto.decryptNoteAny> }> = [];
      const custodyRevisionAdmissions: Array<{ id: string; retired: boolean }> = [], custodyRevisionRequests: Array<{ id: string; retired: boolean }> = [];
      const originalNotes = api.notes, originalRevisions = api.noteRevisions, originalNoteAny = portalCrypto.decryptNoteAny;
      const oldNotes = Object.getOwnPropertyDescriptor(api, "notes"), oldRevisions = Object.getOwnPropertyDescriptor(api, "noteRevisions");
      let restoreNoteAny: (() => void) | undefined;
      const passwordKdfWindow = custodyBoundary === "after salt" || custodyBoundary === "after current keys";
      const credentialWindow = custodyBoundary === "after profile" || custodyBoundary === "after private key" || custodyBoundary === "after identity key";
      const finalSecurityWindow = custodyBoundary === "after final custody" || custodyBoundary === "after sealed ring";
      const atomicRetryWindow = custodyBoundary === "after password failure";
      const originalPasswordAtomic = api.changePasswordAtomic, oldPasswordAtomic = Object.getOwnPropertyDescriptor(api, "changePasswordAtomic");
      const atomicOriginals: Array<{ retired: boolean; original: ReturnType<typeof api.changePasswordAtomic> }> = [];
      const firstAtomicArrived = deferred(); let heldAtomicResponse: ServerResponse | undefined, atomicPasswordRequests = 0;
      const originalSealRing = portalCrypto.sealNotesKeyring, originalSealPrivate = portalCrypto.sealPrivateKeyForUpload;
      const sealRingOriginals: Array<ReturnType<typeof portalCrypto.sealNotesKeyring>> = [], sealPrivateOriginals: Array<ReturnType<typeof portalCrypto.sealPrivateKeyForUpload>> = [];
      let restoreSealRing: (() => void) | undefined, restoreSealPrivate: (() => void) | undefined;
      const finalEncryptAdmissions: Array<{ kind: "notes ring" | "private wrap"; retired: boolean; original: Promise<ArrayBuffer>; successful: boolean }> = [];
      const ringSealAad = Buffer.from(JSON.stringify(["portal-notes-keyring", OWNER, "v1"])), privateSealAad = Buffer.from(JSON.stringify(["therapist-key", USER]));
      const finalRevisionsArrived = deferred(); let finalRevisionsHeld: ServerResponse | undefined, finalRevisionsOriginal: ReturnType<typeof api.noteRevisions> | undefined;
      const oldMe = Object.getOwnPropertyDescriptor(api, "me"), originalMe = api.me;
      const originalOpenPrivate = portalCrypto.openSealedPrivateKey, originalIdentityKey = portalCrypto.noteKeyV2FromPrivateKey, originalOpenRing = portalCrypto.openNotesKeyring;
      const credentialMeOriginals: Array<ReturnType<typeof api.me>> = [], credentialCryptoOriginals: Promise<unknown>[] = [];
      const identityKdfAdmissions: Array<{ retired: boolean; algorithm: "HKDF"; hash: "SHA-256"; bitLength: 256; zeroSaltLength: 32; info: "mindpattern/portal-notes/v2" }> = [];
      const identityInfo = Buffer.from("mindpattern/portal-notes/v2");
      let heldMeResponse: ServerResponse | undefined, firstCredentialRetirementObserved = false;
      const heldMeArrived = deferred();
      let restoreOpenPrivate: (() => void) | undefined, restoreIdentityKey: (() => void) | undefined, restoreOpenRing: (() => void) | undefined;
      const originalSaltFor = auth.saltFor, oldSaltFor = Object.getOwnPropertyDescriptor(auth, "saltFor");
      const originalMasterKey = portalCrypto.deriveMasterKey, originalPortalKeys = portalCrypto.derivePortalKeys;
      const securitySaltOriginals: Array<ReturnType<typeof auth.saltFor>> = [], securityKeyOriginals: Promise<unknown>[] = [];
      const passwordKdfAdmissions: Array<{ retired: boolean; algorithm: "PBKDF2"; hash: "SHA-256"; iterations: 600000; bitLength: 256; saltLength: 16; saltB64: string; keyAlgorithm: "PBKDF2"; keyType: "secret"; keyUsage: "deriveBits"; keyExtractable: false }> = [];
      const generatedSecuritySalts: string[] = [];
      let firstSecurityPortalKeysObserved = false, restoreMasterKey: (() => void) | undefined, restorePortalKeys: (() => void) | undefined;
      const sameBytes = (input: BufferSource | undefined, expected: Uint8Array): boolean => {
        if (input === undefined) return false;
        const bytes = ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(input);
        return bytes.length === expected.length && bytes.every((value, index) => value === expected[index]);
      };
      let accountSalt = SALT, verifier = accountKeys.auth.toString("base64"), envelope = seal(accountKeys.wrap, ["therapist-key", USER], privateBytes), custodyBlob: string | undefined;
      if (custodyBoundary !== "none") custodyBlob = seal(accountKeys.wrap, ["portal-notes-keyring", OWNER, "v1"], Buffer.from(JSON.stringify({ v: 1, active: accountKeys.note.toString("base64"), historical: [identityNote.toString("base64")] })));
      const credentialNativeProbes = credentialWindow ? [
        { kind: "private wrap", blob: envelope, aad: ["therapist-key", USER] },
        { kind: "notes ring", blob: custodyBlob!, aad: ["portal-notes-keyring", OWNER, "v1"] },
      ].map(row => { const wire = Buffer.from(row.blob, "base64"); return { kind: row.kind, blob: row.blob, nonce: wire.subarray(0, 12), cipher: wire.subarray(12), aad: Buffer.from(JSON.stringify(row.aad)), calls: 0, retiredCalls: 0, successes: 0 }; }) : [];
      let custodyVersion = 0, successfulLogins = 0, saltRequests = 0, passwordCommits = 0, logoutRequests = 0;
      const tokens = new Set<string>(), requests: Array<{ path: string; bearer: string | null }> = [], faults: unknown[] = [], unhandled: unknown[] = [];
      const created: Promise<unknown>[] = [], producers = new Set<Promise<unknown>>(), nativeBodies: Promise<unknown>[] = [], handlers: Promise<void>[] = [];
      const secretArrays: Uint8Array[] = [], saltArrays: Uint8Array[] = [], heldSalt = deferred();
      let heldResponse: ServerResponse | undefined, root: ReactTestRenderer | undefined, phase = "initial login", origin = "";
      const oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), nativeFetch = globalThis.fetch;
      const subtle = globalThis.crypto.subtle, originalBits = subtle.deriveBits, originalDecrypt = subtle.decrypt, originalRandom = crypto.getRandomValues;
      const oldBits = Object.getOwnPropertyDescriptor(subtle, "deriveBits"), oldDecrypt = Object.getOwnPropertyDescriptor(subtle, "decrypt"), oldRandom = Object.getOwnPropertyDescriptor(crypto, "getRandomValues");
      const oldEncrypt = Object.getOwnPropertyDescriptor(subtle, "encrypt"), originalEncrypt = subtle.encrypt;
      const originalJson = Response.prototype.json, oldJson = Object.getOwnPropertyDescriptor(Response.prototype, "json");
      const observeUnhandled = (error: unknown) => { unhandled.push(error); };
      process.on("unhandledRejection", observeUnhandled);
      function track<T>(original: Promise<T>, expectedRejection?: (error: unknown) => boolean) {
        created.push(original); producers.add(original);
        void original.then(() => { producers.delete(original); }, error => { producers.delete(original); if (!expectedRejection?.(error)) faults.push(error); });
        return original;
      }
      function clean() { if (faults.length) throw setup("unknown owned producer/server fault", faults[0]); }
      async function complete(label: string, predicate: () => boolean) {
        const until = Date.now() + 15000;
        while (!predicate()) { clean(); if (Date.now() >= until) throw setup(`public completion missing: ${label}`); await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); }); }
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
      function retireCustodyThroughCurrentB() {
        if (custodyRetired || custodyActOpen) throw setup("custody retirement repeated or original submit act still open");
        const card = root!.root.findAllByType("div").find(node => node.props.className === "row-between" && text(node).includes(currentPatientName));
        const open = card?.findAllByType("button").find(node => text(node) === "Open patterns");
        if (!open || open.props.disabled) throw setup("enabled distinct current B Open patterns button missing");
        custodyRetired = true;
        // This closes a real synchronous React act before the earlier original
        // crypto Promise's caller reaction resumes. No callback or Promise is replaced.
        act(() => { open.props.onClick({ preventDefault() {} }); });
        if (!hasSession()) throw setup("Open patterns unexpectedly retired the API owner");
        retirementObserved.resolve();
      }
      function releaseCustodyNotes() {
        if (originalNotesHeld && !originalNotesHeld.writableEnded) send(originalNotesHeld, boundaryRows, 200, { "X-Notes-Revision": "17" });
      }
      function releaseCustodyRevisions() {
        if (originalRevisionsHeld && !originalRevisionsHeld.writableEnded) send(originalRevisionsHeld, boundaryRevisions);
      }
      function releaseAtomicFailure() {
        if (heldAtomicResponse && !heldAtomicResponse.writableEnded) send(heldAtomicResponse, { detail: "Owned transient failure before an atomic commit" }, 500);
      }
      async function settleOriginalAtomicProducers() {
        for (;;) {
          const originals = atomicOriginals.map(row => row.original);
          await finite("same original atomic password request producers", Promise.allSettled(originals));
          if (originals.length === atomicOriginals.length) break;
        }
        clean();
      }
      function releaseFinalRevisions() {
        if (finalRevisionsHeld && !finalRevisionsHeld.writableEnded) send(finalRevisionsHeld, []);
      }
      async function settleOriginalFinalSealProducers() {
        for (;;) {
          const originals = [...sealRingOriginals, ...sealPrivateOriginals];
          await finite("same original full ring/private seal producers", Promise.all(originals));
          if (originals.length === sealRingOriginals.length + sealPrivateOriginals.length) break;
        }
        clean();
      }
      async function settleOriginalCustodyProducers() {
        // Producer expansion, not a fixed turn budget: every original full public
        // API/decrypt Promise owns its dependent HTTP/importKey/decrypt continuations.
        for (;;) {
          const originals = [...notesOriginals, ...revisionsOriginals, ...custodyDecrypts.map(row => row.original)];
          await finite("original custody API and authenticated crypto producers", Promise.all(originals));
          if (originals.length === notesOriginals.length + revisionsOriginals.length + custodyDecrypts.length) break;
        }
        clean();
      }
      async function settleOriginalSecurityKeyProducers() {
        // The API Promise is registered after the component's salt await, and
        // each full exported KDF Promise owns its actual importKey/HKDF/PBKDF2
        // dependencies. Repeat only when those exact producers expand the graph.
        for (;;) {
          const originals = [...securitySaltOriginals, ...securityKeyOriginals];
          await finite("original salt and full exported KDF producers", Promise.all(originals));
          if (originals.length === securitySaltOriginals.length + securityKeyOriginals.length) break;
        }
        clean();
      }
      function releaseCredentialMe() {
        if (heldMeResponse && !heldMeResponse.writableEnded) send(heldMeResponse, { username: USER, display_name: "Dr. Native Retirement", wrap_pub_key: publicKey, wrap_key_blob: envelope, notes_keyring_blob: custodyBlob, custody_version: custodyVersion, totp_enabled: true });
      }
      async function settleOriginalCredentialProducers() {
        for (;;) {
          const originals = [...credentialMeOriginals, ...credentialCryptoOriginals];
          await finite("original security profile and full exported credential crypto producers", Promise.all(originals));
          if (originals.length === credentialMeOriginals.length + credentialCryptoOriginals.length) break;
        }
        clean();
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
        await complete("same clinician authenticated caseload", () => hasSession() && rendered().includes("Patients — Dr. Native Retirement") && rendered().includes("Native custody patient"));
        if (waitForDrain) await drain();
      }
      function send(response: ServerResponse, value: unknown, status = 200, headers: Record<string, string> = {}) {
        response.writeHead(status, { "content-type": "application/json", ...headers }); response.end(status === 204 ? undefined : JSON.stringify(value));
      }
      const server = createServer((request, response) => {
        const original = (async () => {
          let wire = ""; for await (const part of request) wire += String(part);
          const body = wire ? JSON.parse(wire) as Record<string, unknown> : {}, path = new URL(request.url ?? "", origin).pathname;
          const bearer = request.headers.authorization ?? null; requests.push({ path, bearer });
          if (wire.includes(PASSWORD) || wire.includes(NEW_PASSWORD)) throw setup("plaintext password crossed native HTTP");
          if (path === "/api/v1/meta") return send(response, { sharing_available: true });
          if (path === "/api/v1/auth/salt") {
            saltRequests += 1;
            if ((scenario === "retired salt completion" || passwordKdfWindow || credentialWindow || finalSecurityWindow || atomicRetryWindow) && saltRequests === 3) {
              heldResponse = response; heldSalt.resolve();
              if (cleanupReleasesCustody) send(response, { salt: accountSalt }); return;
            }
            return send(response, { salt: accountSalt });
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
          if (path === "/api/v1/therapist/me") {
            if (credentialWindow && custodyBoundary === "after profile" && phase === "security action") {
              if (heldMeResponse) throw setup("security profile HTTP unexpectedly repeated");
              heldMeResponse = response; heldMeArrived.resolve(); if (cleanupReleasesCustody) releaseCredentialMe(); return;
            }
            return send(response, { username: USER, display_name: "Dr. Native Retirement", wrap_pub_key: publicKey, wrap_key_blob: envelope, notes_keyring_blob: custodyBlob, custody_version: custodyVersion, totp_enabled: true });
          }
          if (path === "/api/v1/therapist/patients") return send(response, [{ user_id: patientId, username: "Native custody patient", status: "active", granted_at: "2026-10-01T12:00:00Z", revoked_at: null, wrapped_key: null, ephemeral_pub: null }, ...(custodyBoundary === "none" ? [] : [currentPatient])]);
          if (custodyBoundary !== "none" && path === `/api/v1/therapist/patients/${currentPatientId}/notes`) return send(response, currentRows, 200, { "X-Notes-Revision": "23" });
          if (custodyBoundary !== "none" && path === `/api/v1/therapist/patients/${currentPatientId}/measures`) return send(response, [], 200, { "X-Measures-Revision": "23" });
          if (custodyBoundary !== "none" && path === `/api/v1/therapist/patients/${currentPatientId}/insights`) return send(response, { phase: "baseline", active_days: 1, streak: 1, days_remaining: 3, state_seq: 0, blob: null });
          if (custodyBoundary !== "none" && path === `/api/v1/therapist/patients/${patientId}/notes`) {
            if (originalNotesHeld) throw setup("custody A first-page HTTP request unexpectedly repeated");
            originalNotesHeld = response; notesArrived.resolve();
            if (cleanupReleasesCustody) releaseCustodyNotes(); return;
          }
          if (custodyBoundary !== "none" && path === `/api/v1/therapist/notes/${boundaryNoteId}/revisions`) {
            custodyRevisionRequests.push({ id: boundaryNoteId, retired: custodyRetired });
            if (custodyBoundary === "after revisions") { originalRevisionsHeld = response; revisionsArrived.resolve(); if (cleanupReleasesCustody) releaseCustodyRevisions(); return; }
            return send(response, boundaryRevisions);
          }
          if ((finalSecurityWindow || atomicRetryWindow) && path === `/api/v1/therapist/notes/${currentNoteId}/revisions`) {
            if (custodyBoundary === "after final custody") {
              if (finalRevisionsHeld) throw setup("last original custody B revisions HTTP unexpectedly repeated");
              finalRevisionsHeld = response; finalRevisionsArrived.resolve(); if (cleanupReleasesCustody) releaseFinalRevisions(); return;
            }
            return send(response, []);
          }
          if (path === `/api/v1/therapist/patients/${patientId}/notes`) {
            const offset = new URL(request.url ?? "", origin).searchParams.get("offset") ?? "0";
            const expected = new URL(request.url ?? "", origin).searchParams.get("expected_revision");
            if (offset === "0") {
              if (expected !== null) throw setup("first custody page unexpectedly carries a revision");
              return send(response, [noteRows[0]], 200, { "X-Next-Offset": "1", ...(scenario === "legacy to snapshot custody" || legacyHeaderless ? {} : { "X-Notes-Revision": "17" }) });
            }
            if (offset !== "1" || expected !== (scenario === "legacy to snapshot custody" || legacyHeaderless ? null : "17")) throw setup("custody continuation query differs");
            return send(response, [noteRows[1]], 200, legacyHeaderless ? {} : { "X-Notes-Revision": "17" });
          }
          const revisionProbe = noteProbes.find(probe => path === `/api/v1/therapist/notes/${probe.id}/revisions`);
          if (revisionProbe) {
            if (revisionProbe.calls !== 4 || revisionProbe.failures !== 3 || revisionProbe.successes !== 1) throw setup("owned note did not authenticate after its exact custody fallback probes");
            revisionRequests.push(revisionProbe.id); return send(response, []);
          }
          if (path === "/api/v1/therapist/password") {
            atomicPasswordRequests += 1;
            if (atomicRetryWindow && atomicPasswordRequests === 1) {
              heldAtomicResponse = response; firstAtomicArrived.resolve();
              if (cleanupReleasesCustody) releaseAtomicFailure(); return;
            }
            if (body.verifier !== verifier || body.expected_custody_version !== custodyVersion || body.custody_version !== custodyVersion + 1 || body.wrap_pub_key !== publicKey) throw setup("atomic password proof/identity/version mismatch");
            const next = keys(NEW_PASSWORD, String(body.new_salt)); let reopened: Buffer | undefined, ringPlain: Buffer | undefined;
            try {
              if (body.new_verifier !== next.auth.toString("base64")) throw setup("new independent password verifier mismatch");
              reopened = open(next.wrap, ["therapist-key", USER], String(body.wrap_key_blob));
              if (!reopened.equals(privateBytes)) throw setup("password change replaced public/private identity");
              ringPlain = open(next.wrap, ["portal-notes-keyring", OWNER, "v1"], String(body.notes_keyring_blob));
              const ring = JSON.parse(ringPlain.toString("utf8")) as { v: number; active: string; historical: string[] };
              if (ring.v !== 1 || Buffer.from(ring.active, "base64").length !== 32 || !(ring.historical.includes(accountKeys.note.toString("base64")) || (atomicRetryWindow && ring.active === accountKeys.note.toString("base64"))) || !ring.historical.includes(identityNote.toString("base64"))) throw setup("independent notes custody authentication differs");
              accountSalt = String(body.new_salt); verifier = String(body.new_verifier); envelope = String(body.wrap_key_blob); custodyBlob = String(body.notes_keyring_blob); custodyVersion += 1; passwordCommits += 1; tokens.clear();
              return send(response, null, 204);
            } finally { next.auth.fill(0); next.wrap.fill(0); next.note.fill(0); reopened?.fill(0); ringPlain?.fill(0); }
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
          const original = nativeFetch(...args); return track(original);
        });
        Object.defineProperty(Response.prototype, "json", { ...oldJson, value: function (this: Response) { const original = originalJson.call(this); nativeBodies.push(track(original)); return original; } });
        Object.defineProperty(subtle, "deriveBits", { ...oldBits, configurable: true, value: (...args: Parameters<SubtleCrypto["deriveBits"]>) => {
          const owned = phase === "security action" || phase === "retired action", retiredAtAdmission = custodyRetired;
          const original = originalBits.apply(subtle, args);
          if (passwordKdfWindow && phase === "security action" && typeof args[0] === "object" && args[0].name === "PBKDF2") {
            const parameters = args[0] as Pbkdf2Params;
            const salt = ArrayBuffer.isView(parameters.salt) ? new Uint8Array(parameters.salt.buffer, parameters.salt.byteOffset, parameters.salt.byteLength) : new Uint8Array(parameters.salt);
            const hash = typeof parameters.hash === "string" ? parameters.hash : parameters.hash.name;
            if (hash !== "SHA-256" || parameters.iterations !== 600000 || args[2] !== 256 || salt.length !== 16
              || args[1].algorithm.name !== "PBKDF2" || args[1].type !== "secret" || args[1].extractable !== false
              || args[1].usages.length !== 1 || args[1].usages[0] !== "deriveBits") throw setup("native password KDF algorithm, usage or salt shape differs");
            passwordKdfAdmissions.push({ retired: retiredAtAdmission, algorithm: "PBKDF2", hash: "SHA-256", iterations: 600000, bitLength: 256, saltLength: 16, saltB64: Buffer.from(salt).toString("base64"), keyAlgorithm: "PBKDF2", keyType: "secret", keyUsage: "deriveBits", keyExtractable: false });
          }
          if (credentialWindow && phase === "security action" && typeof args[0] === "object" && args[0].name === "HKDF") {
            const parameters = args[0] as HkdfParams;
            if (sameBytes(parameters.info, identityInfo)) {
              const hash = typeof parameters.hash === "string" ? parameters.hash : parameters.hash.name;
              if (hash !== "SHA-256" || args[2] !== 256 || !sameBytes(parameters.salt, new Uint8Array(32))
                || args[1].algorithm.name !== "HKDF" || args[1].type !== "secret" || args[1].extractable !== false
                || args[1].usages.length !== 1 || args[1].usages[0] !== "deriveBits") throw setup("native identity HKDF parameters or key usage differ");
              identityKdfAdmissions.push({ retired: retiredAtAdmission, algorithm: "HKDF", hash: "SHA-256", bitLength: 256, zeroSaltLength: 32, info: "mindpattern/portal-notes/v2" });
            }
          }
          void original.then(bits => { if (owned) secretArrays.push(new Uint8Array(bits)); }, error => { faults.push(error); }); return track(original);
        } });
        Object.defineProperty(subtle, "decrypt", { ...oldDecrypt, configurable: true, value: (...args: Parameters<SubtleCrypto["decrypt"]>) => {
          const owned = phase === "security action" || phase === "retired action";
          const algorithm = typeof args[0] === "object" && args[0].name === "AES-GCM" ? args[0] as AesGcmParams : undefined;
          const probe = phase === "security action" && algorithm && algorithm.tagLength === undefined
            ? noteProbes.find(row => sameBytes(algorithm.iv, row.nonce) && sameBytes(algorithm.additionalData, row.aad) && sameBytes(args[2], row.cipher)) : undefined;
          if (probe) probe.calls += 1;
          const boundaryProbe = custodyBoundary !== "none" && algorithm && algorithm.tagLength === undefined
            ? boundaryNativeProbes.find(row => sameBytes(algorithm.iv, row.nonce) && sameBytes(algorithm.additionalData, row.aad) && sameBytes(args[2], row.cipher)) : undefined;
          if (boundaryProbe) { boundaryProbe.calls += 1; if (custodyRetired) boundaryProbe.retiredCalls += 1; }
          const credentialProbe = credentialWindow && phase === "security action" && algorithm && algorithm.tagLength === undefined
            ? credentialNativeProbes.find(row => sameBytes(algorithm.iv, row.nonce) && sameBytes(algorithm.additionalData, row.aad) && sameBytes(args[2], row.cipher)) : undefined;
          if (credentialProbe) {
            if (args[1].algorithm.name !== "AES-GCM" || (args[1].algorithm as AesKeyAlgorithm).length !== 256 || args[1].type !== "secret" || args[1].extractable !== false
              || args[1].usages.length !== 2 || args[1].usages[0] !== "encrypt" || args[1].usages[1] !== "decrypt") throw setup("native credential AES-GCM key algorithm or encrypt/decrypt usage differs");
            credentialProbe.calls += 1; if (custodyRetired) credentialProbe.retiredCalls += 1;
          }
          const original = originalDecrypt.apply(subtle, args);
          void original.then(bytes => {
            if (owned) secretArrays.push(new Uint8Array(bytes));
            if (boundaryProbe) boundaryProbe.successes += 1;
            if (credentialProbe) credentialProbe.successes += 1;
            if (probe) {
              if (probe.calls !== 4 || probe.failures !== 3 || probe.successes !== 0 || !sameBytes(bytes, probe.plain)) faults.push(setup("owned note plaintext or custody fallback sequence differs"));
              probe.successes += 1;
            }
          }, () => { /* the exact native rejection is classified once by track */ });
          return track(original, error => {
            if (!probe || !(error instanceof DOMException) || error.name !== "OperationError" || probe.calls > 3 || probe.failures >= 3 || probe.successes !== 0) return false;
            probe.failures += 1; return true;
          });
        } });
        if (finalSecurityWindow) Object.defineProperty(subtle, "encrypt", { ...oldEncrypt, configurable: true, value: (...args: Parameters<SubtleCrypto["encrypt"]>) => {
          const parameters = typeof args[0] === "object" && args[0].name === "AES-GCM" ? args[0] as AesGcmParams : undefined;
          const kind = parameters && phase === "security action" && (parameters.tagLength === undefined || parameters.tagLength === 128)
            ? sameBytes(parameters.additionalData, ringSealAad) ? "notes ring" : sameBytes(parameters.additionalData, privateSealAad) ? "private wrap" : undefined : undefined;
          if (kind) {
            if (args[1].algorithm.name !== "AES-GCM" || (args[1].algorithm as AesKeyAlgorithm).length !== 256 || args[1].type !== "secret" || args[1].extractable !== false
              || args[1].usages.length !== 2 || args[1].usages[0] !== "encrypt" || args[1].usages[1] !== "decrypt") throw setup("native final seal AES-GCM algorithm or key usages differ");
            if (kind === "private wrap" && !sameBytes(args[2], privateBytes)) throw setup("native private reseal does not own the genuine original PKCS8 bytes");
          }
          const original = originalEncrypt.apply(subtle, args);
          if (kind) {
            const admission: (typeof finalEncryptAdmissions)[number] = { kind, retired: custodyRetired, original, successful: false }; finalEncryptAdmissions.push(admission);
            void original.then(() => { admission.successful = true; }, error => { faults.push(error); });
          }
          return track(original);
        } });
        Object.defineProperty(crypto, "getRandomValues", { ...oldRandom, configurable: true, value: <T extends ArrayBufferView>(array: T): T => {
          const original = originalRandom.call(crypto, array);
          if ((phase === "security action" || phase === "retired action") && array instanceof Uint8Array && (array.length === 16 || array.length === 32)) saltArrays.push(array);
          if (passwordKdfWindow && phase === "security action" && array instanceof Uint8Array && array.length === 16) generatedSecuritySalts.push(Buffer.from(array).toString("base64"));
          return original as T;
        } });
        if (passwordKdfWindow || credentialWindow || finalSecurityWindow || atomicRetryWindow) {
          Object.defineProperty(auth, "saltFor", { ...oldSaltFor, value: function (this: unknown, ...args: Parameters<typeof auth.saltFor>) {
            const original = originalSaltFor.apply(this, args);
            if (phase === "security action") securitySaltOriginals.push(original); return track(original);
          } });
          const masterObserver = vi.spyOn(portalCrypto, "deriveMasterKey"); restoreMasterKey = () => masterObserver.mockRestore();
          masterObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.deriveMasterKey>) {
            const original = originalMasterKey.apply(this, args);
            if (phase === "security action") securityKeyOriginals.push(original); return track(original);
          });
          const portalObserver = vi.spyOn(portalCrypto, "derivePortalKeys"); restorePortalKeys = () => portalObserver.mockRestore();
          portalObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.derivePortalKeys>) {
            const original = originalPortalKeys.apply(this, args);
            if (phase === "security action") {
              securityKeyOriginals.push(original);
              if (custodyBoundary === "after current keys" && !firstSecurityPortalKeysObserved) {
                firstSecurityPortalKeysObserved = true;
                // Registered before deriveFor awaits this identical original
                // Promise. Its private finally only wipes master/salt before
                // returning to the target332; no producer is replaced or held.
                void original.then(() => {
                  try { retireCustodyThroughCurrentB(); } catch (error) { faults.push(error); }
                }, error => { faults.push(error); });
              }
            }
            return track(original);
          });
        }
        if (credentialWindow) {
          Object.defineProperty(api, "me", { ...oldMe, value: function (this: unknown, ...args: Parameters<typeof api.me>) {
            const original = originalMe.apply(this, args); if (phase === "security action") credentialMeOriginals.push(original); return track(original);
          } });
          const privateObserver = vi.spyOn(portalCrypto, "openSealedPrivateKey"); restoreOpenPrivate = () => privateObserver.mockRestore();
          privateObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.openSealedPrivateKey>) {
            const original = originalOpenPrivate.apply(this, args);
            if (phase === "security action") {
              if (args[1] !== envelope || args[2] !== USER) throw setup("security private-wrap original input differs");
              credentialCryptoOriginals.push(original);
              if (custodyBoundary === "after private key" && !firstCredentialRetirementObserved) {
                firstCredentialRetirementObserved = true;
                // This reaction owns the same full original decrypt Promise,
                // before the component's353 await reaction can admit identity HKDF.
                void original.then(value => {
                  try { if (!value || !sameBytes(value, privateBytes)) throw setup("genuine private-wrap plaintext differs"); retireCustodyThroughCurrentB(); } catch (error) { faults.push(error); }
                }, error => { faults.push(error); });
              }
            }
            return track(original);
          });
          const identityObserver = vi.spyOn(portalCrypto, "noteKeyV2FromPrivateKey"); restoreIdentityKey = () => identityObserver.mockRestore();
          identityObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.noteKeyV2FromPrivateKey>) {
            const original = originalIdentityKey.apply(this, args);
            if (phase === "security action") {
              if (!sameBytes(args[0], privateBytes)) throw setup("security identity HKDF original input differs");
              credentialCryptoOriginals.push(original);
              if (custodyBoundary === "after identity key" && !firstCredentialRetirementObserved) {
                firstCredentialRetirementObserved = true;
                // Register before the original full identity-key Promise is
                // returned to355. The next target358 precedes keyring AES-GCM.
                void original.then(value => {
                  try { if (!sameBytes(value, identityNote)) throw setup("genuine identity HKDF output differs"); retireCustodyThroughCurrentB(); } catch (error) { faults.push(error); }
                }, error => { faults.push(error); });
              }
            }
            return track(original);
          });
          const ringObserver = vi.spyOn(portalCrypto, "openNotesKeyring"); restoreOpenRing = () => ringObserver.mockRestore();
          ringObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.openNotesKeyring>) {
            const original = originalOpenRing.apply(this, args);
            if (phase === "security action") {
              if (args[1] !== OWNER || args[2] !== custodyBlob) throw setup("security custody-ring original input differs");
              credentialCryptoOriginals.push(original);
            }
            return track(original);
          });
        }
        if (finalSecurityWindow) {
          const ringSealObserver = vi.spyOn(portalCrypto, "sealNotesKeyring"); restoreSealRing = () => ringSealObserver.mockRestore();
          ringSealObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.sealNotesKeyring>) {
            const original = originalSealRing.apply(this, args); sealRingOriginals.push(original);
            if (args[1] !== OWNER) throw setup("original final ring seal owner differs");
            if (custodyBoundary === "after sealed ring") void original.then(blob => {
              try {
                if (typeof blob !== "string" || Buffer.from(blob, "base64").length < 29 || !finalEncryptAdmissions.some(row => row.kind === "notes ring" && row.successful && !row.retired)) throw setup("full original ring seal lacks its successful genuine native encrypt");
                if (!cleanupReleasesCustody) retireCustodyThroughCurrentB();
              } catch (error) { faults.push(error); }
            }, error => { faults.push(error); });
            // Return the same full Promise, after registering the fulfilled
            // prereaction. Its own plaintext finally has already run at fulfill.
            return track(original);
          });
          const privateSealObserver = vi.spyOn(portalCrypto, "sealPrivateKeyForUpload"); restoreSealPrivate = () => privateSealObserver.mockRestore();
          privateSealObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.sealPrivateKeyForUpload>) {
            if (args[2] !== USER || !sameBytes(args[1], privateBytes)) throw setup("original private reseal owner or PKCS8 differs");
            const original = originalSealPrivate.apply(this, args); sealPrivateOriginals.push(original); return track(original);
          });
        }
        if (atomicRetryWindow) Object.defineProperty(api, "changePasswordAtomic", { ...oldPasswordAtomic, value: function (this: unknown, ...args: Parameters<typeof api.changePasswordAtomic>) {
          const original = originalPasswordAtomic.apply(this, args);
          atomicOriginals.push({ retired: custodyRetired, original });
          // The service's own genuine 500 rejection remains unchanged. Observe
          // and return the identical full exported API Promise to its caller.
          return track(original, error => error instanceof ApiError && error.status === 500);
        } });
        if (custodyBoundary !== "none") {
          Object.defineProperty(api, "notes", { ...oldNotes, value: function (this: unknown, ...args: Parameters<typeof api.notes>) {
            const original = originalNotes.apply(this, args); notesOriginals.push(original); return track(original);
          } });
          Object.defineProperty(api, "noteRevisions", { ...oldRevisions, value: function (this: unknown, ...args: Parameters<typeof api.noteRevisions>) {
            custodyRevisionAdmissions.push({ id: args[0], retired: custodyRetired });
            const original = originalRevisions.apply(this, args); revisionsOriginals.push(original);
            if (finalSecurityWindow && args[0] === currentNoteId) {
              if (finalRevisionsOriginal) throw setup("last original B revision API Promise unexpectedly repeated");
              finalRevisionsOriginal = original;
            }
            return track(original);
          } });
          const observer = vi.spyOn(portalCrypto, "decryptNoteAny"); restoreNoteAny = () => observer.mockRestore();
          observer.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.decryptNoteAny>) {
            const original = originalNoteAny.apply(this, args); custodyDecrypts.push({ blob: args[5], retired: custodyRetired, original });
            const retireAtThisExactOriginal = custodyBoundary === "after note" && args[5] === boundaryRows[0]!.blob
              || custodyBoundary === "after revision" && args[5] === boundaryRevisions[0]!.blob;
            if (retireAtThisExactOriginal) void original.then(() => {
              try { retireCustodyThroughCurrentB(); } catch (error) { faults.push(error); }
            }, error => { faults.push(error); });
            return track(original);
          });
        }
        await act(async () => { root = RTR.create(<App />); }); await login();
        await press("Show account security"); await complete("enrolled native account status", () => rendered().includes("Disable two-factor")); await drain();
        await input("Current password", PASSWORD); await input("New password", NEW_PASSWORD); await input("Repeat new password", NEW_PASSWORD);
        phase = "security action";
        custodyActOpen = custodyBoundary !== "none";
        try { await press("Change password"); } finally { custodyActOpen = false; }
        if (atomicRetryWindow) {
          await finite("genuine retry third salt request after submit act closes", heldSalt.promise);
          if (!heldResponse || heldResponse.writableEnded || custodyActOpen) throw setup("atomic retry original salt gate or closed submit act missing");
          send(heldResponse, { salt: SALT });
          await finite("original custody A notes HTTP arrival before first atomic attempt", notesArrived.promise); releaseCustodyNotes();
          await finite("first original atomic password HTTP awaits genuine response", firstAtomicArrived.promise);
          if (atomicOriginals.length !== 1 || atomicOriginals[0]!.retired || !heldAtomicResponse || heldAtomicResponse.writableEnded) throw setup("first live atomic password request not genuinely held");
          retireCustodyThroughCurrentB();
          await complete("distinct current B authenticates under the still-live bearer before old 500 release", () => hasSession() && rendered().includes(currentPlain) && rendered().includes("Still in the baseline phase"));
          if (passwordCommits !== 0 || !tokens.has("owned-retirement-bearer-1")) throw setup("owned transient failure must precede any credential/token-epoch commit");
          releaseAtomicFailure();
          await settleOriginalAtomicProducers(); await settleOriginalCustodyProducers(); await settleOriginalSecurityKeyProducers(); await drain();
          expect(atomicOriginals.filter(row => row.retired), "An obsolete password action cannot retry its authenticated atomic write after current chart navigation").toEqual([]);
          expect(atomicPasswordRequests).toBe(1); expect(passwordCommits).toBe(0); expect(logoutRequests).toBe(0);
          expect(hasSession()).toBe(true); expect(successfulLogins).toBe(1); expect(rendered()).toContain(currentPlain);
        } else if (finalSecurityWindow) {
          await finite("genuine final-security third salt request after submit act closed", heldSalt.promise);
          if (!heldResponse || heldResponse.writableEnded || custodyActOpen) throw setup("final-security original salt gate or closed submit act missing");
          send(heldResponse, { salt: SALT });
          await finite("original final custody A notes HTTP arrival", notesArrived.promise); releaseCustodyNotes();
          if (custodyBoundary === "after final custody") {
            await finite("last original terminal-empty B revisions HTTP arrival", finalRevisionsArrived.promise);
            const original = finalRevisionsOriginal;
            if (!original || !finalRevisionsHeld || finalRevisionsHeld.writableEnded || custodyActOpen) throw setup("same last original revisions Promise or held HTTP missing");
            // The real HTTP request can arrive only after api.noteRevisions
            // returned and verifyNotesCustody registered its292 await. Register
            // this postreaction now, while its response remains genuinely held.
            // That earlier reaction passes292, sees[], and fulfills the helper;
            // this already-queued reaction retires the view before caller366.
            void original.then(rows => {
              try { if (rows.length !== 0) throw setup("last original revisions page must be terminal empty"); if (!cleanupReleasesCustody) retireCustodyThroughCurrentB(); }
              catch (error) { faults.push(error); }
            }, error => { faults.push(error); });
            releaseFinalRevisions();
          }
          await finite("same final API postreaction or full-seal prereaction retires through current B", retirementObserved.promise);
          await settleOriginalCustodyProducers(); await settleOriginalSecurityKeyProducers(); await settleOriginalFinalSealProducers();
          await complete("authenticated current B survives the final obsolete security continuation", () => hasSession() && rendered().includes(currentPlain)); await drain();
          const forbiddenKind = custodyBoundary === "after final custody" ? "notes ring" : "private wrap";
          expect(finalEncryptAdmissions.filter(row => row.kind === forbiddenKind && row.retired), "a retired final custody or completed ring seal cannot admit the next exact genuine native seal encryption").toEqual([]);
          expect(finalEncryptAdmissions.filter(row => row.kind === "notes ring" && !row.retired)).toHaveLength(custodyBoundary === "after sealed ring" ? 1 : 0);
          expect(finalEncryptAdmissions.every(row => row.successful), "every admitted final native ring/private encryption genuinely succeeds").toBe(true);
          expect(sealPrivateOriginals).toHaveLength(0);
          expect(hasSession()).toBe(true); expect(logoutRequests).toBe(0); expect(passwordCommits).toBe(0); expect(successfulLogins).toBe(1); expect(rendered()).toContain(currentPlain);
        } else if (credentialWindow) {
          await finite("genuine credential third salt request after submit act closed", heldSalt.promise);
          const saltOriginal = securitySaltOriginals[0];
          if (!saltOriginal || !heldResponse || heldResponse.writableEnded || custodyActOpen) throw setup("credential original salt producer or closed submit act missing");
          send(heldResponse, { salt: SALT }); await finite("same original credential auth.saltFor Promise", saltOriginal);
          if (custodyBoundary === "after profile") {
            await finite("genuine security profile HTTP held before original reply", heldMeArrived.promise);
            const meOriginal = credentialMeOriginals[0]; if (!meOriginal || !heldMeResponse || heldMeResponse.writableEnded) throw setup("original security profile Promise missing");
            retireCustodyThroughCurrentB();
            await complete("distinct authenticated B settles before original security profile release", () => hasSession() && rendered().includes(currentPlain) && rendered().includes("Still in the baseline phase"));
            releaseCredentialMe(); await finite("same original public api.me Promise", meOriginal);
          } else await finite("same original full credential crypto Promise retires view", retirementObserved.promise);
          await settleOriginalSecurityKeyProducers(); await settleOriginalCredentialProducers();
          await complete("current B authenticated plaintext survives retired credential producer", () => hasSession() && rendered().includes(currentPlain)); await drain();
          const privateProbe = credentialNativeProbes.find(row => row.kind === "private wrap")!, ringProbe = credentialNativeProbes.find(row => row.kind === "notes ring")!;
          const forbiddenCredentialAdmissions = custodyBoundary === "after profile" ? privateProbe.retiredCalls
            : custodyBoundary === "after private key" ? identityKdfAdmissions.filter(row => row.retired).length : ringProbe.retiredCalls;
          expect(forbiddenCredentialAdmissions, "a retired credential action cannot admit its next exact genuine native cryptographic operation").toBe(0);
          expect(privateProbe.calls - privateProbe.retiredCalls, "genuine private-wrap AES-GCM precedes the later identity boundaries").toBe(custodyBoundary === "after profile" ? 0 : 1);
          expect(identityKdfAdmissions.filter(row => !row.retired), "only the final identity boundary completes one genuine identity HKDF before retirement").toHaveLength(custodyBoundary === "after identity key" ? 1 : 0);
          expect(credentialNativeProbes.every(row => row.calls === row.successes), "every admitted exact private-wrap or ring envelope authenticates natively").toBe(true);
          expect(hasSession()).toBe(true); expect(logoutRequests).toBe(0); expect(passwordCommits).toBe(0); expect(successfulLogins).toBe(1); expect(rendered()).toContain(currentPlain);
        } else if (passwordKdfWindow) {
          await finite("genuine third salt HTTP request after submit act closed", heldSalt.promise);
          const saltOriginal = securitySaltOriginals[0];
          if (!saltOriginal || !heldResponse || heldResponse.writableEnded || custodyActOpen) throw setup("original salt producer or closed submit act missing");
          if (custodyBoundary === "after salt") {
            retireCustodyThroughCurrentB();
            await complete("current authenticated B plaintext before original salt release", () => hasSession() && rendered().includes(currentPlain) && rendered().includes("Still in the baseline phase"));
          }
          send(heldResponse, { salt: SALT });
          await finite("same original public auth.saltFor Promise", saltOriginal);
          if (custodyBoundary === "after current keys") await finite("same original full current portal-keys Promise retires view", retirementObserved.promise);
          await settleOriginalSecurityKeyProducers();
          await complete("current B remains authenticated after old KDF continuation", () => hasSession() && rendered().includes(currentPlain)); await drain();
          expect(passwordKdfAdmissions.filter(row => row.retired), "a retired password action cannot admit another genuine 600k PBKDF2-SHA256 derivation").toEqual([]);
          expect(passwordKdfAdmissions.filter(row => !row.retired)).toHaveLength(custodyBoundary === "after current keys" ? 1 : 0);
          if (custodyBoundary === "after current keys") expect(passwordKdfAdmissions[0]?.saltB64, "the retiring current-password derivation uses the exact native HTTP salt").toBe(SALT);
          for (const admission of passwordKdfAdmissions.filter(row => row.retired)) {
            if (custodyBoundary === "after salt") expect(admission.saltB64).toBe(SALT);
            else expect(generatedSecuritySalts).toContain(admission.saltB64);
          }
          expect(hasSession()).toBe(true); expect(logoutRequests).toBe(0); expect(passwordCommits).toBe(0); expect(successfulLogins).toBe(1); expect(rendered()).toContain(currentPlain);
        } else if (custodyBoundary !== "none") {
          await finite("original custody notes A HTTP arrival", notesArrived.promise);
          const notesOriginal = notesOriginals[0]; if (!notesOriginal) throw setup("original custody notes A Promise missing");
          if (custodyBoundary === "after notes") {
            retireCustodyThroughCurrentB();
            await complete("distinct valid current chart B settles before A notes release", () => hasSession() && rendered().includes(currentPlain) && rendered().includes("Still in the baseline phase"));
            releaseCustodyNotes(); await finite("same original custody notes A Promise", notesOriginal);
          } else {
            releaseCustodyNotes();
            if (custodyBoundary === "after revisions") {
              await finite("original custody revisions A HTTP arrival", revisionsArrived.promise);
              const revisionsOriginal = revisionsOriginals[0]; if (!revisionsOriginal) throw setup("original custody revisions A Promise missing");
              retireCustodyThroughCurrentB();
              await complete("distinct valid current chart B settles before A revisions release", () => hasSession() && rendered().includes(currentPlain) && rendered().includes("Still in the baseline phase"));
              releaseCustodyRevisions(); await finite("same original custody revisions A Promise", revisionsOriginal);
            } else await finite("same original crypto Promise retires A through B navigation", retirementObserved.promise);
          }
          await settleOriginalCustodyProducers();
          await complete("distinct current B plaintext remains rendered", () => hasSession() && rendered().includes(currentPlain)); await drain();
          expect(hasSession()).toBe(true); expect(logoutRequests).toBe(0); expect(passwordCommits).toBe(0); expect(rendered()).toContain(currentPlain);
          if (custodyBoundary === "after note") {
            expect(custodyRevisionRequests.filter(row => row.id === boundaryNoteId && row.retired)).toEqual([]);
            expect(custodyRevisionAdmissions.filter(row => row.id === boundaryNoteId && row.retired)).toEqual([]);
          } else {
            const forbidden = custodyBoundary === "after notes" ? boundaryNativeProbes.slice(0, 1)
              : custodyBoundary === "after revisions" ? boundaryNativeProbes.slice(1) : boundaryNativeProbes.slice(2);
            expect(forbidden.map(row => row.retiredCalls)).toEqual(forbidden.map(() => 0));
            expect(custodyDecrypts.filter(row => row.retired && forbidden.some(probe => row.blob === probe.blob))).toEqual([]);
          }
          expect(boundaryNativeProbes.every(row => row.calls === row.successes)).toBe(true);
          expect(custodyDecrypts.filter(row => row.blob === currentRows[0]!.blob)).toHaveLength(1);
        } else if (scenario === "live completion") {
          await complete("authenticated atomic password change", () => (passwordCommits === 1 && !hasSession() && rendered().includes("Password changed. Every session")) || (legacyHeaderless && rendered().includes("server changed the note pagination protocol during custody verification — nothing was changed."))); await drain();
          expect(passwordCommits).toBe(1); expect(custodyVersion).toBe(1); expect(successfulLogins).toBe(1); expect(hasSession()).toBe(false); expect(root!.root.findAllByType("button").filter(node => text(node) === "Sign in")).toHaveLength(1);
          expect(revisionRequests).toEqual(noteRows.map(note => note.id));
          expect(noteProbes.map(({ calls, failures, successes }) => ({ calls, failures, successes }))).toEqual([{ calls: 4, failures: 3, successes: 1 }, { calls: 4, failures: 3, successes: 1 }]);
          expect(secretArrays.length).toBeGreaterThanOrEqual(9); expect(saltArrays.length).toBe(2);
        } else if (scenario === "legacy to snapshot custody") {
          // Both outcomes settle normally: the baseline commits, while the fixed
          // view refuses the mixed collection before constructing a mutation.
          await complete("public custody verification outcome", () => passwordCommits === 1 || rendered().includes("server changed the note pagination protocol during custody verification"));
          await drain();
          expect(passwordCommits).toBe(0);
          expect(custodyVersion).toBe(0); expect(successfulLogins).toBe(1); expect(hasSession()).toBe(true);
          expect(rendered()).toContain("nothing was changed.");
          // Refusal retires the submitted passwords; the live form accepts fresh input.
          await input("Current password", PASSWORD); await input("New password", NEW_PASSWORD); await input("Repeat new password", NEW_PASSWORD);
          expect(button("Change password")).toBeDefined();
          expect(revisionRequests).toEqual([noteRows[0]!.id]);
          expect(noteProbes.map(({ calls, failures, successes }) => ({ calls, failures, successes }))).toEqual([{ calls: 4, failures: 3, successes: 1 }, { calls: 0, failures: 0, successes: 0 }]);
        } else {
          await finite("owned pending old-form salt request", heldSalt.promise);
          // This enabled rendered button is the actual App lockDown path.
          await press("Sign out"); await complete("old bearer revoked and public login shown", () => logoutRequests === 1 && !hasSession() && rendered().includes("Sign in"));
          phase = "replacement login"; await login(false);
          const before = requests.length; phase = "retired action";
          if (!heldResponse || heldResponse.writableEnded) throw setup("owned old salt response unavailable"); send(heldResponse, { salt: SALT }); await drain();
          expect(requests.slice(before).filter(row => row.bearer !== null)).toEqual([]);
          expect(revisionRequests).toEqual([]);
          expect(noteProbes.map(({ calls, failures, successes }) => ({ calls, failures, successes }))).toEqual([{ calls: 0, failures: 0, successes: 0 }, { calls: 0, failures: 0, successes: 0 }]);
          expect(passwordCommits).toBe(0); expect(successfulLogins).toBe(2); expect(tokens.has("owned-retirement-bearer-2")).toBe(true); expect(hasSession()).toBe(true); expect(rendered()).toContain("Patients — Dr. Native Retirement"); expect(button("Sign out")).toBeDefined();
        }
        for (const bytes of [...secretArrays, ...saltArrays]) expect(bytes.every(value => value === 0)).toBe(true);
        expect(nativeBodies.length).toBeGreaterThanOrEqual(6); expect(unhandled).toEqual([]); clean();
      } finally {
        if (heldResponse && !heldResponse.writableEnded) send(heldResponse, { salt: SALT });
        cleanupReleasesCustody = true; releaseAtomicFailure(); releaseCustodyNotes(); releaseCustodyRevisions(); releaseCredentialMe(); releaseFinalRevisions();
        const cleanupFaults: unknown[] = [];
        if (custodyBoundary !== "none") try { await settleOriginalCustodyProducers(); } catch (error) { cleanupFaults.push(error); }
        if (passwordKdfWindow || credentialWindow || finalSecurityWindow || atomicRetryWindow) try { await settleOriginalSecurityKeyProducers(); } catch (error) { cleanupFaults.push(error); }
        if (atomicRetryWindow) try { await settleOriginalAtomicProducers(); } catch (error) { cleanupFaults.push(error); }
        if (finalSecurityWindow) try { await settleOriginalFinalSealProducers(); } catch (error) { cleanupFaults.push(error); }
        if (credentialWindow) try { await settleOriginalCredentialProducers(); } catch (error) { cleanupFaults.push(error); }
        try { if (root) await act(async () => root!.unmount()); } catch (error) { cleanupFaults.push(error); }
        try { await drain(); } catch (error) { cleanupFaults.push(error); }
        clearSession();
        try { await finite("owned server handlers retired", Promise.all(handlers)); } catch (error) { cleanupFaults.push(error); }
        server.closeAllConnections();
        try { if (server.listening) await finite("owned server closed", new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))); } catch (error) { cleanupFaults.push(error); }
        restore(subtle, "deriveBits", oldBits); restore(subtle, "decrypt", oldDecrypt); restore(subtle, "encrypt", oldEncrypt); restore(crypto, "getRandomValues", oldRandom); restore(Response.prototype, "json", oldJson); restore(window.location, "origin", oldOrigin);
        restoreNoteAny?.(); restore(api, "notes", oldNotes); restore(api, "noteRevisions", oldRevisions);
        restoreMasterKey?.(); restorePortalKeys?.(); restore(auth, "saltFor", oldSaltFor);
        restoreOpenPrivate?.(); restoreIdentityKey?.(); restoreOpenRing?.(); restore(api, "me", oldMe);
        restoreSealRing?.(); restoreSealPrivate?.(); restore(api, "changePasswordAtomic", oldPasswordAtomic);
        vi.restoreAllMocks(); process.removeListener("unhandledRejection", observeUnhandled); window.location.hash = "";
        for (const bytes of [accountKeys.auth, accountKeys.wrap, accountKeys.note, identityNote, privateBytes]) bytes.fill(0);
        for (const probe of noteProbes) for (const bytes of [probe.nonce, probe.cipher, probe.aad, probe.plain]) bytes.fill(0);
        for (const probe of boundaryNativeProbes) for (const bytes of [probe.nonce, probe.cipher, probe.aad]) bytes.fill(0);
        for (const probe of credentialNativeProbes) for (const bytes of [probe.nonce, probe.cipher, probe.aad]) bytes.fill(0);
        if (cleanupFaults.length) throw setup("owned cleanup failed", cleanupFaults[0]);
        clean(); if (unhandled.length) throw setup("native unhandled rejection", unhandled[0]);
      }
    }
  }
});
