/** Prospective Node/RTR fixture only. Synthetic authenticated account/ciphertexts,
 * genuine owned Node HTTP/native fetch/WebCrypto/Blob URLs, installed fake-IDB
 * native request/transaction API. No provider or typing qualification is implied. */
import { createCipheriv, createDecipheriv, createHash, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { IDBFactory, IDBObjectStore } from "fake-indexeddb";
import { act, Profiler } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { vi } from "vitest";
import { App } from "../../src/App";
import { ApiError, api, clearSession, hasSession } from "../../src/api";
import * as portalCrypto from "../../src/crypto";
import { drainPortalDraftWritesForTests } from "../../src/noteDrafts";
import { kv, resetKvConnectionForTests, setKvBackendForTests, StorageReadError } from "../../src/kvstore";

export const USERNAME = "synthetic_portal_public_gap", PASSWORD = "correct horse battery staple";
export const OWNER = "0123456789abcdef0123456789abcdef", PATIENT = "fedcba9876543210fedcba9876543210";
const TOKEN = "synthetic-public-gap-token", SALT = "AAECAwQFBgcICQoLDA0ODw==";
const DATES = ["2026-10-01", "2026-10-02"], ATTACHMENT = "synthetic-audio-row";
export const SAVED_DRAFT = "Existing authenticated local writing", SAVED_NOTE = "Original authenticated note", WINNING_NOTE = "Colleague authenticated winning note", MINE = "My preserved authenticated edit";
const setup = (label: string, cause?: unknown) => new Error(`SetupError: ${label}`, cause === undefined ? undefined : { cause });
export const nodeText = (value: unknown): string => {
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(nodeText).join("");
  return value && typeof value === "object" && "children" in value ? nodeText((value as { children: unknown }).children) : "";
};
async function finite<T>(label: string, original: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([original, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(`completion deadline: ${label}`)), 15000); })]); }
  finally { if (timer) clearTimeout(timer); }
}
function seal(key: Buffer, aadParts: string[], plain: Buffer): string {
  const nonce = randomBytes(12), aad = Buffer.from(JSON.stringify(aadParts)), cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad); const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]), tag = cipher.getAuthTag();
  const opener = createDecipheriv("aes-256-gcm", key, nonce); opener.setAAD(aad); opener.setAuthTag(tag);
  const checked = Buffer.concat([opener.update(encrypted), opener.final()]);
  try { if (!checked.equals(plain)) throw setup("independent fixture authentication differs"); }
  finally { checked.fill(0); }
  return Buffer.concat([nonce, encrypted, tag]).toString("base64");
}
function open(key: Buffer, aadParts: string[], blob: string): Buffer {
  const wire = Buffer.from(blob, "base64"), opener = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  opener.setAAD(Buffer.from(JSON.stringify(aadParts))); opener.setAuthTag(wire.subarray(-16));
  return Buffer.concat([opener.update(wire.subarray(12, -16)), opener.final()]);
}
function authenticatedFixture(laterPage: boolean, emptyPatientId: boolean, retryEvidence: boolean, nativeMeasures: boolean) {
  const patientId = emptyPatientId ? "" : PATIENT;
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/portal-wrap/v1", 32));
  const identity = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = identity.privateKey.export({ type: "pkcs8", format: "der" }), publicDer = identity.publicKey.export({ type: "spki", format: "der" });
  const ephemeralDer = ephemeral.publicKey.export({ type: "spki", format: "der" });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: identity.publicKey }), dataKey = emptyPatientId ? Buffer.alloc(32, 31) : randomBytes(32);
  const consentKey = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeralDer, publicDer]), "mindpattern/wrap/v1", 32));
  const noteKey = Buffer.from(hkdfSync("sha256", privateDer, Buffer.alloc(32), "mindpattern/portal-notes/v2", 32));
  const audioPlain = Buffer.from("independently authenticated synthetic audio bytes"), audioDigest = createHash("sha256").update(audioPlain).digest("hex");
  const note = (index: number, text: string, version: number) => {
    const client_note_id = `native-note-client-${index}`, plain = Buffer.from(JSON.stringify({ v: 1, text }));
    try { return { id: `native-note-${index}`, client_note_id, pattern_pid: null, blob: seal(noteKey, ["note", OWNER, patientId, client_note_id], plain), version, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" }; }
    finally { plain.fill(0); }
  };
  try {
    const targetIndex = laterPage ? 100 : 0, target = note(targetIndex, SAVED_NOTE, 4), winning = note(targetIndex, WINNING_NOTE, 5);
    const notes = laterPage ? [...Array.from({ length: 100 }, (_, index) => note(index, `Earlier authenticated note ${index}`, 1)), target] : [target];
    const pattern = { kind: "temporal", label: "Native evidence", occurrences: 2, confidence: 0.8, detail: { day: "Thursday", pattern_pid: "temporal:native-evidence", pattern_state: "confirmed", evidence_dates: DATES, first_seen: DATES[0], last_seen: DATES[1] } };
    const patterns = retryEvidence ? [
      { ...pattern, label: "Earlier native pattern", detail: { ...pattern.detail, pattern_pid: "temporal:earlier-native", evidence_dates: [DATES[0]!] } },
      { ...pattern, label: "Current native pattern", detail: { ...pattern.detail, pattern_pid: "temporal:current-native", evidence_dates: [DATES[1]!] } },
    ] : [pattern];
    const insightsPlain = Buffer.from(JSON.stringify({ v: 2, state_seq: 7, stats: { total_entries: 2, active_days: 2, avg_sentiment: 0.1, patterns } }));
    const entryPlain = Buffer.from(JSON.stringify({ v: 2, text: "Authenticated audio evidence", sentiment: 0.1 }));
    const draftPlain = Buffer.from(JSON.stringify({ v: 1, state: { text: { general: SAVED_DRAFT }, editing: null, pending: {} } }));
    const measurePlain = nativeMeasures ? Buffer.from(JSON.stringify({ v: 1, measure: "phq2", score: 2, completed_at: "2026-10-01T12:00:00Z" })) : null;
    try { return { noteKey, notes, target, winning, verifier: auth.toString("base64"), publicKey: publicDer.toString("base64"), envelope: seal(wrap, ["therapist-key", USERNAME], privateDer),
      draft: seal(noteKey, ["portal-draft", OWNER, patientId], draftPlain), audioDigest,
      measure: measurePlain === null ? null : { id: "native-measure-row", client_measure_id: "native-measure-client", measure_date: DATES[0]!, received_at: "2026-10-01T12:00:00Z", blob: seal(dataKey, ["measure", patientId, "native-measure-client"], measurePlain) },
      patient: { user_id: patientId, username: "Synthetic native public patient", status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null, share_voice: true, ephemeral_pub: ephemeralDer.toString("base64"), wrapped_key: seal(consentKey, ["consent-wrap", patientId, OWNER], dataKey) },
      insights: { phase: "insight", active_days: 4, streak: 1, days_remaining: 0, state_seq: 7, blob: seal(dataKey, ["insights", patientId, "patterns"], insightsPlain) },
      entries: [{ id: "native-evidence-row", client_entry_id: "native-entry-client", entry_date: DATES[0], content_version: 1, blob: seal(dataKey, ["entry", patientId, "native-entry-client", "1"], entryPlain), audio: { attachment_id: ATTACHMENT, expires_at: "2099-10-02T00:00:00Z" } }],
      audio: { id: ATTACHMENT, client_entry_id: "native-entry-client", blob: seal(dataKey, ["audio", patientId, "native-entry-client", "1"], audioPlain), mime_type: "audio/webm", duration_seconds: 1, size_bytes: audioPlain.length, created_at: "2026-10-01T00:00:00Z", expires_at: "2099-10-02T00:00:00Z" } };
    } finally { insightsPlain.fill(0); entryPlain.fill(0); draftPlain.fill(0); measurePlain?.fill(0); }
  } catch (error) { noteKey.fill(0); throw error; }
  finally { master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0); dataKey.fill(0); shared.fill(0); consentKey.fill(0); audioPlain.fill(0); }
}
export async function openNativeChart(options: { failFirstDraftRead?: boolean; holdAudio?: boolean; conflict?: boolean; laterPage?: boolean; emptyPatientId?: boolean; nullBackupCodesMfa?: boolean; retryEvidence?: boolean; retiredNotesPagination?: boolean; retiredInitialNotesDecrypt?: boolean; retiredSinglePageNotes?: boolean; retiredMeasures?: boolean; nativeMeasures?: boolean; retiredEditConflict?: "before-refetch" | "failed-refetch" | "after-latest-decrypt" | "after-terminal-refetch"; retiredSasDigest?: boolean; repeatedSas?: boolean; native205Patients?: boolean } = {}) {
  const account = authenticatedFixture(options.laterPage === true || options.retiredNotesPagination === true || options.retiredInitialNotesDecrypt === true, options.emptyPatientId === true, options.retryEvidence === true, options.retiredMeasures === true || options.nativeMeasures === true), faults: unknown[] = [];
  const requests: Array<{ path: string; method: string; offset: string | null; revision: string | null }> = [];
  const patchBodies: Array<{ plaintext: string; baseVersion: unknown; aad: string[] }> = [];
  const mfaEnableBodies: Array<{ verifier: unknown; code: unknown }> = [];
  const nativeFetch = globalThis.fetch, oldFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch"), oldIdb = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  const oldWindow = Object.getOwnPropertyDescriptor(globalThis, "window"), originalGet = IDBObjectStore.prototype.get;
  const nativeCreate = URL.createObjectURL, nativeRevoke = URL.revokeObjectURL, createDescriptor = Object.getOwnPropertyDescriptor(URL, "createObjectURL"), revokeDescriptor = Object.getOwnPropertyDescriptor(URL, "revokeObjectURL");
  if (typeof nativeFetch !== "function" || typeof nativeCreate !== "function" || typeof nativeRevoke !== "function") throw setup("genuine native fetch/Blob URL capability missing");
  const audioDescriptor = Object.getOwnPropertyDescriptor(api, "patientAudio"), originalAudio = api.patientAudio;
  const notesDescriptor = Object.getOwnPropertyDescriptor(api, "notes"), originalNotes = api.notes;
  const sasDescriptor = Object.getOwnPropertyDescriptor(api, "pairingSas"), originalSas = api.pairingSas;
  const patientsDescriptor = Object.getOwnPropertyDescriptor(api, "patients"), originalPatients = api.patients;
  const native205Responses = new WeakSet<Response>();
  const native205JsonOriginals: Promise<unknown>[] = [], native205PatientsOriginals: Array<ReturnType<typeof api.patients>> = [], native205Observers: Promise<unknown>[] = [];
  let native205Armed = false, native205Arrived = false, native205BackActClosed = false, native205CleanupStarted = false;
  let releaseNative205: (() => void) | undefined, native205Finish: Promise<void> | undefined;
  let native205JsonError: unknown, native205PatientsError: unknown, native205Signouts = 0, native205ResponseCount = 0;
  const sasOriginals: Array<ReturnType<typeof api.pairingSas>> = [];
  const sasFetches = new Set<Promise<Response>>(), sasHandlers = new Set<Promise<void>>();
  const retiredSasDigestAdmissions: Array<{ algorithm: string; publicSpkiBase64: string }> = [];
  let releaseSas: (() => void) | undefined, sasArrived = false, sasRetired = false, sasReleased = false;
  let repeatedSasCount = 0, firstRepeatedSasDigestStart = 0;
  const repeatedSasDigestAdmissions: Array<{ algorithm: string; publicSpkiBase64: string; original: Promise<unknown> }> = [];
  const sasCode = "7X2KQM4N";
  const sasFingerprint = createHash("sha256").update(Buffer.from(account.publicKey, "base64")).digest("hex").slice(0, 16);
  const originalNoteDecrypt = portalCrypto.decryptNoteAny;
  const measuresDescriptor = Object.getOwnPropertyDescriptor(api, "patientMeasures"), originalMeasures = api.patientMeasures;
  const originalMeasureDecrypt = portalCrypto.decryptMeasure;
  const measureOriginals: Array<ReturnType<typeof api.patientMeasures>> = [];
  const measureDecrypts: Array<{ blob: string; original: ReturnType<typeof portalCrypto.decryptMeasure> }> = [];
  let restoreMeasureDecryptObserver: (() => void) | undefined;
  let releaseFirstMeasures: (() => void) | undefined;
  let firstMeasuresArrived = false, firstMeasuresSeen = false, firstMeasuresFinished = false;
  const noteOriginals: Array<ReturnType<typeof api.notes>> = [];
  const editDescriptor = Object.getOwnPropertyDescriptor(api, "updateNote"), originalEdit = api.updateNote;
  const editOriginals: Array<ReturnType<typeof api.updateNote>> = [];
  const authoredEditErrors = new Set<unknown>();
  const retiredEditNoteDispatches: Array<{ path: string; method: string; offset: string | null; revision: string | null }> = [];
  let releaseEditPatch: (() => void) | undefined, releaseEditRefetch: (() => void) | undefined;
  let editPatchArrived = false, editRefetchArrived = false, initialEditInsightsFailed = false;
  let editPatchResponseSent = false, editRefetchResponseSent = false, retiredEditReleased = false;
  const noteDecrypts: Array<{ clientNoteId: string; blob: string; original: ReturnType<typeof portalCrypto.decryptNoteAny>; settled: boolean }> = [];
  let initialNoteRetryArmed = false, initialNoteRetryStarted = false, initialNoteDrainFinished = false;
  let collectInitialNoteCommits = false;
  const initialNoteCommittedTexts: string[] = [];
  let releaseLatestConflictNotes: (() => void) | undefined;
  let latestConflictNotesArrived = false, latestConflictRetryArmed = false, latestConflictRetryStarted = false, latestConflictDrainFinished = false;
  let collectLatestConflictCommits = false;
  const latestConflictCommittedTexts: string[] = [];
  let releaseTerminalConflictNotes: (() => void) | undefined;
  let terminalConflictNotesArrived = false, terminalConflictRetryArmed = false, terminalConflictRetryStarted = false, terminalConflictDrainFinished = false;
  let terminalConflictOriginal: ReturnType<typeof api.notes> | undefined;
  let terminalNotesFinished = false;
  const noteWireDispatches: Array<{ path: string; method: string; offset: string | null; revision: string | null }> = [];
  let restoreNoteDecryptObserver: (() => void) | undefined;
  const entryDescriptor = Object.getOwnPropertyDescriptor(api, "patientEntries"), originalEntries = api.patientEntries;
  const retryEntries: Array<ReturnType<typeof api.patientEntries>> = [], retryDecrypts: Array<ReturnType<typeof portalCrypto.decryptEntry>> = [];
  const originalEntryDecrypt = portalCrypto.decryptEntry;
  let restoreEntryDecryptObserver: (() => void) | undefined;
  const subtle = crypto.subtle, decryptDescriptor = Object.getOwnPropertyDescriptor(subtle, "decrypt"), originalDecrypt = subtle.decrypt;
  const fetches: Promise<Response>[] = [], decrypts: Promise<ArrayBuffer>[] = [], reads: Promise<ArrayBuffer>[] = [], handlers: Promise<void>[] = [], audioOriginals: Array<ReturnType<typeof api.patientAudio>> = [];
  const publicAudioDecrypts: Array<ReturnType<typeof portalCrypto.decryptAudio>> = [], publicKeyUnwraps: Array<ReturnType<typeof portalCrypto.unwrapPatientDataKey>> = [], nativeOriginals: Promise<unknown>[] = [], bodyOriginals: Promise<unknown>[] = [], storageOriginals: Promise<unknown>[] = [];
  const originalPublicAudioDecrypt = portalCrypto.decryptAudio, originalPublicKeyUnwrap = portalCrypto.unwrapPatientDataKey;
  const keyUnwrapResults: Array<Awaited<ReturnType<typeof portalCrypto.unwrapPatientDataKey>>> = [];
  const audioCiphertextDecryptAdmissions: Promise<ArrayBuffer>[] = [];
  const audioEnvelope = Buffer.from(account.audio.blob, "base64");
  const audioAad = Buffer.from(JSON.stringify(["audio", account.patient.user_id, account.audio.client_entry_id, "1"]));
  const observedBytes = (value: BufferSource): Buffer => value instanceof ArrayBuffer ? Buffer.from(value) : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  let restorePublicAudioObserver: (() => void) | undefined, restorePublicKeyObserver: (() => void) | undefined;
  const ownedResponses = new WeakSet<Response>();
  const bodyDescriptors = new Map<"json" | "text", PropertyDescriptor | undefined>();
  const cryptoDescriptors = new Map<string, PropertyDescriptor | undefined>();
  const storageDescriptors = new Map<keyof typeof kv, PropertyDescriptor | undefined>();
  let expectedReadError: DOMException | null = null, expectedReadRefusalObserved = false;
  const urls = new Map<string, { active: boolean; digest: string | null }>();
  const factory = new IDBFactory(), databases: IDBDatabase[] = [], originalOpen = factory.open;
  factory.open = (...args: Parameters<IDBFactory["open"]>) => {
    const original = originalOpen.apply(factory, args);
    original.addEventListener("success", () => databases.push(original.result));
    return original;
  };
  let root: ReactTestRenderer | undefined, releaseAudio: (() => void) | undefined, audioArrived = false, abortRead = options.failFirstDraftRead === true, conflicted = false, closed = false;
  let releaseRetryA: (() => void) | undefined, releaseRetryB: (() => void) | undefined;
  let retryAArrived = false, retryBArrived = false, retryAFinished = false, retryBFinished = false, retryNotesFailed = false;
  let releaseFirstNotes: (() => void) | undefined;
  let firstNotesArrived = false, firstNotesSeen = false, firstInsightFailed = false, firstNotesFinished = false;
  let retiredNoteDispatches: typeof noteWireDispatches = [];
  const text = () => root ? nodeText(root.root) : "";
  function clean() { if (faults.length) throw setup("unknown native fixture/observer fault", faults[0]); }
  async function completed(label: string, condition: () => boolean) {
    const deadline = Date.now() + 15000;
    while (!condition()) { clean(); if (Date.now() >= deadline) throw setup(`public completion not observed: ${label}`); await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); }); }
    clean();
  }
  async function finishRetryA() {
    if (!retryAArrived || retryAFinished) return;
    if (!releaseRetryA) throw setup("held earlier evidence release missing");
    releaseRetryA();
    await completed("original public earlier entry decrypt starts", () => retryDecrypts.length > 0);
    await act(async () => { await finite("exact original earlier entry decrypt", retryDecrypts[0]!); });
    retryAFinished = true; clean();
  }
  async function finishRetryB() {
    if (!retryBArrived || retryBFinished) return;
    if (!releaseRetryB) throw setup("held current evidence release missing");
    const before = publicKeyUnwraps.length;
    releaseRetryB();
    await completed("original public current evidence key unwrap starts", () => publicKeyUnwraps.length > before);
    await act(async () => { await strictDrain("original current evidence key unwrap", publicKeyUnwraps.slice(before)); });
    await strictDrain("original public evidence API completions", retryEntries);
    retryBFinished = true; clean();
  }
  async function finishHeldNotesFirstPage() {
    if (firstNotesFinished) return;
    const original = noteOriginals[0];
    if (!original) { if (closed) return; throw setup("original public notes Promise missing"); }
    const dispatchStart = noteWireDispatches.length, decryptStart = noteDecrypts.length;
    releaseFirstNotes?.();
    await act(async () => {
      const page = await finite("exact original held notes first-page completion", original);
      if (page.notes.length !== 100 || page.nextOffset !== 100 || page.revision !== "7") throw setup("held native notes page lacks its valid continuation");
    });
    // The traversal's await of this identical public Promise was registered
    // before this fixture await. Its post-response guard and next native
    // fetch dispatch contain no additional await on this valid page path.
    retiredNoteDispatches = noteWireDispatches.slice(dispatchStart);
    if (retiredNoteDispatches.length) {
      // Own the admitted traversal to its known final authenticated row.
      // This is cleanup of an original public Promise, never a turn budget
      // or an observation of the component's private load Promise/state.
      await completed("original final authenticated note decrypt starts", () => noteDecrypts.slice(decryptStart).some(value => value.clientNoteId === account.target.client_note_id));
      const last = noteDecrypts.slice(decryptStart).find(value => value.clientNoteId === account.target.client_note_id);
      if (!last) throw setup("final original note decrypt missing");
      await act(async () => { await finite("exact original final authenticated note decrypt", last.original); });
    }
    await strictDrain("original public notes API completions", noteOriginals);
    firstNotesFinished = true; clean();
  }
  const button = (label: string) => {
    const found = root?.root.findAllByType("button").find(node => nodeText(node) === label);
    if (!found) throw setup(`public button missing: ${label}`); return found;
  };
  const press = async (label: string) => {
    const node = button(label); if (node.props.disabled) throw setup(`public button disabled: ${label}`);
    await act(async () => { if (node.props.type === "submit") {
      let parent = node.parent; while (parent && parent.type !== "form") parent = parent.parent;
      if (!parent) throw setup("native submit lacks its public form"); parent.props.onSubmit({ preventDefault() {} });
    } else node.props.onClick({ preventDefault() {} }); });
  };
  async function input(label: string, value: string) {
    const field = root?.root.findAllByType("input").find(node => root!.root.findAllByType("label").some(owner => owner.props.htmlFor === node.props.id && nodeText(owner).includes(label)));
    if (!field || field.props.disabled) throw setup(`public input unavailable: ${label}`);
    await act(async () => field.props.onChange({ target: { value } }));
  }
  const composer = () => {
    const node = root?.root.findAllByType("textarea").find(field => String(field.props.placeholder).startsWith("Note about this"));
    if (!node) throw setup("public note composer missing"); return node;
  };
  async function strictDrain(label: string, originals: Promise<unknown>[]) {
    const settled = await finite(label, Promise.allSettled(originals));
    const rejected = settled.find(row => row.status === "rejected"); if (rejected?.status === "rejected") throw setup(`unknown original producer rejection: ${label}`, rejected.reason);
  }
  async function drainNotesAndEditProducers() {
    // Earlier public caller reactions may admit the next finite page/decrypt.
    // Repeat only when those original producers actually added a new Promise.
    for (;;) {
      const originals = [...editOriginals, ...noteOriginals];
      const originalDecrypts = noteDecrypts.map(value => value.original);
      await act(async () => {
        const settled = await finite("original public edit and notes producers", Promise.allSettled(originals));
        for (const result of settled) if (result.status === "rejected" && !authoredEditErrors.has(result.reason)) throw setup("unexpected original edit/notes rejection", result.reason);
        await strictDrain("original public note decrypt completion", originalDecrypts);
      });
      if (originals.length === editOriginals.length + noteOriginals.length && originalDecrypts.length === noteDecrypts.length) return;
    }
  }
  async function drainMeasureProducers() {
    for (;;) {
      const pages = [...measureOriginals], keys = [...publicKeyUnwraps], opened = measureDecrypts.map(value => value.original);
      await act(async () => {
        await strictDrain("original public measures page completion", pages);
        await strictDrain("original exported measure-key unwrap completion", keys);
        await strictDrain("original exported authenticated measure decrypt completion", opened);
      });
      if (pages.length === measureOriginals.length && keys.length === publicKeyUnwraps.length && opened.length === measureDecrypts.length) return;
    }
  }
  function restore(target: object, name: PropertyKey, descriptor: PropertyDescriptor | undefined) {
    if (descriptor) Object.defineProperty(target, name, descriptor); else Reflect.deleteProperty(target, name);
  }
  const server = createServer((request, response) => {
    const originalHandler = (async () => {
      const body: Buffer[] = []; for await (const part of request) body.push(Buffer.from(part));
      const wire = Buffer.concat(body).toString("utf8"), parsed = wire ? JSON.parse(wire) as Record<string, unknown> : {};
      const url = new URL(request.url ?? "", origin), path = url.pathname;
      requests.push({ path, method: request.method ?? "GET", offset: url.searchParams.get("offset"), revision: url.searchParams.get("expected_revision") });
      if (wire.includes(PASSWORD)) throw setup("plaintext password reached native HTTP");
      let value: unknown, status = 200; const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (path === "/api/v1/meta") value = { sharing_available: true };
      else if (path === "/api/v1/auth/salt") value = { salt: SALT };
      else if (path === "/api/v1/auth/login") {
        if (parsed.username !== USERNAME || parsed.verifier !== account.verifier) throw setup("independent600k authentication mismatch");
        if (options.nullBackupCodesMfa && parsed.totp_code === undefined) value = { token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86400, mfa_enrollment_required: true };
        else if (parsed.totp_code === undefined) { status = 401; value = { code: "totp_required", detail: "MFA is required" }; }
        else { if (parsed.totp_code !== "123456") throw setup("unexpected public MFA code"); value = { token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86400, mfa_enrollment_required: false }; }
      } else {
        if (request.headers.authorization !== `Bearer ${TOKEN}`) throw setup("protected request lacks current owner bearer");
        if (options.nullBackupCodesMfa && path === "/api/v1/account/totp/setup") {
          if (parsed.verifier !== account.verifier) throw setup("native enrollment verifier differs from independent authentication");
          value = { secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:synthetic?secret=JBSWY3DPEHPK3PXP" };
        } else if (options.nullBackupCodesMfa && path === "/api/v1/account/totp/enable") {
          mfaEnableBodies.push({ verifier: parsed.verifier, code: parsed.code });
          if (mfaEnableBodies.length === 1) {
            if (parsed.verifier !== account.verifier || parsed.code !== "123456") throw setup("first native enrollment proof differs");
            value = { backup_codes: null };
          } else { status = 403; value = { detail: "proof required" }; }
        } else if (path === "/api/v1/therapist/me") value = { username: USERNAME, display_name: "Dr. Native Public", wrap_pub_key: account.publicKey, wrap_key_blob: account.envelope, totp_enabled: true };
        else if (path === "/api/v1/therapist/patients") {
          if (options.native205Patients && native205Armed) {
            if (request.method !== "GET" || native205Arrived) throw setup("native205 caseload request differs or repeats");
            native205Arrived = true;
            if (!closed && !native205CleanupStarted) await new Promise<void>(resolve => { releaseNative205 = resolve; });
            // A real successful HTTP205 has a null native fetch body. Its
            // original JSON consumer rejects with its own native SyntaxError.
            response.writeHead(205, { "Content-Type": "application/json", "Content-Length": "0" }); response.end(); return;
          }
          value = [account.patient];
        }
        else if ((options.retiredSasDigest || options.repeatedSas) && path === "/api/v1/therapist/pairing-codes") {
          if (request.method !== "POST") throw setup("native pairing-code method differs");
          value = { code: sasCode, expires_in: 900 };
        } else if (options.repeatedSas && path === "/api/v1/therapist/pairing/sas") {
          if (request.method !== "GET" || request.headers["x-pairing-code"] !== sasCode || url.searchParams.get("patient_user_id") !== account.patient.user_id || repeatedSasCount >= 2) throw setup("native repeated SAS tuple differs");
          repeatedSasCount += 1;
          if (repeatedSasCount === 2 && !closed && !repeatedSasCleanupStarted) await new Promise<void>(resolve => { releaseSas = resolve; });
          value = { sas: "123456", wrap_key_fingerprint: sasFingerprint, expires_in: 900 };
        } else if (options.retiredSasDigest && path === "/api/v1/therapist/pairing/sas") {
          if (request.method !== "GET" || sasArrived || request.headers["x-pairing-code"] !== sasCode || url.searchParams.get("patient_user_id") !== account.patient.user_id) throw setup("native held SAS tuple differs");
          sasArrived = true;
          if (!closed) await new Promise<void>(resolve => { releaseSas = resolve; });
          value = { sas: "123456", wrap_key_fingerprint: sasFingerprint, expires_in: 900 };
        }
        else if (path.endsWith(`/patients/${account.patient.user_id}/insights`)) {
          if (options.retiredEditConflict && !initialEditInsightsFailed) { initialEditInsightsFailed = true; status = 503; value = { detail: "initial chart read temporarily unavailable" }; }
          else if ((options.retiredNotesPagination || options.retiredMeasures || options.retiredInitialNotesDecrypt || options.retiredSinglePageNotes) && !firstInsightFailed) { firstInsightFailed = true; status = 503; value = { detail: "temporary native insight read unavailable" }; }
          else value = account.insights;
        }
        else if (path.endsWith(`/patients/${account.patient.user_id}/entries`)) {
          if (options.retryEvidence && url.searchParams.get("since") === DATES[0]) {
            retryAArrived = true; if (!closed) await new Promise<void>(resolve => { releaseRetryA = resolve; }); value = account.entries;
          } else if (options.retryEvidence && url.searchParams.get("since") === DATES[1]) {
            retryBArrived = true; if (!closed) await new Promise<void>(resolve => { releaseRetryB = resolve; }); value = [];
          } else { if (options.retryEvidence) throw setup("evidence request lacks its authored pattern date"); value = account.entries; }
        }
        else if (path.endsWith(`/patients/${account.patient.user_id}/measures`)) {
          if (options.retiredMeasures && !firstMeasuresSeen) {
            firstMeasuresSeen = true; firstMeasuresArrived = true;
            if (!closed) await new Promise<void>(resolve => { releaseFirstMeasures = resolve; });
            value = [account.measure!]; headers["X-Measures-Revision"] = "7";
          } else if (options.nativeMeasures) { value = [account.measure!]; headers["X-Measures-Revision"] = "7"; }
          else { value = []; if (options.retiredMeasures) headers["X-Measures-Revision"] = "8"; }
        }
        else if (path.endsWith(`/patients/${account.patient.user_id}/notes`)) {
          const initialSnapshot = (options.retiredInitialNotesDecrypt === true || options.retiredSinglePageNotes === true) && (!firstNotesSeen || url.searchParams.get("expected_revision") === "7");
          const replacementSnapshot = (options.retiredInitialNotesDecrypt === true || options.retiredSinglePageNotes === true) && !initialSnapshot;
          const rows = replacementSnapshot ? [account.winning] : conflicted ? account.notes.map(row => row.id === account.target.id ? account.winning : row) : account.notes;
          const offset = Number(url.searchParams.get("offset") ?? "0"), revision = options.retiredEditConflict === "after-terminal-refetch" && conflicted && terminalConflictNotesArrived ? "9" : replacementSnapshot || conflicted ? "8" : "7";
          const terminalConflictSnapshot = options.retiredEditConflict === "after-terminal-refetch" && conflicted && !terminalConflictNotesArrived;
          if (!Number.isSafeInteger(offset) || offset < 0 || (url.searchParams.has("expected_revision") && url.searchParams.get("expected_revision") !== revision)) throw setup("notes snapshot query is incoherent");
          if (options.retryEvidence && !retryNotesFailed) { retryNotesFailed = true; status = 503; value = { detail: "temporary native notes read unavailable" }; }
          else {
            if ((options.retiredInitialNotesDecrypt || options.retiredSinglePageNotes) && initialSnapshot && offset === 0 && !firstNotesSeen) {
              firstNotesSeen = true; firstNotesArrived = true;
              if (!closed) await new Promise<void>(resolve => { releaseFirstNotes = resolve; });
            }
            if (options.retiredNotesPagination && offset === 0 && !firstNotesSeen) {
              firstNotesSeen = true; firstNotesArrived = true;
              if (!closed) await new Promise<void>(resolve => { releaseFirstNotes = resolve; });
            }
            if (terminalConflictSnapshot) {
              terminalConflictNotesArrived = true;
              if (!closed) await new Promise<void>(resolve => { releaseTerminalConflictNotes = resolve; });
            }
            // Hold only the old valid conflict-refetch HTTP response. The
            // original Save-edit act closes before any decrypt reaction can
            // invoke Retry, and every exported/API Promise stays unchanged.
            if (options.retiredEditConflict === "after-latest-decrypt" && conflicted && !latestConflictNotesArrived) {
              latestConflictNotesArrived = true;
              if (!closed) await new Promise<void>(resolve => { releaseLatestConflictNotes = resolve; });
            }
            if (options.retiredEditConflict === "failed-refetch" && conflicted && !editRefetchArrived) {
              editRefetchArrived = true;
              if (!closed) await new Promise<void>(resolve => { releaseEditRefetch = resolve; });
              editRefetchResponseSent = true; status = 503;
              value = { detail: "old conflict refetch temporarily unavailable", code: "native_retired_conflict_refetch_unavailable" };
            } else value = terminalConflictSnapshot ? [] : rows.slice(offset, offset + 100);
            headers["X-Notes-Revision"] = revision;
            if (offset + 100 < rows.length) headers["X-Next-Offset"] = String(offset + 100);
          }
        } else if (path === `/api/v1/therapist/notes/${account.target.id}` && request.method === "PATCH") {
          if (typeof parsed.blob !== "string") throw setup("PATCH lacks encrypted note blob");
          const aad = ["note", OWNER, account.patient.user_id, account.target.client_note_id], plain = open(account.noteKey, aad, parsed.blob);
          try { const payload = JSON.parse(plain.toString("utf8")) as { v: number; text: string }; if (payload.v !== 1 || payload.text !== MINE) throw setup("independently opened PATCH differs from public mine"); patchBodies.push({ plaintext: payload.text, baseVersion: parsed.base_version, aad }); }
          finally { plain.fill(0); }
          if (options.retiredEditConflict) {
            editPatchArrived = true;
            if (options.retiredEditConflict === "before-refetch" && !closed) await new Promise<void>(resolve => { releaseEditPatch = resolve; });
            editPatchResponseSent = true; conflicted = true; status = 409;
            value = { detail: "note version conflict", code: "version_conflict" };
          } else if (options.conflict && !conflicted) { conflicted = true; status = 409; value = { detail: "note version conflict", code: "version_conflict" }; }
          else if (parsed.base_version !== 5) { status = 409; value = { detail: "note version conflict", code: "version_conflict" }; }
          else value = { ...account.winning, blob: parsed.blob, version: 6 };
        } else if (path.endsWith(`/audio/${ATTACHMENT}`)) {
          audioArrived = true; if (options.holdAudio && !closed) await new Promise<void>(resolve => { releaseAudio = resolve; }); value = account.audio;
        } else if (path === "/api/v1/auth/logout") { status = 204; value = undefined; }
        else throw setup(`unsupported native route: ${path}`);
      }
      response.writeHead(status, headers); response.end(value === undefined ? undefined : JSON.stringify(value));
    })(); handlers.push(originalHandler);
    if (options.retiredSasDigest && request.url?.split("?")[0] === "/api/v1/therapist/pairing/sas") sasHandlers.add(originalHandler);
    void originalHandler.catch(error => { faults.push(error); if (!response.headersSent) response.writeHead(500); response.end(); });
  });
  let origin = "";
  server.on("error", error => faults.push(error));
  let repeatedSasCleanupStarted = false;
  let repeatedSasFinish: Promise<void> | undefined;
  function finishPendingRepeatedSas(): Promise<void> {
    if (!options.repeatedSas) throw setup("repeated current SAS fixture was not selected");
    if (repeatedSasFinish) return repeatedSasFinish;
    // Mark before release: a genuine second HTTP handler that arrives while
    // cleanup is draining must never create a new held gate.
    repeatedSasCleanupStarted = true;
    sasReleased = true;
    releaseSas?.();
    const original = (async () => {
      for (;;) {
        const census = [sasOriginals.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
        await act(async () => {
          await strictDrain("identical original current SAS API Promises before App retirement", sasOriginals);
          await strictDrain("all original repeated SAS dependencies before App retirement", [...fetches, ...handlers, ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
        });
        const after = [sasOriginals.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
        if (census.every((count, index) => count === after[index])) break;
      }
      if (!hasSession()) throw setup("pending repeated SAS cleanup lost its live authenticated owner");
      clean();
    })();
    repeatedSasFinish = original;
    return original;
  }
  async function drainNative205Dependencies() {
    for (;;) {
      const census = [fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length, native205PatientsOriginals.length, native205JsonOriginals.length, native205Observers.length];
      await act(async () => {
        const nativeJsonCount = native205JsonOriginals.length;
        const originals: Promise<unknown>[] = [...native205JsonOriginals, ...native205PatientsOriginals];
        const settled = await finite("exact original native205 JSON and exported patients rejection", Promise.allSettled(originals));
        for (let index = 0; index < settled.length; index += 1) {
          const row = settled[index]!;
          const exactNative = index < nativeJsonCount;
          const expected = exactNative ? native205JsonError : native205PatientsError;
          if (row.status !== "rejected" || row.reason !== expected || expected === undefined) throw setup("native205 original rejection identity or completion differs");
        }
        await strictDrain("native205 observers and all original public/native dependencies", [...native205Observers, ...fetches, ...handlers, ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
      });
      const after = [fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length, native205PatientsOriginals.length, native205JsonOriginals.length, native205Observers.length];
      if (census.every((count, index) => count === after[index])) break;
    }
    clean();
  }
  function finishPendingNative205Patients(): Promise<void> {
    if (!options.native205Patients) throw setup("native205 patients fixture was not selected");
    if (native205Finish) return native205Finish;
    // Set before releasing: an already dispatched HTTP handler that arrives
    // during cleanup must not create another held gate.
    native205CleanupStarted = true; releaseNative205?.();
    const original = (async () => {
      if (!native205Armed) return;
      await drainNative205Dependencies();
      if (native205ResponseCount !== 1 || native205JsonOriginals.length !== 1 || native205PatientsOriginals.length !== 1 || native205Signouts !== 1 || !(native205JsonError instanceof SyntaxError) || native205JsonError.constructor !== SyntaxError || hasSession()) throw setup("native205 exact native error/public signout control incomplete");
      // Both literal outcomes are owned for retirement. Only the assertion
      // in the existing test body decides whether the API preserved identity.
      if (native205PatientsError !== native205JsonError && !(native205PatientsError instanceof ApiError && native205PatientsError.constructor === ApiError && native205PatientsError.status === 0 && native205PatientsError.message === "session ended")) throw setup("unexpected original patients rejection after native205 signout", native205PatientsError);
      clean();
    })();
    native205Finish = original; return original;
  }
  async function retire() {
    if (closed) return;
    const cleanupFaults: unknown[] = [];
    if (options.native205Patients && native205Armed) try { await finishPendingNative205Patients(); } catch (error) { cleanupFaults.push(error); }
    closed = true; releaseAudio?.(); releaseFirstNotes?.(); releaseFirstMeasures?.(); releaseEditPatch?.(); releaseEditRefetch?.(); releaseLatestConflictNotes?.(); releaseTerminalConflictNotes?.(); releaseSas?.(); releaseNative205?.();
    if (options.retryEvidence) {
      try { await finishRetryA(); } catch (error) { cleanupFaults.push(error); releaseRetryA?.(); }
      try { await finishRetryB(); } catch (error) { cleanupFaults.push(error); releaseRetryB?.(); }
    }
    try { await act(async () => root?.unmount()); root = undefined; }
    catch (error) { cleanupFaults.push(error); }
    const cleanup = async (work: () => Promise<unknown>): Promise<void> => { try { await work(); } catch (error) { cleanupFaults.push(error); } };
    await cleanup(() => finite("durable encrypted draft cleanup", drainPortalDraftWritesForTests()));
    // Earlier playback awaits register the next original producer before
    // these sequential drains resume. Retire that chain in causal order.
    await cleanup(() => strictDrain("original exported patient key unwraps", publicKeyUnwraps));
    await cleanup(() => strictDrain("original public audio API completion", audioOriginals));
    await cleanup(() => strictDrain("original exported audio decrypt completion", publicAudioDecrypts));
    await cleanup(() => strictDrain("original public evidence API completion", retryEntries));
    await cleanup(() => strictDrain("original public entry decrypt completion", retryDecrypts));
    await cleanup(drainNotesAndEditProducers);
    await cleanup(() => strictDrain("exact original held SAS API completion", sasOriginals));
    await cleanup(drainMeasureProducers);
    await cleanup(() => strictDrain("original native HTTP handlers", handlers));
    await cleanup(() => strictDrain("original native fetch/body/crypto/Blob producers", [...fetches, ...bodyOriginals, ...decrypts, ...nativeOriginals, ...reads]));
    try {
      // getItem retains its exact original rejection; the sole authored read
      // abort is admitted by object identity in its observer, never by message.
      await finite("original durable storage completion", Promise.allSettled(storageOriginals));
      clean();
    }
    catch (error) { cleanupFaults.push(error); }
    try { server.closeAllConnections(); await finite("owned HTTP close", new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))); }
    catch (error) { cleanupFaults.push(error); }
    try {
      for (const database of databases) database.close();
      await finite("owned IDB database retirement", new Promise<void>((resolve, reject) => {
        const original = factory.deleteDatabase("mindpattern-portal");
        original.onsuccess = () => resolve(); original.onerror = () => reject(original.error); original.onblocked = () => reject(setup("owned IDB retirement blocked"));
      }));
    } catch (error) { cleanupFaults.push(error); }
    const restoration = (work: () => void) => { try { work(); } catch (error) { cleanupFaults.push(error); } };
    restoration(() => restoreEntryDecryptObserver?.()); restoration(() => restore(api, "patientEntries", entryDescriptor));
    restoration(() => restoreNoteDecryptObserver?.()); restoration(() => restore(api, "notes", notesDescriptor));
    restoration(() => restoreMeasureDecryptObserver?.()); restoration(() => restore(api, "patientMeasures", measuresDescriptor));
    restoration(() => restore(api, "updateNote", editDescriptor));
    restoration(() => restore(api, "pairingSas", sasDescriptor));
    restoration(() => restore(api, "patients", patientsDescriptor));
    restoration(() => restorePublicAudioObserver?.()); restoration(() => restorePublicKeyObserver?.());
    restoration(() => restore(api, "patientAudio", audioDescriptor)); restoration(() => restore(subtle, "decrypt", decryptDescriptor));
    restoration(() => restore(URL, "createObjectURL", createDescriptor)); restoration(() => restore(URL, "revokeObjectURL", revokeDescriptor));
    for (const [name, descriptor] of cryptoDescriptors) restoration(() => restore(subtle, name, descriptor));
    for (const [name, descriptor] of bodyDescriptors) restoration(() => restore(Response.prototype, name, descriptor));
    for (const [name, descriptor] of storageDescriptors) restoration(() => restore(kv, name, descriptor));
    restoration(() => { IDBObjectStore.prototype.get = originalGet; }); restoration(() => restore(globalThis, "fetch", oldFetch));
    restoration(() => restore(globalThis, "indexedDB", oldIdb)); restoration(() => restore(globalThis, "window", oldWindow));
    restoration(() => setKvBackendForTests(null)); restoration(resetKvConnectionForTests); restoration(clearSession); account.noteKey.fill(0);
    // Observer-held synthetic native keys are wiped only after the public assertions and original-producer retirement.
    for (const key of keyUnwrapResults) key.fill(0);
    for (const record of urls.values()) if (record.active) cleanupFaults.push(setup("native Blob URL owner survived fixture cleanup"));
    if (faults.length || cleanupFaults.length) throw setup("owned cleanup/native producer failed", faults[0] ?? cleanupFaults[0]);
  }
  try {
    clearSession(); setKvBackendForTests(null); resetKvConnectionForTests(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = "";
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, writable: true, value: factory });
    await kv.setItem(`portal.draft.${OWNER}.${account.patient.user_id}`, account.draft);
    IDBObjectStore.prototype.get = function (...args: Parameters<IDBObjectStore["get"]>) {
      const original = originalGet.apply(this, args);
      if (abortRead && args[0] === `portal.draft.${OWNER}.${account.patient.user_id}`) {
        abortRead = false; const transaction = this.transaction;
        original.addEventListener("error", () => {
          const error = original.error;
          if (error instanceof DOMException && error.name === "AbortError") expectedReadError = error;
          else faults.push(setup("authored native draft abort did not produce its exact AbortError", error));
        });
        queueMicrotask(() => { try { transaction.abort(); } catch (error) { faults.push(error); } });
      }
      return original;
    };
    if (options.native205Patients) {
      Object.defineProperty(api, "patients", { ...patientsDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.patients>) {
        const original = originalPatients.apply(this, args);
        if (native205Armed) {
          native205PatientsOriginals.push(original);
          const observer = original.then(() => { faults.push(setup("native205 patients unexpectedly fulfilled")); }, error => { native205PatientsError = error; });
          native205Observers.push(observer);
        }
        return original;
      } });
    }
    if (options.retiredSasDigest || options.repeatedSas) {
      Object.defineProperty(api, "pairingSas", { ...sasDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.pairingSas>) {
        const original = originalSas.apply(this, args); sasOriginals.push(original);
        void original.then(() => undefined, error => { faults.push(error); }); return original;
      } });
    }
    if (options.retryEvidence) {
      const entryObserver = vi.spyOn(portalCrypto, "decryptEntry");
      restoreEntryDecryptObserver = () => entryObserver.mockRestore();
      entryObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.decryptEntry>) {
        const original = originalEntryDecrypt.apply(this, args); retryDecrypts.push(original);
        void original.then(() => undefined, error => { faults.push(error); }); return original;
      });
      Object.defineProperty(api, "patientEntries", { ...entryDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.patientEntries>) {
        const original = originalEntries.apply(this, args); retryEntries.push(original);
        void original.then(() => undefined, error => { faults.push(error); }); return original;
      } });
    }
    if (options.retiredEditConflict) {
      Object.defineProperty(api, "updateNote", { ...editDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.updateNote>) {
        const original = originalEdit.apply(this, args); editOriginals.push(original);
        void original.then(() => undefined, error => {
          if (editPatchResponseSent && args[0] === account.target.id && error instanceof ApiError && error.status === 409 && error.code === "version_conflict") authoredEditErrors.add(error);
          else faults.push(error);
        }); return original;
      } });
    }
    if (options.retiredNotesPagination || options.retiredEditConflict || options.retiredInitialNotesDecrypt || options.retiredSinglePageNotes) {
      Object.defineProperty(api, "notes", { ...notesDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.notes>) {
        const original = originalNotes.apply(this, args); noteOriginals.push(original);
        if (options.retiredEditConflict === "after-terminal-refetch" && editPatchResponseSent && !terminalConflictOriginal && args[0] === account.patient.user_id) {
          terminalConflictOriginal = original;
          // Registered before loadPatientNotes awaits this identical original.
          // On fulfillment this prereaction queues exactly one public Retry.
          // The already-queued API-await reaction runs559 first and returns
          // non-null terminal[]. Retry then runs before loadStableCollection's
          // await/adoption can resume the outer1245 caller. This is an input
          // schedule derived from the actual await graph, not a turn oracle.
          void original.then(() => {
            if (!terminalConflictRetryArmed || closed) return;
            terminalConflictRetryArmed = false;
            queueMicrotask(() => {
              if (closed) return;
              try {
                const current = button("Retry loading this patient");
                if (current.props.disabled) throw setup("current public Retry disabled after terminal conflict response");
                collectLatestConflictCommits = true;
                act(() => { current.props.onClick({ preventDefault() {} }); });
                terminalConflictRetryStarted = true;
              } catch (error) { faults.push(error); }
            });
          }, error => { faults.push(error); });
        }
        void original.then(() => undefined, error => {
          if (editRefetchResponseSent && args[0] === account.patient.user_id && error instanceof ApiError && error.status === 503 && error.code === "native_retired_conflict_refetch_unavailable") authoredEditErrors.add(error);
          else faults.push(error);
        }); return original;
      } });
    }
    if (options.retiredNotesPagination || options.retiredInitialNotesDecrypt || options.retiredSinglePageNotes || options.retiredEditConflict === "after-latest-decrypt" || options.retiredEditConflict === "after-terminal-refetch") {
      const noteObserver = vi.spyOn(portalCrypto, "decryptNoteAny");
      restoreNoteDecryptObserver = () => noteObserver.mockRestore();
      noteObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.decryptNoteAny>) {
        const original = originalNoteDecrypt.apply(this, args);
        const observed = { clientNoteId: args[4], blob: args[5], original, settled: false }; noteDecrypts.push(observed);
        // This reaction is registered before the caller receives the same
        // exported Promise. Retire through its current public Retry control
        // only after this original authenticated first-row decrypt succeeds.
        void original.then(() => {
          observed.settled = true;
          if (options.retiredInitialNotesDecrypt && initialNoteRetryArmed && !closed && args[5] === account.notes[0]!.blob) {
            initialNoteRetryArmed = false;
            try {
              const current = button("Retry loading this patient");
              if (current.props.disabled) throw setup("current public Retry became disabled before initial note decrypt settled");
              collectInitialNoteCommits = true;
              act(() => { current.props.onClick({ preventDefault() {} }); });
              initialNoteRetryStarted = true;
            } catch (error) { faults.push(error); }
          }
          if (options.retiredEditConflict === "after-latest-decrypt" && latestConflictRetryArmed && editPatchResponseSent && !closed
            && args[2] === OWNER && args[3] === account.patient.user_id && args[4] === account.target.client_note_id && args[5] === account.winning.blob) {
            // This exact first winning-note original belongs to the old409
            // refetch: current Retry has not started yet. Registering here
            // precedes saveNoteEdit's await reaction on this identical Promise.
            latestConflictRetryArmed = false;
            try {
              const current = button("Retry loading this patient");
              if (current.props.disabled) throw setup("current public Retry disabled at latest conflict decrypt completion");
              collectLatestConflictCommits = true;
              act(() => { current.props.onClick({ preventDefault() {} }); });
              latestConflictRetryStarted = true;
            } catch (error) { faults.push(error); }
          }
        }, error => { observed.settled = true; faults.push(error); }); return original;
      });
    }
    if (options.retiredMeasures || options.nativeMeasures) {
      Object.defineProperty(api, "patientMeasures", { ...measuresDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.patientMeasures>) {
        const original = originalMeasures.apply(this, args); measureOriginals.push(original);
        void original.then(() => undefined, error => { faults.push(error); }); return original;
      } });
      const measureObserver = vi.spyOn(portalCrypto, "decryptMeasure");
      restoreMeasureDecryptObserver = () => measureObserver.mockRestore();
      measureObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.decryptMeasure>) {
        const original = originalMeasureDecrypt.apply(this, args); measureDecrypts.push({ blob: args[2].blob, original });
        void original.then(() => undefined, error => { faults.push(error); }); return original;
      });
    }
    const publicAudioObserver = vi.spyOn(portalCrypto, "decryptAudio");
    restorePublicAudioObserver = () => { publicAudioObserver.mockRestore(); };
    publicAudioObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.decryptAudio>) {
      const original = originalPublicAudioDecrypt.apply(this, args);
      publicAudioDecrypts.push(original); void original.then(() => undefined, error => { faults.push(error); });
      return original;
    });
    const publicKeyObserver = vi.spyOn(portalCrypto, "unwrapPatientDataKey");
    restorePublicKeyObserver = () => { publicKeyObserver.mockRestore(); };
    publicKeyObserver.mockImplementation(function (this: unknown, ...args: Parameters<typeof portalCrypto.unwrapPatientDataKey>) {
      const original = originalPublicKeyUnwrap.apply(this, args);
      publicKeyUnwraps.push(original); void original.then(value => { keyUnwrapResults.push(value); }, error => { faults.push(error); });
      return original;
    });
    Object.defineProperty(api, "patientAudio", { ...audioDescriptor, value: function (this: unknown, ...args: Parameters<typeof api.patientAudio>) { const original = originalAudio.apply(this, args); audioOriginals.push(original); void original.then(() => undefined, error => { faults.push(error); }); return original; } });
    for (const name of ["importKey", "deriveBits", "encrypt", "digest"] as const) {
      const originalMethod = subtle[name], descriptor = Object.getOwnPropertyDescriptor(subtle, name);
      cryptoDescriptors.set(name, descriptor);
      Object.defineProperty(subtle, name, { configurable: true, writable: true, value: function (this: SubtleCrypto, ...args: unknown[]) {
        if (options.retiredSasDigest && sasRetired && name === "digest" && args[0] === "SHA-256") {
          const input = args[1];
          const bytes = ArrayBuffer.isView(input) ? Buffer.from(input.buffer, input.byteOffset, input.byteLength) : input instanceof ArrayBuffer ? Buffer.from(input) : null;
          if (bytes?.equals(Buffer.from(account.publicKey, "base64"))) retiredSasDigestAdmissions.push({ algorithm: "SHA-256", publicSpkiBase64: bytes.toString("base64") });
        }
        let original: Promise<unknown>;
        try { original = Reflect.apply(originalMethod, this, args) as Promise<unknown>; }
        catch (error) { faults.push(error); throw error; }
        if (options.repeatedSas && name === "digest" && args[0] === "SHA-256") {
          const input = args[1];
          const bytes = ArrayBuffer.isView(input) ? Buffer.from(input.buffer, input.byteOffset, input.byteLength) : input instanceof ArrayBuffer ? Buffer.from(input) : null;
          if (bytes?.equals(Buffer.from(account.publicKey, "base64"))) repeatedSasDigestAdmissions.push({ algorithm: "SHA-256", publicSpkiBase64: bytes.toString("base64"), original });
        }
        nativeOriginals.push(original); void original.then(() => undefined, error => { faults.push(error); }); return original;
      } });
    }
    for (const name of ["json", "text"] as const) {
      const originalMethod = Response.prototype[name]; bodyDescriptors.set(name, Object.getOwnPropertyDescriptor(Response.prototype, name));
      Object.defineProperty(Response.prototype, name, { configurable: true, writable: true, value: function (this: Response, ...args: unknown[]) {
        let original: Promise<unknown>;
        try { original = Reflect.apply(originalMethod, this, args) as Promise<unknown>; }
        catch (error) { if (ownedResponses.has(this)) faults.push(error); throw error; }
        if (options.native205Patients && name === "json" && native205Responses.has(this)) {
          native205JsonOriginals.push(original);
          // Register before fetchWithTimeout receives this identical original
          // Promise. Its wrapped-body rejection reaction registers afterward.
          const observer = original.then(() => { faults.push(setup("native205 native JSON unexpectedly fulfilled")); }, error => {
            try {
              if (!(error instanceof SyntaxError) || error.constructor !== SyntaxError || native205JsonError !== undefined || !native205BackActClosed || native205Signouts !== 0 || !hasSession()) throw setup("native205 rejection lacks its unique current public owner", error);
              native205JsonError = error;
              const signouts = root!.root.findAllByType("button").filter(node => nodeText(node) === "Sign out");
              if (signouts.length !== 1) throw setup("native205 unique current public Sign out missing");
              const signout = signouts[0]!;
              if (signout.props.disabled || typeof signout.props.onClick !== "function") throw setup("native205 enabled current public Sign out missing");
              act(() => { signout.props.onClick({ preventDefault() {} }); });
              native205Signouts += 1;
              if (hasSession()) throw setup("native205 public Sign out did not synchronously retire the API owner");
            } catch (error) { faults.push(error); }
          });
          native205Observers.push(observer);
        } else if (ownedResponses.has(this)) { bodyOriginals.push(original); void original.then(() => undefined, error => { faults.push(error); }); }
        return original;
      } });
    }
    for (const name of ["getItem", "setItem", "removeItem", "multiRemove", "keys"] as const) {
      const originalMethod = kv[name]; storageDescriptors.set(name, Object.getOwnPropertyDescriptor(kv, name));
      Object.defineProperty(kv, name, { configurable: true, writable: true, value: function (this: typeof kv, ...args: unknown[]) {
        let original: Promise<unknown>;
        try { original = Reflect.apply(originalMethod, this, args) as Promise<unknown>; }
        catch (error) { faults.push(error); throw error; }
        storageOriginals.push(original);
        void original.then(() => undefined, error => {
          if (name === "getItem" && args[0] === `portal.draft.${OWNER}.${account.patient.user_id}` && !expectedReadRefusalObserved
            && expectedReadError !== null && error instanceof StorageReadError && error.constructor === StorageReadError && error.cause === expectedReadError) expectedReadRefusalObserved = true;
          else faults.push(error);
        });
        return original;
      } });
    }
    Object.defineProperty(subtle, "decrypt", { configurable: true, writable: true, value: (...args: Parameters<SubtleCrypto["decrypt"]>) => {
      const original = originalDecrypt.apply(subtle, args); decrypts.push(original);
      // Observe the genuine native admission using all authenticated wire parts.
      // Preserve the original Promise and never retain a patient key or plaintext.
      const algorithm = args[0];
      if (typeof algorithm === "object" && algorithm.name === "AES-GCM") {
        const gcm = algorithm as AesGcmParams;
        if (gcm.additionalData !== undefined && observedBytes(gcm.iv).equals(audioEnvelope.subarray(0, 12))
          && observedBytes(args[2]).equals(audioEnvelope.subarray(12)) && observedBytes(gcm.additionalData).equals(audioAad)) audioCiphertextDecryptAdmissions.push(original);
      }
      void original.catch(error => faults.push(error)); return original;
    } });
    Object.defineProperty(URL, "createObjectURL", { ...createDescriptor, value: (blob: Blob) => {
      let original: string;
      try { original = nativeCreate.call(URL, blob); } catch (error) { faults.push(error); throw error; }
      const record = { active: true, digest: null as string | null }; urls.set(original, record);
      const reading = blob.arrayBuffer(); reads.push(reading); void reading.then(bytes => { const ownedBytes = Buffer.from(bytes); try { record.digest = createHash("sha256").update(ownedBytes).digest("hex"); } finally { ownedBytes.fill(0); } }, error => { faults.push(error); }).catch(error => { faults.push(error); }); return original;
    } });
    Object.defineProperty(URL, "revokeObjectURL", { ...revokeDescriptor, value: (url: string) => { let result: void; try { result = nativeRevoke.call(URL, url); } catch (error) { faults.push(error); throw error; } const record = urls.get(url); if (record) record.active = false; return result; } });
    await finite("owned native HTTP listen", new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }));
    const address = server.address(); if (!address || typeof address === "string") throw setup("owned HTTP address missing"); origin = `http://127.0.0.1:${address.port}`;
    Object.defineProperty(globalThis, "window", { configurable: true, writable: true, value: { ...window, location: { ...window.location, origin } } });
    Object.defineProperty(globalThis, "fetch", { ...oldFetch, value: (request: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof request === "string" ? request : request instanceof URL ? request.href : request.url); if (url.origin !== origin) throw setup("native fetch origin not owned");
      if (options.retiredNotesPagination && url.pathname === `/api/v1/therapist/patients/${PATIENT}/notes`) {
        noteWireDispatches.push({ path: url.pathname, method: init?.method ?? (request instanceof Request ? request.method : "GET"), offset: url.searchParams.get("offset"), revision: url.searchParams.get("expected_revision") });
      }
      if (options.retiredEditConflict && retiredEditReleased && url.pathname === `/api/v1/therapist/patients/${account.patient.user_id}/notes`) {
        retiredEditNoteDispatches.push({ path: url.pathname, method: init?.method ?? (request instanceof Request ? request.method : "GET"), offset: url.searchParams.get("offset"), revision: url.searchParams.get("expected_revision") });
      }
      const original = nativeFetch(request, init); fetches.push(original);
      if (options.retiredSasDigest && url.pathname === "/api/v1/therapist/pairing/sas") sasFetches.add(original);
      void original.then(response => {
        ownedResponses.add(response);
        if (options.native205Patients && native205Armed && url.pathname === "/api/v1/therapist/patients") {
          native205ResponseCount += 1;
          if (!(response instanceof Response) || response.status !== 205 || response.ok !== true || response.body !== null || response.url !== url.href) faults.push(setup("native205 original HTTP Response differs"));
          else native205Responses.add(response);
        }
        if (response.json !== Response.prototype.json || response.text !== Response.prototype.text) faults.push(setup("owned native Response bypassed exact body observers"));
      }, error => { faults.push(error); }); return original;
    } });
    await act(async () => {
      root = RTR.create(options.retiredInitialNotesDecrypt || options.retiredEditConflict === "after-latest-decrypt" || options.retiredEditConflict === "after-terminal-refetch" ? <Profiler id="initial-notes-public-commits" onRender={() => {
        if (collectInitialNoteCommits && root && !closed) {
          try { initialNoteCommittedTexts.push(nodeText(root.root)); } catch (error) { faults.push(error); }
        }
        if (collectLatestConflictCommits && root && !closed) {
          try { latestConflictCommittedTexts.push(nodeText(root.root)); } catch (error) { faults.push(error); }
        }
      }}><App /></Profiler> : <App />);
    });
    await input("Username", USERNAME); await input("Password", PASSWORD); await press("Sign in");
    if (options.nullBackupCodesMfa) {
      await completed("public mandatory enrollment", () => text().includes("Set up two-factor authentication to continue") && text().includes("JBSWY3DPEHPK3PXP"));
    } else {
    await completed("public required MFA", () => text().includes("Verify code"));
    if (hasSession()) throw setup("password-only login adopted owner before MFA");
    await input("Authenticator code (or recovery code)", "123456"); await press("Verify code"); await completed("public authenticated caseload", () => hasSession() && text().includes("Synthetic native public patient"));
    await press("Open patterns"); await completed("public chart/notes", () => options.retiredEditConflict ? text().includes(SAVED_NOTE) && text().includes("Retry loading this patient") : options.retiredNotesPagination || options.retiredMeasures || options.retiredInitialNotesDecrypt || options.retiredSinglePageNotes ? text().includes("Retry loading this patient") : text().includes("See the evidence") && (options.retryEvidence ? text().includes("Retry loading this patient") : text().includes(SAVED_NOTE)));
    await completed("public encrypted draft settles", () => options.failFirstDraftRead ? text().includes("Local encrypted records could not be read") : composer().props.value === SAVED_DRAFT);
    if (options.failFirstDraftRead && !expectedReadRefusalObserved) throw setup("public draft refusal lacked its exact authored native read abort");
    }
    return { text, button, press, input, composer, requests, patchBodies, mfaEnableBodies, urls, keyUnwrapResults, audioCiphertextDecryptAdmissions, root: () => root!, account, clean, completed, retire,
      async beginNative205Patients() {
        if (!options.native205Patients || native205Armed) throw setup("native205 patients fixture unavailable or repeated");
        // Retire every initial chart producer before the public Back action;
        // the subsequent JSON rejection is the only admitted session race.
        await drainNative205Dependencies();
        if (!hasSession()) throw setup("native205 initial healthy chart has no current API owner");
        native205Armed = true;
        await press("Back to patients"); native205BackActClosed = true;
        await completed("original next caseload HTTP request held after public Back act", () => native205Arrived && releaseNative205 !== undefined && native205PatientsOriginals.length === 1);
        if (!hasSession()) throw setup("native205 pending caseload lost owner before native JSON");
      },
      finishPendingNative205Patients,
      native205Errors: () => ({ nativeError: native205JsonError, exportedError: native205PatientsError, signouts: native205Signouts }),
      async beginRepeatedSas() {
        if (!options.repeatedSas) throw setup("repeated current SAS fixture was not selected");
        await press("Back to patients");
        await completed("current caseload fingerprint and public navigation", () => root!.root.findAll(node => node.props["data-testid"] === "key-fingerprint").length === 1 && root!.root.findAllByType("button").some(node => nodeText(node) === "Open patterns" && node.props.disabled !== true));
        await press("Generate pairing code");
        await completed("genuine current native pairing code for repeated SAS", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-code").some(node => nodeText(node) === sasCode));
        await input("Patient's account id (shown in their app)", account.patient.user_id);
        firstRepeatedSasDigestStart = repeatedSasDigestAdmissions.length;
        await press("Show verification code");
        await completed("first genuine SAS and local fingerprint publicly verified", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-sas").some(node => nodeText(node) === "123456") && text().includes(`key id ${sasFingerprint}`) && !text().includes("KEY FINGERPRINT MISMATCH") && !text().includes("This portal could not compute the fingerprint") && root!.root.findAllByType("button").some(node => nodeText(node) === "Show verification code" && node.props.disabled !== true));
        if (repeatedSasCount !== 1 || sasOriginals.length !== 1 || !hasSession()) throw setup("first repeated SAS lost its actual native producer or authenticated owner");
        clean();
      },
      firstRepeatedSasDigestAdmissions: () => repeatedSasDigestAdmissions.slice(firstRepeatedSasDigestStart),
      async beginSecondHeldSas() {
        if (!options.repeatedSas || repeatedSasCount !== 1) throw setup("second current SAS requires the first genuine completion");
        await press("Show verification code");
        // The held real HTTP response, rather than a turn or sleep budget,
        // keeps this same tuple pending while its Checking commit is read.
        await completed("second original native SAS held under public Checking", () => repeatedSasCount === 2 && releaseSas !== undefined && sasOriginals.length === 2 && root!.root.findAllByType("button").some(node => nodeText(node) === "Checking…" && node.props.disabled === true));
        if (!hasSession()) throw setup("second current SAS changed authenticated owner");
        clean();
      },
      finishPendingRepeatedSas,
      async finishRepeatedSas() {
        if (!options.repeatedSas || repeatedSasCount !== 2 || sasOriginals.length !== 2 || !releaseSas) throw setup("second native SAS release lacks its original producer");
        await finishPendingRepeatedSas();
      },
      async beginHeldSas() {
        if (!options.retiredSasDigest) throw setup("SAS retirement fixture was not selected");
        await press("Back to patients");
        await completed("current caseload public fingerprint and enabled navigation", () => root!.root.findAll(node => node.props["data-testid"] === "key-fingerprint").length === 1 && root!.root.findAllByType("button").some(node => nodeText(node) === "Open patterns" && node.props.disabled !== true));
        await press("Generate pairing code");
        await completed("genuine current native pairing code", () => root!.root.findAll(node => node.props["data-testid"] === "pairing-code").some(node => nodeText(node) === sasCode));
        await input("Patient's account id (shown in their app)", account.patient.user_id);
        await press("Show verification code");
        await completed("held original current native SAS request", () => sasArrived && releaseSas !== undefined && sasOriginals.length === 1);
      },
      async retireSasThroughPatterns(editBeforeRetirement: boolean) {
        if (!sasArrived || sasReleased) throw setup("SAS response is not held during public retirement");
        if (editBeforeRetirement) await input("Patient's account id (shown in their app)", "11111111111111111111111111111111");
        await press("Open patterns");
        sasRetired = true;
        await completed("current authenticated chart and restored local draft", () => text().includes("See the evidence") && text().includes(SAVED_NOTE) && composer().props.value === SAVED_DRAFT);
        // Exclude only the one genuinely held SAS request. The changing
        // producer census, rather than a Promise-turn budget, owns late work.
        for (;;) {
          const snapshot = [fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          await act(async () => {
            await strictDrain("all non-held native chart producers", [...fetches.filter(value => !sasFetches.has(value)), ...handlers.filter(value => !sasHandlers.has(value)), ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
          });
          const after = [fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          if (snapshot.every((count, index) => count === after[index])) break;
        }
        if (!hasSession()) throw setup("native SAS retirement lost the current authenticated session");
        clean();
      },
      async finishRetiredSas() {
        if (!sasRetired || sasOriginals.length !== 1 || !releaseSas) throw setup("retired original SAS completion lacks its producer");
        sasReleased = true; releaseSas();
        // showSas registered its await on this identical original public API
        // Promise before this fixture await. Its current-generation branch
        // admits the original fingerprint digest before our await resumes.
        await act(async () => { await finite("exact original retired SAS response", sasOriginals[0]!); });
        await strictDrain("all original native SAS fingerprint dependencies", [...nativeOriginals, ...bodyOriginals, ...fetches, ...handlers]);
        if (!hasSession()) throw setup("released SAS response changed authenticated owner custody");
        clean();
      },
      retiredSasDigestAdmissions: () => retiredSasDigestAdmissions,
      async finishKeyUnwraps() {
        await act(async () => { await strictDrain("exact original public patient-key unwrap settlement", publicKeyUnwraps); });
        await strictDrain("original native key-unwrap dependencies", [...nativeOriginals, ...decrypts]); clean();
      },
      async pressPatternEvidence(label: string) {
        const card = root!.root.findAllByType("section").find(node => node.findAllByType("h2").some(title => title.parent === node && nodeText(title) === label));
        const evidence = card?.findAllByType("button").find(node => nodeText(node) === "See the evidence");
        if (!evidence || evidence.props.disabled) throw setup("public named pattern evidence button missing or disabled");
        await act(async () => { evidence.props.onClick(); });
      },
      async retryEvidenceArrives(which: "earlier" | "current") { await completed("owned held native evidence request: " + which, () => which === "earlier" ? retryAArrived && releaseRetryA !== undefined : retryBArrived && releaseRetryB !== undefined); },
      finishRetiredRetryEvidence: finishRetryA,
      measureDecryptAdmissions: (blob: string) => measureDecrypts.filter(value => value.blob === blob).map(value => value.original),
      async measuresFirstPageArrives() { await completed("actual held original measures HTTP request", () => firstMeasuresArrived && releaseFirstMeasures !== undefined); },
      async finishRetiredMeasures() {
        if (!options.retiredMeasures || !releaseFirstMeasures || !measureOriginals[0]) throw setup("held original measures request missing");
        if (firstMeasuresFinished) throw setup("retired measures schedule cannot be repeated");
        releaseFirstMeasures();
        await drainMeasureProducers();
        await strictDrain("original retired measures native dependencies", [...bodyOriginals, ...nativeOriginals, ...decrypts]);
        firstMeasuresFinished = true; clean();
      },
      noteDecryptAdmissions: (blob: string) => noteDecrypts.filter(value => value.blob === blob).map(value => value.original),
      async finishRetiredTerminalNotes() {
        if (!options.retiredSinglePageNotes || !releaseFirstNotes || !noteOriginals[0]) throw setup("held original terminal notes request missing");
        if (terminalNotesFinished) throw setup("terminal notes schedule cannot be repeated");
        releaseFirstNotes();
        // Drain the same original API and exported crypto producer graph with
        // React's public act flush, repeating only when new originals appear.
        // No private load Promise, fixed microtask count, or fake decrypt is used.
        await drainNotesAndEditProducers();
        await strictDrain("original terminal notes native dependencies", [...bodyOriginals, ...nativeOriginals, ...decrypts]);
        terminalNotesFinished = true; clean();
      },
      initialNoteCommitTexts: () => [...initialNoteCommittedTexts],
      async finishInitialNotesThroughCurrentRetry() {
        if (!options.retiredInitialNotesDecrypt || !releaseFirstNotes || !noteOriginals[0]) throw setup("held original initial notes request missing");
        if (initialNoteDrainFinished) throw setup("initial notes schedule cannot be repeated");
        initialNoteRetryArmed = true; releaseFirstNotes();
        await completed("original first authenticated note decrypt admits current public Retry", () => initialNoteRetryStarted);
        // Own all genuine producers and React commits. Native scheduling of A
        // versus B is unrestricted; the public Profiler records either order.
        for (;;) {
          const census = [noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          await drainNotesAndEditProducers();
          await act(async () => {
            await strictDrain("all original initial and current notes native producers", [...fetches, ...handlers, ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
          });
          const after = [noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          if (census.every((count, index) => count === after[index])) break;
        }
        if (!noteDecrypts.some(value => value.blob === account.target.blob && value.settled)
          || !noteDecrypts.some(value => value.blob === account.winning.blob && value.settled)) throw setup("initial and replacement original authenticated note producers did not settle");
        initialNoteDrainFinished = true; clean();
      },
      latestConflictCommitTexts: () => [...latestConflictCommittedTexts],
      async finishTerminalConflictThroughCurrentRetry() {
        if (options.retiredEditConflict !== "after-terminal-refetch" || terminalConflictDrainFinished) throw setup("terminal conflict schedule missing or repeated");
        await completed("old valid terminal-empty conflict-refetch HTTP arrives after Save-edit act closes", () => terminalConflictNotesArrived && releaseTerminalConflictNotes !== undefined);
        if (!terminalConflictOriginal || !editPatchResponseSent || !editOriginals[0] || authoredEditErrors.size !== 1) throw setup("same original terminal conflict notes or PATCH409 producer missing");
        terminalConflictRetryArmed = true; releaseTerminalConflictNotes!();
        await completed("same original terminal notes completion queues current enabled public Retry", () => terminalConflictRetryStarted);
        for (;;) {
          const census = [editOriginals.length, noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          await drainNotesAndEditProducers();
          await act(async () => {
            await strictDrain("all original terminal-conflict and current Retry native producers", [...fetches, ...handlers, ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
          });
          const after = [editOriginals.length, noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          if (census.every((count, index) => count === after[index])) break;
        }
        // The old authenticated page was empty, so this genuine winning-note
        // decrypt belongs only to current Retry. No removed guard is inferred.
        if (noteDecrypts.filter(value => value.blob === account.winning.blob && value.settled).length !== 1) throw setup("current Retry original authenticated winning-note decrypt did not settle exactly once");
        terminalConflictDrainFinished = true; clean();
      },
      async finishLatestConflictDecryptThroughCurrentRetry() {
        if (options.retiredEditConflict !== "after-latest-decrypt" || latestConflictDrainFinished) throw setup("latest conflict decrypt schedule missing or repeated");
        await completed("old valid conflict-refetch HTTP arrives after Save-edit act closes", () => latestConflictNotesArrived && releaseLatestConflictNotes !== undefined);
        if (!editPatchResponseSent || !editOriginals[0] || authoredEditErrors.size !== 1) throw setup("original authenticated PATCH409 producer missing");
        latestConflictRetryArmed = true; releaseLatestConflictNotes!();
        await completed("original authenticated latest conflict decrypt invokes current public Retry", () => latestConflictRetryStarted);
        // All original HTTP/API/crypto/storage producers and public commits
        // settle in their actual order. No B-before-A or final-B predicate is
        // needed: the commit history retains an obsolete comparison warning.
        for (;;) {
          const census = [editOriginals.length, noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          await drainNotesAndEditProducers();
          await act(async () => {
            await strictDrain("all original latest-conflict and current Retry native producers", [...fetches, ...handlers, ...bodyOriginals, ...nativeOriginals, ...decrypts, ...storageOriginals, ...publicKeyUnwraps]);
          });
          const after = [editOriginals.length, noteOriginals.length, noteDecrypts.length, fetches.length, handlers.length, bodyOriginals.length, nativeOriginals.length, decrypts.length, storageOriginals.length, publicKeyUnwraps.length];
          if (census.every((count, index) => count === after[index])) break;
        }
        if (noteDecrypts.filter(value => value.blob === account.winning.blob && value.settled).length !== 2) throw setup("old conflict and current Retry original authenticated winning-note decrypts did not both settle");
        latestConflictDrainFinished = true; clean();
      },
      async notesFirstPageArrives() { await completed("actual held native notes first page", () => firstNotesArrived && releaseFirstNotes !== undefined); },
      finishHeldNotesFirstPage,
      retiredNoteDispatches: () => retiredNoteDispatches,
      async evidence() { await press("See the evidence"); await completed("public authenticated audio evidence", () => text().includes("Authenticated audio evidence") && text().includes("play recording")); },
      async finishAudio() {
        if (!audioOriginals[0]) throw setup("public audio original Promise not observed"); releaseAudio?.();
        await finite("exact original public patientAudio settlement", audioOriginals[0]);
        // The caller's API-await continuation was registered before this one.
        // It has now either returned at the staged generation fence or invoked
        // the observed original decryptAudio. Its exact exported Promise owns
        // the entire importKey→decrypt chain, including work not yet enqueued.
        // The caller's decrypt-await continuation is likewise registered first;
        // it synchronously creates or refuses the URL before our await resumes.
        await act(async () => { await strictDrain("exact original public decryptAudio completion", publicAudioDecrypts); });
        await strictDrain("original native body and cryptographic work", [...bodyOriginals, ...nativeOriginals, ...decrypts]);
        await strictDrain("original native Blob reads", reads); clean();
      },
      async audioArrives() { await completed("actual held native HTTP audio request", () => audioArrived && releaseAudio !== undefined); },
      async audioVisible() { await completed("actual public audio and independently matching Blob digest", () => root!.root.findAllByType("audio").length === 1 && [...urls.values()].some(record => record.active && record.digest === account.audioDigest)); },
      retiredEditNoteDispatches: () => retiredEditNoteDispatches,
      async retiredEditArrives() {
        if (options.retiredEditConflict === "before-refetch") await completed("actual held original PATCH409 response", () => editPatchArrived && releaseEditPatch !== undefined);
        else if (options.retiredEditConflict === "failed-refetch") await completed("actual admitted original conflict-refetch GET503 response", () => editRefetchArrived && releaseEditRefetch !== undefined);
        else throw setup("retired edit response route was not selected");
      },
      async currentRetryLoaded() {
        const expected = options.retiredEditConflict === "before-refetch" ? SAVED_NOTE : WINNING_NOTE;
        await completed("new current Retry commits its authenticated note and healthy chart", () => text().includes(expected) && text().includes("See the evidence") && !text().includes("Retry loading this patient"));
      },
      async finishRetiredEdit() {
        retiredEditReleased = true; releaseEditPatch?.(); releaseEditRefetch?.();
        // The current committed Save-edit control acknowledges the whole old
        // operation's finally, not a guessed number of Promise/React turns.
        await completed("old edit settles and current Save-edit is enabled", () => {
          const node = root?.root.findAllByType("button").find(value => nodeText(value) === "Save edit");
          return !!node && node.props.disabled !== true;
        });
        await drainNotesAndEditProducers(); clean();
      },
      async editTarget() {
        if (account.notes.length > 2) { const search = root!.root.findAllByType("input").find(node => node.props.placeholder === "Search notes…"); if (!search) throw setup("public notes filter missing"); await act(async () => search.props.onChange({ target: { value: SAVED_NOTE } })); }
        await press("Edit"); const area = root!.root.findAllByType("textarea").find(node => node.props.placeholder === "Editing note…"); if (!area) throw setup("public note edit field missing"); await act(async () => area.props.onChange({ target: { value: MINE } }));
        const search = root!.root.findAllByType("input").find(node => node.props.placeholder === "Search notes…");
        if (search) await act(async () => search.props.onChange({ target: { value: "" } }));
      },
    };
  } catch (error) { try { await retire(); } catch (cleanup) { throw setup("fixture setup and cleanup failed", { error, cleanup }); } throw error; }
}
