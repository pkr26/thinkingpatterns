/**
 * Portal crypto — the WebCrypto mirror of the backend's contracts
 * (backend/app/security/{kdf,sharing,crypto}.py), pinned byte-for-byte by
 * shared/vectors.json (see tests/crypto.test.ts).
 *
 * Key schedule (same as the patient apps, plus the two portal subkeys):
 *   master    = PBKDF2-HMAC-SHA256(password, salt, 600_000)
 *   auth_key  = HKDF-SHA256(master, salt=zeros, info="mindpattern/auth/v1")
 *   wrap_kek  = HKDF-SHA256(master, salt=zeros, info="mindpattern/portal-wrap/v1")
 *   note_key  = HKDF-SHA256(master, salt=zeros, info="mindpattern/portal-notes/v1")
 *
 * The wrap KEK opens the therapist's P-256 identity key. The v1 note key
 * is retained for legacy decryption; identity-derived v2 keys and the
 * active notes keyring preserve access across credential changes.
 * Patient data keys are unwrapped per patient and remain in session memory.
 */
import { buildAad } from "./aad";


const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto is unavailable in this browser");
  return c.subtle;
};

export const KDF_ITERATIONS = 600_000;
export const KEY_SIZE = 32;
/** Byte buffers are always ArrayBuffer-backed: WebCrypto's BufferSource
 * rejects the ArrayBufferLike default of a bare Uint8Array annotation. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** Best-effort erasure for buffers this module owns.  WebCrypto key handles
 * are deliberately non-extractable and cannot be overwritten; byte arrays
 * decoded, derived, or decrypted transiently can and must be. */
function zeroize(...buffers: Array<Uint8Array | null | undefined>): void {
  for (const buffer of buffers) buffer?.fill(0);
}

const AUTH_INFO = new TextEncoder().encode("mindpattern/auth/v1");
const PORTAL_WRAP_INFO = new TextEncoder().encode("mindpattern/portal-wrap/v1");
const PORTAL_NOTES_INFO = new TextEncoder().encode("mindpattern/portal-notes/v1");

/** Identity-derived note keys use the therapist's P-256 private key
 *  (HKDF over the P-256 private key), not the password. The private key's
 *  BYTES are unchanged by a password change (only their locker is
 *  re-wrapped), so notes — and every future revision — stay decryptable
 *  across password changes. The legacy password-derived label survives
 *  only for decrypting pre-migration blobs. */
const PORTAL_NOTES_INFO_V2 = new TextEncoder().encode("mindpattern/portal-notes/v2");

export async function noteKeyV2FromPrivateKey(pkcs8: Bytes): Promise<Bytes> {
  const key = await subtle().importKey("raw", pkcs8, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: PORTAL_NOTES_INFO_V2 },
    key,
    KEY_SIZE * 8,
  );
  return new Uint8Array(bits);
}
const WRAP_INFO = new TextEncoder().encode("mindpattern/wrap/v1");
/** HKDF salt for the master-key subkeys: RFC 5869 default (HashLen zeros),
 * matching backend kdf.hkdf_sha256(salt=None). */
const ZERO_SALT = new Uint8Array(32);

export const toBase64 = (bytes: Bytes): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

export const fromBase64 = (text: string): Bytes => {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
};

async function hkdf(ikm: BufferSource, salt: BufferSource, info: BufferSource, length: number): Promise<Bytes> {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

export async function deriveMasterKey(password: string, salt: Bytes): Promise<Bytes> {
  const key = await subtle().importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERATIONS },
    key,
    KEY_SIZE * 8,
  );
  return new Uint8Array(bits);
}

export async function derivePortalKeys(
  master: Bytes,
): Promise<{ authKey: Bytes; wrapKek: Bytes; noteKey: Bytes }> {
  const [authKey, wrapKek, noteKey] = await Promise.all([
    hkdf(master, ZERO_SALT, AUTH_INFO, KEY_SIZE),
    hkdf(master, ZERO_SALT, PORTAL_WRAP_INFO, KEY_SIZE),
    hkdf(master, ZERO_SALT, PORTAL_NOTES_INFO, KEY_SIZE),
  ]);
  // Audit fix P-1 (2026-09-20): the auth verifier is password-equivalent, so
  // it must not persist as an immutable base64 string on an object that
  // outlives the flow. It is returned as zeroizable raw bytes; callers derive
  // the base64 form only at the moment of the network send and wipe the raw
  // bytes right after.
  return { authKey, wrapKek, noteKey };
}

// --- AES-256-GCM envelope: nonce(12) || ct || tag — backend crypto.py ------

export const NONCE_SIZE = 12;
export const MIN_BLOB_SIZE = NONCE_SIZE + 16;

export class TamperError extends Error {
  constructor() {
    super("blob failed authentication");
    this.name = "TamperError";
  }
}

async function aesKey(raw: Bytes): Promise<CryptoKey> {
  return subtle().importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encrypt(key: Bytes, plaintext: Bytes, aad?: Bytes): Promise<Bytes> {
  if (key.length !== KEY_SIZE) throw new Error(`key must be ${KEY_SIZE} bytes`);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const cipher = await subtle().encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    await aesKey(key),
    plaintext,
  );
  // WebCrypto returns ct||tag — the backend envelope is nonce||ct||tag.
  const out = new Uint8Array(new ArrayBuffer(NONCE_SIZE + cipher.byteLength));
  out.set(nonce, 0);
  out.set(new Uint8Array(cipher), NONCE_SIZE);
  return out;
}

export async function decrypt(key: Bytes, blob: Bytes, aad?: Bytes): Promise<Bytes> {
  if (key.length !== KEY_SIZE) throw new Error(`key must be ${KEY_SIZE} bytes`);
  if (blob.length < MIN_BLOB_SIZE) throw new TamperError();
  try {
    const plain = await subtle().decrypt(
      {
        name: "AES-GCM",
        iv: blob.subarray(0, NONCE_SIZE),
        additionalData: aad,
      },
      await aesKey(key),
      blob.subarray(NONCE_SIZE),
    );
    return new Uint8Array(plain);
  } catch {
    throw new TamperError();
  }
}

// --- therapist key custody ---------------------------------------------------

export const THERAPIST_KEY_CONTEXT = "therapist-key";
export const NOTE_CONTEXT = "note";
export const WRAP_CONTEXT = "consent-wrap";
export const SUMMARY_CONTEXT = "caseload-summary";

/** Decrypt this therapist's stored P-256 private key (PKCS8 DER) with the
 * password-derived wrap KEK. AAD binds the key to the therapist's username,
 * so a blob served for another account cannot unlock here. */
export async function unlockWrapPrivateKey(
  wrapKek: Bytes,
  keyBlobB64: string,
  username: string,
): Promise<CryptoKey> {
  return (await unlockWrapPrivateKeyWithNotesKey(wrapKek, keyBlobB64, username)).privateKey;
}

/** unlockWrapPrivateKey + the v2 notes key, derived in the same instant the
 *  raw PKCS#8 exists (2026-10-01 audit C3): the session holds both, and
 *  the raw bytes still never outlive this call. */
export async function unlockWrapPrivateKeyWithNotesKey(
  wrapKek: Bytes,
  keyBlobB64: string,
  username: string,
): Promise<{ privateKey: CryptoKey; noteKeyV2: Bytes }> {
  let encrypted: Bytes | null = null;
  let pkcs8: Bytes | null = null;
  try {
    encrypted = fromBase64(keyBlobB64);
    pkcs8 = await decrypt(
      wrapKek,
      encrypted,
      buildAad(THERAPIST_KEY_CONTEXT, username),
    );
    const noteKeyV2 = await noteKeyV2FromPrivateKey(pkcs8);
    // `false` makes the resulting CryptoKey non-extractable. Once WebCrypto
    // owns that handle, the raw PKCS#8 copy must not stay in JS memory.
    const privateKey = await subtle().importKey(
      "pkcs8",
      pkcs8,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    return { privateKey, noteKeyV2 };
  } finally {
    zeroize(encrypted, pkcs8);
  }
}

/** The portal-side unwrap of a patient's data key: ECDH against the
 * consent's ephemeral public key, HKDF (salt = both SPKI DERs), AES-GCM
 * open — identical to backend sharing.unwrap_data_key. */
export async function unwrapPatientDataKey(
  therapistPrivateKey: CryptoKey,
  ephemeralPubSpkiB64: string,
  wrappedKeyB64: string,
  userId: string,
  therapistId: string,
  therapistPubSpkiB64: string,
): Promise<Bytes> {
  let ephDer: Bytes | null = null;
  let thDer: Bytes | null = null;
  let wrapped: Bytes | null = null;
  let salt: Bytes | null = null;
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  try {
    ephDer = fromBase64(ephemeralPubSpkiB64);
    thDer = fromBase64(therapistPubSpkiB64);
    wrapped = fromBase64(wrappedKeyB64);
    const ephPub = await subtle().importKey(
      "spki",
      ephDer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedBits = await subtle().deriveBits(
      { name: "ECDH", public: ephPub },
      therapistPrivateKey,
      256,
    );
    shared = new Uint8Array(sharedBits);
    salt = new Uint8Array(new ArrayBuffer(ephDer.length + thDer.length));
    salt.set(ephDer, 0);
    salt.set(thDer, ephDer.length);
    kek = await hkdf(shared, salt, WRAP_INFO, KEY_SIZE);
    return await decrypt(kek, wrapped, buildAad(WRAP_CONTEXT, userId, therapistId));
  } finally {
    // ephDer/thDer/salt are public inputs, while shared/kek are secret; wipe
    // all module-owned buffers to keep the simple lifecycle auditable. The
    // returned patient data key remains the caller's responsibility.
    zeroize(ephDer, thDer, wrapped, salt, shared, kek);
  }
}

// --- measures (MBC, 2026-09-19) --------------------------------------------------

export interface MeasureReading {
  measure: string;
  score: number;
  /** The RAW 0-3 response to the PHQ-9's item 9 (self-harm), when the
   *  payload carries one — clinical review 2026-09-27. Absent (undefined
   *  or null) for gad7/phq2 and for pre-field phq9 payloads, which render
   *  exactly as before; NEVER interpreted here beyond range validation. */
  item9?: number | null;
  completedAt: string | null;
  measureDate: string;
}

const MEASURE_LIMITS = {
  phq9: { maxScore: 27 },
  gad7: { maxScore: 21 },
  phq2: { maxScore: 6 },
} as const;

type KnownMeasure = keyof typeof MEASURE_LIMITS;

function knownMeasure(value: unknown): value is KnownMeasure {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(MEASURE_LIMITS, value);
}

/** Decrypt one patient-recorded measure blob. The payload is the patient's
 *  client contract: {"v":1,"measure":"phq9","score":N,"item9":R,
 *  "completed_at":ISO} — item9 rides phq9 only (an endorsed PHQ-9 item 9
 *  mandates clinical follow-up regardless of the total, so the raw item
 *  response travels beside the score; older payloads without it stay
 *  valid). Sanitized like every decrypted payload — wrong shapes degrade
 *  to null, never render. The portal DISPLAYS scores and surfaces the
 *  item-9 fact; it never interprets either. */
export async function decryptMeasure(
  dataKey: Bytes,
  userId: string,
  measure: { client_measure_id: string; blob: string; measure_date: string },
): Promise<MeasureReading | null> {
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = fromBase64(measure.blob);
    plain = await decrypt(
      dataKey,
      encrypted,
      buildAad("measure", userId, measure.client_measure_id),
    );
    const payload = decodeJson(plain) as Record<string, unknown>;
    // The current wire schema is exactly v1 and carries a validated score,
    // not the full response array. Item-count/per-item revalidation is
    // therefore unavailable at this trust boundary; strict instrument
    // identity, integer totals, and instrument ceilings are enforced here.
    // Unknown future schemas must not be interpreted with today's labels.
    if (payload.v !== 1 || !knownMeasure(payload.measure)) {
      return null;
    }
    const measureName = payload.measure;
    const score = payload.score;
    const limit = MEASURE_LIMITS[measureName];
    // Scores are sums of integer 0-3 item responses. Reject fractions and
    // enforce the instrument-specific ceiling; never clamp hostile data
    // into a clinically plausible-looking value.
    if (
      typeof score !== "number"
      || !Number.isInteger(score)
      || score < 0
      || score > limit.maxScore
    ) {
      return null;
    }
    // item9 (2026-09-27): parsed ONLY for phq9, and only as an integer
    // 0-3 — anything else (a gad7 carrying the field, a 7, a string, a
    // negative) is not a fact this portal may render, so it reads as
    // absent. For PHQ-9, a PRESENT malformed item9 invalidates the whole
    // row: selectively dropping a self-harm response while retaining its
    // total would create a dangerously incomplete clinical display.
    const rawItem9 = payload.item9;
    if (
      rawItem9 !== undefined
      && (measureName !== "phq9"
        || typeof rawItem9 !== "number"
        || !Number.isInteger(rawItem9)
        || rawItem9 < 0
        || rawItem9 > 3)
    ) return null;
    const item9 = measureName === "phq9" && typeof rawItem9 === "number" ? rawItem9 : null;
    return {
      measure: measureName,
      score: Math.round(score),
      item9,
      completedAt:
        typeof payload.completed_at === "string" ? payload.completed_at.slice(0, 10) : null,
      measureDate: measure.measure_date.slice(0, 10),
    };
  } catch {
    return null;
  } finally {
    zeroize(encrypted, plain);
  }
}

// --- caseload summaries --------------------------------------------------------

export interface CaseloadSummary {
  patterns: number;
  sensitive: boolean;
  newest: string | null;
  forDate: string | null;
}

/** The portal-side open of a per-consent caseload summary — the exact
 * construction unwrapPatientDataKey uses (ECDH against the summary's
 * ephemeral key, HKDF salted by both SPKI DERs, AES-GCM), with the AAD
 * context "caseload-summary" separating the role from the data-key wrap.
 * The server writes these at each patient recompute; triaging decrypts N
 * small blobs instead of N full insight blobs. Output is sanitized like
 * every decrypted payload: wrong shapes degrade to null, never render. */
export async function decryptCaseloadSummary(
  therapistPrivateKey: CryptoKey,
  therapistPubSpkiB64: string,
  ephemeralPubSpkiB64: string,
  summaryBlobB64: string,
  userId: string,
  therapistId: string,
): Promise<CaseloadSummary | null> {
  let ephDer: Bytes | null = null;
  let thDer: Bytes | null = null;
  let wrapped: Bytes | null = null;
  let salt: Bytes | null = null;
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    ephDer = fromBase64(ephemeralPubSpkiB64);
    thDer = fromBase64(therapistPubSpkiB64);
    wrapped = fromBase64(summaryBlobB64);
    const ephPub = await subtle().importKey(
      "spki",
      ephDer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedBits = await subtle().deriveBits(
      { name: "ECDH", public: ephPub },
      therapistPrivateKey,
      256,
    );
    shared = new Uint8Array(sharedBits);
    salt = new Uint8Array(new ArrayBuffer(ephDer.length + thDer.length));
    salt.set(ephDer, 0);
    salt.set(thDer, ephDer.length);
    kek = await hkdf(shared, salt, WRAP_INFO, KEY_SIZE);
    plain = await decrypt(
      kek,
      wrapped,
      buildAad(SUMMARY_CONTEXT, userId, therapistId),
    );
    const parsed = JSON.parse(new TextDecoder().decode(plain)) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    const raw = parsed as Record<string, unknown>;
    const patterns =
      typeof raw.patterns === "number" && Number.isFinite(raw.patterns)
        ? Math.max(0, Math.floor(raw.patterns))
        : 0;
    const newest = typeof raw.newest === "string" ? raw.newest.slice(0, 10) : null;
    const forDate = typeof raw.for_date === "string" ? raw.for_date.slice(0, 10) : null;
    return { patterns, sensitive: raw.sensitive === true, newest, forDate };
  } catch {
    // Tamper/relocation/wrong key: no summary, rendered as "—".
    return null;
  } finally {
    // The decrypted summary plaintext is zeroized like every sibling
    // decrypt (audit L-73): a caseload overview left in the heap after a
    // failed JSON.parse would be the one unscrubbed plaintext in the
    // module. ephDer/thDer/salt are public inputs; shared/kek are secret;
    // wipe all module-owned buffers to keep the lifecycle auditable.
    zeroize(ephDer, thDer, wrapped, salt, shared, kek, plain);
  }
}

// --- notes ---------------------------------------------------------------------

export interface NoteSealed {
  clientNoteId: string;
  blobB64: string;
}

export async function encryptNote(
  noteKey: Bytes,
  therapistId: string,
  userId: string,
  clientNoteId: string,
  text: string,
): Promise<NoteSealed> {
  const payload = new TextEncoder().encode(JSON.stringify({ v: 1, text })) as Bytes;
  try {
    const blob = await encrypt(
      noteKey,
      payload,
      buildAad(NOTE_CONTEXT, therapistId, userId, clientNoteId),
    );
    return { clientNoteId, blobB64: toBase64(blob) };
  } finally {
    zeroize(payload);
  }
}

/** Try the active notes key, then legacy and historical custody keys.
 * Credential changes rewrap the keyring while preserving existing note keys. */
export async function decryptNoteAny(
  noteKeyV2: Bytes,
  legacyNoteKey: Bytes,
  therapistId: string,
  userId: string,
  clientNoteId: string,
  blobB64: string,
  historicalKeys: Bytes[] = [],
): Promise<string> {
  for (const key of [noteKeyV2, legacyNoteKey, ...historicalKeys]) {
    try { return await decryptNote(key, therapistId, userId, clientNoteId, blobB64); } catch { /* try authenticated historical custody */ }
  }
  throw new Error("This note could not be authenticated with the account's notes custody. It was not changed.");
}

export async function decryptNote(
  noteKey: Bytes,
  therapistId: string,
  userId: string,
  clientNoteId: string,
  blobB64: string,
): Promise<string> {
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = fromBase64(blobB64);
    plain = await decrypt(
      noteKey,
      encrypted,
      buildAad(NOTE_CONTEXT, therapistId, userId, clientNoteId),
    );
    const payload = JSON.parse(new TextDecoder().decode(plain)) as { v?: number; text?: string };
    if (typeof payload.text !== "string") throw new Error("note payload malformed");
    return payload.text;
  } finally {
    zeroize(encrypted, plain);
  }
}

// --- shared payload decryption ---------------------------------------------------

/** 2026-10-01 audit M1: session-lifetime set of (userId:clientEntryId)
 *  pairs that authenticated under the version-bound v2 entry AAD. */
const v2BoundEntries = new Set<string>();

const decodeJson = (bytes: Uint8Array): unknown => JSON.parse(new TextDecoder().decode(bytes));

export interface MoodSummary {
  observations: number;
  explicit_mood: number;
  text_estimates: number;
  excluded_entries: number;
  source: "explicit_mood" | "text_estimate" | "mixed" | "unavailable";
}

export async function decryptInsights(
  dataKey: Bytes,
  userId: string,
  blobB64: string,
): Promise<{
  /** Analysis generation embedded INSIDE the encrypted payload (backend
   *  insights.py seals {"v":2,"state_seq":N,"stats":…}). The rollback-replay
   *  sentinel: PatientView checks it against the response's plaintext echo
   *  (2026-09-26 audit L). Absent on pre-2026-09-19 payloads — the guard
   *  treats absence as unverifiable and fails closed. */
  state_seq?: number;
  stats: {
    patterns: PatternPayload[];
    /** Aggregate account stats the backend already packs into the same
     *  blob (2026-09-17: the portal stopped discarding them). */
    avg_sentiment?: number | null;
    mood_summary?: MoodSummary;
    total_entries?: number;
    active_days?: number;
    first_date?: string;
    last_date?: string;
  };
}> {
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = fromBase64(blobB64);
    plain = await decrypt(dataKey, encrypted, buildAad("insights", userId, "patterns"));
    return validateInsights(decodeJson(plain)) as unknown as { state_seq?: number; stats: { patterns: PatternPayload[] } };
  } finally {
    zeroize(encrypted, plain);
  }
}

/** The only entry payload schema versions this portal understands — the
 *  web client's guard (web/src/crypto/patient.ts ENTRY_PAYLOAD_VERSIONS)
 *  mirrored (M-8b, audit 2026-09-29): v1 is the base shape, v2 the
 *  structured check-in channels, v3 the voice channels. An unknown
 *  version must throw LOUDLY, never be silently miscast as today's shape
 *  — a future v4 misread is how a schema roll corrupts the clinical
 *  chart with wrong-typed fields. */
export const ENTRY_PAYLOAD_VERSIONS: readonly number[] = [1, 2, 3];

export async function decryptEntry(
  dataKey: Bytes,
  userId: string,
  entry: { client_entry_id: string; blob: string; content_version?: number },
): Promise<{
  text: string;
  created_at?: string;
  sentiment?: number | null;
  /** Voice channels (payload v3, VOICE_PLAN 2026-09-29): absent on every
   *  pre-voice entry. */
  input_mode?: "typed" | "voice";
  transcript_lang?: string;
  english_text?: string | null;
}> {
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = fromBase64(entry.blob);
    // Deep-audit 2026-09-28 CRITICAL fix: since M-2 (2026-09-20) every
    // patient client writes entries under the four-part v2 AAD and the
    // server-side rekey upgrades every row to v2 — a v1-only attempt
    // failed GCM for every current entry, rendering the therapist
    // evidence drill-down permanently undecryptable. Mirror the server's
    // entry_aad_candidates order exactly: v2 first, legacy v1 fallback
    // for every generation (a legacy client's edit bumps content_version
    // while still sealing the legacy binding).
    const version =
      entry.content_version !== undefined &&
      Number.isSafeInteger(entry.content_version) &&
      entry.content_version >= 1
        ? entry.content_version
        : 1;
    const candidates = [
      buildAad("entry", userId, entry.client_entry_id, String(version)),
      buildAad("entry", userId, entry.client_entry_id),
    ];
    let failure: unknown = null;
    // 2026-10-01 audit M1: within this session, an id that has EVER
    // authenticated under the v2 binding may no longer use the legacy
    // fallback — a blob that now fails v2 is a stale-ciphertext replay
    // (the read-only portal re-fetches per session, so session scope
    // covers every render this viewer makes).
    const boundKey = `${userId}:${entry.client_entry_id}`;
    for (const aad of candidates) {
      try {
        plain = await decrypt(dataKey, encrypted, aad);
        if (aad !== candidates[1]) v2BoundEntries.add(boundKey);
        break;
      } catch (err) {
        failure = err;
        plain = null;
        if (aad === candidates[0] && v2BoundEntries.has(boundKey)) break; // refuse the replay
      }
    }
    if (plain === null) throw failure ?? new Error("entry could not be decrypted");
    const payload = validateEntry(decodeJson(plain));
    return payload as { text: string };
  } finally {
    zeroize(encrypted, plain);
  }
}

/** One surfaced pattern, as the brain's encrypted payload carries it
 * (backend app/services/brain.py — surfaced detail dict). */
export interface PatternPayload {
  kind: string;
  label: string;
  occurrences: number;
  confidence: number;
  detail: {
    pattern_pid?: string;
    pattern_state?: string;
    strength?: number;
    first_seen?: string;
    last_seen?: string;
    is_new?: boolean;
    sample_days?: number;
    sample_entries?: number;
    evidence_dates?: string[];
    sensitive?: boolean;
    [key: string]: unknown;
  };
}

// --- registration keypair ---------------------------------------------------------

/** Seal the RAW PKCS#8 private-key bytes for upload under the wrap KEK.
 * Takes bytes, never a base64 string (audit fix P-1, 2026-09-20): the base64
 * form of the raw private key must not exist as an immutable string at any
 * point, so this consumes the DER directly and zeroizes it before returning.
 * The envelope is unchanged: nonce||ct||tag AES-256-GCM under AAD
 * ("therapist-key", username) — byte-identical uploads to the previous
 * string-round-tripping flow. */
export async function sealPrivateKeyForUpload(
  wrapKek: Bytes,
  pkcs8: Bytes,
  username: string,
): Promise<string> {
  try {
    const blob = await encrypt(
      wrapKek,
      pkcs8,
      buildAad(THERAPIST_KEY_CONTEXT, username),
    );
    return toBase64(blob);
  } finally {
    zeroize(pkcs8);
  }
}

/** Open a sealed wrap_key_blob back to the RAW PKCS#8 bytes — the decrypt
 * counterpart of sealPrivateKeyForUpload, added with the verifier-gated
 * rotation surface (audit NEW-3 / F.4, 2026-09-22). unlockWrapPrivateKey
 * deliberately returns a NON-extractable handle, which is right for
 * unwrapping grants and wrong for re-wrapping custody: a password change
 * must re-seal the SAME private key under the new password-derived KEK,
 * and a non-extractable handle cannot be re-exported. This function
 * returns the DER bytes and makes the caller their custodian — feed them
 * straight into sealPrivateKeyForUpload (which consumes and wipes them)
 * and fill(0) them on every failure path. A wrong KEK, a blob sealed for
 * another username (AAD binds the account), or a corrupt/truncated
 * envelope fails CLOSED to null: never a throw, and never plaintext the
 * caller did not ask to own. */
export async function openSealedPrivateKey(
  wrapKek: Bytes,
  keyBlobB64: string,
  username: string,
): Promise<Bytes | null> {
  let encrypted: Bytes | null = null;
  try {
    encrypted = fromBase64(keyBlobB64);
    return await decrypt(
      wrapKek,
      encrypted,
      buildAad(THERAPIST_KEY_CONTEXT, username),
    );
  } catch {
    // Wrong password-derived KEK or a relocated/corrupt blob: there is no
    // re-wrappable key here, and the caller's only sane reaction is its
    // error path — null keeps TamperError flattening out of every caller.
    return null;
  } finally {
    zeroize(encrypted);
  }
}

/** Generate this therapist's P-256 wrap keypair AND seal the private half
 * for upload in the same call (audit fix P-1, 2026-09-20). The raw PKCS#8
 * exists only as a zeroized byte buffer inside this function — its base64
 * form is never materialized, and no long-lived object field carries
 * extractable private material. The returned object holds public material
 * (the SPKI toBase64 — public, safe as a string) and the sealed blob only; the
 * bytes uploaded are exactly what the previous generate-then-seal flow
 * produced (same KEK, same AAD, same envelope). */
export async function generateTherapistKeyPair(
  wrapKek: Bytes,
  username: string,
): Promise<{ publicKeySpkiB64: string; wrapKeyBlobB64: string }> {
  const pair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const spki = new Uint8Array(await subtle().exportKey("spki", pair.publicKey));
  let pkcs8: Bytes | null = null;
  try {
    pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
    return {
      publicKeySpkiB64: toBase64(spki),
      wrapKeyBlobB64: await sealPrivateKeyForUpload(wrapKek, pkcs8, username),
    };
  } finally {
    // sealPrivateKeyForUpload already consumed the DER; this double wipe
    // also covers the exportKey rejection path.
    zeroize(spki, pkcs8);
  }
}

/** Human-verifiable fingerprint of a P-256 SPKI public key: SHA-256 over
 * the DER, first 16 bytes as eight spaced hex groups ("A1B2 C3D4 E5F6
 * 0718 …"). The patient's app derives the SAME string from the key the
 * pairing lookup returned, so the two humans can read it to each other
 * and notice a substituted key (the 2026-09-17 audit's out-of-band
 * check). Formatting is pinned identical to the mobile implementation.
 *
 * L-5 (2026-09-20): widened from 8 to 16 bytes — the old 32-bit prefix let
 * a determined attacker grind a colliding P-256 key (~2^32) and defeat the
 * read-back. Both platforms changed together (cross-platform contract). */
export async function keyFingerprint(spkiB64: string): Promise<string> {
  const digest = new Uint8Array(await subtle().digest("SHA-256", fromBase64(spkiB64)));
  let hex = "";
  for (const byte of digest.subarray(0, 16)) hex += byte.toString(16).padStart(2, "0");
  hex = hex.toUpperCase();
  return hex.match(/.{4}/g)?.join(" ") ?? hex;
}

/** independent audit 2026-09-27: the SHORT server-format wrap-key
 *  fingerprint — first 16 hex chars of SHA-256 over the SPKI DER,
 *  lowercase, no separators — byte-identical to backend
 *  sharing.wrap_key_fingerprint(der). Running the portal's OWN wrap
 *  public key through this function yields the value the pairing-SAS
 *  response's `wrap_key_fingerprint` must be cross-checked against: the
 *  server computes BOTH pairing SAS strings, so the SAS alone proves
 *  nothing against a malicious server; this locally computed digest is
 *  the actual key-substitution check. */
export async function serverWrapKeyFingerprint(spkiB64: string): Promise<string> {
  const digest = new Uint8Array(await subtle().digest("SHA-256", fromBase64(spkiB64)));
  let hex = "";
  for (const byte of digest.subarray(0, 8)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}


/** Decrypt one kept voice recording (VOICE_PLAN 2026-09-29): the same
 *  AES-GCM envelope as entries under the patient's data key, AAD context
 *  "audio" bound to (userId, clientEntryId, audio version 1). Called only
 *  for consents carrying share_voice; the fetched bytes stay in memory and
 *  the object URL the caller mints is revoked after playback. */
export const AUDIO_PAYLOAD_VERSION = 1;

export async function decryptAudio(
  dataKey: Bytes,
  userId: string,
  clientEntryId: string,
  blobB64: string,
): Promise<Bytes> {
  const encrypted = fromBase64(blobB64);
  return await decrypt(
    dataKey,
    encrypted,
    buildAad("audio", userId, clientEntryId, String(AUDIO_PAYLOAD_VERSION)),
  );
}

/** Password-sealed independent notes custody. Historical keys preserve authenticated revisions. */
export interface NotesKeyring { active: Bytes; historical: Bytes[] }
export function createNotesKeyring(legacy: Bytes, identity: Bytes): NotesKeyring {
  const active = new Uint8Array(KEY_SIZE); crypto.getRandomValues(active);
  return { active, historical: [new Uint8Array(legacy), new Uint8Array(identity)] };
}
export function wipeNotesKeyring(ring: NotesKeyring | null | undefined): void {
  ring?.active.fill(0); for (const key of ring?.historical ?? []) key.fill(0);
}
export async function sealNotesKeyring(kek: Bytes, therapistId: string, ring: NotesKeyring): Promise<string> {
  if (ring.active.length !== KEY_SIZE || ring.historical.length > 512 || ring.historical.some(key => key.length !== KEY_SIZE)) throw new Error("Invalid notes custody.");
  const plain = new TextEncoder().encode(JSON.stringify({ v: 1, active: toBase64(ring.active), historical: ring.historical.map(toBase64) }));
  try { return toBase64(await encrypt(kek, plain, buildAad("portal-notes-keyring", therapistId, "v1"))); }
  finally { plain.fill(0); }
}
export async function openNotesKeyring(kek: Bytes, therapistId: string, blob: string): Promise<NotesKeyring> {
  const plain = await decrypt(kek, fromBase64(blob), buildAad("portal-notes-keyring", therapistId, "v1"));
  const keys: Bytes[] = [];
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(plain));
    if (!value || typeof value !== "object") throw new Error("Invalid notes custody.");
    const row = value as Record<string, unknown>;
    if (row.v !== 1 || typeof row.active !== "string" || !Array.isArray(row.historical) || row.historical.length > 512) throw new Error("Unsupported notes custody.");
    for (const encoded of [row.active, ...row.historical]) {
      if (typeof encoded !== "string") throw new Error("Invalid notes custody key.");
      const key = fromBase64(encoded); keys.push(key);
      if (key.length !== KEY_SIZE || toBase64(key) !== encoded) throw new Error("Invalid notes custody key.");
    }
    return { active: keys[0]!, historical: keys.slice(1) };
  } catch (err) { for (const key of keys) key.fill(0); throw err; }
  finally { plain.fill(0); }
}


function payloadRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted payload must be an object.");
  return value as Record<string, unknown>;
}
function finiteField(row: Record<string, unknown>, key: string, min: number, max: number): void {
  const value = row[key];
  if (value !== undefined && value !== null && (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max)) throw new Error(`Invalid encrypted ${key}.`);
}
function validateEntry(value: unknown): Record<string, unknown> {
  const row = payloadRecord(value);
  if (![1,2,3].includes(row.v as number)) throw new Error(`unsupported entry payload version: ${String(row.v)}`);
  if (typeof row.text !== "string" || row.text.length > 100_000) throw new Error("entry payload malformed");
  if (row.created_at !== undefined && (typeof row.created_at !== "string" || !Number.isFinite(Date.parse(row.created_at)))) throw new Error("Invalid encrypted entry date.");
  finiteField(row,"sentiment",-1,1); finiteField(row,"energy",-1,5); finiteField(row,"sleep",1,5);
  if (row.tags !== undefined && (!Array.isArray(row.tags) || row.tags.length > 200 || row.tags.some(tag => typeof tag !== "string" || tag.length > 200))) throw new Error("Invalid encrypted tags.");
  if (row.english_text !== undefined && row.english_text !== null && (typeof row.english_text !== "string" || row.english_text.length > 100_000)) throw new Error("Invalid encrypted translation.");
  if (row.input_mode !== undefined && row.input_mode !== "typed" && row.input_mode !== "voice") throw new Error("Invalid encrypted input mode.");
  if (row.transcript_lang !== undefined && (typeof row.transcript_lang !== "string" || !/^[a-z]{2,3}(?:-[A-Za-z]{2,8})?$/.test(row.transcript_lang))) throw new Error("Invalid encrypted transcript language.");
  if (row.tod !== undefined && !["morning","afternoon","evening","night"].includes(row.tod as string)) throw new Error("Invalid encrypted time bucket.");
  return row;
}
function validateInsights(value: unknown): Record<string, unknown> {
  const row = payloadRecord(value);
  if (row.v !== 2) throw new Error(`unsupported insights payload version: ${String(row.v)}`);
  if (row.state_seq !== undefined && (!Number.isSafeInteger(row.state_seq) || (row.state_seq as number) < 0)) throw new Error("Invalid encrypted analysis generation.");
  if (row.stats === undefined) return row;
  const stats = payloadRecord(row.stats);
  finiteField(stats,"avg_sentiment",-1,1); finiteField(stats,"total_entries",0,10_000_000); finiteField(stats,"active_days",0,10_000_000);
  if (stats.mood_summary !== undefined) {
    const summary = payloadRecord(stats.mood_summary);
    for (const key of ["observations", "explicit_mood", "text_estimates", "excluded_entries"]) {
      if (!Number.isSafeInteger(summary[key]) || (summary[key] as number) < 0 || (summary[key] as number) > 10_000_000) throw new Error("Invalid encrypted mood coverage.");
    }
    const observations = summary.observations as number;
    const explicit = summary.explicit_mood as number;
    const estimates = summary.text_estimates as number;
    const source = observations === 0 ? "unavailable" : explicit === 0 ? "text_estimate" : estimates === 0 ? "explicit_mood" : "mixed";
    if (explicit + estimates !== observations || summary.source !== source ||
        (observations === 0 ? stats.avg_sentiment !== null : typeof stats.avg_sentiment !== "number") ||
        (stats.total_entries !== undefined && observations + (summary.excluded_entries as number) !== stats.total_entries)) throw new Error("Inconsistent encrypted mood coverage.");
  }
  for (const key of ["first_date", "last_date"]) if (stats[key] !== undefined && stats[key] !== null && (typeof stats[key] !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(stats[key] as string))) throw new Error("Invalid encrypted chart date.");
  if (stats.patterns !== undefined) {
    if (!Array.isArray(stats.patterns) || stats.patterns.length > 1_000) throw new Error("Invalid encrypted patterns.");
    for (const raw of stats.patterns) {
      const pattern = payloadRecord(raw);
      if (typeof pattern.label !== "string" || pattern.label.length > 1_000 || typeof pattern.kind !== "string" || pattern.kind.length > 100) throw new Error("Invalid encrypted pattern label.");
      if (typeof pattern.confidence !== "number" || typeof pattern.occurrences !== "number") throw new Error("Invalid encrypted pattern evidence.");
      finiteField(pattern,"confidence",0,1); finiteField(pattern,"occurrences",0,10_000_000);
      {
        // All renderers access detail directly, including legacy patterns.
        const detail = payloadRecord(pattern.detail);
        finiteField(detail,"strength",0,1);
        for (const key of ["sample_days", "sample_entries"]) finiteField(detail,key,0,10_000_000);
        if (detail.evidence_dates !== undefined && (!Array.isArray(detail.evidence_dates) || detail.evidence_dates.length > 10_000 || detail.evidence_dates.some(date => typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)))) throw new Error("Invalid encrypted evidence dates.");
        for (const key of ["pattern_pid","pattern_state","first_seen","last_seen"]) if (detail[key] !== undefined && typeof detail[key] !== "string") throw new Error("Invalid encrypted pattern detail.");
        for (const key of ["sensitive","is_new"]) if (detail[key] !== undefined && typeof detail[key] !== "boolean") throw new Error("Invalid encrypted pattern flags.");
      }
    }
  }
  return row;
}

/** Preserve current legacy-client keys before a credential/identity change too. */
export function includeNotesCustodyKey(ring: NotesKeyring, key: Bytes): void {
  if ([ring.active,...ring.historical].some(known => known.length === key.length && known.every((value,index) => value === key[index]))) return;
  if (key.length !== KEY_SIZE || ring.historical.length >= 512) throw new Error("Notes custody requires a verified key retirement before another rotation; nothing was changed.");
  ring.historical.push(new Uint8Array(key));
}
