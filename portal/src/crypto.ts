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
 * The wrap KEK decrypts THIS therapist's P-256 private key (fetched from
 * GET /therapist/me as an opaque blob); the note key encrypts notes. The
 * patient data key is never stored — it is unwrapped per patient per
 * session (ECDH + HKDF over the consent's wrapped key) and kept in memory
 * only.
 */

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
const WRAP_INFO = new TextEncoder().encode("mindpattern/wrap/v1");
/** HKDF salt for the master-key subkeys: RFC 5869 default (HashLen zeros),
 * matching backend kdf.hkdf_sha256(salt=None). */
const ZERO_SALT = new Uint8Array(32);

const b64 = (bytes: Bytes): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

const unb64 = (text: string): Bytes => {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
};

export { b64 as toBase64, unb64 as fromBase64 };

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
): Promise<{ authKeyB64: string; wrapKek: Bytes; noteKey: Bytes }> {
  const [auth, wrapKek, noteKey] = await Promise.all([
    hkdf(master, ZERO_SALT, AUTH_INFO, KEY_SIZE),
    hkdf(master, ZERO_SALT, PORTAL_WRAP_INFO, KEY_SIZE),
    hkdf(master, ZERO_SALT, PORTAL_NOTES_INFO, KEY_SIZE),
  ]);
  try {
    return { authKeyB64: b64(auth), wrapKek, noteKey };
  } finally {
    // The string form is needed for the authentication request, but the
    // raw derived verifier has no reason to survive alongside it.
    zeroize(auth);
  }
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
  const { buildAad } = await import("./aad");
  let encrypted: Bytes | null = null;
  let pkcs8: Bytes | null = null;
  try {
    encrypted = unb64(keyBlobB64);
    pkcs8 = await decrypt(
      wrapKek,
      encrypted,
      buildAad(THERAPIST_KEY_CONTEXT, username),
    );
    // `false` makes the resulting CryptoKey non-extractable. Once WebCrypto
    // owns that handle, the raw PKCS#8 copy must not stay in JS memory.
    return await subtle().importKey(
      "pkcs8",
      pkcs8,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
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
  const { buildAad } = await import("./aad");
  let ephDer: Bytes | null = null;
  let thDer: Bytes | null = null;
  let wrapped: Bytes | null = null;
  let salt: Bytes | null = null;
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  try {
    ephDer = unb64(ephemeralPubSpkiB64);
    thDer = unb64(therapistPubSpkiB64);
    wrapped = unb64(wrappedKeyB64);
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
  completedAt: string | null;
  measureDate: string;
}

/** Decrypt one patient-recorded measure blob. The payload is the patient's
 *  client contract: {"v":1,"measure":"phq9","score":N,"completed_at":ISO}.
 *  Sanitized like every decrypted payload — wrong shapes degrade to null,
 *  never render. The portal DISPLAYS scores; it never interprets them. */
export async function decryptMeasure(
  dataKey: Bytes,
  userId: string,
  measure: { client_measure_id: string; blob: string; measure_date: string },
): Promise<MeasureReading | null> {
  const { buildAad } = await import("./aad");
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = unb64(measure.blob);
    plain = await decrypt(
      dataKey,
      encrypted,
      buildAad("measure", userId, measure.client_measure_id),
    );
    const payload = decodeJson(plain) as Record<string, unknown>;
    const score = payload.score;
    if (typeof score !== "number" || !Number.isFinite(score)) return null;
    return {
      measure: typeof payload.measure === "string" ? payload.measure.slice(0, 24) : "measure",
      score: Math.max(0, Math.min(100, Math.round(score))),
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
  const { buildAad } = await import("./aad");
  let ephDer: Bytes | null = null;
  let thDer: Bytes | null = null;
  let wrapped: Bytes | null = null;
  let salt: Bytes | null = null;
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    ephDer = unb64(ephemeralPubSpkiB64);
    thDer = unb64(therapistPubSpkiB64);
    wrapped = unb64(summaryBlobB64);
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
    if (typeof parsed !== "object" || parsed === null) return null;
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
  const { buildAad } = await import("./aad");
  const payload = new TextEncoder().encode(JSON.stringify({ v: 1, text })) as Bytes;
  try {
    const blob = await encrypt(
      noteKey,
      payload,
      buildAad(NOTE_CONTEXT, therapistId, userId, clientNoteId),
    );
    return { clientNoteId, blobB64: b64(blob) };
  } finally {
    zeroize(payload);
  }
}

export async function decryptNote(
  noteKey: Bytes,
  therapistId: string,
  userId: string,
  clientNoteId: string,
  blobB64: string,
): Promise<string> {
  const { buildAad } = await import("./aad");
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = unb64(blobB64);
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

const decodeJson = (bytes: Uint8Array): unknown => JSON.parse(new TextDecoder().decode(bytes));

export async function decryptInsights(
  dataKey: Bytes,
  userId: string,
  blobB64: string,
): Promise<{
  stats: {
    patterns: PatternPayload[];
    /** Aggregate account stats the backend already packs into the same
     *  blob (2026-09-17: the portal stopped discarding them). */
    avg_sentiment?: number;
    total_entries?: number;
    active_days?: number;
    first_date?: string;
    last_date?: string;
  };
}> {
  const { buildAad } = await import("./aad");
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = unb64(blobB64);
    plain = await decrypt(dataKey, encrypted, buildAad("insights", userId, "patterns"));
    return decodeJson(plain) as { stats: { patterns: PatternPayload[] } };
  } finally {
    zeroize(encrypted, plain);
  }
}

export async function decryptEntry(
  dataKey: Bytes,
  userId: string,
  entry: { client_entry_id: string; blob: string },
): Promise<{ text: string; created_at?: string; sentiment?: number | null }> {
  const { buildAad } = await import("./aad");
  let encrypted: Bytes | null = null;
  let plain: Bytes | null = null;
  try {
    encrypted = unb64(entry.blob);
    plain = await decrypt(dataKey, encrypted, buildAad("entry", userId, entry.client_entry_id));
    const payload = decodeJson(plain) as { text?: string };
    if (typeof payload.text !== "string") throw new Error("entry payload malformed");
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
    evidence_dates?: string[];
    sensitive?: boolean;
    [key: string]: unknown;
  };
}

// --- registration keypair ---------------------------------------------------------

export async function generateTherapistKeyPair(): Promise<{
  publicKeySpkiB64: string;
  privateKeyPkcs8B64: string;
  privateKey: CryptoKey;
}> {
  const pair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const spki = new Uint8Array(await subtle().exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
  try {
    return {
      publicKeySpkiB64: b64(spki),
      // Sealed for upload by sealPrivateKeyForUpload once the password-derived
      // KEK exists (the raw private key never leaves the browser unencrypted).
      privateKeyPkcs8B64: b64(pkcs8),
      privateKey: pair.privateKey,
    };
  } finally {
    zeroize(spki, pkcs8);
  }
}

export async function sealPrivateKeyForUpload(
  wrapKek: Bytes,
  privateKeyPkcs8B64: string,
  username: string,
): Promise<string> {
  const { buildAad } = await import("./aad");
  let pkcs8: Bytes | null = null;
  try {
    pkcs8 = unb64(privateKeyPkcs8B64);
    const blob = await encrypt(
      wrapKek,
      pkcs8,
      buildAad(THERAPIST_KEY_CONTEXT, username),
    );
    return b64(blob);
  } finally {
    zeroize(pkcs8);
  }
}

/** Human-verifiable fingerprint of a P-256 SPKI public key: SHA-256 over
 * the DER, first 8 bytes as four spaced hex groups ("A1B2 C3D4 E5F6
 * 0718"). The patient's app derives the SAME string from the key the
 * pairing lookup returned, so the two humans can read it to each other
 * and notice a substituted key (the 2026-09-17 audit's out-of-band
 * check). Formatting is pinned identical to the mobile implementation. */
export async function keyFingerprint(spkiB64: string): Promise<string> {
  const digest = new Uint8Array(await subtle().digest("SHA-256", unb64(spkiB64)));
  let hex = "";
  for (const byte of digest.subarray(0, 8)) hex += byte.toString(16).padStart(2, "0");
  hex = hex.toUpperCase();
  return hex.match(/.{4}/g)?.join(" ") ?? hex;
}
