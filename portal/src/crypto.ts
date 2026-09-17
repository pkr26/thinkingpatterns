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
  return { authKeyB64: b64(auth), wrapKek, noteKey };
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

/** Decrypt this therapist's stored P-256 private key (PKCS8 DER) with the
 * password-derived wrap KEK. AAD binds the key to the therapist's username,
 * so a blob served for another account cannot unlock here. */
export async function unlockWrapPrivateKey(
  wrapKek: Bytes,
  keyBlobB64: string,
  username: string,
): Promise<CryptoKey> {
  const { buildAad } = await import("./aad");
  const pkcs8 = await decrypt(wrapKek, unb64(keyBlobB64), buildAad(THERAPIST_KEY_CONTEXT, username));
  return subtle().importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
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
  const ephDer = unb64(ephemeralPubSpkiB64);
  const thDer = unb64(therapistPubSpkiB64);
  const ephPub = await subtle().importKey("spki", ephDer, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedBits = await subtle().deriveBits({ name: "ECDH", public: ephPub }, therapistPrivateKey, 256);
  const salt = new Uint8Array(new ArrayBuffer(ephDer.length + thDer.length));
  salt.set(ephDer, 0);
  salt.set(thDer, ephDer.length);
  const kek = await hkdf(new Uint8Array(sharedBits), salt, WRAP_INFO, KEY_SIZE);
  return decrypt(kek, unb64(wrappedKeyB64), buildAad(WRAP_CONTEXT, userId, therapistId));
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
  const blob = await encrypt(
    noteKey,
    payload,
    buildAad(NOTE_CONTEXT, therapistId, userId, clientNoteId),
  );
  return { clientNoteId, blobB64: b64(blob) };
}

export async function decryptNote(
  noteKey: Bytes,
  therapistId: string,
  userId: string,
  clientNoteId: string,
  blobB64: string,
): Promise<string> {
  const { buildAad } = await import("./aad");
  const plain = await decrypt(
    noteKey,
    unb64(blobB64),
    buildAad(NOTE_CONTEXT, therapistId, userId, clientNoteId),
  );
  const payload = JSON.parse(new TextDecoder().decode(plain)) as { v?: number; text?: string };
  if (typeof payload.text !== "string") throw new Error("note payload malformed");
  return payload.text;
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
  const plain = await decrypt(dataKey, unb64(blobB64), buildAad("insights", userId, "patterns"));
  return decodeJson(plain) as { stats: { patterns: PatternPayload[] } };
}

export async function decryptEntry(
  dataKey: Bytes,
  userId: string,
  entry: { client_entry_id: string; blob: string },
): Promise<{ text: string; created_at?: string; sentiment?: number | null }> {
  const { buildAad } = await import("./aad");
  const plain = await decrypt(dataKey, unb64(entry.blob), buildAad("entry", userId, entry.client_entry_id));
  const payload = decodeJson(plain) as { text?: string };
  if (typeof payload.text !== "string") throw new Error("entry payload malformed");
  return payload as { text: string };
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
  return {
    publicKeySpkiB64: b64(spki),
    // Sealed for upload by sealPrivateKeyForUpload once the password-derived
    // KEK exists (the raw private key never leaves the browser unencrypted).
    privateKeyPkcs8B64: b64(pkcs8),
    privateKey: pair.privateKey,
  };
}

export async function sealPrivateKeyForUpload(
  wrapKek: Bytes,
  privateKeyPkcs8B64: string,
  username: string,
): Promise<string> {
  const { buildAad } = await import("./aad");
  const blob = await encrypt(
    wrapKek,
    unb64(privateKeyPkcs8B64),
    buildAad(THERAPIST_KEY_CONTEXT, username),
  );
  return b64(blob);
}
