/**
 * The v2 key envelope (2026-09-26 crypto-architecture wave) — the web
 * mirror of backend/app/security/envelope.py, pinned byte-for-byte by
 * shared/vectors.json `envelope_vectors` (see tests/envelope.test.ts).
 *
 *     data_key  = random 32 bytes                       (client-generated)
 *     kek       = HKDF-SHA256(ikm  = the password-derived master key
 *                              (the SAME PBKDF2-600k output the login
 *                              verifier comes from),
 *                              salt = the account's client KDF salt,
 *                              info = "mindpattern/envelope/v2", 32 bytes)
 *     wrapped   = nonce(12) || AES-256-GCM(kek, data_key, aad) || tag
 *                 — exactly 60 bytes on the wire
 *     aad       = {"context":"envelope","kdf_params":{…},"username":"…"}
 *                 compact, ASCII-only, FIXED field order (the pinned
 *                 vectors own this byte layout; kdf_params rides in the
 *                 backend's canonical dict order: algorithm, version,
 *                 iterations, memory_kib, parallelism).
 *
 * The point of the scheme: the DATA key stops being derived from the
 * password, so a password change re-wraps one 60-byte blob instead of
 * re-encrypting the corpus (PUT /account/password is O(1)), while the
 * KEK input still never leaves the client — a database dump yields the
 * data key only against the password, exactly like v1.
 */
import {
  decrypt,
  encryptWithFixedNonce,
  fromBase64,
  hkdfSha256,
  KDF_ITERATIONS,
  KEY_SIZE,
  NONCE_SIZE,
  TamperError,
  toBase64,
  zeroize,
  type Bytes,
} from "./core";

const ENVELOPE_KEK_INFO = new TextEncoder().encode("mindpattern/envelope/v2");
export const ENVELOPE_CONTEXT = "envelope";
/** nonce(12) + ct(32) + tag(16): the wrapped 32-byte data key's exact size. */
export const WRAPPED_DATA_KEY_BYTES = NONCE_SIZE + KEY_SIZE + 16;

/** The kdf_params blob's schema version. This is the BACKEND's contract
 *  constant (kdf.KDF_PARAMS_VERSION — the blob format's version, pinned
 *  at 1 by validate_kdf_params and by the envelope vectors); it is NOT
 *  the key-scheme version (v1/v2), which names the ACCOUNT scheme. */
export const KDF_PARAMS_VERSION = 1;

export type KdfAlgorithm = "pbkdf2-sha256" | "argon2id";

/** The validated kdf_params shape (backend kdf.validate_kdf_params). The
 *  canonical FIELD ORDER below is load-bearing: it is the order the AAD
 *  serializes the blob in, matching the backend dict's insertion order. */
export interface KdfParams {
  algorithm: KdfAlgorithm;
  version: number;
  iterations: number;
  memory_kib?: number;
  parallelism?: number;
}

/** Bounds mirroring backend kdf.py — a hostile or buggy server must not
 *  be able to feed this client params that burn unbounded CPU, and a
 *  tampered echo of the account's blob must fail loudly, not half-parse. */
const MIN_ITERATIONS = 100_000;
const PBKDF2_MAX_ITERATIONS = 10_000_000;
const ARGON2_MIN_ITERATIONS = 2;
/** independent audit 2026-09-27 (P3): the backend caps argon2id at
 *  10_000_000 too (kdf.py ARGON2_MAX_ITERATIONS) — validation must mirror
 *  the server on BOTH sides of the range, or a hostile/buggy echo above
 *  the cap would pass here and die (or burn CPU) server-side. */
const ARGON2_MAX_ITERATIONS = 10_000_000;
const ARGON2_MIN_MEMORY_KIB = 19 * 1024;
const ARGON2_MAX_MEMORY_KIB = 256 * 1024;
const ARGON2_MAX_PARALLELISM = 4;

const isCostInt = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Validate + canonicalize a kdf_params blob (the register payload, or the
 *  server's echo from GET /auth/key-envelope). Unknown fields are REJECTED,
 *  not ignored — the AAD rule is "the bytes that bind are the bytes that
 *  were sent", so a narrowed blob must never silently authenticate. */
export function validateKdfParams(value: unknown): KdfParams {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("kdf_params must be a JSON object");
  }
  const raw = value as Record<string, unknown>;
  const unknown = Object.keys(raw).filter(
    (key) => key !== "algorithm" && key !== "version" && key !== "iterations" && key !== "memory_kib" && key !== "parallelism",
  );
  if (unknown.length > 0) throw new Error(`kdf_params has unknown fields: ${unknown.sort().join(", ")}`);
  const algorithm = raw.algorithm;
  if (algorithm !== "pbkdf2-sha256" && algorithm !== "argon2id") {
    throw new Error("kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'");
  }
  if (raw.version !== KDF_PARAMS_VERSION) {
    throw new Error(`kdf_params.version must be ${KDF_PARAMS_VERSION}`);
  }
  const canonical: KdfParams = { algorithm, version: KDF_PARAMS_VERSION, iterations: 0 };
  if (algorithm === "pbkdf2-sha256") {
    if ("memory_kib" in raw || "parallelism" in raw) {
      throw new Error("pbkdf2-sha256 kdf_params carry iterations only");
    }
    if (!isCostInt(raw.iterations) || raw.iterations < MIN_ITERATIONS || raw.iterations > PBKDF2_MAX_ITERATIONS) {
      throw new Error(`kdf_params.iterations must be ${MIN_ITERATIONS}-${PBKDF2_MAX_ITERATIONS} for pbkdf2-sha256`);
    }
    canonical.iterations = raw.iterations;
    return canonical;
  }
  for (const field of ["iterations", "memory_kib", "parallelism"] as const) {
    if (!isCostInt(raw[field])) throw new Error(`argon2id kdf_params require ${field}`);
  }
  const iterations = raw.iterations as number;
  const memoryKib = raw.memory_kib as number;
  const parallelism = raw.parallelism as number;
  if (iterations < ARGON2_MIN_ITERATIONS || iterations > ARGON2_MAX_ITERATIONS) {
    throw new Error(`kdf_params.iterations must be ${ARGON2_MIN_ITERATIONS}-${ARGON2_MAX_ITERATIONS} for argon2id`);
  }
  if (memoryKib < ARGON2_MIN_MEMORY_KIB || memoryKib > ARGON2_MAX_MEMORY_KIB) {
    throw new Error(`kdf_params.memory_kib must be ${ARGON2_MIN_MEMORY_KIB}-${ARGON2_MAX_MEMORY_KIB}`);
  }
  if (parallelism < 1 || parallelism > ARGON2_MAX_PARALLELISM) {
    throw new Error(`kdf_params.parallelism must be 1-${ARGON2_MAX_PARALLELISM}`);
  }
  canonical.iterations = iterations;
  canonical.memory_kib = memoryKib;
  canonical.parallelism = parallelism;
  return canonical;
}

/** The params THIS client registers with: the existing 600k PBKDF2 contract
 *  (the same constant core.KDF_ITERATIONS the master key derives with).
 *  Argon2id blobs are accepted and unwrapped for what they are, but this
 *  build cannot derive one (no native WebCrypto Argon2), so it never
 *  advertises one. */
export const KDF_PARAMS_DEFAULT: KdfParams = {
  algorithm: "pbkdf2-sha256",
  version: KDF_PARAMS_VERSION,
  iterations: KDF_ITERATIONS,
};

/** Python json.dumps(..., ensure_ascii=True) semantics: every UTF-16 code
 *  unit >= 0x7F escapes as \uXXXX (DEL included; astral chars arrive here
 *  as surrogate pairs, both escaped). Identical to crypto/aad.ts's rule —
 *  usernames are ASCII by contract, but the envelope AAD is a pinned byte
 *  layout and must not depend on that upstream validation. */
function ensureAscii(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out += code >= 0x7f ? "\\u" + code.toString(16).padStart(4, "0") : text[i]!;
  }
  return out;
}

/** Canonical AAD binding the wrap to (context, account, KDF params).
 *  FIXED field order — {"context","kdf_params","username"} — because the
 *  order is itself part of the pinned vectors; ``kdfParams`` must already
 *  be canonical (validateKdfParams) so the stored blob and its AAD can
 *  never disagree by a normalization step. */
export function envelopeAad(username: string, kdfParams: KdfParams): Bytes {
  const payload = `{"context":"${ENVELOPE_CONTEXT}","kdf_params":${JSON.stringify(kdfParams)},"username":${JSON.stringify(username)}}`;
  return new TextEncoder().encode(ensureAscii(payload)) as Bytes;
}

/** KEK = HKDF-SHA256(password-derived master key, account salt,
 *  "mindpattern/envelope/v2"). Reusing the ACCOUNT salt (not a fresh one)
 *  is the backend's contract: the salt already travels pre-login via
 *  POST /auth/salt, and the info label domain-separates the KEK from the
 *  auth/data subkeys derived over the same master. */
export async function envelopeKek(masterKey: Bytes, salt: Bytes): Promise<Bytes> {
  if (masterKey.length < 16) throw new Error("password-derived key material must be at least 16 bytes");
  return hkdfSha256(masterKey, salt, ENVELOPE_KEK_INFO, KEY_SIZE);
}

/** Wrap the random data key under the password-derived KEK. The nonce is
 *  random in production; the fixed-nonce seam exists for the shared vector
 *  pins (deterministic bytes), exactly like core.encryptWithFixedNonce. */
export async function wrapDataKey(
  dataKey: Bytes,
  kek: Bytes,
  username: string,
  kdfParams: KdfParams,
  nonce?: Bytes,
): Promise<Bytes> {
  if (dataKey.length !== KEY_SIZE) throw new Error(`data_key must be ${KEY_SIZE} bytes`);
  if (kek.length !== KEY_SIZE) throw new Error(`kek must be ${KEY_SIZE} bytes`);
  const aad = envelopeAad(username, kdfParams);
  if (nonce !== undefined) {
    try {
      return await encryptWithFixedNonce(kek, dataKey, nonce, aad);
    } finally {
      zeroize(aad);
    }
  }
  const fresh = globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(NONCE_SIZE)) as Bytes);
  try {
    return await encryptWithFixedNonce(kek, dataKey, fresh, aad);
  } finally {
    zeroize(fresh, aad);
  }
}

/** Verify + open the envelope. A structurally impossible blob is an Error
 *  ("not an envelope"); an authentication failure (wrong password, wrong
 *  account, tampered bytes) is TamperError — the same distinction every
 *  other GCM surface here makes. */
export async function unwrapDataKey(
  wrapped: Bytes,
  kek: Bytes,
  username: string,
  kdfParams: KdfParams,
): Promise<Bytes> {
  if (wrapped.length !== WRAPPED_DATA_KEY_BYTES) {
    throw new Error(`wrapped data key must be exactly ${WRAPPED_DATA_KEY_BYTES} bytes`);
  }
  if (kek.length !== KEY_SIZE) throw new Error(`kek must be ${KEY_SIZE} bytes`);
  const aad = envelopeAad(username, kdfParams);
  try {
    return await decrypt(kek, wrapped, aad);
  } finally {
    zeroize(aad);
  }
}

/** The complete registration envelope (v2 default since 2026-09-26): draw
 *  a random data key, wrap it under the password-derived KEK, hand back
 *  the wire pair + the raw key for the vault. The caller owns the data
 *  key's lifecycle from here (the vault, ultimately). */
export async function createRegistrationEnvelope(
  masterKey: Bytes,
  salt: Bytes,
  username: string,
  kdfParams: KdfParams = KDF_PARAMS_DEFAULT,
): Promise<{ dataKey: Bytes; kdfParams: KdfParams; wrappedDataKeyB64: string }> {
  const dataKey = globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(KEY_SIZE)) as Bytes);
  let kek: Bytes | null = null;
  try {
    kek = await envelopeKek(masterKey, salt);
    const wrapped = await wrapDataKey(dataKey, kek, username, kdfParams);
    return { dataKey, kdfParams, wrappedDataKeyB64: toBase64(wrapped) };
  } finally {
    zeroize(kek);
  }
}

/** Re-wrap an EXISTING data key under a (possibly new) password-derived
 *  master + salt — the O(1) password change (the data key itself never
 *  rotates) and the v1→v2 self-upgrade (the v1 password-DERIVED data key
 *  becomes the wrapped key) are the same call with different inputs. */
export async function rewrapDataKey(
  dataKey: Bytes,
  masterKey: Bytes,
  salt: Bytes,
  username: string,
  kdfParams: KdfParams = KDF_PARAMS_DEFAULT,
): Promise<string> {
  let kek: Bytes | null = null;
  try {
    kek = await envelopeKek(masterKey, salt);
    return toBase64(await wrapDataKey(dataKey, kek, username, kdfParams));
  } finally {
    zeroize(kek);
  }
}

/** The v2 unlock half: validate the server-echoed params, derive the KEK
 *  from the SAME master the login verifier came from, open the envelope.
 *  A wrong password, a relocated blob, or a tampered echo all fail closed
 *  (TamperError / Error — never a wrong key). */
export async function unwrapEnvelope(
  masterKey: Bytes,
  salt: Bytes,
  username: string,
  wrappedDataKeyB64: string,
  kdfParamsValue: unknown,
): Promise<Bytes> {
  const kdfParams = validateKdfParams(kdfParamsValue);
  let kek: Bytes | null = null;
  try {
    kek = await envelopeKek(masterKey, salt);
    // core.fromBase64 is forgiving about marginally malformed base64; the
    // unwrap's exact-60-byte size check right after is the real gate, so
    // a server blob that is not the envelope dies there, loudly.
    return await unwrapDataKey(fromBase64(wrappedDataKeyB64), kek, username, kdfParams);
  } finally {
    zeroize(kek);
  }
}

export { TamperError };
