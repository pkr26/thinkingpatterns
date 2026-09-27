/**
 * v2 key envelope — a RANDOM data key wrapped under a password-derived KEK.
 * Must match backend/app/security/envelope.py (+ security/kdf.py's
 * kdf_params contract) exactly; shared/vectors.json envelope_vectors pins
 * the bytes and tests/vectors.test.ts replays them through this module.
 *
 *   data_key  = random 32 bytes                        (client-generated)
 *   kek       = HKDF-SHA256(ikm  = the password-derived PBKDF2 master key
 *                               the client already computes for login,
 *                           salt = the account's client KDF salt,
 *                           info = "mindpattern/envelope/v2", 32 bytes)
 *   aad       = {"context":"envelope","kdf_params":<canonical>,
 *                "username":<name>}                    (compact, ensure_ascii)
 *   wrapped   = nonce(12) || AES-256-GCM ct(32) || tag(16) — 60 bytes
 *
 * Why v2 exists: v1 derives the DATA key directly from the password, so a
 * password change re-keys the whole corpus (O(corpus) server work) and any
 * password weakening retroactively weakens stored ciphertext. With the
 * random-key envelope a password change is O(1) — unwrap locally with the
 * old password, re-wrap under a fresh salt, upload. The same data key keeps
 * encrypting the corpus, riding processing sessions, and being wrapped to
 * therapists' public keys unchanged.
 *
 * AAD binding, per the backend's deliberate deviation note: the bound
 * identity is the account USERNAME (the server mints user_id at INSERT
 * time, unknown to a client wrapping at registration), plus the kdf_params
 * blob — a wrap cannot be replayed onto another account, and a cost-profile
 * change forces a genuine re-wrap because the old blob's AAD names the old
 * parameters.
 *
 * kdf_params canonical order — TWO serializations exist on the backend and
 * this module must not confuse them:
 *   - the AAD embeds the canonical dict in its OWN insertion order:
 *     {"algorithm":…,"version":…,"iterations":…} (version BEFORE
 *     iterations — pinned by envelope_vectors);
 *   - the server's STORAGE serialization sorts keys (algorithm, iterations,
 *     version). A stored blob re-serialized by JSON.stringify of a parsed
 *     object would come out sorted — WRONG for the AAD. Every KdfParams
 *     this module builds therefore uses the fixed wrap order, and
 *     validateKdfParams REBUILDS unknown input into that order.
 */
import { jsonEnsureAscii } from "./aad";
import { decrypt, encrypt, encryptWithFixedNonce, KEY_SIZE, NONCE_SIZE, TamperError } from "./envelope";
import { engine } from "./engine";
import { KDF_ITERATIONS, MIN_ITERATIONS, zeroize } from "./kdf";

export { TamperError };

/** nonce(12) + ct(32) + tag(16): the wrapped 32-byte data key's exact size.
 *  Mirrors backend WRAPPED_DATA_KEY_BYTES — the server rejects anything
 *  else with 422, so refuse before the network. */
export const WRAPPED_DATA_KEY_BYTES = NONCE_SIZE + KEY_SIZE + 16;

/** Mirrors backend kdf.KDF_PARAMS_VERSION (the params-blob schema version —
 *  deliberately NOT the key-scheme version; a v2 envelope currently wraps
 *  a v1-schema pbkdf2 params blob). */
export const KDF_PARAMS_VERSION = 1;
export const KDF_ALGORITHM = "pbkdf2-sha256";
/** Mirrors backend kdf.PBKDF2_MAX_ITERATIONS: a hostile/buggy server must
 *  not be able to park this client on unbounded KDF work per unlock. */
export const MAX_KDF_ITERATIONS = 10_000_000;

/** The validated, canonical pbkdf2 kdf_params blob. Field order is the AAD
 *  wrap order (see the module note) — it is load-bearing, not cosmetic. */
export interface KdfParams {
  algorithm: typeof KDF_ALGORITHM;
  version: number;
  iterations: number;
}

/** The shipped-client parameters — the constant every current derivation
 *  uses ({pbkdf2-sha256, the 600k contract}). What registration, the v1→v2
 *  upgrade and every v2 re-wrap send by default. */
export function defaultKdfParams(): KdfParams {
  return { algorithm: KDF_ALGORITHM, version: KDF_PARAMS_VERSION, iterations: KDF_ITERATIONS };
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

/**
 * Strict validation of an (attacker-controllable) kdf_params blob — the
 * mobile mirror of backend kdf.validate_kdf_params for the pbkdf2 shape.
 * Unknown fields are rejected, not ignored ("the bytes you sent are the
 * bytes that bind"); bools are rejected explicitly (JSON true is not a
 * cost); bounds match the backend exactly. argon2id blobs answer null: this
 * client cannot derive them (no native Argon2id without a new dependency),
 * and silently deriving pbkdf2 over an argon2-declared blob would produce
 * a KEK that can never open the stored envelope — refuse loudly instead.
 * Returns the canonical object in AAD order, or null.
 */
export function validateKdfParams(value: unknown): KdfParams | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const params = value as Record<string, unknown>;
  for (const key of Object.keys(params)) {
    if (key !== "algorithm" && key !== "version" && key !== "iterations") return null;
  }
  if (params.algorithm !== KDF_ALGORITHM) return null;
  if (!isInteger(params.version) || params.version !== KDF_PARAMS_VERSION) return null;
  if (!isInteger(params.iterations)) return null;
  if (params.iterations < MIN_ITERATIONS || params.iterations > MAX_KDF_ITERATIONS) return null;
  return { algorithm: KDF_ALGORITHM, version: params.version, iterations: params.iterations };
}

/** The envelope AAD: compact JSON, fixed field order (context,
 *  kdf_params, username — the backend's envelope_aad insertion order, NOT
 *  sorted), ensure_ascii like every other cross-platform binding. */
export function envelopeAad(username: string, params: KdfParams): Buffer {
  const payload = JSON.stringify({
    context: "envelope",
    kdf_params: params,
    username,
  });
  // Stryker disable StringLiteral
return Buffer.from(jsonEnsureAscii(payload), "utf8");
  // Stryker restore StringLiteral
}

/** HKDF info labels are rebuilt at call time (same discipline as kdf.ts):
 *  every derivation exercises the exact label bytes. */
function envelopeKekInfo(): Buffer {
  return Buffer.from("mindpattern/envelope/v2", "utf8");
}

/**
 * KEK = HKDF-SHA256(password-derived master key, salt=the ACCOUNT salt,
 * info="mindpattern/envelope/v2", 32 bytes). The ikm is the SAME PBKDF2-600k
 * master key the client already computes for login (the auth/data HKDF
 * labels and this one are domain-separated by their info strings over the
 * same salt); reusing the account salt means the pre-login POST /auth/salt
 * hand-off already carries everything the envelope needs.
 */
export function envelopeKek(masterKey: Buffer, salt: Buffer): Buffer {
  if (masterKey.length < 16) throw new Error("password-derived key material must be at least 16 bytes");
  const derived = engine.hkdfSync("sha256", masterKey, salt, envelopeKekInfo(), 32);
  // Copy the engine's bytes out, then overwrite them so the original does
  // not linger to GC (the kdf.ts hkdfSha256 discipline — the copy goes
  // through a Uint8Array because Buffer.from(arrayBuffer) would share it).
  const bytes = new Uint8Array(derived as ArrayBuffer);
  const copy = Buffer.from(bytes);
  bytes.fill(0);
  return copy;
}

/** A fresh random 32-byte data key — the v2 account's storage key. */
export function generateDataKey(): Buffer {
  return Buffer.from(engine.randomBytes(KEY_SIZE));
}

/**
 * Wrap the random data key under the password-derived KEK (fresh random
 * nonce via envelope.encrypt — deterministic output is a nonce-reuse
 * hazard). Output is exactly WRAPPED_DATA_KEY_BYTES (60) by construction.
 */
export function wrapDataKey(dataKey: Buffer, kek: Buffer, username: string, params: KdfParams): Buffer {
  if (dataKey.length !== KEY_SIZE) throw new Error(`data_key must be ${KEY_SIZE} bytes`);
  if (kek.length !== KEY_SIZE) throw new Error(`kek must be ${KEY_SIZE} bytes`);
  return encrypt(kek, dataKey, envelopeAad(username, params));
}

/** Fixed-nonce wrap — TEST/VECTOR GENERATION ONLY (mirrors the backend's
 *  wrap_data_key, whose every caller is vector code). Never import from a
 *  screen or store path. */
export function wrapDataKeyWithFixedNonce(
  dataKey: Buffer,
  kek: Buffer,
  username: string,
  params: KdfParams,
  nonce: Buffer,
): Buffer {
  if (dataKey.length !== KEY_SIZE) throw new Error(`data_key must be ${KEY_SIZE} bytes`);
  if (kek.length !== KEY_SIZE) throw new Error(`kek must be ${KEY_SIZE} bytes`);
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  return encryptWithFixedNonce(kek, dataKey, envelopeAad(username, params), nonce);
}

/**
 * Verify + open the envelope. TamperError on any mismatch — a wrong
 * password fails exactly like every other GCM surface here. A structurally
 * impossible blob (wrong size) throws a plain Error so callers can tell
 * "not an envelope" from "wrong password / tampered bytes".
 */
export function unwrapDataKey(wrapped: Buffer, kek: Buffer, username: string, params: KdfParams): Buffer {
  if (wrapped.length !== WRAPPED_DATA_KEY_BYTES) {
    throw new Error(`wrapped data key must be exactly ${WRAPPED_DATA_KEY_BYTES} bytes`);
  }
  if (kek.length !== KEY_SIZE) throw new Error(`kek must be ${KEY_SIZE} bytes`);
  return decrypt(kek, wrapped, envelopeAad(username, params));
}

export { zeroize };
