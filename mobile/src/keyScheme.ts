/**
 * v2 key-scheme session glue (2026-09-26 crypto wave).
 *
 * The account's key scheme decides where the session data key comes from:
 *   v1 — derived directly from the password (HKDF "mindpattern/data/v1"
 *        over the PBKDF2 master key), exactly as before;
 *   v2 — a RANDOM 32-byte key, stored server-side as a password-wrapped
 *        envelope; the client fetches /auth/key-envelope after login and
 *        unwraps LOCALLY (crypto/keyEnvelope.ts). The GCM authentication
 *        doubles as the offline password proof — a wrong password fails
 *        the tag, not a server round-trip.
 *
 * This module holds the screen-facing orchestration (sanitize the server's
 * answer, build the registration envelope, resolve the session data key,
 * cache the envelope for offline unlock). The bytes live in crypto/.
 */
import { api, ApiError, type KeyEnvelopeCacheRecord, type KeyEnvelopeResponse } from "./api/client";
import { deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import {
  TamperError,
  defaultKdfParams,
  envelopeKek,
  generateDataKey,
  unwrapDataKey,
  validateKdfParams,
  wrapDataKey,
  WRAPPED_DATA_KEY_BYTES,
  type KdfParams,
} from "./crypto/keyEnvelope";

export type KeyScheme = "v1" | "v2";

/** The sanitized envelope answer. v2 records carry the unwrap material; a
 *  v1 record is a scheme marker (its data key stays password-derived). */
export interface EnvelopeInfo {
  scheme: KeyScheme;
  saltB64: string;
  kdfParams: KdfParams | null;
  wrappedB64: string | null;
}

/** Server input is attacker-controllable: adopt only the exact shapes this
 *  client can act on, mirroring the backend's own write-side validation.
 *  A v2 answer whose kdf_params this client cannot derive (argon2id, a
 *  future profile, garbage) refuses rather than guessing — an honest
 *  "cannot unlock this account" beats a KEK that can never open the blob.
 *  A FUTURE scheme ("v3") also refuses: treating it as v1 would derive a
 *  wrong data key and silently seal new entries under it. Returns null
 *  for anything else. */
export function sanitizeEnvelopeResponse(raw: unknown): EnvelopeInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const body = raw as Partial<KeyEnvelopeResponse>;
  if (typeof body.salt !== "string" || Buffer.from(body.salt, "base64").length < 8) return null;
  if (body.key_scheme === "v2") {
    const params = validateKdfParams(body.kdf_params);
    if (params === null) return null;
    if (typeof body.wrapped_data_key !== "string") return null;
    if (Buffer.from(body.wrapped_data_key, "base64").length !== WRAPPED_DATA_KEY_BYTES) return null;
    return { scheme: "v2", saltB64: body.salt, kdfParams: params, wrappedB64: body.wrapped_data_key };
  }
  // v1 — and ONLY v1 (the backend's explicit default). Unknown schemes
  // refuse above-and-here rather than degrading to v1 semantics.
  if (body.key_scheme !== "v1") return null;
  // No envelope fields are consulted — extra fields are ignored, never
  // trusted.
  return { scheme: "v1", saltB64: body.salt, kdfParams: null, wrappedB64: null };
}

export type EnvelopeFetch =
  | { status: "ok"; envelope: EnvelopeInfo }
  /** 404: the endpoint does not exist — a pre-2026-09-26 server. No v2
   *  account can live there, so v1 semantics hold without an extra flag. */
  | { status: "legacy" }
  /** No answer: offline or a server error. Retryable. */
  | { status: "unreachable" }
  /** The server ANSWERED, but with a shape this client refuses (e.g. an
   *  argon2id kdf_params blob no shipped client can derive). Not
   *  retryable as-is — callers surface "update the app"-style honesty,
   *  never "check your connection". */
  | { status: "invalid" };

export async function fetchEnvelope(): Promise<EnvelopeFetch> {
  let raw: unknown;
  try {
    raw = await api.keyEnvelope();
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { status: "legacy" };
    return { status: "unreachable" };
  }
  const envelope = sanitizeEnvelopeResponse(raw);
  return envelope === null ? { status: "invalid" } : { status: "ok", envelope };
}

/** The registration envelope: a FRESH random data key wrapped under the
 *  password-derived KEK. Every NEW account is v2 (the 2026-09-26 default);
 *  the derived auth key still authenticates the login, the random data key
 *  encrypts everything, and the unused v1 data label never protects
 *  storage. All key material except the returned data key is zeroized. */
export interface RegistrationEnvelope {
  dataKey: Buffer;
  kdfParams: KdfParams;
  wrappedB64: string;
}

export async function buildRegistrationEnvelope(
  password: string,
  salt: Buffer,
  username: string,
): Promise<RegistrationEnvelope> {
  // The SAME PBKDF2-600k master key the login derivation produces (the
  // caller usually has one in hand, but the HKDF cost is trivial and the
  // screens keep a single responsibility: derive once for login, once for
  // the envelope's KEK input, both async so the JS thread never freezes).
  const master = await deriveMasterKeyAsync(password, salt);
  try {
    const kek = envelopeKek(master, salt);
    try {
      const dataKey = generateDataKey();
      const kdfParams = defaultKdfParams();
      const wrapped = wrapDataKey(dataKey, kek, username, kdfParams);
      return { dataKey, kdfParams, wrappedB64: wrapped.toString("base64") };
    } finally {
      zeroize(kek);
    }
  } finally {
    zeroize(master);
  }
}

export type SessionDataKeyResult =
  | { ok: true; dataKey: Buffer }
  /** The envelope did not authenticate: wrong password (or tampered bytes)
   *  — callers map this to the wrong-password funnel, exactly like the
   *  sealed unlock proof's "wrong". */
  | { ok: false; reason: "tamper" }
  /** The envelope is unusable as handed (wrong scheme, undecodable
   *  material): never retried blindly. */
  | { ok: false; reason: "bad-envelope" };

/** Resolve the v2 session data key: unwrap the envelope under the KEK.
 *
 *  derivedMaster lets the unlock path REUSE the master key it already
 *  derived for login when (and only when) it was derived under the
 *  envelope's own salt and iteration count — otherwise a fresh async
 *  derivation happens here (same bytes; a salt/params change raced the
 *  login mid-flow is exactly the case this re-derivation covers). */
export async function unwrapSessionDataKey(input: {
  password: string;
  username: string;
  envelope: EnvelopeInfo;
  derivedMaster?: { key: Buffer; saltB64: string; iterations: number } | null;
}): Promise<SessionDataKeyResult> {
  const { password, username, envelope } = input;
  if (envelope.scheme !== "v2" || envelope.kdfParams === null || envelope.wrappedB64 === null) {
    return { ok: false, reason: "bad-envelope" };
  }
  const params = envelope.kdfParams;
  const salt = Buffer.from(envelope.saltB64, "base64");
  const wrapped = Buffer.from(envelope.wrappedB64, "base64");
  if (salt.length < 8 || wrapped.length !== WRAPPED_DATA_KEY_BYTES) {
    return { ok: false, reason: "bad-envelope" };
  }
  const reuse =
    input.derivedMaster !== undefined &&
    input.derivedMaster !== null &&
    input.derivedMaster.saltB64 === envelope.saltB64 &&
    input.derivedMaster.iterations === params.iterations;
  let master: Buffer;
  let derivedHere = false;
  if (reuse) {
    master = input.derivedMaster!.key;
  } else {
    master = await deriveMasterKeyAsync(password, salt, params.iterations);
    derivedHere = true;
  }
  try {
    const kek = envelopeKek(master, salt);
    try {
      return { ok: true, dataKey: unwrapDataKey(wrapped, kek, username, params) };
    } catch (err) {
      return err instanceof TamperError ? { ok: false, reason: "tamper" } : { ok: false, reason: "bad-envelope" };
    } finally {
      zeroize(kek);
    }
  } finally {
    // Never zeroize a caller-owned master (the caller's derivation, the
    // caller's cleanup); only the copy made here.
    if (derivedHere) zeroize(master);
  }
}

/** Persist the envelope for the NEXT (possibly offline) unlock. The
 *  wrapped key is password-locked ciphertext — inert without the password
 *  — and origin-bound by the client's cache discipline. */
export async function cacheEnvelope(username: string, envelope: EnvelopeInfo): Promise<void> {
  const record: KeyEnvelopeCacheRecord = {
    scheme: envelope.scheme,
    saltB64: envelope.saltB64,
    kdfParams: envelope.kdfParams,
    wrappedB64: envelope.wrappedB64,
  };
  await api.cacheKeyEnvelope(username, record);
}

/** The last cached envelope, re-validated on read (a hand-edited or corrupt
 *  record answers null — never a half-parsed envelope an unlock might
 *  trust). The v1 marker counts: an offline unlock then knows to use the
 *  sealed-proof path instead of guessing. */
export async function cachedEnvelope(username: string): Promise<EnvelopeInfo | null> {
  const record = await api.getCachedKeyEnvelope(username);
  if (record === null) return null;
  if (record.scheme === "v1") return { scheme: "v1", saltB64: record.saltB64, kdfParams: null, wrappedB64: null };
  const params = validateKdfParams(record.kdfParams);
  if (params === null || typeof record.wrappedB64 !== "string") return null;
  if (Buffer.from(record.wrappedB64, "base64").length !== WRAPPED_DATA_KEY_BYTES) return null;
  return { scheme: "v2", saltB64: record.saltB64, kdfParams: params, wrappedB64: record.wrappedB64 };
}

export async function clearCachedEnvelope(username: string): Promise<void> {
  await api.clearCachedKeyEnvelope(username);
}
