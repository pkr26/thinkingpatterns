/**
 * The patient key schedule — HKDF subkeys of the password-derived master
 * key, byte-identical to backend kdf.py and mobile kdf.ts:
 *
 *   auth_key = HKDF(master, salt=zeros, info="mindpattern/auth/v1")
 *              -> ONLY this crosses the network, as the login verifier
 *   data_key = HKDF(master, salt=zeros, info="mindpattern/data/v1")
 *              -> encrypts everything; leaves only inside a single-use
 *                 processing session or a therapist wrap
 *
 * Both subkeys are pinned by shared/vectors.json (`vectors` cases carry
 * auth_key AND data_key).
 */
import { hkdfSha256, zeroize, type Bytes, KEY_SIZE } from "./core";

const AUTH_INFO = new TextEncoder().encode("mindpattern/auth/v1");
const DATA_INFO = new TextEncoder().encode("mindpattern/data/v1");
/** HKDF salt for the master-key subkeys: RFC 5869 default (HashLen zeros),
 * matching backend kdf.hkdf_sha256(salt=None). */
const ZERO_SALT = new Uint8Array(new ArrayBuffer(32));

export interface PatientKeys {
  /** The master key is returned ONLY so the caller can zeroize it — no
   *  consumer downstream needs it (both subkeys are already derived). */
  masterKey: Bytes;
  authKey: Bytes;
  dataKey: Bytes;
}

/** Derive both patient subkeys from the master key. The caller owns the
 *  master key's lifecycle: zeroize it immediately after this call (the
 *  vault takes over auth/data). */
export async function derivePatientKeys(master: Bytes): Promise<PatientKeys> {
  const [authKey, dataKey] = await Promise.all([
    hkdfSha256(master, ZERO_SALT, AUTH_INFO, KEY_SIZE),
    hkdfSha256(master, ZERO_SALT, DATA_INFO, KEY_SIZE),
  ]);
  return { masterKey: master, authKey, dataKey };
}

export { zeroize };
