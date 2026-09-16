/**
 * AES-256-GCM envelope — must match backend/app/security/crypto.py exactly.
 *
 * Wire format:  nonce(12) || ciphertext || tag(16)
 * AAD binds the blob to (context, userId, itemId) so a hostile server cannot
 * relocate blobs between entries or users undetected (see aad.ts for the
 * canonical encoding contract).
 */
import { buildAad } from "./aad";
import { engine } from "./engine";

export const NONCE_SIZE = 12;
export const KEY_SIZE = 32;
const ALGO = "aes-256-gcm";

export { buildAad };

export function generateKey(): Buffer {
  return engine.randomBytes(KEY_SIZE);
}

export function encrypt(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  // The nonce is ALWAYS fresh and random — deterministic output is a
  // nonce-reuse hazard, so the fixed-nonce path is deliberately NOT
  // reachable through this signature. Test-vector generation uses
  // encryptWithFixedNonce below (unmistakably named, never called from a
  // production path).
  return encryptWithFixedNonce(key, plaintext, aad, engine.randomBytes(NONCE_SIZE));
}

/** Fixed-nonce encryption — TEST/VECTOR GENERATION ONLY (never import from
 *  a screen or store path). shared/vectors.json pins this output; mirrors
 *  the backend's crypto.encrypt_with_nonce seam removal (2026-09-16). */
export function encryptWithFixedNonce(
  key: Buffer,
  plaintext: Buffer,
  aad: Buffer | undefined,
  nonce: Buffer,
): Buffer {
  if (key.length !== KEY_SIZE) throw new Error(`key must be ${KEY_SIZE} bytes`);
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  const cipher = engine.createCipheriv(ALGO, key, nonce);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

export class TamperError extends Error {
  constructor() {
    super("blob failed authentication");
    this.name = "TamperError";
  }
}

export function decrypt(key: Buffer, blob: Buffer, aad?: Buffer): Buffer {
  if (key.length !== KEY_SIZE) throw new Error(`key must be ${KEY_SIZE} bytes`);
  if (blob.length < NONCE_SIZE + 16) throw new TamperError();
  const nonce = blob.subarray(0, NONCE_SIZE);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(NONCE_SIZE, blob.length - 16);
  const decipher = engine.createDecipheriv(ALGO, key, nonce);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new TamperError();
  }
}
