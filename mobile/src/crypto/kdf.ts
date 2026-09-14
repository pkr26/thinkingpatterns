/**
 * Client-side key schedule — must match backend/app/security/kdf.py exactly.
 *
 *   master_key = PBKDF2-HMAC-SHA256(password, salt, 600_000)
 *   auth_key   = HKDF-SHA256(master_key, info="mindpattern/auth/v1")  -> sent to server
 *   data_key   = HKDF-SHA256(master_key, info="mindpattern/data/v1")  -> never leaves
 *                                                            the device, except into a
 *                                                            TLS-delivered, single-use
 *                                                            processing session.
 *
 * Byte-for-byte compatibility is pinned by shared/vectors.json; run
 * `npm test` (the real modules against the vectors) — it replaces the old
 * webcrypto-only reference check.
 */
import { engine } from "./engine";

export const KDF_ITERATIONS = 600_000;
const MIN_SALT_SIZE = 8;

// HKDF info strings are rebuilt at call time, not captured at module scope:
// every derivation then exercises (and mutation-tests) the exact label
// bytes, and no warm test worker can cache a stale value.
function authInfo(): Buffer {
  // "utf8" is Buffer's default; an empty encoding string decodes identically.
// Stryker disable StringLiteral
return Buffer.from("mindpattern/auth/v1", "utf8");
// Stryker restore StringLiteral
}

function dataInfo(): Buffer {
  // Stryker disable StringLiteral
return Buffer.from("mindpattern/data/v1", "utf8");
  // Stryker restore StringLiteral
}

export function deriveMasterKey(password: string, salt: Buffer, iterations = KDF_ITERATIONS): Buffer {
  if (salt.length < MIN_SALT_SIZE) {
    throw new Error(`salt must be at least ${MIN_SALT_SIZE} bytes`);
  }
  if (iterations < 1) {
    throw new Error("iterations must be positive");
  }
  return engine.pbkdf2Sync(password, salt, iterations, 32, "sha256");
}

/**
 * The async derivation — PREFER this in UI paths. The sync form freezes
 * the JS thread for ~100-400ms at 600k iterations; the engine's async
 * pbkdf2 (quick-crypto's JSI worker on device, node:crypto's thread pool
 * in tests) keeps the UI responsive. Same bytes, same vectors.
 */
export async function deriveMasterKeyAsync(
  password: string,
  salt: Buffer,
  iterations = KDF_ITERATIONS,
): Promise<Buffer> {
  if (salt.length < MIN_SALT_SIZE) {
    throw new Error(`salt must be at least ${MIN_SALT_SIZE} bytes`);
  }
  if (iterations < 1) {
    throw new Error("iterations must be positive");
  }
  return new Promise((resolve, reject) => {
    engine.pbkdf2(password, salt, iterations, 32, "sha256", (err, derivedKey) => {
      if (err) {
        reject(err);
        return;
      }
      if (!derivedKey) {
        reject(new Error("pbkdf2 produced no key"));
        return;
      }
      resolve(Buffer.from(derivedKey));
    });
  });
}

export function deriveAuthKey(masterKey: Buffer): Buffer {
  // Empty salt -> RFC 5869 default of HashLen zeros, matching the backend.
  return hkdfSha256(masterKey, authInfo());
}

export function deriveDataKey(masterKey: Buffer): Buffer {
  return hkdfSha256(masterKey, dataInfo());
}

/**
 * hkdfSync returns an ArrayBuffer (Node API parity in quick-crypto), not a
 * Buffer — wrap it so Buffer methods (toString("base64"), fill, subarray)
 * actually exist on the result.
 */
function hkdfSha256(ikm: Buffer, info: Buffer): Buffer {
  const derived = engine.hkdfSync("sha256", ikm, Buffer.alloc(32), info, 32);
  return Buffer.from(derived as ArrayBuffer);
}

/** Overwrite key material buffers as soon as they are no longer needed. */
export function zeroize(...buffers: (Buffer | undefined | null)[]): void {
  for (const buf of buffers) {
    if (buf) buf.fill(0);
  }
}
