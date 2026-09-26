/**
 * WebCrypto core — the browser mirror of the backend's contracts
 * (backend/app/security/{kdf,crypto}.py), pinned byte-for-byte by
 * shared/vectors.json (see tests/crypto.test.ts). Forked from the
 * portal's crypto core with the deterministic-nonce seam the mobile
 * envelope exports (needed by the vector pins and later by the P5
 * interop-fixture generator).
 *
 * Key schedule (identical labels on every platform):
 *   master    = PBKDF2-HMAC-SHA256(password, salt, 600_000)
 *   auth_key  = HKDF-SHA256(master, salt=zeros, info="mindpattern/auth/v1")
 *   data_key  = HKDF-SHA256(master, salt=zeros, info="mindpattern/data/v1")
 */

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto is unavailable in this browser");
  return c.subtle;
};

export const KDF_ITERATIONS = 600_000;
/** Runtime floor for caller-supplied iteration counts, mirroring the
 *  backend's kdf.MIN_ITERATIONS and mobile's kdf.ts (red-team finding A4):
 *  no honest code path can silently downgrade the 600k contract. */
export const MIN_ITERATIONS = 100_000;
const MIN_SALT_SIZE = 8;
export const KEY_SIZE = 32;
/** Byte buffers are always ArrayBuffer-backed: WebCrypto's BufferSource
 * rejects the ArrayBufferLike default of a bare Uint8Array annotation. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** Best-effort erasure for buffers this module owns.  WebCrypto key handles
 * are deliberately non-extractable and cannot be overwritten; byte arrays
 * decoded, derived, or decrypted transiently can and must be. */
export function zeroize(...buffers: Array<Uint8Array | null | undefined>): void {
  for (const buffer of buffers) buffer?.fill(0);
}

const b64 = (bytes: Bytes): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

const unb64 = (text: string): Bytes => {
  const binary = atob(text);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
};

export { b64 as toBase64, unb64 as fromBase64 };

async function hkdf(ikm: BufferSource, salt: BufferSource, info: BufferSource, length: number): Promise<Bytes> {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

export async function deriveMasterKey(
  password: string,
  salt: Bytes,
  iterations: number = KDF_ITERATIONS,
): Promise<Bytes> {
  if (salt.length < MIN_SALT_SIZE) throw new Error(`salt must be at least ${MIN_SALT_SIZE} bytes`);
  if (iterations < MIN_ITERATIONS) {
    throw new Error(
      `iterations must be at least ${MIN_ITERATIONS} ` +
        `(got ${iterations}; the cross-platform contract is ${KDF_ITERATIONS})`,
    );
  }
  const key = await subtle().importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    KEY_SIZE * 8,
  );
  return new Uint8Array(bits);
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
  return encryptWithFixedNonce(key, plaintext, globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(NONCE_SIZE)) as Bytes), aad);
}

/** Deterministic envelope construction with a caller-supplied nonce. This is
 *  the test/fixture seam the mobile envelope also exports: the shared
 *  vectors and the P5 interop fixtures pin exact bytes, which a random nonce
 *  cannot reproduce. Production callers use encrypt(). */
export async function encryptWithFixedNonce(
  key: Bytes,
  plaintext: Bytes,
  nonce: Bytes,
  aad?: Bytes,
): Promise<Bytes> {
  if (key.length !== KEY_SIZE) throw new Error(`key must be ${KEY_SIZE} bytes`);
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
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

/** HKDF-SHA256 with an explicit salt (the wrap construction salts with both
 *  SPKI DERs, unlike the zero-salt subkey schedule). Exported because the
 *  wrap path and its vector pins exercise exactly these bytes. */
export async function hkdfSha256(
  ikm: BufferSource,
  salt: BufferSource,
  info: BufferSource,
  length: number,
): Promise<Bytes> {
  return hkdf(ikm, salt, info, length);
}
