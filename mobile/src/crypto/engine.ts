/**
 * Crypto backend seam.
 *
 * The app runs on react-native-quick-crypto. Tools and tests run under
 * Node, where quick-crypto cannot resolve — there the identical API surface
 * of node:crypto backs the same modules. This is what lets the vector
 * verifier and vitest suite execute the REAL shipping crypto code instead
 * of a parallel reimplementation that could silently drift.
 */

export interface CryptoEngine {
  randomBytes(size: number): Buffer;
  pbkdf2Sync(password: string | Buffer, salt: Buffer, iterations: number, keylen: number, digest: string): Buffer;
  /** The async form: quick-crypto (>= 0.7) runs the derivation on its
   *  native JSI worker and node:crypto on the libuv thread pool — both keep
   *  the JS thread free, unlike pbkdf2Sync's ~100-400ms freeze at 600k
   *  iterations. Node-style callback; a missing derivedKey on success is
   *  treated as an error by the caller. */
  pbkdf2(
    password: string | Buffer,
    salt: Buffer,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey?: Buffer) => void,
  ): void;
  hkdfSync(digest: string, ikm: Buffer, salt: Buffer, info: Buffer, length: number): ArrayBuffer;
  createCipheriv(algorithm: string, key: Buffer, iv: Buffer): {
    setAAD(aad: Buffer): unknown;
    update(data: Buffer): Buffer;
    final(): Buffer;
    getAuthTag(): Buffer;
  };
  createDecipheriv(algorithm: string, key: Buffer, iv: Buffer): {
    setAuthTag(tag: Buffer): unknown;
    setAAD(aad: Buffer): unknown;
    update(data: Buffer): Buffer;
    final(): Buffer;
  };
  // --- therapist sharing (2026-09-16): the EC subset used by the data-key
  // wrap. Mirrors node:crypto / quick-crypto exactly (generateKeyPairSync
  // for "ec", KeyObject DER import/export, diffieHellman) so the same cast
  // in loadEngine covers both backends.
  /** Opaque EC key handle — the KeyObject surface the sharing code touches
   *  (DER export only; nothing else is observable through the seam). */
  generateKeyPairSync(
    type: "ec",
    options: { namedCurve: string },
  ): { publicKey: EcKeyObject; privateKey: EcKeyObject };
  createPublicKey(input: { key: Buffer; format: "der"; type: "spki" }): EcKeyObject;
  diffieHellman(config: { privateKey: EcKeyObject; publicKey: EcKeyObject }): Buffer;
}

/** The KeyObject subset the sharing code relies on. KeyObjects are opaque;
 *  DER export is the one operation shared verbatim by both backends. */
export interface EcKeyObject {
  export(options: { format: "der"; type: "spki" | "pkcs8" }): Buffer;
}

// Metro (React Native) and tsc-emitted CJS provide require(); declare it
// locally so typechecking does not depend on @types/node.
declare const require: ((id: string) => unknown) | undefined;

type RequireFn = (id: string) => unknown;

// vite-node, Metro and every CJS host provide require(). An ESM-only host
// does not, and the bare reference below throws ReferenceError at import —
// loud on purpose: a silently wrong crypto backend would be worse.
function hostRequire(): RequireFn {
  return require as RequireFn;
}

/**
 * Resolve the crypto backend. The require function is injectable so every
 * branch is testable: on a device it returns the native quick-crypto addon;
 * under plain-node tools the addon fails to load and node:crypto implements
 * the same API surface.
 */
export function loadEngine(req: RequireFn = hostRequire()): CryptoEngine {
  try {
    return req("react-native-quick-crypto") as CryptoEngine;
  } catch {
    return req("node:crypto") as CryptoEngine;
  }
}

export const engine: CryptoEngine = loadEngine();
