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
