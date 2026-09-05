/**
 * engine.ts loader branches, imported lazily inside each test so that a
 * mutant breaking module initialization fails the TEST (a collection-level
 * failure is invisible to mutation runners' kill accounting).
 */
import { describe, expect, it } from "vitest";
import nodeCrypto from "node:crypto";

describe("crypto engine loader", () => {
  it("module-level engine resolves a working backend via require()", async () => {
    const { engine } = await import("../src/crypto/engine");
    // vite-node's require + the quickCryptoMock alias -> node:crypto.
    expect(engine.randomBytes(4)).toHaveLength(4);
    expect(engine.pbkdf2Sync("pw", Buffer.alloc(8), 1, 32, "sha256")).toHaveLength(32);
  });

  it("prefers react-native-quick-crypto when the resolver provides it", async () => {
    const { loadEngine } = await import("../src/crypto/engine");
    const sentinel = { randomBytes: () => Buffer.alloc(0) } as never;
    const req = (id: string) => (id === "react-native-quick-crypto" ? sentinel : nodeCrypto);
    expect(loadEngine(req)).toBe(sentinel);
  });

  it("falls back to node:crypto when quick-crypto cannot load", async () => {
    const { loadEngine } = await import("../src/crypto/engine");
    const req = (id: string) => {
      if (id === "react-native-quick-crypto") throw new Error("native addon unavailable");
      if (id === "node:crypto") return nodeCrypto;
      throw new Error(`unexpected require: ${id}`);
    };
    const resolved = loadEngine(req);
    expect(Buffer.from(resolved.hkdfSync("sha256", Buffer.alloc(32, 1), Buffer.alloc(32), Buffer.alloc(0), 32) as ArrayBuffer)).toHaveLength(32);

    const cipher = resolved.createCipheriv("aes-256-gcm", Buffer.alloc(32, 2), Buffer.alloc(12, 3));
    cipher.setAAD(Buffer.from("aad"));
    const ct = Buffer.concat([cipher.update(Buffer.from("m")), cipher.final()]);
    expect(ct.length).toBe(1);
    expect(cipher.getAuthTag()).toHaveLength(16);
  });

  it("fails loudly when no require() exists at all", async () => {
    const { loadEngine } = await import("../src/crypto/engine");
    // In an ESM-only host the bare `require` reference throws
    // ReferenceError at module load — loud on purpose.
    const req = () => {
      throw new ReferenceError("require is not defined");
    };
    expect(() => loadEngine(req)).toThrow(ReferenceError);
  });
});
