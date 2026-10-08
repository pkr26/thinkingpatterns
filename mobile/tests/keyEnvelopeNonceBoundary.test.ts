import { expect, it } from "vitest";
import { wrapDataKeyWithFixedNonce, type KdfParams } from "../src/crypto/keyEnvelope";

it("rejects an invalid fixed-vector nonce before evaluating fallible AAD serialization", () => {
  const params: KdfParams & { toJSON(): never } = {
    algorithm: "pbkdf2-sha256", version: 1, iterations: 600000,
    toJSON() { throw new Error("AAD serialization is unavailable"); },
  };
  expect(() => wrapDataKeyWithFixedNonce(Buffer.alloc(32), Buffer.alloc(32), "alice", params, Buffer.alloc(11))).toThrow("nonce must be 12 bytes");
  expect(() => wrapDataKeyWithFixedNonce(Buffer.alloc(32), Buffer.alloc(32), "alice", params, Buffer.alloc(12))).toThrow("AAD serialization is unavailable");
});
