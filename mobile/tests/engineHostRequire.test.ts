import { expect, it } from "vitest";

it("the exported default loader resolves a usable host crypto engine when called after module import", async () => {
  const { loadEngine } = await import("../src/crypto/engine");
  const engine = loadEngine();
  expect(engine.randomBytes(16)).toHaveLength(16);
  const key = engine.pbkdf2Sync("host loader password", Buffer.alloc(16, 7), 1, 32, "sha256");
  expect(key).toHaveLength(32);
  const cipher = engine.createCipheriv("aes-256-gcm", key, Buffer.alloc(12, 3));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from("host loader plaintext")), cipher.final()]);
  const decipher = engine.createDecipheriv("aes-256-gcm", key, Buffer.alloc(12, 3));
  decipher.setAuthTag(cipher.getAuthTag());
  expect(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")).toBe("host loader plaintext");
});
