import nodeCrypto from "node:crypto";
import { expect, it } from "vitest";
import { unsealDataKeyWithRecoveryScheme } from "../src/crypto/recovery";

it("opens only the declared recovery generation and refuses an authentic blob from the other generation", () => {
  const owner = "a".repeat(32), recoveryKey = Buffer.alloc(32, 3), dataKey = Buffer.alloc(32, 4);
  for (const scheme of ["v1", "v2"] as const) {
    const label = scheme === "v1" ? "mindpattern/recovery/v1" : "mindpattern/recovery-seal/v2";
    const kek = Buffer.from(nodeCrypto.hkdfSync("sha256", recoveryKey, Buffer.alloc(32), Buffer.from(label), 32));
    const nonce = Buffer.alloc(12, scheme === "v1" ? 5 : 6);
    const cipher = nodeCrypto.createCipheriv("aes-256-gcm", kek, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify(["recovery", owner, "data-key"]), "ascii"));
    const sealed = Buffer.concat([nonce, cipher.update(dataKey), cipher.final(), cipher.getAuthTag()]);
    try {
      expect(unsealDataKeyWithRecoveryScheme(recoveryKey, sealed, owner, scheme)).toEqual(dataKey);
      expect(unsealDataKeyWithRecoveryScheme(recoveryKey, sealed, owner, scheme === "v1" ? "v2" : "v1")).toBeNull();
    } finally { kek.fill(0); sealed.fill(0); }
  }
});
