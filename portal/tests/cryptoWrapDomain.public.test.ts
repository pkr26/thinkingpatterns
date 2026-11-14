import { describe, expect, it } from "vitest";
import { derivePortalKeys } from "../src/crypto";

const ZERO_SALT = new Uint8Array(32);
const master = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

async function expectedSubkey(infoText: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: new TextEncoder().encode(infoText) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

describe("portal key schedule domain labels", () => {
  it("derives the wrap KEK with the public portal wrap domain label", async () => {
    const keys = await derivePortalKeys(master);
    expect(Array.from(keys.wrapKek)).toEqual(Array.from(await expectedSubkey("mindpattern/portal-wrap/v1")));
  });
});
