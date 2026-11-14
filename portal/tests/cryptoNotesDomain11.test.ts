import { expect, it } from "vitest";

import { derivePortalKeys } from "../src/crypto";

it("derives the legacy portal notes key from its documented domain label", async () => {
  const master = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const key = await globalThis.crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const expected = new Uint8Array(await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("mindpattern/portal-notes/v1"),
    },
    key,
    256,
  ));

  const actual = await derivePortalKeys(master);
  expect(Array.from(actual.noteKey)).toEqual(Array.from(expected));
});
