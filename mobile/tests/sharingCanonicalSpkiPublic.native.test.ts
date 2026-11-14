/** Public therapist-key format boundary: trailing bytes are refused even
 * when the native DER parser accepts the same underlying public P-256 key. */
import { expect, it } from "vitest";
import { wrapDataKeyForTherapist } from "../src/crypto/sharing";

const PUBLIC_SPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";

it.each([1, 2])("refuses a therapist public key with %s trailing zero bytes", trailing => {
  const padded = Buffer.concat([Buffer.from(PUBLIC_SPKI, "base64"), Buffer.alloc(trailing)]).toString("base64");
  const key = Buffer.alloc(32, 7);
  try {
    expect(() => wrapDataKeyForTherapist(key, padded, "a".repeat(32), "b".repeat(32))).toThrow();
  } finally {
    key.fill(0);
  }
});
