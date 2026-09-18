/**
 * Therapist sharing: the patient-side wrap of the data key — must match
 * backend/app/security/sharing.py and the web portal byte for byte.
 *
 *   shared = ECDH-P256(ephemeral_priv, therapist_pub)
 *   kek    = HKDF-SHA256(shared, salt = ephemeral_spki || therapist_spki,
 *                        info = "mindpattern/wrap/v1")
 *   wrap   = AES-256-GCM(kek, data_key,
 *                        aad = buildAad("consent-wrap", userId, therapistId))
 *
 * Public keys travel as base64 SPKI DER (91 bytes for P-256). The HKDF salt
 * pins BOTH public keys into the KEK — a wrap made for one therapist can
 * never be replayed against another — and the AAD pins the (patient,
 * therapist) pair so the server cannot relocate a wrap between consents.
 *
 * Cross-platform outputs are pinned by shared/vectors.json (wrap_vectors);
 * run `npm test` (the real modules under node:crypto) to verify.
 */
import { buildAad } from "./aad";
import { engine } from "./engine";
import { encrypt } from "./envelope";
import { zeroize } from "./kdf";

export const WRAP_CONTEXT = "consent-wrap";
const CURVE = "prime256v1";
const KEY_SIZE = 32;
const SPKI_P256_B64_LENGTH = 124; // b64(91 bytes) — exact, so a wrong key fails fast

// HKDF info rebuilt at call time (same standing as kdf.ts): every wrap
// exercises the exact label bytes.
function wrapInfo(): Buffer {
  return Buffer.from("mindpattern/wrap/v1", "utf8");
}

export interface TherapistWrap {
  /** b64 SPKI DER of the per-grant ephemeral P-256 public key. */
  ephemeralPubB64: string;
  /** b64 AES-256-GCM envelope of the data key under the derived KEK. */
  wrappedKeyB64: string;
}

/** HKDF-SHA256 over the ECDH secret with both public keys as the salt.
 * Exported for the vector test (which pins these exact bytes); production
 * callers use wrapDataKeyForTherapist. */
export function deriveWrapKek(shared: Buffer, ephemeralSpki: Buffer, therapistSpki: Buffer): Buffer {
  const derived = engine.hkdfSync(
    "sha256",
    shared,
    Buffer.concat([ephemeralSpki, therapistSpki]),
    wrapInfo(),
    KEY_SIZE,
  );
  return Buffer.from(derived as ArrayBuffer);
}

/**
 * Wrap the data key to a therapist's public wrap key. The data key LEAVES
 * the device exactly once, in this envelope — never in the clear. The
 * therapist's public key comes from the server's pairing lookup; the
 * userId/therapistId pair binds the envelope to this consent.
 */
export function wrapDataKeyForTherapist(
  dataKey: Buffer,
  therapistPubSpkiB64: string,
  userId: string,
  therapistId: string,
): TherapistWrap {
  if (dataKey.length !== KEY_SIZE) {
    throw new Error(`data key must be ${KEY_SIZE} bytes`);
  }
  // b64(91 bytes) is exactly 124 chars: a wrong-format key fails fast here,
  // and Buffer.from's lenient base64 decoding cannot mask a wrong size.
  if (therapistPubSpkiB64.length !== SPKI_P256_B64_LENGTH) {
    throw new Error("therapist public key has the wrong format");
  }
  const therapistPubDer = Buffer.from(therapistPubSpkiB64, "base64");
  if (therapistPubDer.length !== 91) {
    throw new Error("therapist public key has the wrong format");
  }

  const ephemeral = engine.generateKeyPairSync("ec", { namedCurve: CURVE });
  const ephemeralSpki = ephemeral.publicKey.export({ format: "der", type: "spki" });
  const shared = engine.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: engine.createPublicKey({ key: therapistPubDer, format: "der", type: "spki" }),
  });
  const kek = deriveWrapKek(shared, ephemeralSpki, therapistPubDer);
  const wrapped = encrypt(kek, dataKey, buildAad(WRAP_CONTEXT, userId, therapistId));
  zeroize(shared, kek);
  return {
    ephemeralPubB64: ephemeralSpki.toString("base64"),
    wrappedKeyB64: wrapped.toString("base64"),
  };
}

/** Human-verifiable fingerprint of a therapist's public wrap key:
 * SHA-256 over the SPKI DER, first 8 bytes as four spaced hex groups
 * ("A1B2 C3D4 E5F6 0718"). The portal shows the SAME string next to its
 * pairing code, so a patient can read it back to the therapist (or vice
 * versa) and notice a substituted key — the out-of-band check the
 * 2026-09-17 audit asked for: the server relays the key at pairing
 * lookup, and without a fingerprint nothing binds that key to the human.
 * Both platforms format identically (pinned by tests). */
export function therapistKeyFingerprint(therapistPubSpkiB64: string): string {
  const digest = engine.createHash("sha256").update(Buffer.from(therapistPubSpkiB64, "base64")).digest();
  const hex = digest.subarray(0, 8).toString("hex").toUpperCase();
  return hex.match(/.{4}/g)?.join(" ") ?? hex;
}
