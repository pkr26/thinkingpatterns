/**
 * Therapist sharing — the PATIENT-side wrap of the data key (the direction
 * the portal only unwraps), ported from mobile's sharing.ts onto WebCrypto.
 * Must match backend/app/security/sharing.py byte for byte:
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
 * Pinned by shared/vectors.json wrap_vectors (both directions, plus the
 * deterministic-kek construction via encryptWithFixedNonce).
 */
import { buildAad } from "./aad";
import {
  decrypt,
  encrypt,
  encryptWithFixedNonce,
  fromBase64,
  hkdfSha256,
  toBase64,
  zeroize,
  KEY_SIZE,
  type Bytes,
} from "./core";

export const WRAP_CONTEXT = "consent-wrap";
const WRAP_INFO = new TextEncoder().encode("mindpattern/wrap/v1");
const SPKI_P256_B64_LENGTH = 124; // b64(91 bytes) — exact, so a wrong key fails fast

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto is unavailable in this browser");
  return c.subtle;
};

export interface TherapistWrap {
  /** b64 SPKI DER of the per-grant ephemeral P-256 public key. */
  ephemeralPubB64: string;
  /** b64 AES-256-GCM envelope of the data key under the derived KEK. */
  wrappedKeyB64: string;
}

/** The KEK derivation both wrap directions share. Exported for the vector
 *  pins (which verify these exact bytes end-to-end by opening the vector's
 *  wrapped blob). */
export async function deriveWrapKek(
  shared: Bytes,
  ephemeralSpki: Bytes,
  therapistSpki: Bytes,
): Promise<Bytes> {
  const salt = new Uint8Array(new ArrayBuffer(ephemeralSpki.length + therapistSpki.length));
  salt.set(ephemeralSpki, 0);
  salt.set(therapistSpki, ephemeralSpki.length);
  try {
    return await hkdfSha256(shared, salt, WRAP_INFO, KEY_SIZE);
  } finally {
    // shared is secret; salt is public input but module-owned here.
    zeroize(shared, salt);
  }
}

/** Wrap with a CALLER-SUPPLIED ephemeral private key — the deterministic
 *  core the vector pins and the P5 interop fixtures exercise; production
 *  callers use wrapDataKeyForTherapist, which generates the ephemeral
 *  pair and delegates here. */
export async function wrapWithEphemeralPrivate(
  ephemeralPrivateKey: CryptoKey,
  ephemeralPubSpki: Bytes,
  dataKey: Bytes,
  therapistPubSpkiB64: string,
  userId: string,
  therapistId: string,
): Promise<{ wrappedKeyB64: string }> {
  if (dataKey.length !== KEY_SIZE) throw new Error(`data key must be ${KEY_SIZE} bytes`);
  if (therapistPubSpkiB64.length !== SPKI_P256_B64_LENGTH) {
    throw new Error("therapist public key has the wrong format");
  }
  const therapistPubDer = fromBase64(therapistPubSpkiB64);
  if (therapistPubDer.length !== 91) {
    throw new Error("therapist public key has the wrong format");
  }
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  try {
    const therapistPub = await subtle().importKey("spki", therapistPubDer, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const sharedBits = await subtle().deriveBits({ name: "ECDH", public: therapistPub }, ephemeralPrivateKey, 256);
    shared = new Uint8Array(sharedBits);
    kek = await deriveWrapKek(shared, ephemeralPubSpki, therapistPubDer);
    const wrapped = await encrypt(kek, dataKey, buildAad(WRAP_CONTEXT, userId, therapistId));
    return { wrappedKeyB64: toBase64(wrapped) };
  } finally {
    zeroize(shared, kek, therapistPubDer);
  }
}

/** Wrap the data key to a therapist's public wrap key. The data key LEAVES
 *  the client exactly once, in this envelope — never in the clear. The
 *  therapist's public key comes from the server's pairing lookup; the
 *  userId/therapistId pair binds the envelope to this consent. */
export async function wrapDataKeyForTherapist(
  dataKey: Bytes,
  therapistPubSpkiB64: string,
  userId: string,
  therapistId: string,
): Promise<TherapistWrap> {
  const pair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  let ephSpki: Bytes | null = null;
  let pkcs8: Bytes | null = null;
  try {
    ephSpki = new Uint8Array(await subtle().exportKey("spki", pair.publicKey));
    pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
    const ephPriv = await subtle().importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const { wrappedKeyB64 } = await wrapWithEphemeralPrivate(
      ephPriv,
      ephSpki,
      dataKey,
      therapistPubSpkiB64,
      userId,
      therapistId,
    );
    return { ephemeralPubB64: toBase64(ephSpki), wrappedKeyB64 };
  } finally {
    // The exported PKCS#8 of the ephemeral key never needed to exist as
    // bytes at all (WebCrypto could hold the handle); re-importing
    // non-extractable is the one reason it does — wipe it right after.
    zeroize(ephSpki, pkcs8);
  }
}

/** The patient-side UNWRAP of a wrap made for THIS account — used by the
 *  rewrap flow (P7) to verify the current wrap still opens before
 *  replacing it, and by tests to pin both directions. Same construction as
 *  the portal's unwrapPatientDataKey. */
export async function unwrapDataKey(
  therapistPrivateKey: CryptoKey,
  therapistPubSpkiB64: string,
  ephemeralPubSpkiB64: string,
  wrappedKeyB64: string,
  userId: string,
  therapistId: string,
): Promise<Bytes> {
  const ephDer = fromBase64(ephemeralPubSpkiB64);
  const thDer = fromBase64(therapistPubSpkiB64);
  const wrapped = fromBase64(wrappedKeyB64);
  let shared: Bytes | null = null;
  let kek: Bytes | null = null;
  try {
    const ephPub = await subtle().importKey("spki", ephDer, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const sharedBits = await subtle().deriveBits({ name: "ECDH", public: ephPub }, therapistPrivateKey, 256);
    shared = new Uint8Array(sharedBits);
    kek = await deriveWrapKek(shared, ephDer, thDer);
    return await decrypt(kek, wrapped, buildAad(WRAP_CONTEXT, userId, therapistId));
  } finally {
    zeroize(ephDer, thDer, wrapped, shared, kek);
  }
}

/** Human-verifiable fingerprint of a therapist's public wrap key:
 * SHA-256 over the SPKI DER, first 16 bytes as eight spaced hex groups
 * ("A1B2 C3D4 E5F6 0718 …"). The portal shows the SAME string next to its
 * pairing code, so the two humans can read it back to each other and
 * notice a substituted key — the out-of-band check. Formatting is pinned
 * identical to mobile and the portal (a shared fixture in P5 pins all
 * three at once).
 *
 * 16 bytes (128 bits): the old 32-bit prefix let a determined attacker
 * grind a colliding P-256 key and defeat the read-back. */
export async function keyFingerprint(spkiB64: string): Promise<string> {
  const digest = new Uint8Array(await subtle().digest("SHA-256", fromBase64(spkiB64)));
  let hex = "";
  for (const byte of digest.subarray(0, 16)) hex += byte.toString(16).padStart(2, "0");
  hex = hex.toUpperCase();
  return hex.match(/.{4}/g)?.join(" ") ?? hex;
}
