/**
 * Mutation pins for portal/src/crypto.ts (2026-09-18 Stryker campaign).
 *
 * The portal's first Stryker run (2,262 mutants, 1.41% baseline) showed
 * the vector suite pins everything SHARED with the backend, but the
 * portal-only seams survived: the two portal HKDF subkeys (any
 * self-consistent key passes a round-trip), the cross-binding failures
 * (a blob sealed for one identity decrypting under another), and the
 * wrong-key-size guards. These pins close exactly those holes; expected
 * bytes derive from backend kdf.hkdf_sha256 over the shared vector's
 * master key (same standing as the vector corpus).
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decryptNote,
  deriveMasterKey,
  derivePortalKeys,
  encrypt,
  encryptNote,
  KEY_SIZE,
  sealPrivateKeyForUpload,
  TamperError,
  unlockWrapPrivateKey,
  type Bytes,
} from "../src/crypto";

const here = import.meta.dirname;
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf-8")) as {
  vectors: Array<{ password: string; salt: string; master_key: string }>;
};

const VECTOR = vectors[0]!;
// hkdf_sha256(master, zeros-salt, info) — computed with the backend
// reference implementation over VECTOR's master key.
const WRAP_KEK_B64 = "aiSOaHb+PxjD+yirFw3cFdb7PTrJAlxKnZP0/C8MqVI=";
const NOTE_KEY_B64 = "+0vQ36KZhGkGhXDlFWW/2EXSh4gpJ0rvDh10cd0+GR0=";

const unb64 = (text: string): Bytes => {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
};

describe("portal-only HKDF subkeys (mutation pins)", () => {
  it("the wrap KEK is the backend-derived portal-wrap subkey, byte-for-byte", async () => {
    const master = unb64(VECTOR.master_key);
    const { wrapKek } = await derivePortalKeys(master);
    expect(btoa(String.fromCharCode(...wrapKek))).toBe(WRAP_KEK_B64);
  });

  it("the note key is the backend-derived portal-notes subkey, byte-for-byte", async () => {
    const master = unb64(VECTOR.master_key);
    const { noteKey } = await derivePortalKeys(master);
    expect(btoa(String.fromCharCode(...noteKey))).toBe(NOTE_KEY_B64);
  });

  it("auth, wrap, and notes are three DISTINCT subkeys of one master", async () => {
    const master = await deriveMasterKey(VECTOR.password, unb64(VECTOR.salt));
    // Audit fix P-1 (2026-09-20): the auth verifier is returned as raw bytes
    // (its base64 is derived only at the network send), so this pin encodes
    // the derivation instead of reading a string field.
    const { authKey, wrapKek, noteKey } = await derivePortalKeys(master);
    const b64 = (b: Bytes) => btoa(String.fromCharCode(...b));
    expect(b64(authKey)).not.toBe(b64(wrapKek));
    expect(b64(authKey)).not.toBe(b64(noteKey));
    expect(b64(wrapKek)).not.toBe(b64(noteKey));
  });
});

describe("identity cross-binding (mutation pins)", () => {
  it("a private key sealed for one therapist does not unlock under another username", async () => {
    const master = unb64(VECTOR.master_key);
    const { wrapKek } = await derivePortalKeys(master);
    const sealed = await sealPrivateKeyForUpload(
      wrapKek,
      // Any PKCS#8-shaped bytes suffice — the failure must happen at the
      // GCM authentication layer, before key parsing. Audit fix P-1
      // (2026-09-20): the DER is passed as raw bytes; a base64 string of a
      // private key no longer exists anywhere in the flow.
      unb64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQGGdG0="),
      "alice",
    );
    await expect(unlockWrapPrivateKey(wrapKek, sealed, "mallory")).rejects.toThrow(
      TamperError,
    );
  });

  it("a note sealed for one (therapist, patient, note) triple fails under every wrong id", async () => {
    const master = unb64(VECTOR.master_key);
    const { noteKey } = await derivePortalKeys(master);
    const sealed = await encryptNote(noteKey, "t1", "p1", "n1", "patient feels...");
    await expect(decryptNote(noteKey, "t2", "p1", "n1", sealed.blobB64)).rejects.toThrow(
      TamperError,
    );
    await expect(decryptNote(noteKey, "t1", "p2", "n1", sealed.blobB64)).rejects.toThrow(
      TamperError,
    );
    await expect(decryptNote(noteKey, "t1", "p1", "n2", sealed.blobB64)).rejects.toThrow(
      TamperError,
    );
    await expect(decryptNote(noteKey, "t1", "p1", "n1", sealed.blobB64)).resolves.toBe(
      "patient feels...",
    );
  });
});

describe("envelope guards (mutation pins)", () => {
  it("encrypt refuses a wrong-size key with the size named in the error", async () => {
    const short = new Uint8Array(KEY_SIZE - 1) as Bytes;
    await expect(encrypt(short, new Uint8Array(1))).rejects.toThrow(/32 bytes/);
  });

  it("two encryptions of one plaintext never share a nonce (distinct blobs)", async () => {
    const key = unb64(NOTE_KEY_B64);
    const a = await encrypt(key, new TextEncoder().encode("same plaintext") as Bytes);
    const b = await encrypt(key, new TextEncoder().encode("same plaintext") as Bytes);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});
