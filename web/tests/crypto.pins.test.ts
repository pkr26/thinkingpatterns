/**
 * Security pins beyond the shared vectors (WEB_PLAN P2.4/P2.5): subkey
 * separation, nonce uniqueness, the first tamper/fuzz tranche (every
 * corrupted envelope fails CLOSED — never a wrong plaintext, never a
 * crash), and zeroization of decrypt-path buffers.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { buildAad } from "../src/crypto/aad";
import {
  decrypt,
  encrypt,
  encryptWithFixedNonce,
  fromBase64,
  hkdfSha256,
  toBase64,
  type Bytes,
  KEY_SIZE,
} from "../src/crypto/core";
import { decryptEntry, encryptEntry } from "../src/crypto/patient";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { encrypt_vectors: encryptVectors } = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  encrypt_vectors: { data_key: string; plaintext: string; aad_parts: string[]; nonce: string }[];
};

const dataKey = fromBase64(encryptVectors[0]!.data_key);
const plaintext = fromBase64(encryptVectors[0]!.plaintext);
const aad = buildAad(...encryptVectors[0]!.aad_parts);

describe("subkey separation", () => {
  it("auth and data subkeys are never the same bytes", async () => {
    // From an arbitrary master: the two HKDF labels must diverge.
    const master = fromBase64(encryptVectors[0]!.data_key); // any 32 bytes as IKM
    const zeroSalt = new Uint8Array(new ArrayBuffer(32));
    const auth = await hkdfSha256(master, zeroSalt, new TextEncoder().encode("mindpattern/auth/v1"), KEY_SIZE);
    const data = await hkdfSha256(master, zeroSalt, new TextEncoder().encode("mindpattern/data/v1"), KEY_SIZE);
    expect(toBase64(auth)).not.toBe(toBase64(data));
  });
});

describe("nonce uniqueness", () => {
  it("two encryptions of the same plaintext never share a blob", async () => {
    const one = await encrypt(dataKey, plaintext, aad);
    const two = await encrypt(dataKey, plaintext, aad);
    expect(toBase64(one)).not.toBe(toBase64(two));
    // ...and both open cleanly: the divergence is the nonce, not the key.
    expect(toBase64(await decrypt(dataKey, one, aad))).toBe(encryptVectors[0]!.plaintext);
    expect(toBase64(await decrypt(dataKey, two, aad))).toBe(encryptVectors[0]!.plaintext);
  });
});

/** First tamper/fuzz tranche (WEB_PLAN P2.5): every corrupted envelope must
 *  raise TamperError — never return wrong plaintext, never crash with an
 *  unrelated error. Positions cover the nonce, ciphertext body, and the
 *  GCM tag; truncations cover every short length. */
function bitFlips(blob: Bytes): Bytes[] {
  const positions = [0, 5, 11, 12, blob.length - 17, Math.floor(blob.length / 2), blob.length - 1];
  return positions.map((position) => {
    const copy = new Uint8Array(new ArrayBuffer(blob.length));
    copy.set(blob);
    copy[position]! ^= 0x01;
    return copy;
  });
}

describe("systematic byte-offset fuzz (P9.3 deepening)", () => {
  it("every single-byte corruption across a full envelope fails closed", async () => {
    const blob = await encrypt(dataKey, plaintext, aad);
    let rejected = 0;
    for (let position = 0; position < blob.length; position += 1) {
      for (const mask of [0x01, 0x80, 0xff]) {
        const copy = new Uint8Array(new ArrayBuffer(blob.length));
        copy.set(blob);
        copy[position]! ^= mask;
        const outcome = await decrypt(dataKey, copy, aad).then(() => "opened", (err: unknown) => err instanceof Error ? err.name : "threw");
        // The ONLY acceptable outcomes are rejection (TamperError) — never
        // a wrong-plaintext open. (Nonce-bit flips also reject: the tag
        // covers the nonce implicitly through GCM's construction.)
        if (outcome === "TamperError") rejected += 1;
        else if (outcome === "opened") throw new Error(`byte ${position} mask ${mask}: corrupted blob OPENED`);
        else throw new Error(`byte ${position} mask ${mask}: unexpected ${outcome}`);
      }
    }
    expect(rejected).toBe(blob.length * 3);
  });
});

describe("tamper tranche: raw envelope", () => {
  it("every single-bit flip fails authentication", async () => {
    const blob = await encrypt(dataKey, plaintext, aad);
    for (const flipped of bitFlips(blob)) {
      await expect(decrypt(dataKey, flipped, aad)).rejects.toThrow("blob failed authentication");
    }
  });

  it("every truncation fails closed, including empty and too-short", async () => {
    const blob = await encrypt(dataKey, plaintext, aad);
    for (let length = 0; length <= 27; length += 3) {
      await expect(decrypt(dataKey, blob.subarray(0, length), aad)).rejects.toThrow();
    }
  });

  it("a relocated AAD (another user) fails authentication", async () => {
    const blob = await encrypt(dataKey, plaintext, aad);
    const otherUser = buildAad("entry", "user-999", encryptVectors[0]!.aad_parts[2]!);
    await expect(decrypt(dataKey, blob, otherUser)).rejects.toThrow("blob failed authentication");
  });

  it("the wrong key fails authentication", async () => {
    const blob = await encrypt(dataKey, plaintext, aad);
    const wrongKey = new Uint8Array(new ArrayBuffer(KEY_SIZE));
    wrongKey[0] = 1;
    await expect(decrypt(wrongKey, blob, aad)).rejects.toThrow("blob failed authentication");
  });
});

describe("tamper tranche: payload layer", () => {
  it("corrupted entry blobs fail closed through decryptEntry", async () => {
    const { blobB64 } = await encryptEntry(dataKey, "user-1", "entry-1", "text", "2026-09-25T00:00:00Z", 0);
    const blob = fromBase64(blobB64);
    for (const flipped of bitFlips(blob)) {
      await expect(decryptEntry(dataKey, "user-1", "entry-1", toBase64(flipped))).rejects.toThrow(
        "blob failed authentication",
      );
    }
    // Truncated well below MIN_BLOB_SIZE:
    await expect(decryptEntry(dataKey, "user-1", "entry-1", toBase64(blob.subarray(0, 10)))).rejects.toThrow(
      "blob failed authentication",
    );
  });

  it("invalid base64 fails closed (atob raises, no wrong plaintext)", async () => {
    await expect(decryptEntry(dataKey, "user-1", "entry-1", "!!!not-base64!!!")).rejects.toThrow();
  });
});

describe("zeroization pins", () => {
  /** Capture the exact ArrayBuffer WebCrypto decrypt returns: the payload
   *  layer wraps it in a Uint8Array, so its finally-fill must erase the
   *  same memory the engine produced. */
  function captureDecryptBuffer(): { bytes: () => Uint8Array; restore: () => void } {
    const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    let captured: ArrayBuffer | null = null;
    const spy = vi.spyOn(crypto.subtle, "decrypt").mockImplementation(
      async (...args: Parameters<SubtleCrypto["decrypt"]>) => {
        const result = await nativeDecrypt(...args);
        captured = result;
        return result;
      },
    );
    return {
      bytes: () => {
        if (captured === null) throw new Error("expected WebCrypto decrypt to run");
        return new Uint8Array(captured);
      },
      restore: () => spy.mockRestore(),
    };
  }

  it("decryptEntry wipes the decrypted plaintext buffer after parsing", async () => {
    const { blobB64 } = await encryptEntry(dataKey, "user-1", "entry-1", "secret text", "2026-09-25T00:00:00Z", 0);
    const capture = captureDecryptBuffer();
    try {
      const payload = await decryptEntry(dataKey, "user-1", "entry-1", blobB64);
      expect(payload.text).toBe("secret text");
      expect([...capture.bytes()]).toEqual(new Array<number>(capture.bytes().length).fill(0));
    } finally {
      capture.restore();
    }
  });

  it("decryptEntry wipes the buffer even when the payload version is unknown", async () => {
    const v3 = new TextEncoder().encode(JSON.stringify({ v: 3, text: "future" }));
    const blob = await encryptWithFixedNonce(dataKey, v3, fromBase64(encryptVectors[0]!.nonce), buildAad("entry", "user-1", "entry-1"));
    const capture = captureDecryptBuffer();
    try {
      await expect(decryptEntry(dataKey, "user-1", "entry-1", toBase64(blob))).rejects.toThrow(
        "unsupported entry payload version",
      );
      expect([...capture.bytes()]).toEqual(new Array<number>(capture.bytes().length).fill(0));
    } finally {
      capture.restore();
    }
  });
});
