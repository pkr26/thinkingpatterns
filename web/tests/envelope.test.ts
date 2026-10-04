/** The v2 key envelope (2026-09-26 crypto-architecture wave): the shared
 *  cross-platform vectors in shared/vectors.json `envelope_vectors` pin the
 *  wrap/unwrap construction byte-for-byte (KEK derivation, canonical AAD,
 *  the 60-byte wire format) — including BOTH tamper negatives, which must
 *  raise TamperError and never a wrong key. The entry-aad-v2 pair pins the
 *  other half of the contract: a v2 account's data key still opens the
 *  shared entry corpus unchanged (the scheme changes where the key LIVES,
 *  not what it encrypts). */
// @ts-nocheck

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildAad } from "../src/crypto/aad";
import { decrypt, deriveMasterKey, encrypt, fromBase64, toBase64, TamperError } from "../src/crypto/core";
import {
  createRegistrationEnvelope,
  envelopeAad,
  envelopeKek,
  rewrapDataKey,
  unwrapDataKey,
  unwrapEnvelope,
  validateKdfParams,
  wrapDataKey,
  KDF_PARAMS_DEFAULT,
  KDF_PARAMS_VERSION,
  WRAPPED_DATA_KEY_BYTES,
  type KdfParams,
} from "../src/crypto/envelope";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const { envelope_vectors: envelopeVectors } = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  envelope_vectors: Array<{
    kind: string;
    password?: string;
    salt: string;
    iterations?: number;
    master_key?: string;
    kdf_params?: Record<string, unknown>;
    kek?: string;
    username?: string;
    data_key?: string;
    aad?: string;
    nonce?: string;
    wrapped?: string;
    plaintext?: string;
    aad_parts?: string[];
    blob?: string;
    expect?: string;
  }>;
};

const wrapVector = envelopeVectors.find((v) => v.kind === "key-envelope-wrap")!;
const wrapTampered = envelopeVectors.find((v) => v.kind === "key-envelope-wrap-tampered")!;
const entryVector = envelopeVectors.find((v) => v.kind === "entry-aad-v2")!;
const entryTampered = envelopeVectors.find((v) => v.kind === "entry-aad-v2-tampered")!;

describe("envelope vectors (shared/vectors.json)", () => {
  it("the vector's master key is our PBKDF2-600k derivation of the password", async () => {
    expect(toBase64(await deriveMasterKey(wrapVector.password!, fromBase64(wrapVector.salt)))).toBe(wrapVector.master_key);
  });

  it("KEK = HKDF-SHA256(master, account salt, 'mindpattern/envelope/v2') — pinned bytes", async () => {
    expect(toBase64(await envelopeKek(fromBase64(wrapVector.master_key!), fromBase64(wrapVector.salt)))).toBe(wrapVector.kek);
  });

  it("the canonical AAD is the pinned bytes: fixed field order, compact, ascii-only", () => {
    const params = validateKdfParams(wrapVector.kdf_params);
    expect(toBase64(envelopeAad(wrapVector.username!, params))).toBe(wrapVector.aad);
    // And it is the exact JSON the backend serializes:
    expect(new TextDecoder().decode(envelopeAad(wrapVector.username!, params))).toBe(
      '{"context":"envelope","kdf_params":{"algorithm":"pbkdf2-sha256","version":1,"iterations":600000},"username":"envelope-wrap-user"}',
    );
  });

  it("wrap lands on the pinned 60-byte blob with the pinned nonce", async () => {
    const wrapped = await wrapDataKey(
      fromBase64(wrapVector.data_key!),
      fromBase64(wrapVector.kek!),
      wrapVector.username!,
      validateKdfParams(wrapVector.kdf_params!),
      fromBase64(wrapVector.nonce!),
    );
    expect(wrapped.length).toBe(WRAPPED_DATA_KEY_BYTES);
    expect(WRAPPED_DATA_KEY_BYTES).toBe(60);
    expect(toBase64(wrapped)).toBe(wrapVector.wrapped);
  });

  it("unwrap recovers the pinned data key", async () => {
    const dataKey = await unwrapDataKey(
      fromBase64(wrapVector.wrapped!),
      fromBase64(wrapVector.kek!),
      wrapVector.username!,
      validateKdfParams(wrapVector.kdf_params!),
    );
    expect(toBase64(dataKey)).toBe(wrapVector.data_key!);
  });

  it("TAMPER NEGATIVE: the corrupted wrap raises TamperError, never a wrong key", async () => {
    expect(wrapTampered.expect).toBe("tamper");
    await expect(
      unwrapDataKey(
        fromBase64(wrapTampered.wrapped!),
        fromBase64(wrapVector.kek!),
        wrapVector.username!,
        validateKdfParams(wrapVector.kdf_params!),
      ),
    ).rejects.toThrow(TamperError);
  });

  it("relocation to another account fails authentication (AAD binds the username)", async () => {
    await expect(
      unwrapDataKey(
        fromBase64(wrapVector.wrapped!),
        fromBase64(wrapVector.kek!),
        "mallory",
        validateKdfParams(wrapVector.kdf_params!),
      ),
    ).rejects.toThrow(TamperError);
  });

  it("a kdf_params change fails authentication (the blob binds its own cost parameters)", async () => {
    const other: KdfParams = { ...validateKdfParams(wrapVector.kdf_params!), iterations: 600_001 };
    await expect(
      unwrapDataKey(fromBase64(wrapVector.wrapped!), fromBase64(wrapVector.kek!), wrapVector.username!, other),
    ).rejects.toThrow(TamperError);
  });

  it("a wrong password (different KEK) is TamperError, not plaintext", async () => {
    const wrongKek = await envelopeKek(new Uint8Array(new ArrayBuffer(32)).fill(7), fromBase64(wrapVector.salt));
    await expect(
      unwrapDataKey(
        fromBase64(wrapVector.wrapped!),
        wrongKek,
        wrapVector.username!,
        validateKdfParams(wrapVector.kdf_params!),
      ),
    ).rejects.toThrow(TamperError);
  });

  it("a structurally wrong size is an Error (not an envelope), exactly 60 is required", async () => {
    await expect(
      unwrapDataKey(new Uint8Array(new ArrayBuffer(59)), fromBase64(wrapVector.kek!), wrapVector.username!, validateKdfParams(wrapVector.kdf_params!)),
    ).rejects.toThrow("exactly 60");
    await expect(
      unwrapDataKey(new Uint8Array(new ArrayBuffer(61)), fromBase64(wrapVector.kek!), wrapVector.username!, validateKdfParams(wrapVector.kdf_params!)),
    ).rejects.toThrow("exactly 60");
  });

  it("entry-aad-v2: the envelope-era data key opens the shared entry corpus unchanged", async () => {
    // The positive: the vector's data key + AAD decrypt the blob.
    const aad = buildAad(...entryVector.aad_parts!);
    const plain = await decrypt(fromBase64(entryVector.data_key!), fromBase64(entryVector.blob!), aad);
    expect(toBase64(plain)).toBe(entryVector.plaintext!);
  });

  it("entry-aad-v2 TAMPER NEGATIVE: the corrupted entry blob fails closed", async () => {
    expect(entryTampered.expect).toBe("tamper");
    const aad = buildAad(...entryTampered.aad_parts!);
    await expect(decrypt(fromBase64(entryTampered.data_key!), fromBase64(entryTampered.blob!), aad)).rejects.toThrow(TamperError);
  });
});

describe("kdf_params canonicalization (backend kdf.validate_kdf_params)", () => {
  it("accepts wire params in ANY order and canonicalizes to the fixed field order", () => {
    const canonical = validateKdfParams({ iterations: 600_000, version: 1, algorithm: "pbkdf2-sha256" });
    expect(Object.keys(canonical)).toEqual(["algorithm", "version", "iterations"]);
    expect(canonical).toEqual<KdfParams>({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 });
  });

  it("the argon2id shape canonicalizes algorithm, version, iterations, memory_kib, parallelism", () => {
    const canonical = validateKdfParams({ parallelism: 1, memory_kib: 65536, iterations: 3, version: 1, algorithm: "argon2id" });
    expect(Object.keys(canonical)).toEqual(["algorithm", "version", "iterations", "memory_kib", "parallelism"]);
  });

  it("the shipped client blob is pbkdf2-sha256 at the 600k contract constant", () => {
    expect(KDF_PARAMS_DEFAULT).toEqual({ algorithm: "pbkdf2-sha256", version: KDF_PARAMS_VERSION, iterations: 600_000 });
    expect(KDF_PARAMS_VERSION).toBe(1); // the BACKEND's blob-schema version (kdf.KDF_PARAMS_VERSION)
  });

  it("unknown fields, wrong version, and out-of-bounds costs are rejected loudly", () => {
    expect(() => validateKdfParams({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000, extra: 1 })).toThrow("unknown fields");
    expect(() => validateKdfParams({ algorithm: "pbkdf2-sha256", version: 2, iterations: 600_000 })).toThrow("version");
    expect(() => validateKdfParams({ algorithm: "pbkdf2-sha256", version: 1, iterations: 99_999 })).toThrow("iterations");
    expect(() => validateKdfParams({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000, memory_kib: 65536 })).toThrow("iterations only");
    expect(() => validateKdfParams({ algorithm: "argon2id", version: 1, iterations: 3 })).toThrow("require");
    expect(() => validateKdfParams(null)).toThrow("JSON object");
  });

  // independent audit 2026-09-27 (P3): the backend caps argon2id
  // iterations at 10_000_000 (kdf.py ARGON2_MAX_ITERATIONS) — the client
  // only checked the floor, so validation did NOT mirror the server.
  it("argon2id iterations mirror the server on BOTH bounds (audit 2026-09-27)", () => {
    const shape = { algorithm: "argon2id", version: 1, memory_kib: 65536, parallelism: 1 } as const;
    expect(() => validateKdfParams({ ...shape, iterations: 2 })).not.toThrow(); // at the floor
    expect(() => validateKdfParams({ ...shape, iterations: 10_000_000 })).not.toThrow(); // at the cap
    expect(() => validateKdfParams({ ...shape, iterations: 1 })).toThrow("2-10000000"); // below the floor
    expect(() => validateKdfParams({ ...shape, iterations: 10_000_001 })).toThrow("2-10000000"); // above the cap
  });
});

describe("envelope lifecycle helpers", () => {
  const SALT = fromBase64("sLGys7S1tre4ubq7vL2+vw==");

  it("a registration envelope wraps a RANDOM key that round-trips through unwrapEnvelope", async () => {
    const master = fromBase64("lMtwRy9DzK0MFTW7BaAgDXJZ9tEeA5rwnEeZ4u5tG9g=");
    const envelope = await createRegistrationEnvelope(master, SALT, "round-trip-user");
    expect(fromBase64(envelope.wrappedDataKeyB64).length).toBe(60);
    const opened = await unwrapEnvelope(master, SALT, "round-trip-user", envelope.wrappedDataKeyB64, envelope.kdfParams);
    expect(toBase64(opened)).toBe(toBase64(envelope.dataKey));
    // The data key is genuinely random: never the v1 HKDF data label, and
    // never the same twice.
    const second = await createRegistrationEnvelope(master, SALT, "round-trip-user");
    expect(toBase64(second.dataKey)).not.toBe(toBase64(envelope.dataKey));
  });

  it("rewrapDataKey re-locks the SAME key under a new password/salt (the O(1) change)", async () => {
    const dataKey = fromBase64(wrapVector.data_key!);
    const newMaster = new Uint8Array(new ArrayBuffer(32)).fill(9);
    const newSalt = fromBase64("oKGio6SlpqeoqaqrrK2urw==");
    const wrapped = await rewrapDataKey(dataKey, newMaster, newSalt, "rewrap-user");
    expect(fromBase64(wrapped).length).toBe(60);
    const opened = await unwrapEnvelope(newMaster, newSalt, "rewrap-user", wrapped, KDF_PARAMS_DEFAULT);
    expect(toBase64(opened)).toBe(wrapVector.data_key!);
    // ...and the OLD master cannot open the re-wrapped blob.
    await expect(unwrapEnvelope(fromBase64(wrapVector.master_key!), newSalt, "rewrap-user", wrapped, KDF_PARAMS_DEFAULT)).rejects.toThrow(TamperError);
  });

  it("two production wraps of one key never share a blob (random nonce)", async () => {
    const kek = fromBase64(wrapVector.kek!);
    const one = await wrapDataKey(fromBase64(wrapVector.data_key!), kek, "alice", KDF_PARAMS_DEFAULT);
    const two = await wrapDataKey(fromBase64(wrapVector.data_key!), kek, "alice", KDF_PARAMS_DEFAULT);
    expect(toBase64(one)).not.toBe(toBase64(two));
  });

  it("the envelope's GCM layer is the shared core: an envelope-keyed entry still fails closed on tamper", async () => {
    const kek = await envelopeKek(fromBase64(wrapVector.master_key!), SALT);
    expect(kek.length).toBe(32);
    // Domain separation: the KEK is neither the auth nor the data label over
    // the same master (pinned on the backend side; the client must agree).
    const { derivePatientKeys } = await import("../src/crypto/keys");
    const keys = await derivePatientKeys(fromBase64(wrapVector.master_key!));
    expect(toBase64(kek)).not.toBe(toBase64(keys.authKey));
    expect(toBase64(kek)).not.toBe(toBase64(keys.dataKey));
    const blob = await encrypt(kek, new TextEncoder().encode("x"), buildAad("envelope", "u"));
    blob[blob.length - 1]! ^= 0x01;
    await expect(decrypt(kek, blob, buildAad("envelope", "u"))).rejects.toThrow(TamperError);
  });
});
