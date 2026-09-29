/** Voice-journaling contracts on mobile (VOICE_PLAN P4, 2026-09-29):
 *  payload v3 round-trips + back-compatibility, the audio envelope's AAD
 *  binding, and the recorder's pinned constants — mirroring the web suite
 *  so both clients stay pinned to shared/audio_vectors.json together. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AUDIO_PAYLOAD_VERSION,
  decryptAudio,
  decryptEntry,
  encryptAudio,
  encryptEntry,
} from "../src/crypto/MindPatternCrypto";
import { MAX_RECORDING_SECONDS } from "../src/audio/recorder";
// The mobile fixed-nonce seam: production encrypt() draws a fresh random
// nonce by design, so byte-pins go through encryptWithFixedNonce — the
// same unmistakably-named test seam web/tests/audioVoice.test.ts uses.
import { buildAad, decrypt, encryptWithFixedNonce } from "../src/crypto/envelope";

const here = dirname(fileURLToPath(import.meta.url));
const keys = { dataKey: Buffer.alloc(32, 7) };

describe("entry payload v3 (voice channels)", () => {
  it("a voice entry round-trips with the v3 channels intact", () => {
    const { blobB64 } = encryptEntry(
      keys,
      "user-1",
      "entry-voice-1",
      "Hoy fue un día difícil.",
      "2026-09-29T00:00:00Z",
      null,
      { tod: "evening" },
      1,
      { inputMode: "voice", transcriptLang: "es", englishText: "Today was a hard day." },
    );
    const payload = decryptEntry(keys, "user-1", "entry-voice-1", blobB64, 1);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.transcript_lang).toBe("es");
    expect(payload.english_text).toBe("Today was a hard day.");
    expect(payload.tod).toBe("evening");
  });

  it("english_text may be null (degraded translation mode)", () => {
    const { blobB64 } = encryptEntry(
      keys, "user-1", "entry-voice-2", "Bonjour", "2026-09-29T00:00:00Z", null,
      undefined, 1,
      { inputMode: "voice", englishText: null },
    );
    const payload = decryptEntry(keys, "user-1", "entry-voice-2", blobB64, 1);
    expect(payload.v).toBe(3);
    expect(payload.english_text).toBeNull();
  });

  it("a typed entry stays v1/v2 (no voice channels leak)", () => {
    const { blobB64 } = encryptEntry(keys, "user-1", "entry-typed", "typed", "2026-09-29T00:00:00Z", 0);
    const payload = decryptEntry(keys, "user-1", "entry-typed", blobB64);
    expect([1, 2]).toContain(payload.v);
    expect(payload.input_mode).toBeUndefined();
  });
});

describe("audio envelope (kept recordings)", () => {
  const audio = Buffer.alloc(256, 3);

  it("encryptAudio → decryptAudio round-trips under the audio AAD", () => {
    const { blobB64 } = encryptAudio(keys, "user-1", "entry-a", audio);
    expect(decryptAudio(keys, "user-1", "entry-a", blobB64).equals(audio)).toBe(true);
  });

  it("the audio AAD binds user AND entry: grafts fail closed", () => {
    const { blobB64 } = encryptAudio(keys, "user-1", "entry-a", audio);
    expect(() => decryptAudio(keys, "user-2", "entry-a", blobB64)).toThrow();
    expect(() => decryptAudio(keys, "user-1", "entry-b", blobB64)).toThrow();
  });

  it("audio ciphertext is not entry ciphertext (context separation)", () => {
    const { blobB64 } = encryptAudio(keys, "user-1", "entry-a", audio);
    expect(() => decryptEntry(keys, "user-1", "entry-a", blobB64, 1)).toThrow();
  });

  it("the audio payload version is pinned to 1", () => {
    expect(AUDIO_PAYLOAD_VERSION).toBe(1);
  });
});

describe("shared/audio_vectors.json pins", () => {
  const shared = JSON.parse(
    readFileSync(join(here, "..", "..", "shared", "audio_vectors.json"), "utf8"),
  ) as { recording_limits: { max_duration_seconds_client: number } };

  it("the client recording cap matches the shared contract", () => {
    expect(MAX_RECORDING_SECONDS).toBe(shared.recording_limits.max_duration_seconds_client);
  });
});

describe("shared cross-client crypto vectors (audit 2026-09-29, mobile side)", () => {
  // The vectors pin byte-level agreement between web, mobile, and portal
  // (mirrors web/tests/audioVoice.test.ts's block of the same name): the
  // ENCRYPTING clients must reproduce the pinned blobs exactly through
  // their fixed-nonce seams, and every client must DECRYPT the pinned
  // blobs back to the pinned plaintexts.
  const vec = (
    JSON.parse(readFileSync(join(here, "..", "..", "shared", "audio_vectors.json"), "utf8")) as {
      crypto_vectors: {
        data_key_b64: string;
        nonce_b64: string;
        user_id: string;
        client_entry_id: string;
        audio_envelope: { plaintext_b64: string; blob_b64: string };
        entry_payload_v3_envelope: {
          blob_b64: string;
          blob_b64_legacy_aad: string;
          plaintext_json: { text: string; transcript_lang: string; english_text: string };
        };
      };
    }
  ).crypto_vectors;
  const vecKeys = { dataKey: Buffer.from(vec.data_key_b64, "base64") };
  const vecNonce = Buffer.from(vec.nonce_b64, "base64");
  const audio = vec.audio_envelope;
  const entry = vec.entry_payload_v3_envelope;

  it("the audio envelope reproduces the pinned blob byte-for-byte through the fixed-nonce seam", () => {
    const blob = encryptWithFixedNonce(
      vecKeys.dataKey,
      Buffer.from(audio.plaintext_b64, "base64"),
      buildAad("audio", vec.user_id, vec.client_entry_id, "1"),
      vecNonce,
    );
    expect(blob.toString("base64")).toBe(audio.blob_b64);
  });

  it("the pinned audio blob decrypts to the pinned plaintext (cross-client)", () => {
    expect(
      decryptAudio(vecKeys, vec.user_id, vec.client_entry_id, audio.blob_b64).toString("base64"),
    ).toBe(audio.plaintext_b64);
  });

  it("the pinned audio blob fails under every documented negative case", () => {
    expect(() => decryptAudio(vecKeys, "vector-user-0002", vec.client_entry_id, audio.blob_b64)).toThrow();
    expect(() => decryptAudio(vecKeys, vec.user_id, "vector-entry-0002", audio.blob_b64)).toThrow();
    // Context separation: the audio blob must not decrypt under the ENTRY AAD.
    expect(() =>
      decrypt(
        vecKeys.dataKey,
        Buffer.from(audio.blob_b64, "base64"),
        buildAad("entry", vec.user_id, vec.client_entry_id, "1"),
      ),
    ).toThrow();
  });

  it("the pinned v3 entry blob decrypts with the voice channels intact (contentVersion 1)", () => {
    const payload = decryptEntry(vecKeys, vec.user_id, vec.client_entry_id, entry.blob_b64, 1);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.transcript_lang).toBe(entry.plaintext_json.transcript_lang);
    expect(payload.english_text).toBe(entry.plaintext_json.english_text);
    expect(payload.text).toBe(entry.plaintext_json.text);
    // The legacy-AAD variant decrypts through the fallback ladder (no
    // contentVersion → legacy binding only).
    const legacy = decryptEntry(vecKeys, vec.user_id, vec.client_entry_id, entry.blob_b64_legacy_aad);
    expect(legacy.v).toBe(3);
    expect(legacy.input_mode).toBe("voice");
    expect(legacy.english_text).toBe(entry.plaintext_json.english_text);
    // Version-bound AAD negative: a mismatched contentVersion must fail.
    expect(() => decryptEntry(vecKeys, vec.user_id, vec.client_entry_id, entry.blob_b64, 2)).toThrow();
  });

  it("the pinned v3 entry plaintext seals back to the pinned blob (key order pinned)", () => {
    // Canonical JSON.stringify of the pinned payload, sealed with the
    // fixed nonce under the version-bound entry AAD — the same bytes
    // encryptEntry's voice branch emits (its spread order is pinned by
    // this equality).
    const blob = encryptWithFixedNonce(
      vecKeys.dataKey,
      Buffer.from(JSON.stringify(entry.plaintext_json), "utf8"),
      buildAad("entry", vec.user_id, vec.client_entry_id, "1"),
      vecNonce,
    );
    expect(blob.toString("base64")).toBe(entry.blob_b64);
  });
});
