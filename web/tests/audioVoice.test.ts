/** Voice-journaling contracts (VOICE_PLAN P3, 2026-09-29): payload v3
 *  round-trips and back-compatibility, the audio envelope's AAD binding,
 *  the recorder's mime fallback chain, and the shared/audio_vectors.json
 *  pins (the repo's copy-and-pin discipline). */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptAudio, decryptEntry, encryptAudio, encryptEntry } from "../src/crypto/patient";
import { encryptWithFixedNonce, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import {
  extensionForMime,
  normalizeMime,
  pickRecorderMime,
} from "../src/audio/recorder";

const here = dirname(fileURLToPath(import.meta.url));
const dataKey = new Uint8Array(32).fill(7);

describe("entry payload v3 (voice channels)", () => {
  it("a voice entry round-trips with the v3 channels intact", async () => {
    const { blobB64 } = await encryptEntry(
      dataKey,
      "user-1",
      "entry-voice-1",
      "Hoy fue un día difícil.",
      "2026-09-29T00:00:00Z",
      null,
      { tod: "evening" },
      1,
      { inputMode: "voice", transcriptLang: "es", englishText: "Today was a hard day." },
    );
    const payload = await decryptEntry(dataKey, "user-1", "entry-voice-1", blobB64, 1);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.transcript_lang).toBe("es");
    expect(payload.english_text).toBe("Today was a hard day.");
    expect(payload.tod).toBe("evening");
  });

  it("english_text may be null (degraded translation mode)", async () => {
    const { blobB64 } = await encryptEntry(
      dataKey, "user-1", "entry-voice-2", "Bonjour", "2026-09-29T00:00:00Z", null,
      undefined, 1,
      { inputMode: "voice", englishText: null },
    );
    const payload = await decryptEntry(dataKey, "user-1", "entry-voice-2", blobB64, 1);
    expect(payload.v).toBe(3);
    expect(payload.english_text).toBeNull();
  });

  it("a typed entry stays byte-shape v1/v2 (no voice channels leak)", async () => {
    const plain = await encryptEntry(dataKey, "user-1", "entry-typed", "typed text", "2026-09-29T00:00:00Z", 0);
    const payload = await decryptEntry(dataKey, "user-1", "entry-typed", plain.blobB64);
    expect([1, 2]).toContain(payload.v);
    expect(payload.input_mode).toBeUndefined();
    expect(payload.transcript_lang).toBeUndefined();
    expect(payload.english_text).toBeUndefined();
  });

  it("a v3 blob fails under the WRONG entry AAD (no relocation)", async () => {
    const { blobB64 } = await encryptEntry(
      dataKey, "user-1", "entry-a", "text", "2026-09-29T00:00:00Z", null, undefined, 1,
      { inputMode: "voice", englishText: null },
    );
    await expect(decryptEntry(dataKey, "user-1", "entry-b", blobB64, 1)).rejects.toThrow();
    await expect(decryptEntry(dataKey, "user-2", "entry-a", blobB64, 1)).rejects.toThrow();
  });
});

describe("audio envelope (kept recordings)", () => {
  const audio = new Uint8Array(256).fill(3);

  it("encryptAudio → decryptAudio round-trips under the audio AAD", async () => {
    const { blobB64 } = await encryptAudio(dataKey, "user-1", "entry-voice-1", audio);
    const recovered = await decryptAudio(dataKey, "user-1", "entry-voice-1", blobB64);
    expect(Array.from(recovered)).toEqual(Array.from(audio));
  });

  it("the audio AAD binds user AND entry: grafts fail closed", async () => {
    const { blobB64 } = await encryptAudio(dataKey, "user-1", "entry-a", audio);
    await expect(decryptAudio(dataKey, "user-2", "entry-a", blobB64)).rejects.toThrow();
    await expect(decryptAudio(dataKey, "user-1", "entry-b", blobB64)).rejects.toThrow();
  });

  it("audio ciphertext is NOT entry ciphertext (context separation)", async () => {
    const { blobB64: audioB64 } = await encryptAudio(dataKey, "user-1", "entry-a", audio);
    // An audio blob must not decrypt under the ENTRY AAD and vice versa.
    await expect(decryptEntry(dataKey, "user-1", "entry-a", audioB64, 1)).rejects.toThrow();
  });

  it("round-trips through the same base64 helpers as entries", async () => {
    const { blobB64 } = await encryptAudio(dataKey, "user-1", "entry-a", audio);
    expect(fromBase64(toBase64(fromBase64(blobB64))).byteLength).toBe(
      fromBase64(blobB64).byteLength,
    );
  });
});

describe("recorder mime contract", () => {
  it("normalizes codec parameters off the wire mime", () => {
    expect(normalizeMime("audio/webm;codecs=opus")).toBe("audio/webm");
    expect(normalizeMime("AUDIO/MP4")).toBe("audio/mp4");
  });

  it("extensions follow the actual mime (never a hardcoded .webm)", () => {
    expect(extensionForMime("audio/webm")).toBe(".webm");
    expect(extensionForMime("audio/mp4")).toBe(".m4a");
    expect(extensionForMime("audio/ogg")).toBe(".ogg");
    expect(extensionForMime("audio/mpeg")).toBe(".mp3");
  });

  it("picks the first supported candidate (Safari: mp4, Chrome: webm)", () => {
    const original = globalThis.MediaRecorder;
    try {
      (globalThis as Record<string, unknown>).MediaRecorder = class {
        static isTypeSupported(mime: string): boolean {
          return mime === "audio/mp4";
        }
      };
      expect(pickRecorderMime()).toBe("audio/mp4");
      (globalThis as Record<string, unknown>).MediaRecorder = class {
        static isTypeSupported(mime: string): boolean {
          return mime.startsWith("audio/webm");
        }
      };
      expect(pickRecorderMime()).toBe("audio/webm;codecs=opus");
    } finally {
      if (original === undefined) delete (globalThis as Record<string, unknown>).MediaRecorder;
      else (globalThis as Record<string, unknown>).MediaRecorder = original;
    }
  });

});

describe("shared/audio_vectors.json pins", () => {
  const shared = JSON.parse(readFileSync(join(here, "..", "..", "shared", "audio_vectors.json"), "utf8")) as {
    mime_types: Record<string, string>;
    recording_limits: { max_duration_seconds_client: number };
    audio_aad: { tuple: string[]; audio_version: number };
  };

  it("the mime→extension table matches the shared contract", () => {
    const pinned = Object.fromEntries(
      Object.entries(shared.mime_types).filter(([key]) => key !== "notes"),
    );
    const local = Object.fromEntries(
      Object.entries({
        "audio/webm": ".webm",
        "audio/mp4": ".m4a",
        "audio/m4a": ".m4a",
        "audio/x-m4a": ".m4a",
        "audio/ogg": ".ogg",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
      }).map(([mime]) => [mime, extensionForMime(mime)]),
    );
    expect(local).toEqual(pinned);
  });

  it("the AAD tuple context and version match", () => {
    expect(shared.audio_aad.tuple[0]).toBe("audio");
    expect(shared.audio_aad.audio_version).toBe(1);
  });
});

describe("shared cross-client crypto vectors (audit 2026-09-29, M3)", () => {
  // The vectors pin byte-level agreement between web, mobile, and portal:
  // the two ENCRYPTING clients must reproduce the pinned blobs exactly
  // through their fixed-nonce seams, and every client must DECRYPT the
  // pinned blobs back to the pinned plaintexts. Production pairing is
  // web/mobile encrypt -> portal decrypt, so the decrypt side is the
  // compatibility that actually ships.
  const vec = (JSON.parse(
    readFileSync(join(here, "..", "..", "shared", "audio_vectors.json"), "utf8"),
  ) as { crypto_vectors: {
    data_key_b64: string; nonce_b64: string; user_id: string; client_entry_id: string;
    audio_envelope: { plaintext_b64: string; blob_b64: string };
    entry_payload_v3_envelope: {
      blob_b64: string; blob_b64_legacy_aad: string;
      plaintext_json: { transcript_lang: string; english_text: string; text: string };
    };
  } }).crypto_vectors;
  const vecKey = fromBase64(vec.data_key_b64);
  const vecNonce = fromBase64(vec.nonce_b64);
  const audio = vec.audio_envelope;
  const entry = vec.entry_payload_v3_envelope;

  it("encryptAudio's envelope reproduces the pinned audio blob byte-for-byte", async () => {
    const blob = await encryptWithFixedNonce(
      vecKey, fromBase64(audio.plaintext_b64), vecNonce,
      buildAad("audio", vec.user_id, vec.client_entry_id, "1"),
    );
    expect(toBase64(blob)).toBe(audio.blob_b64);
  });

  it("the pinned audio blob decrypts to the pinned plaintext (cross-client)", async () => {
    const recovered = await decryptAudio(vecKey, vec.user_id, vec.client_entry_id, audio.blob_b64);
    expect(toBase64(recovered)).toBe(audio.plaintext_b64);
  });

  it("the pinned audio blob fails under every documented negative case", async () => {
    await expect(decryptAudio(vecKey, "vector-user-0002", vec.client_entry_id, audio.blob_b64)).rejects.toThrow();
    await expect(decryptAudio(vecKey, vec.user_id, "vector-entry-0002", audio.blob_b64)).rejects.toThrow();
    // Context separation: the audio blob must not decrypt under the ENTRY AAD.
    await expect(
      (async () => {
        const { decrypt } = await import("../src/crypto/core");
        return decrypt(vecKey, fromBase64(audio.blob_b64), buildAad("entry", vec.user_id, vec.client_entry_id, "1"));
      })(),
    ).rejects.toThrow();
  });

  it("the pinned v3 entry blob decrypts with voice channels intact (web reads web)", async () => {
    const payload = await decryptEntry(vecKey, vec.user_id, vec.client_entry_id, entry.blob_b64, 1);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.transcript_lang).toBe(entry.plaintext_json.transcript_lang);
    expect(payload.english_text).toBe(entry.plaintext_json.english_text);
    // The legacy-AAD variant decrypts through the fallback ladder too.
    const legacy = await decryptEntry(vecKey, vec.user_id, vec.client_entry_id, entry.blob_b64_legacy_aad);
    expect(legacy.text).toBe(entry.plaintext_json.text);
    // Version-bound AAD negative: a mismatched contentVersion must fail.
    await expect(decryptEntry(vecKey, vec.user_id, vec.client_entry_id, entry.blob_b64, 2)).rejects.toThrow();
  });

  it("encryptEntry's v3 envelope reproduces the pinned entry blob byte-for-byte", async () => {
    // Canonical JSON.stringify of the pinned payload, sealed with the
    // fixed nonce under the version-bound entry AAD.
    const plaintext = new TextEncoder().encode(JSON.stringify(entry.plaintext_json));
    const blob = await encryptWithFixedNonce(
      vecKey, plaintext, vecNonce,
      buildAad("entry", vec.user_id, vec.client_entry_id, "1"),
    );
    expect(toBase64(blob)).toBe(entry.blob_b64);
  });
});
