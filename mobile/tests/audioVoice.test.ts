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
