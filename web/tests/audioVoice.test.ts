/** Voice-journaling contracts (VOICE_PLAN P3, 2026-09-29): payload v3
 *  round-trips and back-compatibility, the audio envelope's AAD binding,
 *  the recorder's mime fallback chain, and the shared/audio_vectors.json
 *  pins (the repo's copy-and-pin discipline). */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptAudio, decryptEntry, encryptAudio, encryptEntry } from "../src/crypto/patient";
import { fromBase64, toBase64 } from "../src/crypto/core";
import {
  MAX_RECORDING_SECONDS,
  RECORDER_MIME_CANDIDATES,
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

  it("the fallback chain order is pinned", () => {
    expect(RECORDER_MIME_CANDIDATES[0]).toBe("audio/webm;codecs=opus");
    expect(RECORDER_MIME_CANDIDATES).toContain("audio/mp4");
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

  it("the client cap is the 5-minute plan cap", () => {
    expect(MAX_RECORDING_SECONDS).toBe(300);
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

  it("the client recording cap matches the shared contract", () => {
    expect(MAX_RECORDING_SECONDS).toBe(shared.recording_limits.max_duration_seconds_client);
  });

  it("the AAD tuple context and version match", () => {
    expect(shared.audio_aad.tuple[0]).toBe("audio");
    expect(shared.audio_aad.audio_version).toBe(1);
  });
});
