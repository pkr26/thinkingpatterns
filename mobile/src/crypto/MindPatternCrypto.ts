/**
 * The device-side crypto orchestrator: key derivation, entry envelopes,
 * and decryption of insight/question payloads. Mirrors backend/tests/helpers.py
 * (the client emulator) — if these ever disagree, shared/vectors.json fails.
 */
import { buildAad, decrypt, encrypt } from "./envelope";
import { deriveAuthKey, deriveDataKey, deriveMasterKey, deriveMasterKeyAsync, KDF_ITERATIONS, zeroize } from "./kdf";

export interface Keys {
  masterKey: Buffer;
  authKey: Buffer; // only this ever crosses the network (as the login verifier)
  dataKey: Buffer; // encrypts everything
}

export interface EntryPayload {
  v: 1 | 2 | 3;
  text: string;
  sentiment: number | null; // computed on-device before encryption
  created_at: string; // ISO date
  /** v2 structured channels (all optional, all user-supplied ratings/tags). */
  energy?: number;
  sleep?: number; // 1..5 quality rating
  tags?: string[];
  /** Coarse local writing window (P3, 2026-09-21): "morning" | "afternoon"
   *  | "evening" | "night". Deliberately a BUCKET, never a clock time —
   *  the entry contract stays date-granular for privacy; the bucket is
   *  enough for the "Sunday evening" analysis refinement. */
  tod?: string;
  /** v3 voice channels (VOICE_PLAN 2026-09-29): how this entry was made
   *  and, for voice entries, the detected language + the English
   *  translation of the SAVED text. */
  input_mode?: "typed" | "voice";
  transcript_lang?: string;
  english_text?: string | null;
}

/** The local-hour bucket for the entry payload's optional time-of-day
 *  channel: 05-11 morning, 12-16 afternoon, 17-22 evening, else night.
 *  Pure and total so tests pin the boundaries. */
export function timeOfDayBucket(hour: number): "morning" | "afternoon" | "evening" | "night" {
  if (hour >= 5 && hour < 12) return "morning";
  if (hour >= 12 && hour < 17) return "afternoon";
  if (hour >= 17 && hour < 23) return "evening";
  return "night";
}

export function deriveKeys(password: string, salt: Buffer): Keys {
  const masterKey = deriveMasterKey(password, salt);
  return { masterKey, authKey: deriveAuthKey(masterKey), dataKey: deriveDataKey(masterKey) };
}

/** deriveKeys without the JS-thread freeze (see deriveMasterKeyAsync) —
 *  the login/unlock screens' preferred path. `iterations` defaults to the
 *  600k contract; the v2 password rotation passes the account envelope's
 *  OWN kdf_params count so the re-wrap KEK can never disagree with the AAD
 *  the wrap declares (re-audit 2026-09-27). */
export async function deriveKeysAsync(password: string, salt: Buffer, iterations = KDF_ITERATIONS): Promise<Keys> {
  const masterKey = await deriveMasterKeyAsync(password, salt, iterations);
  return { masterKey, authKey: deriveAuthKey(masterKey), dataKey: deriveDataKey(masterKey) };
}

export function encryptEntry(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  text: string,
  createdAt: string,
  sentiment: number | null,
  structured?: {
    energy?: number | null;
    sleep?: number | null;
    tags?: string[];
    tod?: string;
  },
  /** Content generation for the version-bound v2 AAD (audit fix M-2,
   *  2026-09-20): binds ("entry", userId, id, version) so a compromised
   *  server cannot pair a stale-but-valid ciphertext with a truthful
   *  version echo. Omitted → the legacy three-part AAD (pre-2026-09-20
   *  blobs and cross-platform vectors keep decrypting unchanged). */
  contentVersion?: number,
  /** Voice channels (VOICE_PLAN 2026-09-29): presence upgrades the payload
   *  to v3 — typed entries keep the byte-identical v1/v2 shapes. */
  voice?: {
    inputMode: "voice";
    transcriptLang?: string;
    englishText: string | null;
  },
): { blobB64: string } {
  // Payload v2 (2026-09-17): optional structured channels ride alongside
  // the text. A caller passing none emits the v1 shape byte-for-byte, so
  // older servers and exports behave identically.
  const base: EntryPayload =
    structured &&
    (structured.energy != null ||
      structured.sleep != null ||
      (structured.tags ?? []).length > 0 ||
      structured.tod != null)
      ? {
          v: 2,
          text,
          sentiment,
          created_at: createdAt,
          ...(structured.energy != null ? { energy: structured.energy } : {}),
          ...(structured.sleep != null ? { sleep: structured.sleep } : {}),
          ...((structured.tags ?? []).length > 0 ? { tags: structured.tags } : {}),
          ...(structured.tod != null ? { tod: structured.tod } : {}),
        }
      : { v: 1, text, sentiment, created_at: createdAt };
  const payload: EntryPayload = voice
    ? {
        ...base,
        v: 3,
        input_mode: "voice",
        ...(voice.transcriptLang ? { transcript_lang: voice.transcriptLang } : {}),
        english_text: voice.englishText,
      }
    : base;
  // Stryker disable StringLiteral
const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  // Stryker restore StringLiteral
  const aad =
    contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1
      ? buildAad("entry", userId, clientEntryId, String(contentVersion))
      : buildAad("entry", userId, clientEntryId);
  const blob = encrypt(keys.dataKey, plaintext, aad);
  return { blobB64: blob.toString("base64") };
}

/** The only entry payload schema versions this client understands (v2
 *  added the structured channels; v3 the voice channels, VOICE_PLAN
 *  2026-09-29). Mirrors decryptInsights' loud-fail contract: an unknown
 *  version must throw, never be silently miscast as today's shape — a
 *  future v4 misread is how a schema roll corrupts the journal UI with
 *  wrong-typed fields. */
export const ENTRY_PAYLOAD_VERSIONS: readonly number[] = [1, 2, 3];

export function decryptEntry(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  blobB64: string,
  /** The server-declared content generation of this row. The v2 AAD is
   *  tried first and the legacy three-part AAD is the fallback for ANY
   *  version (audit fix 2026-09-28): the server bumps content_version when
   *  a legacy client edits while entries.py keeps the legacy blob bytes, so
   *  legally-stored rows can carry version >= 2 with a legacy binding —
   *  failing those closed made real entries vanish as TamperError. This
   *  mirrors the server ladder crypto.entry_aad_candidates (v2 then v1 for
   *  any version); a stale-blob-with-fresh-version-echo replay is still
   *  caught by the per-id high-water marks in entryVersions.ts, which is
   *  where the rollback protection actually lives. Omitted version →
   *  legacy binding only (pre-2026-09-20 servers). */
  contentVersion?: number,
  opts: {
    /** 2026-10-01 audit M1: refuse the legacy fallback — the caller has
     *  POSITIVE knowledge (the v2-bound mark) this id authenticated under
     *  the v2 binding before; a failing blob is a stale replay. */
    forbidLegacyAad?: boolean;
    /** Fired when the v2 binding authenticated (record the mark). */
    onV2Bound?: () => void;
  } = {},
): EntryPayload {
  const blob = Buffer.from(blobB64, "base64");
  let plaintext: Buffer;
  if (contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1) {
    try {
      plaintext = decrypt(keys.dataKey, blob, buildAad("entry", userId, clientEntryId, String(contentVersion)));
      opts.onV2Bound?.();
    } catch (v2Error) {
      if (opts.forbidLegacyAad) throw v2Error;
      plaintext = decrypt(keys.dataKey, blob, buildAad("entry", userId, clientEntryId));
    }
  } else {
    plaintext = decrypt(keys.dataKey, blob, buildAad("entry", userId, clientEntryId));
  }
  const payload = JSON.parse(plaintext.toString("utf8")) as { v?: unknown };
  // L-48: same guard as decryptInsights — the AEAD bound the bytes to this
  // account/entry, but nothing else vouches for the version field.
  if (!ENTRY_PAYLOAD_VERSIONS.includes(payload.v as number)) {
    throw new Error(`unsupported entry payload version: ${String(payload.v)}`);
  }
  return payload as EntryPayload;
}

/** The only insights payload schema this client understands (the backend
 *  emits "v": 2). An unknown version must fail LOUDLY here — silently
 *  parsing a future schema as if it were v2 is how a schema roll corrupts
 *  the UI with misread fields. Mirrors the InsightsScreen phase guard. */
export const INSIGHTS_PAYLOAD_VERSION = 2;

export interface InsightsPayload {
  v: number;
  stats?: { patterns?: unknown; language?: unknown };
  /** Analysis generation (2026-09-19): must equal the GET /insights echo
   *  of the same name and never decrease across sessions — the
   *  rollback-replay detection contract (see stateSeqGuard.ts). Absent on
   *  pre-2026-09-19 servers; consumers must treat absence as "nothing to
   *  verify", never as zero. */
  state_seq?: number;
}

export function decryptInsights(keys: Pick<Keys, "dataKey">, userId: string, blobB64: string): InsightsPayload {
  const plaintext = decrypt(keys.dataKey, Buffer.from(blobB64, "base64"), buildAad("insights", userId, "patterns"));
  const payload = JSON.parse(plaintext.toString("utf8")) as { v?: unknown };
  if (payload.v !== INSIGHTS_PAYLOAD_VERSION) {
    throw new Error(`unsupported insights payload version: ${String(payload.v)}`);
  }
  return payload as unknown as InsightsPayload;
}

export function decryptQuestion(keys: Pick<Keys, "dataKey">, userId: string, forDate: string, blobB64: string) {
  const plaintext = decrypt(keys.dataKey, Buffer.from(blobB64, "base64"), buildAad("question", userId, forDate));
  return JSON.parse(plaintext.toString("utf8")) as {
    for_date: string;
    question: string;
    /** The pattern behind the question, when it came from one (routing
     *  for the "did this land?" feedback taps). */
    pattern_pid?: string;
  };
}

export { zeroize };


// --- voice recordings (VOICE_PLAN 2026-09-29) --------------------------------
//
// Same AES-GCM envelope, same data key, AAD context "audio" bound to
// (userId, clientEntryId, audio version 1) — identical contract to web's
// crypto/patient.ts and pinned by shared/audio_vectors.json.

export const AUDIO_PAYLOAD_VERSION = 1;

export function encryptAudio(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  audio: Buffer,
): { blobB64: string } {
  const aad = buildAad("audio", userId, clientEntryId, String(AUDIO_PAYLOAD_VERSION));
  const blob = encrypt(keys.dataKey, audio, aad);
  return { blobB64: blob.toString("base64") };
}

export function decryptAudio(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  blobB64: string,
): Buffer {
  return decrypt(
    keys.dataKey,
    Buffer.from(blobB64, "base64"),
    buildAad("audio", userId, clientEntryId, String(AUDIO_PAYLOAD_VERSION)),
  );
}
