/**
 * The patient payload layer — entry envelopes (payload v1/v2), insights
 * and question blobs. Ported from mobile's FathomCrypto.ts (same
 * wire contract, same loud-fail version guards); the AEAD/AAD primitives
 * come from ./core (portal's WebCrypto implementation).
 */
import { buildAad } from "./aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./core";

export interface EntryPayload {
  v: 1 | 2 | 3;
  text: string;
  sentiment: number | null; // computed on-device before encryption
  created_at: string; // ISO date
  /** v2 structured channels (all optional, all user-supplied ratings/tags). */
  energy?: number;
  sleep?: number; // 1..5 quality rating
  tags?: string[];
  /** Coarse local writing window: "morning" | "afternoon" | "evening" |
   *  "night". Deliberately a BUCKET, never a clock time — the entry
   *  contract stays date-granular for privacy. */
  tod?: string;
  /** v3 voice channels (VOICE_PLAN 2026-09-29): how this entry was made
   *  and, for voice entries, the detected language + the English
   *  translation of the SAVED text (kept in sync by the client: an edit
   *  re-translates before saving). */
  input_mode?: "typed" | "voice";
  transcript_lang?: string; // ISO 639-1, absent when unknown
  english_text?: string | null;
}

/** The local-hour bucket for the entry payload's optional time-of-day
 *  channel: 05-11 morning, 12-16 afternoon, 17-22 evening, else night.
 *  Pure and total so tests pin the boundaries (identical to mobile). */
export function timeOfDayBucket(hour: number): "morning" | "afternoon" | "evening" | "night" {
  if (hour >= 5 && hour < 12) return "morning";
  if (hour >= 12 && hour < 17) return "afternoon";
  if (hour >= 17 && hour < 23) return "evening";
  return "night";
}

export interface EntryStructured {
  energy?: number | null;
  sleep?: number | null;
  tags?: string[];
  tod?: string;
}

/** v3 voice channels (VOICE_PLAN 2026-09-29). Present ⇒ payload v3;
 * absent ⇒ the byte-identical v1/v2 shapes above (a typed entry on this
 * client never carries them, so older servers/exports are untouched). */
export interface VoiceFields {
  inputMode: "voice";
  transcriptLang?: string;
  englishText: string | null;
}
const KNOWN_ENTRY_FIELDS = new Set([
  "v", "text", "sentiment", "created_at", "energy", "sleep", "tags", "tod",
  "input_mode", "transcript_lang", "english_text",
]);

export async function encryptEntry(
  dataKey: Bytes,
  userId: string,
  clientEntryId: string,
  text: string,
  createdAt: string,
  sentiment: number | null,
  structured?: EntryStructured,
  /** Content generation for the version-bound v2 AAD (audit fix M-2,
   *  2026-09-20): binds ("entry", userId, id, version) so a compromised
   *  server cannot pair a stale-but-valid ciphertext with a truthful
   *  version echo. Omitted → the legacy three-part AAD (pre-2026-09-20
   *  blobs and cross-platform vectors keep decrypting unchanged). */
  contentVersion?: number,
  /** Voice channels: presence upgrades the payload to v3. */
  voice?: VoiceFields,
  /** Authenticated original from decryptEntry: carry additive metadata
   * through edits while every known field comes from the new payload. */
  originalPayload?: Readonly<EntryPayload>,
): Promise<{ blobB64: string }> {
  // Payload v2: optional structured channels ride alongside the text. A
  // caller passing none emits the v1 shape byte-for-byte, so older
  // servers and exports behave identically.
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
  const extras = originalPayload
    ? Object.fromEntries(Object.entries(originalPayload).filter(([key]) => !KNOWN_ENTRY_FIELDS.has(key)))
    : {};
  const plaintext = new TextEncoder().encode(JSON.stringify({ ...extras, ...payload }));
  try {
    const aad =
      contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1
        ? buildAad("entry", userId, clientEntryId, String(contentVersion))
        : buildAad("entry", userId, clientEntryId);
    const blob = await encrypt(dataKey, plaintext, aad);
    return { blobB64: toBase64(blob) };
  } finally {
    zeroize(plaintext);
  }
}

export async function decryptEntry(
  dataKey: Bytes,
  userId: string,
  clientEntryId: string,
  blobB64: string,
  /** The server-declared content generation of this row. When present the
   *  version-bound v2 AAD is tried first and the legacy three-part AAD is
   *  the fallback (pre-2026-09-20 rows carry a v1 binding while the row
   *  metadata still declares version 1); omitted → legacy binding only. A
   *  blob that fails BOTH bindings is genuinely tampered and throws. */
  contentVersion?: number,
  opts: {
    /** 2026-10-01 audit M1: refuse the legacy version-free fallback — the
     *  caller has POSITIVE knowledge (the v2-bound mark) that this id has
     *  authenticated under the v2 binding before, so a blob that now fails
     *  it is a stale-ciphertext replay, not a legacy row. */
    forbidLegacyAad?: boolean;
    /** Fired when the v2 binding authenticated (the caller records the
     *  v2-bound mark). */
    onV2Bound?: () => void;
  } = {},
): Promise<EntryPayload> {
  const blob = fromBase64(blobB64);
  let plaintext: Bytes | null = null;
  try {
    if (contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1) {
      try {
        plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId, String(contentVersion)));
        opts.onV2Bound?.();
      } catch (v2Error) {
        if (opts.forbidLegacyAad) throw v2Error;
        plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId));
      }
    } else {
      plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId));
    }
    const payload = validateEntry(JSON.parse(new TextDecoder().decode(plaintext)));
    return payload as unknown as EntryPayload;
  } finally {
    zeroize(blob, plaintext);
  }
}

export interface MoodSummary {
  observations: number; explicit_mood: number; text_estimates: number; excluded_entries: number;
  source: "explicit_mood" | "text_estimate" | "mixed" | "unavailable";
}

export interface InsightsPayload {
  v: number;
  stats?: { patterns?: unknown; language?: unknown; avg_sentiment?: number | null; mood_summary?: MoodSummary };
  /** Analysis generation: must equal the GET /insights echo of the same
   *  name and never decrease across sessions — the rollback-replay
   *  detection contract (stateSeqGuard, P5). Absent on pre-2026-09-19
   *  servers; consumers must treat absence as "nothing to verify", never
   *  as zero. */
  state_seq?: number;
}

export async function decryptInsights(dataKey: Bytes, userId: string, blobB64: string): Promise<InsightsPayload> {
  const blob = fromBase64(blobB64);
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, blob, buildAad("insights", userId, "patterns"));
    const payload = validateInsights(JSON.parse(new TextDecoder().decode(plaintext)));
    return payload as unknown as InsightsPayload;
  } finally {
    zeroize(blob, plaintext);
  }
}

export interface QuestionPayload {
  for_date: string;
  question: string;
  /** The pattern behind the question, when it came from one (routing for
   *  the "did this land?" feedback taps). */
  pattern_pid?: string;
}

export async function decryptQuestion(
  dataKey: Bytes,
  userId: string,
  forDate: string,
  blobB64: string,
): Promise<QuestionPayload> {
  const blob = fromBase64(blobB64);
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, blob, buildAad("question", userId, forDate));
    return JSON.parse(new TextDecoder().decode(plaintext)) as QuestionPayload;
  } finally {
    zeroize(blob, plaintext);
  }
}

// --- voice recordings (VOICE_PLAN 2026-09-29) --------------------------------
//
// Kept recordings use the SAME AES-GCM envelope as entries under the SAME
// data key, with the AAD context "audio" bound to (userId, clientEntryId,
// audio version 1). The server stores the bytes opaquely in S3; the
// therapist portal decrypts only when the patient granted share_voice.

/** The audio envelope's AAD version — independent of the entry
 * content_version; pinned by shared/audio_vectors.json. */
export const AUDIO_PAYLOAD_VERSION = 1;

export async function encryptAudio(
  dataKey: Bytes,
  userId: string,
  clientEntryId: string,
  audio: Bytes,
): Promise<{ blobB64: string }> {
  try {
    const aad = buildAad("audio", userId, clientEntryId, String(AUDIO_PAYLOAD_VERSION));
    const blob = await encrypt(dataKey, audio, aad);
    return { blobB64: toBase64(blob) };
  } finally {
    // The caller owns the plaintext audio (the recorder's blob); this
    // function never zeroes what it did not allocate.
  }
}

export async function decryptAudio(
  dataKey: Bytes,
  userId: string,
  clientEntryId: string,
  blobB64: string,
): Promise<Bytes> {
  const blob = fromBase64(blobB64);
  try {
    return await decrypt(dataKey, blob, buildAad("audio", userId, clientEntryId, String(AUDIO_PAYLOAD_VERSION)));
  } catch (err) {
    zeroize(blob);
    throw err;
  }
}


function payloadRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted payload must be an object.");
  return value as Record<string, unknown>;
}
function finiteField(row: Record<string, unknown>, key: string, min: number, max: number): void {
  const value = row[key];
  if (value !== undefined && value !== null && (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max)) throw new Error(`Invalid encrypted ${key}.`);
}
function validateEntry(value: unknown): Record<string, unknown> {
  const row = payloadRecord(value);
  if (![1,2,3].includes(row.v as number)) throw new Error(`unsupported entry payload version: ${String(row.v)}`);
  if (typeof row.text !== "string" || row.text.length > 100_000) throw new Error("entry payload malformed");
  if (row.created_at !== undefined && (typeof row.created_at !== "string" || !Number.isFinite(Date.parse(row.created_at)))) throw new Error("Invalid encrypted entry date.");
  finiteField(row,"sentiment",-1,1); finiteField(row,"energy",-1,5); finiteField(row,"sleep",1,5);
  if (row.tags !== undefined && (!Array.isArray(row.tags) || row.tags.length > 200 || row.tags.some(tag => typeof tag !== "string" || tag.length > 200))) throw new Error("Invalid encrypted tags.");
  if (row.english_text !== undefined && row.english_text !== null && (typeof row.english_text !== "string" || row.english_text.length > 100_000)) throw new Error("Invalid encrypted translation.");
  if (row.input_mode !== undefined && row.input_mode !== "typed" && row.input_mode !== "voice") throw new Error("Invalid encrypted input mode.");
  if (row.transcript_lang !== undefined && (typeof row.transcript_lang !== "string" || !/^[a-z]{2,3}(?:-[A-Za-z]{2,8})?$/.test(row.transcript_lang))) throw new Error("Invalid encrypted transcript language.");
  if (row.tod !== undefined && !["morning","afternoon","evening","night"].includes(row.tod as string)) throw new Error("Invalid encrypted time bucket.");
  return row;
}
function validateInsights(value: unknown): Record<string, unknown> {
  const row = payloadRecord(value);
  if (row.v !== 2) throw new Error(`unsupported insights payload version: ${String(row.v)}`);
  if (row.state_seq !== undefined && (!Number.isSafeInteger(row.state_seq) || (row.state_seq as number) < 0)) throw new Error("Invalid encrypted analysis generation.");
  if (row.stats === undefined) return row;
  const stats = payloadRecord(row.stats);
  finiteField(stats,"avg_sentiment",-1,1); finiteField(stats,"total_entries",0,10_000_000); finiteField(stats,"active_days",0,10_000_000);
  if (stats.mood_summary !== undefined) {
    const summary = payloadRecord(stats.mood_summary);
    for (const key of ["observations", "explicit_mood", "text_estimates", "excluded_entries"]) {
      if (!Number.isSafeInteger(summary[key]) || (summary[key] as number) < 0 || (summary[key] as number) > 10_000_000) throw new Error("Invalid encrypted mood coverage.");
    }
    const observations = summary.observations as number;
    const explicit = summary.explicit_mood as number;
    const estimates = summary.text_estimates as number;
    const source = observations === 0 ? "unavailable" : explicit === 0 ? "text_estimate" : estimates === 0 ? "explicit_mood" : "mixed";
    if (explicit + estimates !== observations || summary.source !== source ||
        (observations === 0 ? stats.avg_sentiment !== null : typeof stats.avg_sentiment !== "number") ||
        (stats.total_entries !== undefined && observations + (summary.excluded_entries as number) !== stats.total_entries)) throw new Error("Inconsistent encrypted mood coverage.");
  }
  for (const key of ["first_date", "last_date"]) if (stats[key] !== undefined && stats[key] !== null && (typeof stats[key] !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(stats[key] as string))) throw new Error("Invalid encrypted chart date.");
  if (stats.patterns !== undefined) {
    if (!Array.isArray(stats.patterns) || stats.patterns.length > 1_000) throw new Error("Invalid encrypted patterns.");
    for (const raw of stats.patterns) {
      const pattern = payloadRecord(raw);
      if (typeof pattern.label !== "string" || pattern.label.length > 1_000 || typeof pattern.kind !== "string" || pattern.kind.length > 100) throw new Error("Invalid encrypted pattern label.");
      if (typeof pattern.confidence !== "number" || typeof pattern.occurrences !== "number") throw new Error("Invalid encrypted pattern evidence.");
      finiteField(pattern,"confidence",0,1); finiteField(pattern,"occurrences",0,10_000_000);
      {
        // All renderers access detail directly, including legacy patterns.
        const detail = payloadRecord(pattern.detail);
        finiteField(detail,"strength",0,1);
        for (const key of ["sample_days", "sample_entries"]) finiteField(detail,key,0,10_000_000);
        if (detail.evidence_dates !== undefined && (!Array.isArray(detail.evidence_dates) || detail.evidence_dates.length > 10_000 || detail.evidence_dates.some(date => typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)))) throw new Error("Invalid encrypted evidence dates.");
        for (const key of ["pattern_pid","pattern_state","first_seen","last_seen"]) if (detail[key] !== undefined && typeof detail[key] !== "string") throw new Error("Invalid encrypted pattern detail.");
        for (const key of ["sensitive","is_new"]) if (detail[key] !== undefined && typeof detail[key] !== "boolean") throw new Error("Invalid encrypted pattern flags.");
      }
    }
  }
  return row;
}
