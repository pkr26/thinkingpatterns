/**
 * The patient payload layer — entry envelopes (payload v1/v2), insights
 * and question blobs. Ported from mobile's MindPatternCrypto.ts (same
 * wire contract, same loud-fail version guards); the AEAD/AAD primitives
 * come from ./core (portal's WebCrypto implementation).
 */
import { buildAad } from "./aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./core";

export interface EntryPayload {
  v: 1 | 2;
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
): Promise<{ blobB64: string }> {
  // Payload v2: optional structured channels ride alongside the text. A
  // caller passing none emits the v1 shape byte-for-byte, so older
  // servers and exports behave identically.
  const payload: EntryPayload =
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
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
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

/** The only entry payload schema versions this client understands (v2
 *  added the structured channels). An unknown version must throw, never
 *  be silently miscast as today's shape — a future v3 misread is how a
 *  schema roll corrupts the journal UI with wrong-typed fields. */
export const ENTRY_PAYLOAD_VERSIONS: readonly number[] = [1, 2];

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
): Promise<EntryPayload> {
  const blob = fromBase64(blobB64);
  let plaintext: Bytes | null = null;
  try {
    if (contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1) {
      try {
        plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId, String(contentVersion)));
      } catch {
        plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId));
      }
    } else {
      plaintext = await decrypt(dataKey, blob, buildAad("entry", userId, clientEntryId));
    }
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { v?: unknown };
    // The AEAD bound the bytes to this account/entry, but nothing else
    // vouches for the version field.
    if (!ENTRY_PAYLOAD_VERSIONS.includes(payload.v as number)) {
      throw new Error(`unsupported entry payload version: ${String(payload.v)}`);
    }
    return payload as EntryPayload;
  } finally {
    zeroize(blob, plaintext);
  }
}

/** The only insights payload schema this client understands (the backend
 *  emits "v": 2). An unknown version must fail LOUDLY here — silently
 *  parsing a future schema as if it were v2 is how a schema roll corrupts
 *  the UI with misread fields. */
export const INSIGHTS_PAYLOAD_VERSION = 2;

export interface InsightsPayload {
  v: number;
  stats?: { patterns?: unknown; language?: unknown };
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
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { v?: unknown };
    if (payload.v !== INSIGHTS_PAYLOAD_VERSION) {
      throw new Error(`unsupported insights payload version: ${String(payload.v)}`);
    }
    return payload as InsightsPayload;
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
