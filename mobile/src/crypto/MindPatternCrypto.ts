/**
 * The device-side crypto orchestrator: key derivation, entry envelopes,
 * and decryption of insight/question payloads. Mirrors backend/tests/helpers.py
 * (the client emulator) — if these ever disagree, shared/vectors.json fails.
 */
import { buildAad, decrypt, encrypt } from "./envelope";
import { deriveAuthKey, deriveDataKey, deriveMasterKey, deriveMasterKeyAsync, zeroize } from "./kdf";

export interface Keys {
  masterKey: Buffer;
  authKey: Buffer; // only this ever crosses the network (as the login verifier)
  dataKey: Buffer; // encrypts everything
}

export interface EntryPayload {
  v: 1 | 2;
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
 *  the login/unlock screens' preferred path. */
export async function deriveKeysAsync(password: string, salt: Buffer): Promise<Keys> {
  const masterKey = await deriveMasterKeyAsync(password, salt);
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
): { blobB64: string } {
  // Payload v2 (2026-09-17): optional structured channels ride alongside
  // the text. A caller passing none emits the v1 shape byte-for-byte, so
  // older servers and exports behave identically.
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
 *  added the structured channels). Mirrors decryptInsights' loud-fail
 *  contract: an unknown version must throw, never be silently miscast as
 *  today's shape — a future v3 misread is how a schema roll corrupts the
 *  journal UI with wrong-typed fields. */
export const ENTRY_PAYLOAD_VERSIONS: readonly number[] = [1, 2];

export function decryptEntry(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  blobB64: string,
  /** The server-declared content generation of this row. When present the
   *  version-bound v2 AAD is tried first and the legacy three-part AAD is
   *  the fallback (audit fix M-2: pre-2026-09-20 rows carry a v1 binding
   *  while the row metadata still declares version 1); omitted → legacy
   *  binding only. A blob that fails BOTH bindings is genuinely tampered
   *  and throws. */
  contentVersion?: number,
): EntryPayload {
  const blob = Buffer.from(blobB64, "base64");
  let plaintext: Buffer;
  if (contentVersion !== undefined && Number.isSafeInteger(contentVersion) && contentVersion >= 1) {
    try {
      plaintext = decrypt(keys.dataKey, blob, buildAad("entry", userId, clientEntryId, String(contentVersion)));
    } catch {
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
