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
  v: 1;
  text: string;
  sentiment: number | null; // computed on-device before encryption
  created_at: string; // ISO date
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
): { blobB64: string } {
  const payload: EntryPayload = { v: 1, text, sentiment, created_at: createdAt };
  // Stryker disable StringLiteral
const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  // Stryker restore StringLiteral
  const aad = buildAad("entry", userId, clientEntryId);
  const blob = encrypt(keys.dataKey, plaintext, aad);
  return { blobB64: blob.toString("base64") };
}

export function decryptEntry(
  keys: Pick<Keys, "dataKey">,
  userId: string,
  clientEntryId: string,
  blobB64: string,
): EntryPayload {
  const plaintext = decrypt(keys.dataKey, Buffer.from(blobB64, "base64"), buildAad("entry", userId, clientEntryId));
  return JSON.parse(plaintext.toString("utf8")) as EntryPayload;
}

/** The only insights payload schema this client understands (the backend
 *  emits "v": 2). An unknown version must fail LOUDLY here — silently
 *  parsing a future schema as if it were v2 is how a schema roll corrupts
 *  the UI with misread fields. Mirrors the InsightsScreen phase guard. */
export const INSIGHTS_PAYLOAD_VERSION = 2;

export interface InsightsPayload {
  v: number;
  stats?: { patterns?: unknown };
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
  return JSON.parse(plaintext.toString("utf8")) as { for_date: string; question: string };
}

export { zeroize };
