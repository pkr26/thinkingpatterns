/** Registered key-bound local records. Prepare ciphertext replacements before
 * changing server keys; retain a device-sealed resumable journal until all
 * replacements commit. No data key or plaintext content is in the journal. */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { engine } from "./crypto/engine";
import { secureStore } from "./secureStore";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";
import { canonicalOrigin, getBaseUrl } from "./api/client";
import { prepareAudioRekey, abortInFlightAudioFlush, cleanupAudioRekey } from "./audioQueue";
import { prepareQueueRekey, abortInFlightFlush } from "./offlineQueue";
import { waitJournalDraftWrites } from "./journalDraft";
import { accountStorageKey, ACCOUNT_STORAGE_PREFIX } from "./accountStorage";
export interface LocalReplacement { key: string; before: string; after: string }
export interface AtomicRekeyBody { operation_id: string; new_salt: string; new_verifier: string; consent_wraps: Array<{ consent_id: string; therapist_wrap_pub_key: string; ephemeral_pub: string; wrapped_key: string }> }
interface Journal { v: 1; userId: string; origin: string; proof: string; changes: LocalReplacement[]; phase: "prepared" | "server" | "credential"; operationId: string; oldSaltB64?: string; tokens?: { old: string; next: string }; request?: AtomicRekeyBody }
const marker = Buffer.from("mindpattern-local-rekey/v1");
export { markAccountDeleted, assertAccountActive, assertLocalWritesAllowed, __resetLocalKeyLifecycleForTests,
  captureLocalWritePermit, captureOpaqueLocalWritePermit, assertLocalWritePermit, commitLocalWrite, waitLocalWriteCommits } from "./localWriteGuard";
export type { LocalWritePermit } from "./localWriteGuard";
import { freezeLocalKeyWrites, installLocalDataKey, clearLocalKeyState, waitLocalWriteCommits, localWriteScopeEpoch, localKeyGeneration, assertLocalTransitionScope, commitLocalTransitionWrite, commitLocalErasureWrite } from "./localWriteGuard";
async function journalKey(userId: string): Promise<string> {
  return accountStorageKey.localRekey(new URL(await getBaseUrl()).origin, userId);
}

// The device-sealed journal is chunked; a queue near its 1 MiB ceiling
// must not turn the journal itself into an unreadable Android cursor row.
async function readJournal(key: string): Promise<string | null> {
  const raw = await secureStore.getItem(key); if (!raw) return null;
  const index = JSON.parse(raw) as { revision: string; parts: number };
  if (!index.revision || !Number.isInteger(index.parts) || index.parts < 1 || index.parts > 500) throw new Error("Invalid rekey checkpoint index");
  const chunks: string[] = [];
  for (let i = 0; i < index.parts; i++) {
    const chunk = await secureStore.getItem(`${key}.chunk.${index.revision}.${i}`);
    if (chunk === null) throw new Error("Incomplete rekey checkpoint");
    chunks.push(chunk);
  }
  return chunks.join("");
}
async function writeJournal(key: string, value: string): Promise<void> {
  const revision = Buffer.from(engine.randomBytes(16)).toString("hex");
  const chunks = value.match(/[\s\S]{1,64000}/g) ?? [""];
  for (let i = 0; i < chunks.length; i++) await secureStore.setItem(`${key}.chunk.${revision}.${i}`, chunks[i]!);
  await secureStore.setItem(key, JSON.stringify({ revision, parts: chunks.length }));
  const obsolete = (await AsyncStorage.getAllKeys()).filter(k => k.startsWith(`${key}.chunk.`) && !k.startsWith(`${key}.chunk.${revision}.`));
  await AsyncStorage.multiRemove(obsolete);
}
async function deleteJournal(key: string): Promise<void> {
  const chunks = (await AsyncStorage.getAllKeys()).filter(k => k.startsWith(`${key}.chunk.`));
  await AsyncStorage.multiRemove([key, ...chunks]);
}
export async function pendingLocalRekey(userId: string): Promise<boolean> {
  return (await secureStore.getItem(await journalKey(userId))) !== null;
}
function parse(raw: string): Journal {
  const value = JSON.parse(raw) as Journal;
  if (value.v !== 1 || !Array.isArray(value.changes) || !["prepared", "server", "credential"].includes(value.phase) || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.operationId)) throw new Error("Invalid local key-rotation journal");
  return value;
}
function prove(journal: Journal, key: Buffer): void {
  const plain = decrypt(key, Buffer.from(journal.proof, "base64"), buildAad("local-rekey", journal.userId, journal.origin));
  try { if (!plain.equals(marker)) throw new Error("Key-rotation proof mismatch"); } finally { plain.fill(0); }
}
/** Each authored/guard store must appear here; device-key-sealed preferences
 * and generation guards do not depend on the changing account data key. */
export const LOCAL_KEY_BOUND_STORES: ReadonlyArray<readonly [string, string, "origin"?]> = [
  [ACCOUNT_STORAGE_PREFIX.safetyPlan, "safety-plan"],
  [ACCOUNT_STORAGE_PREFIX.safetyPlanDraft, "safety-plan-draft"],
  [ACCOUNT_STORAGE_PREFIX.pendingMeasure, "pending-measure"],
  [ACCOUNT_STORAGE_PREFIX.moodLog, "moodlog"],
  [ACCOUNT_STORAGE_PREFIX.feedback, "feedback-local"],
  [ACCOUNT_STORAGE_PREFIX.entryVersions, "entry-versions"],
  [ACCOUNT_STORAGE_PREFIX.entryV2Bound, "entry-v2-bound"],
  [ACCOUNT_STORAGE_PREFIX.journalDraft, "journal-draft", "origin"],
] as const;
export async function prepareLocalRekey(userId: string, oldKey: Buffer, newKey: Buffer, context?: { oldSaltB64: string }): Promise<void> {
  const scopeEpoch = localWriteScopeEpoch();
  assertLocalTransitionScope(userId, scopeEpoch);
  freezeLocalKeyWrites(userId); abortInFlightFlush(); abortInFlightAudioFlush();
  const transitionGeneration = localKeyGeneration(userId);
  await waitLocalWriteCommits(userId);
  await waitJournalDraftWrites();
  const key = await journalKey(userId);
  const existing = await readJournal(key);
  if (existing) { const journal = parse(existing); prove(journal, newKey); return; }
  const changes: LocalReplacement[] = [];
  const origin = new URL(await getBaseUrl()).origin;
  const boundOrigin = canonicalOrigin(origin);
  for (const [prefix, purpose, bound] of LOCAL_KEY_BOUND_STORES) {
    assertLocalTransitionScope(userId, scopeEpoch, transitionGeneration);
    const slot = bound === "origin" ? `${prefix}${Buffer.from(`${boundOrigin}\0${userId}`).toString("base64url")}` : `${prefix}${userId}`;
    const before = await AsyncStorage.getItem(slot);
    assertLocalTransitionScope(userId, scopeEpoch, transitionGeneration);
    if (before === null) continue;
    const aad = bound === "origin" ? buildAad(purpose, userId, boundOrigin) : buildAad(purpose, userId);
    const plain = decrypt(oldKey, Buffer.from(before, "base64"), aad);
    try { changes.push({ key: slot, before, after: encrypt(newKey, plain, aad).toString("base64") }); }
    finally { plain.fill(0); }
  }
  changes.push(...await prepareQueueRekey(userId, oldKey, newKey));
  changes.push(...await prepareAudioRekey(userId, oldKey, newKey));
  const random = Buffer.from(engine.randomBytes(16)); random[6] = (random[6]! & 0x0f) | 0x40; random[8] = (random[8]! & 0x3f) | 0x80;
  const hex = random.toString("hex"); random.fill(0);
  const operationId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  const journal: Journal = { v: 1, userId, origin, changes, operationId, oldSaltB64: context?.oldSaltB64, phase: "prepared", proof: encrypt(newKey, marker, buildAad("local-rekey", userId, origin)).toString("base64") };
  try { await commitLocalTransitionWrite(userId, scopeEpoch, () => writeJournal(key, JSON.stringify(journal)), transitionGeneration); }
  catch (err) { await cleanupAudioRekey(changes, "after").catch(() => {}); throw err; }
}
export async function pendingLocalRekeyOldSalt(userId: string): Promise<string | null> {
  const raw = await readJournal(await journalKey(userId)); if (!raw) return null;
  const salt = parse(raw).oldSaltB64;
  return typeof salt === "string" && Buffer.from(salt, "base64").length === 16 ? salt : null;
}
/** Tokens are retained only in the device-sealed journal. A response lost
 * after atomic server commit must retry directly with the same operation
 * before attempting any endpoint that requires the new bearer epoch. */
export async function localRekeyRequest(userId: string, dataKey: Buffer): Promise<{ operationId: string; tokens?: { old: string; next: string }; body?: AtomicRekeyBody }> {
  const raw = await readJournal(await journalKey(userId)); if (!raw) throw new Error("Missing key-rotation checkpoint");
  const journal = parse(raw); prove(journal, dataKey);
  return { operationId: journal.operationId, tokens: journal.tokens, body: journal.request };
}
const journalMutations = new Map<string, Promise<unknown>>();
function mutateJournal<T>(userId: string, operation: (epoch: number, generation: number) => Promise<T>): Promise<T> {
  const epoch = localWriteScopeEpoch(), generation = localKeyGeneration(userId), scope = `${epoch}\0${generation}\0${userId}`;
  assertLocalTransitionScope(userId, epoch, generation);
  const prior = journalMutations.get(scope) ?? Promise.resolve();
  const run = prior.then(() => { assertLocalTransitionScope(userId, epoch, generation); return operation(epoch, generation); });
  const tail = run.catch(() => {}); journalMutations.set(scope, tail);
  void tail.finally(() => { if (journalMutations.get(scope) === tail) journalMutations.delete(scope); });
  return run;
}
export async function storeLocalRekeyRequest(userId: string, dataKey: Buffer, request: AtomicRekeyBody): Promise<void> {
  return mutateJournal(userId, async (epoch, generation) => {
    const key = await journalKey(userId); const raw = await readJournal(key); if (!raw) throw new Error("Missing key-rotation checkpoint");
    const journal = parse(raw); prove(journal, dataKey);
    if (request.operation_id !== journal.operationId) throw new Error("Key-rotation operation mismatch");
    if (journal.request && JSON.stringify(journal.request) !== JSON.stringify(request)) throw new Error("Key-rotation request changed");
    await commitLocalTransitionWrite(userId, epoch, () => writeJournal(key, JSON.stringify({ ...journal, request })), generation);
  });
}
export async function storeLocalRekeyTokens(userId: string, dataKey: Buffer, tokens: { old: string; next: string }): Promise<void> {
  if (!tokens.old || !tokens.next) throw new Error("Invalid processing session");
  return mutateJournal(userId, async (epoch, generation) => {
    const key = await journalKey(userId); const raw = await readJournal(key); if (!raw) throw new Error("Missing key-rotation checkpoint");
    const journal = parse(raw); prove(journal, dataKey);
    await commitLocalTransitionWrite(userId, epoch, () => writeJournal(key, JSON.stringify({ ...journal, tokens })), generation);
  });
}
export async function markLocalRekeyPhase(userId: string, phase: Journal["phase"]): Promise<void> {
  return mutateJournal(userId, async (epoch, generation) => {
    const key = await journalKey(userId); const raw = await readJournal(key);
    if (!raw) throw new Error("Missing key-rotation checkpoint");
    await commitLocalTransitionWrite(userId, epoch, () => writeJournal(key, JSON.stringify({ ...parse(raw), phase })), generation);
  });
}
/** Called after credential commit and on every verified unlock. Applying an
 * already-applied row is idempotent; divergent rows are preserved and block
 * unlock rather than being overwritten with a stale snapshot. */
export async function resumeLocalRekey(userId: string, dataKey: Buffer, options?: { credentialConfirmed: boolean }): Promise<void> {
  const scopeEpoch = localWriteScopeEpoch();
  const key = await journalKey(userId); const raw = await readJournal(key);
  assertLocalTransitionScope(userId, scopeEpoch);
  if (!raw) { installLocalDataKey(userId, dataKey); return; }
  const journal = parse(raw);
  if (journal.userId !== userId || journal.origin !== new URL(await getBaseUrl()).origin) throw new Error("Key rotation belongs to a different account or server");
  prove(journal, dataKey);
  if (journal.phase !== "credential" && !options?.credentialConfirmed) throw new Error("The password change must be confirmed online before local records can move");
  freezeLocalKeyWrites(userId);
  const transitionGeneration = localKeyGeneration(userId);
  await waitLocalWriteCommits(userId);
  for (const change of journal.changes) {
    assertLocalTransitionScope(userId, scopeEpoch, transitionGeneration);
    const current = await AsyncStorage.getItem(change.key);
    assertLocalTransitionScope(userId, scopeEpoch, transitionGeneration);
    if (current === change.after) continue;
    if (current !== change.before) throw new Error("A local record changed during rotation; recovery is required");
    await commitLocalTransitionWrite(userId, scopeEpoch, () => AsyncStorage.setItem(change.key, change.after), transitionGeneration);
  }
  await commitLocalTransitionWrite(userId, scopeEpoch, () => cleanupAudioRekey(journal.changes, "before"), transitionGeneration);
  await commitLocalTransitionWrite(userId, scopeEpoch, () => deleteJournal(key), transitionGeneration);
  assertLocalTransitionScope(userId, scopeEpoch, transitionGeneration);
  installLocalDataKey(userId, dataKey);
}
export async function clearLocalRekey(userId: string): Promise<void> {
  const epoch = localWriteScopeEpoch();
  clearLocalKeyState(userId);
  await waitLocalWriteCommits(userId);
  const key = await journalKey(userId);
  const raw = await readJournal(key);
  await commitLocalErasureWrite(userId, epoch, async () => {
    if (raw) { const journal = parse(raw); await cleanupAudioRekey(journal.changes, "before"); await cleanupAudioRekey(journal.changes, "after"); }
    await deleteJournal(key);
  });
}
