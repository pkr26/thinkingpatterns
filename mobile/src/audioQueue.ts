/** Encrypted takes live in files, with small, scoped AsyncStorage descriptors.
 * Acknowledgements compare revisions; clearing beats every outstanding request.
 * No automatic eviction/rejection deletes the user's only recording copy. */
import { captureOpaqueLocalWritePermit, captureLocalWritePermit, assertLocalWritePermit, commitLocalWrite, localWriteScopeEpoch, type LocalWritePermit } from "./localWriteGuard";
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as FileSystem from "expo-file-system/legacy";
import { api, ApiError, canonicalOrigin, getBaseUrl, OriginPinnedError } from "./api/client";
import { engine } from "./crypto/engine";
import { decryptAudio, encryptAudio } from "./crypto/journalCrypto";
import { flushQueue, pendingEntryIds } from "./offlineQueue";
import { cachedEnvelope, fetchEnvelope } from "./keyScheme";
import { ACCOUNT_STORAGE_PREFIX } from "./accountStorage";
const KEY_PREFIX = ACCOUNT_STORAGE_PREFIX.audioQueue;
export const MAX_AUDIO_QUEUE_ITEMS = 12;
export const MAX_TAKE_BYTES = 6_000_000;
const SESSION_EXPIRED_RETRY_MS = 15 * 60_000;
export interface QueuedAudio {
  blobB64: string; mime: string; durationSeconds: number; queuedAt: number;
  notBefore?: number; rejection?: number;
  parentPending?: boolean;
}
interface Descriptor extends Omit<QueuedAudio, "blobB64"> { v: 2; revision: string; uri: string; scope: string }
export class AudioTooLargeError extends Error {
  constructor() { super("kept-recording queue: take exceeds the on-device bound"); this.name = "AudioTooLargeError"; }
}
export class AudioQueueFullError extends Error {
  constructor() { super("kept-recording queue is full — sync or remove a saved take first"); this.name = "AudioQueueFullError"; }
}
let generation = 0;
let mutex: Promise<unknown> = Promise.resolve();
function serialized<T>(op: () => Promise<T>): Promise<T> {
  const result = mutex.then(op, op); mutex = result.catch(() => {}); return result;
}
const keyFor = (origin: string, userId: string, id: string): string => `${KEY_PREFIX}${canonicalOrigin(origin)}:${userId}:${id}`;
const erasedKey = (origin: string, userId: string): string => `${ACCOUNT_STORAGE_PREFIX.audioErase}${Buffer.from(`${canonicalOrigin(origin)}\0${userId}`).toString("base64url")}`;
async function scopeKeys(origin: string, userId: string): Promise<string[]> {
  const prefix = `${KEY_PREFIX}${canonicalOrigin(origin)}:${userId}:`;
  return (await AsyncStorage.getAllKeys()).filter(k => k.startsWith(prefix)).sort();
}
const fileScope = (origin: string, userId: string): string => Buffer.from(`${canonicalOrigin(origin)}\0${userId}`).toString("base64url");
const directoryFor = (origin: string, userId: string): string => `${FileSystem.documentDirectory}mindpattern-audio/${fileScope(origin, userId)}/`;
function parse(raw: string | null, expectedScope?: string): QueuedAudio | Descriptor | null {
  try {
    const x = raw && JSON.parse(raw);
    if (!x || typeof x.mime !== "string" || !Number.isFinite(x.durationSeconds) || x.durationSeconds < 0 || !Number.isFinite(x.queuedAt)) return null;
    if (x.v === 2) {
      return typeof x.uri === "string" && typeof x.revision === "string" && typeof x.scope === "string" && (!expectedScope || x.scope === expectedScope) && validUri(x.uri, x.scope) ? x : null;
    }
    return typeof x.blobB64 === "string" && x.blobB64.length <= MAX_TAKE_BYTES ? x : null;
  } catch { return null; }
}
function validUri(uri: string, scope: string): boolean {
  const dir = FileSystem.documentDirectory;
  const prefix = `${dir}mindpattern-audio/${scope}/`;
  return !!dir && /^[A-Za-z0-9_-]+$/.test(scope) && uri.startsWith(prefix) && /^[a-f0-9]+\.enc$/.test(uri.slice(prefix.length));
}
function isFile(row: QueuedAudio | Descriptor): row is Descriptor { return "v" in row && row.v === 2; }
async function removeFile(row: QueuedAudio | Descriptor | null): Promise<void> {
  if (row && isFile(row)) await FileSystem.deleteAsync(row.uri, { idempotent: true });
}
async function newFile(blobB64: string, item: Omit<QueuedAudio, "blobB64">, origin: string, userId: string): Promise<Descriptor> {
  if (!FileSystem.documentDirectory) throw new Error("Persistent recording storage is unavailable");
  const dir = directoryFor(origin, userId);
  await FileSystem.makeDirectoryAsync(dir, { intermediates: true });
  const revision = Buffer.from(engine.randomBytes(16)).toString("hex");
  const uri = `${dir}${revision}.enc`;
  try {
    // The input is already authenticated ciphertext. UTF8 keeps its base64
    // representation verbatim; no plaintext recording reaches this directory.
    await FileSystem.writeAsStringAsync(uri, blobB64, { encoding: FileSystem.EncodingType.UTF8 });
    return { mime: item.mime, durationSeconds: item.durationSeconds, queuedAt: item.queuedAt,
      ...(item.notBefore === undefined ? {} : { notBefore: item.notBefore }),
      ...(item.rejection === undefined ? {} : { rejection: item.rejection }),
      ...(item.parentPending === undefined ? {} : { parentPending: item.parentPending }),
      v: 2, revision, uri, scope: fileScope(origin, userId) };
  } catch (err) { await FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => {}); throw err; }
}
async function bytes(row: QueuedAudio | Descriptor): Promise<string> {
  const value = isFile(row) ? await FileSystem.readAsStringAsync(row.uri, { encoding: FileSystem.EncodingType.UTF8 }) : row.blobB64;
  if (value.length > MAX_TAKE_BYTES) throw new AudioTooLargeError();
  return value;
}
export async function enqueueAudio(p: { userId: string; clientEntryId: string; blobB64: string; mime: string; durationSeconds: number; parentPending?: boolean }, source?: LocalWritePermit): Promise<void> {
  const permit = captureOpaqueLocalWritePermit(p.userId, source);
  if (p.blobB64.length > MAX_TAKE_BYTES) throw new AudioTooLargeError();
  if (!p.userId || !p.clientEntryId || !Number.isFinite(p.durationSeconds) || p.durationSeconds < 0) throw new Error("Invalid recording");
  const epoch = generation;
  const origin = await getBaseUrl();
  await serialized(async () => {
    assertLocalWritePermit(permit);
    if (epoch !== generation) throw new Error("Recording save was cancelled by account cleanup");
    const key = keyFor(origin, p.userId, p.clientEntryId);
    const oldRaw = await AsyncStorage.getItem(key);
    const keys = await scopeKeys(origin, p.userId);
    if (!keys.includes(key) && keys.length >= MAX_AUDIO_QUEUE_ITEMS) throw new AudioQueueFullError();
    const row = await newFile(p.blobB64, { mime: p.mime, durationSeconds: p.durationSeconds, queuedAt: Date.now(), parentPending: p.parentPending }, origin, p.userId);
    try {
      if (epoch !== generation) throw new Error("Recording save was cancelled by account cleanup");
      await commitLocalWrite(permit, () => AsyncStorage.setItem(key, JSON.stringify(row)));
    } catch (err) { await removeFile(row).catch(() => {}); throw err; }
    await removeFile(parse(oldRaw, fileScope(origin, p.userId))).catch(() => {});
  });
}
export async function audioQueueCount(userId?: string): Promise<number> {
  const owner = userId ?? await api.getUserId(); return owner ? (await scopeKeys(await getBaseUrl(), owner)).length : 0;
}
/** Retained failures are visible and retryable; unreadable legacy blobs are
 * kept in custody rather than silently removed by a cursor-window exception. */
export async function audioQueueStatus(userId?: string): Promise<{ total: number; needsAttention: number }> {
  const owner = userId ?? await api.getUserId(); if (!owner) return { total: 0, needsAttention: 0 };
  const origin = await getBaseUrl();
  const keys = await scopeKeys(origin, owner); let needsAttention = 0;
  for (const key of keys) {
    try { const item = parse(await AsyncStorage.getItem(key), fileScope(origin, owner));
      if (!item || item.rejection || item.parentPending) needsAttention++; else await bytes(item);
    }
    catch { needsAttention++; }
  }
  return { total: keys.length, needsAttention };
}
const inFlight = new Map<string, Promise<number>>();
export async function flushAudioQueue(): Promise<number> {
  const epoch = generation, ownershipEpoch = localWriteScopeEpoch();
  const userId = await api.getUserId(); if (!userId) return 0;
  if (ownershipEpoch !== localWriteScopeEpoch()) return 0;
  const permit = captureLocalWritePermit(userId);
  const origin = await getBaseUrl(); if (epoch !== generation) return 0;
  assertLocalWritePermit(permit);
  const scope = keyFor(origin, userId, "");
  const running = inFlight.get(scope); if (running) return running;
  const task = flush(origin, userId, epoch, permit).finally(() => { if (inFlight.get(scope) === task) inFlight.delete(scope); });
  inFlight.set(scope, task); return task;
}
async function flush(origin: string, userId: string, epoch: number, permit: LocalWritePermit): Promise<number> {
  const eraseEpoch = await AsyncStorage.getItem(erasedKey(origin, userId));
  // A child's ciphertext may upload only after the parent entry is acknowledged.
  await flushQueue(userId).catch(() => {});
  const parents = new Set(await pendingEntryIds(userId));
  let uploaded = 0;
  for (const key of await scopeKeys(origin, userId)) {
    if (epoch !== generation) break;
    try { assertLocalWritePermit(permit); } catch { break; }
    const id = key.slice(keyFor(origin, userId, "").length);
    if (parents.has(id)) continue;
    try {
      let raw = await AsyncStorage.getItem(key);
      let row = parse(raw, fileScope(origin, userId));
      if (!row) continue;
      if (row.parentPending) continue;
      if (row.notBefore && Date.now() < row.notBefore) continue;
      if (!isFile(row)) {
        // Migrate one legacy blob only after its durable file is complete.
        const original = raw;
        const legacy = row;
        await serialized(async () => {
          if (epoch !== generation || await AsyncStorage.getItem(key) !== original) return;
          // The native file is part of the admitted migration, too. Erasure
          // must drain it before deleting this account's directory.
          await commitLocalWrite(permit, async () => {
            const file = await newFile(legacy.blobB64, legacy, origin, userId);
            try {
              if (epoch !== generation || await AsyncStorage.getItem(key) !== original) { await removeFile(file); return; }
              assertLocalWritePermit(permit);
              await AsyncStorage.setItem(key, JSON.stringify(file)); row = file; raw = JSON.stringify(file);
            } catch (error) { await removeFile(file).catch(() => {}); throw error; }
          });
        });
        if (!isFile(row)) continue;
      }
      const snapshot = raw;
      const item = row;
      const blob = await bytes(item);
      if (epoch !== generation || await api.getUserId() !== userId || canonicalOrigin(await getBaseUrl()) !== canonicalOrigin(origin)) break;
      let failure: unknown = null;
      try { await api.uploadAudioAttachment(id, blob, item.mime, item.durationSeconds, origin, permit); }
      catch (err) { failure = err; }
      await serialized(async () => {
        if (epoch !== generation) return;
        const currentEraseEpoch = await AsyncStorage.getItem(erasedKey(origin, userId));
        assertLocalWritePermit(permit);
        if (epoch !== generation || currentEraseEpoch !== eraseEpoch) return;
        const currentRaw = await AsyncStorage.getItem(key);
        assertLocalWritePermit(permit);
        if (epoch !== generation || currentRaw !== snapshot) return;
        if (!failure) {
          await commitLocalWrite(permit, async () => { await AsyncStorage.removeItem(key); await removeFile(item).catch(() => {}); }); uploaded++;
        } else if (failure instanceof ApiError && failure.status === 401) {
          await commitLocalWrite(permit, () => AsyncStorage.setItem(key, JSON.stringify({ ...item, notBefore: Date.now() + SESSION_EXPIRED_RETRY_MS })));
        } else if (failure instanceof ApiError && [403, 404, 409, 413].includes(failure.status)) {
          await commitLocalWrite(permit, () => AsyncStorage.setItem(key, JSON.stringify({ ...item, rejection: failure.status, notBefore: Date.now() + SESSION_EXPIRED_RETRY_MS })));
        }
      });
      if (failure instanceof ApiError && failure.status === 401) break;
      if (failure instanceof OriginPinnedError) break;
    } catch { /* Preserve this unreadable item; continue independent recordings. */ }
  }
  return uploaded;
}
export function abortInFlightAudioFlush(): void { generation++; }
export async function releaseAudioParent(userId: string, id: string, source?: LocalWritePermit): Promise<void> {
  const permit = captureOpaqueLocalWritePermit(userId, source);
  const epoch = generation; const origin = await getBaseUrl();
  await serialized(async () => {
    if (epoch !== generation) return;
    assertLocalWritePermit(permit);
    const key = keyFor(origin, userId, id); const row = parse(await AsyncStorage.getItem(key), fileScope(origin, userId));
    if (epoch !== generation) return;
    if (!row) return;
    delete row.parentPending;
    await commitLocalWrite(permit, () => AsyncStorage.setItem(key, JSON.stringify(row)));
  });
}
export async function retryAudioQueue(userId: string): Promise<void> {
  const permit = captureLocalWritePermit(userId);
  const origin = await getBaseUrl();
  await serialized(async () => {
    assertLocalWritePermit(permit);
    for (const key of await scopeKeys(origin, userId)) {
      const item = parse(await AsyncStorage.getItem(key), fileScope(origin, userId)); if (!item) continue;
      if (item.parentPending) {
        const id = key.slice(keyFor(origin, userId, "").length);
        // A crash between parent commit and releasing the descriptor is
        // recoverable; an actually unsaved parent stays in custody.
        try { await api.getEntry(id, origin, permit); delete item.parentPending; }
        catch { continue; }
      }
      delete item.notBefore; delete item.rejection; await commitLocalWrite(permit, () => AsyncStorage.setItem(key, JSON.stringify(item)));
    }
  });
  await flushAudioQueue();
}
export async function listSavedAudio(userId: string): Promise<Array<{ id: string; queuedAt: number; needsAttention: boolean; revision?: string }>> {
  const origin = await getBaseUrl(); const result = [];
  for (const key of await scopeKeys(origin, userId)) {
    const row = parse(await AsyncStorage.getItem(key), fileScope(origin, userId));
    let needsAttention = !row || !!row.rejection || !!row.parentPending;
    if (row) try { await bytes(row); } catch { needsAttention = true; }
    result.push({ id: key.slice(keyFor(origin, userId, "").length), queuedAt: row?.queuedAt ?? 0, needsAttention, revision: row && isFile(row) ? row.revision : undefined });
  }
  return result;
}
export async function removeSavedAudio(userId: string, id: string, expectedRevision?: string): Promise<void> {
  const permit = captureLocalWritePermit(userId), epoch = generation;
  const origin = await getBaseUrl();
  await serialized(async () => {
    assertLocalWritePermit(permit);
    if (epoch !== generation) throw new Error("Recording removal was cancelled by account cleanup");
    const key = keyFor(origin, userId, id); const row = parse(await AsyncStorage.getItem(key), fileScope(origin, userId));
    if (expectedRevision && (!row || !isFile(row) || row.revision !== expectedRevision)) throw new Error("The saved recording changed; refresh before removing it");
    if (epoch !== generation) throw new Error("Recording removal was cancelled by account cleanup");
    // Drain the complete admitted deletion before a rotation snapshot or
    // credential replacement. The queue mutex keeps its descriptor stable.
    await commitLocalWrite(permit, async () => {
      await removeFile(row); await AsyncStorage.removeItem(key);
      await FileSystem.deleteAsync(`${directoryFor(origin, userId)}exports/${Buffer.from(id).toString("base64url")}.json`, { idempotent: true });
    });
  });
}
/** Bounded, one-record ciphertext export. The native share sheet gets a
 * file, and no plaintext/key is ever shared. Original outbox custody stays. */
export async function exportSavedAudio(userId: string, id: string): Promise<void> {
  const permit = captureLocalWritePermit(userId), epoch = generation;
  const check = () => {
    assertLocalWritePermit(permit);
    if (epoch !== generation) throw new Error("Recording export was cancelled by account cleanup");
  };
  const origin = await getBaseUrl();
  check();
  const row = parse(await AsyncStorage.getItem(keyFor(origin, userId, id)), fileScope(origin, userId));
  check();
  if (!row) throw new Error("This saved recording could not be read");
  const username = await api.getUsername(); if (!username) throw new Error("No saved account");
  check();
  let envelope = await cachedEnvelope(username);
  check();
  if (!envelope) {
    const fetched = await fetchEnvelope();
    check();
    if (fetched.status === "ok") envelope = fetched.envelope;
    else if (fetched.status !== "legacy") throw new Error("The account's encryption format could not be verified; unlock online before exporting");
  }
  const salt = envelope?.saltB64 ?? await api.getCachedSalt(username);
  check();
  if (!salt) throw new Error("Unlock online once before exporting this recording");
  const blob = await bytes(row);
  check();
  const bundle = { version: 2, user_id: userId, username, salt, key_scheme: envelope?.scheme ?? "v1", kdf_params: envelope?.kdfParams ?? null, wrapped_data_key: envelope?.wrappedB64 ?? null, entries: [], insights: [], measures: [], audio: [{ client_entry_id: id, blob, mime_type: row.mime, duration_seconds: row.durationSeconds, content_version: 1, created_at: new Date(row.queuedAt).toISOString() }] };
  const Sharing = await import("expo-sharing");
  check();
  if (!await Sharing.isAvailableAsync()) throw new Error("File sharing is unavailable on this device");
  check();
  const dir = `${directoryFor(origin, userId)}exports/`;
  const uri = `${dir}${Buffer.from(id).toString("base64url")}.json`;
  await serialized(async () => {
    check();
    await commitLocalWrite(permit, async () => {
      await FileSystem.makeDirectoryAsync(dir, { intermediates: true });
      check();
      await FileSystem.writeAsStringAsync(uri, JSON.stringify(bundle), { encoding: FileSystem.EncodingType.UTF8 });
    });
  });
  // Retain encrypted scratch until scoped account cleanup; Android share
  // consumers can read after shareAsync resolves. A canceled sheet must
  // never delete the outbox or its only recording copy.
  check();
  await Sharing.shareAsync(uri, { mimeType: "application/json", UTI: "public.json" });
}
export async function clearAudioQueue(userId?: string): Promise<void> {
  generation++;
  const owner = userId ?? await api.getUserId(); if (!owner) return;
  const origin = await getBaseUrl();
  await serialized(async () => {
    await AsyncStorage.setItem(erasedKey(origin, owner), Buffer.from(engine.randomBytes(16)).toString("hex"));
    // Scope directories include unindexed files left by a process death.
    // This removes precisely this account/origin, including prepared rekeys.
    await FileSystem.deleteAsync(directoryFor(origin, owner), { idempotent: true });
    await AsyncStorage.multiRemove(await scopeKeys(origin, owner));
  });
}
/** Prepare file/descriptor replacements without changing the live old-key
 * records. Rotation's durable journal applies them after the credential commit. */
export async function prepareAudioRekey(userId: string, oldKey: Buffer, newKey: Buffer): Promise<Array<{ key: string; before: string; after: string }>> {
  const origin = await getBaseUrl();
  return serialized(async () => {
    const changes: Array<{ key: string; before: string; after: string }> = [];
    try {
      for (const key of await scopeKeys(origin, userId)) {
        const before = await AsyncStorage.getItem(key); const item = parse(before, fileScope(origin, userId));
        if (!before || !item) throw new Error("A retained recording needs repair before key rotation");
        const id = key.slice(keyFor(origin, userId, "").length);
        const plain = decryptAudio({ dataKey: oldKey }, userId, id, await bytes(item));
        try {
          const blob = encryptAudio({ dataKey: newKey }, userId, id, plain);
          const next = await newFile(blob.blobB64, item, origin, userId);
          changes.push({ key, before, after: JSON.stringify(next) });
        } finally { plain.fill(0); }
      }
      return changes;
    } catch (error) {
      // No journal owns these files until the whole preparation succeeds.
      // A later unreadable take must not leak earlier staged ciphertext on
      // every retry. Live old-key descriptors/files remain untouched.
      await cleanupAudioRekey(changes, "after").catch(() => {});
      throw error;
    }
  });
}

export async function cleanupAudioRekey(changes: Array<{ key: string; before: string; after: string }>, side: "before" | "after"): Promise<void> {
  for (const change of changes) if (change.key.startsWith(KEY_PREFIX)) await removeFile(parse(change[side]));
}
