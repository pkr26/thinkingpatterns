/** Process-local ownership of key-bound writes. A temporary freeze cannot
 * make an old callback valid again when a new generation is installed. */
import { engine } from "./crypto/engine";

export interface LocalWritePermit {
  readonly userId: string;
  readonly generation: number;
  readonly scopeEpoch: number;
  readonly keyId?: string;
}
const frozen = new Set<string>();
const deleted = new Set<string>();
const generations = new Map<string, number>();
const installedKeys = new Map<string, { originEpoch: number; keyId: string }>();
const commits = new Map<string, Set<Promise<unknown>>>();
const ORIGIN_ERASURE_LANE = "\0origin-erasure";
let scopeEpoch = 0;
let originEpoch = 0;
// No account owns writes until a verified login or cold-start credential
// hydration explicitly publishes one. `undefined` is reserved for the
// legacy-permissive test reset seam below; production starts fail-closed.
let sessionOwner: string | null | undefined = null;
const generationOf = (userId: string) => generations.get(userId) ?? 0;
export function localKeyGeneration(userId: string): number { return generationOf(userId); }
function advance(userId: string): void { generations.set(userId, generationOf(userId) + 1); }
function keyId(key: Buffer): string {
  if (key.length !== 32) throw new Error("Invalid local data key");
  return engine.createHash("sha256").update(key).digest().toString("hex");
}
export function localWriteScopeEpoch(): number { return scopeEpoch; }
export function advanceLocalWriteScope(): number { return ++scopeEpoch; }
/** Called before the first asynchronous credential/origin mutation. */
export function changeLocalSessionOwner(userId: string | null): void {
  scopeEpoch++; sessionOwner = userId;
}
/** Cold-start credential hydration establishes the owner that was already
 * durably authenticated. Unlike a fresh login transition, rereading the
 * same owner is a no-op so routine auth checks do not retire valid permits. */
export function hydrateLocalSessionOwner(userId: string | null): void {
  if (sessionOwner === userId) return;
  scopeEpoch++;
  sessionOwner = userId;
}
export function changeLocalOrigin(): void {
  originEpoch++; scopeEpoch++; sessionOwner = null;
}
/** The authoritative origin lifetime, unchanged by login/key rotation. */
export function localWriteOriginEpoch(): number { return originEpoch; }
export function markAccountDeleted(userId: string): void { deleted.add(userId); advance(userId); }
export function assertAccountActive(userId: string): void {
  if (deleted.has(userId)) throw new Error("This account has been deleted; local writes are disabled");
}
export function assertLocalWritesAllowed(userId: string): void {
  assertAccountActive(userId);
  if (frozen.has(userId)) throw new Error("Key rotation is in progress; local writes are paused");
  if (sessionOwner === null || (sessionOwner !== undefined && sessionOwner !== userId)) throw new Error("The local account/session changed; unlock again before writing");
}
export function captureLocalWritePermit(userId: string, dataKey?: Buffer): LocalWritePermit {
  assertLocalWritesAllowed(userId);
  const bound = installedKeys.get(userId);
  const id = dataKey === undefined ? undefined : keyId(dataKey);
  if (bound && (bound.originEpoch !== originEpoch || (id !== undefined && id !== bound.keyId))) throw new Error("The local data-key generation changed; unlock again before writing");
  return Object.freeze({ userId, generation: generationOf(userId), scopeEpoch, ...(id === undefined ? {} : { keyId: id }) });
}
export function assertLocalWritePermit(permit: LocalWritePermit): void {
  assertLocalWritesAllowed(permit.userId);
  if (permit.scopeEpoch !== scopeEpoch || permit.generation !== generationOf(permit.userId)) throw new Error("The local write belongs to a retired account or key generation");
  const bound = installedKeys.get(permit.userId);
  if (bound && (bound.originEpoch !== originEpoch || (permit.keyId !== undefined && permit.keyId !== bound.keyId))) throw new Error("The local write belongs to a retired data key");
}
/** Opaque ciphertext needs its producer's key-bound permit once a verified
 * key has been installed; stored legacy rows remain independently migratable. */
export function captureOpaqueLocalWritePermit(userId: string, source?: LocalWritePermit): LocalWritePermit {
  if (source) {
    if (source.userId !== userId || source.keyId === undefined) throw new Error("Invalid ciphertext producer ownership");
    assertLocalWritePermit(source); return source;
  }
  if (installedKeys.has(userId)) throw new Error("A key-bound ciphertext producer permit is required");
  return captureLocalWritePermit(userId);
}
/** Register the physical commit synchronously. Rotation/erasure drains these
 * writes before snapshot/deletion, including a native write already admitted. */
export function commitLocalWrite<T>(permit: LocalWritePermit, write: () => Promise<T>): Promise<T> {
  assertLocalWritePermit(permit);
  return trackCommit(permit.userId, write);
}
/** Account metadata that is not encrypted under the data key still belongs
 * to the same owner/generation lifecycle. Capture before admission and track
 * the physical commit so deletion/origin replacement cannot race past it. */
export function commitActiveAccountWrite<T>(userId: string, write: () => Promise<T>): Promise<T> {
  const permit = captureLocalWritePermit(userId);
  return commitLocalWrite(permit, async () => {
    assertLocalWritePermit(permit);
    return write();
  });
}
export function assertLocalTransitionScope(userId: string, epoch: number, generation?: number): void {
  assertAccountActive(userId);
  if (epoch !== scopeEpoch || sessionOwner === null || (sessionOwner !== undefined && sessionOwner !== userId)) throw new Error("The local account/server changed during key transition");
  if (generation !== undefined && generation !== generationOf(userId)) throw new Error("This local key transition belongs to a retired generation");
}
export function commitLocalTransitionWrite<T>(userId: string, epoch: number, write: () => Promise<T>, generation?: number): Promise<T> {
  assertLocalTransitionScope(userId, epoch, generation);
  return trackCommit(userId, write);
}
/** Administrative deletion is allowed for a tombstoned account, but its
 * physical work still drains before credential/origin replacement publishes. */
export function commitLocalErasureWrite<T>(userId: string, epoch: number, write: () => Promise<T>): Promise<T> {
  if (epoch !== scopeEpoch) throw new Error("The account/server changed during local erasure");
  return trackCommit(userId, write);
}
/** Origin retirement can include unattributable upgrade-era state (for
 * example the former singleton biometric slot). Keep that physical deletion
 * in the same tracked administrative lane even when no account id survives
 * from which to derive an owner-scoped permit. */
export function commitOriginErasureWrite<T>(epoch: number, write: () => Promise<T>): Promise<T> {
  if (epoch !== scopeEpoch) throw new Error("The account/server changed during origin erasure");
  return trackCommit(ORIGIN_ERASURE_LANE, write);
}
function trackCommit<T>(userId: string, write: () => Promise<T>): Promise<T> {
  const pending = Promise.resolve(write());
  let owned = commits.get(userId);
  if (!owned) { owned = new Set(); commits.set(userId, owned); }
  owned.add(pending);
  return pending.finally(() => { owned!.delete(pending); if (owned!.size === 0) commits.delete(userId); });
}
export async function waitLocalWriteCommits(userId?: string): Promise<void> {
  for (;;) {
    const pending = userId === undefined ? [...commits.values()].flatMap(set => [...set]) : [...(commits.get(userId) ?? [])];
    if (pending.length === 0) return;
    await Promise.allSettled(pending);
  }
}
export function freezeLocalKeyWrites(userId: string): void { assertAccountActive(userId); frozen.add(userId); advance(userId); }
/** Only a verified unlock/committed migration can install an active key. */
export function installLocalDataKey(userId: string, dataKey: Buffer): void {
  assertAccountActive(userId);
  const id = keyId(dataKey), prior = installedKeys.get(userId);
  if (!prior || prior.keyId !== id || prior.originEpoch !== originEpoch) advance(userId);
  installedKeys.set(userId, { originEpoch, keyId: id }); frozen.delete(userId);
}
export function clearLocalKeyState(userId: string): void {
  advance(userId); installedKeys.delete(userId); frozen.delete(userId);
}
export function __resetLocalKeyLifecycleForTests(): void {
  frozen.clear(); deleted.clear(); generations.clear(); installedKeys.clear(); commits.clear(); sessionOwner = undefined; scopeEpoch++; originEpoch++;
}
