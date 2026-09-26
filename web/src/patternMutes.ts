/**
 * The encrypted local pattern-mute store (audit 2026-09-26, M-W4) — ported
 * onto the same seam contract as moodLog/questionFeedback: "never plaintext
 * content in observable storage".
 *
 * A pattern id is CONTENT-DERIVED ("topic:divorce", "rumination:<the
 * phrase>") — storing the muted set in plaintext localStorage handed a
 * device-storage reader a list of exactly the themes the user found
 * heaviest. The set now lives in the kvstore (IndexedDB) as one
 * AES-256-GCM blob under the account's DATA key, AAD-bound to the account
 * id — the same standing as the mood log. The server-side mute sync
 * (questionFeedback's recordPatternMute → recompute blob) is unchanged.
 *
 * Key custody: callers pass the vault's SHARED dataKey buffer; every call
 * snapshots the bytes at call time and zeroizes the copy in finally (a
 * lock mid-await must not produce a blob no future read can open). A
 * corrupt/tampered blob degrades to an empty set — disposable metadata,
 * never a crash.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv } from "./kvstore";
import { localStore } from "./platform";

const storageKey = (userId: string): string => `mindpattern.patternMutes.v1.${userId}`;
/** The pre-fix plaintext localStorage key (M-W4): adopted once, then gone. */
const legacyKey = (userId: string): string => `mindpattern.mutedPids.v1.${userId}`;

/** Serializes read-modify-write cycles (two mutes landing in the same
 *  frame must not read the same set and silently drop each other). */
let muteMutex: Promise<unknown> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const run = muteMutex.then(operation, operation);
  muteMutex = run.catch(() => {});
  return run;
}

function sanitize(raw: unknown): Set<string> {
  const pids = new Set<string>();
  if (!Array.isArray(raw)) return pids;
  for (const pid of raw) {
    if (typeof pid === "string" && pid.length > 0 && pid.length <= 256) pids.add(pid);
  }
  return pids;
}

async function read(dataKey: Bytes, userId: string): Promise<Set<string>> {
  const stored = await kv.getItem(storageKey(userId));
  if (!stored) return new Set();
  let plaintext: Bytes | null = null;
  try {
    plaintext = await decrypt(dataKey, fromBase64(stored), buildAad("pattern-mutes", userId));
    return sanitize(JSON.parse(new TextDecoder().decode(plaintext)));
  } catch {
    // Wrong key, corruption, or tampering: disposable.
    return new Set();
  } finally {
    zeroize(plaintext);
  }
}

/** The muted pid set, decrypted under the data key. */
export async function readMutedPids(dataKey: Bytes, userId: string): Promise<Set<string>> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    return await serialized(() => read(keyCopy, userId));
  } finally {
    zeroize(keyCopy);
  }
}

/** Persist the muted pid set as one encrypted blob. */
export async function writeMutedPids(dataKey: Bytes, userId: string, pids: Iterable<string>): Promise<void> {
  const keyCopy = new Uint8Array(new ArrayBuffer(dataKey.length));
  keyCopy.set(dataKey);
  try {
    await serialized(async () => {
      const payload = new TextEncoder().encode(JSON.stringify([...pids]));
      try {
        const blob = await encrypt(keyCopy, payload, buildAad("pattern-mutes", userId));
        await kv.setItem(storageKey(userId), toBase64(blob));
      } finally {
        zeroize(payload);
      }
    });
  } finally {
    zeroize(keyCopy);
  }
}

/** One-time adoption of the pre-fix plaintext mute list (M-W4): the pids
 *  move into the encrypted blob and the localStorage key is removed — the
 *  migration must not leave the plaintext copy behind. Storage without the
 *  legacy key is a no-op. */
export async function adoptLegacyPlaintextMutes(dataKey: Bytes, userId: string): Promise<Set<string>> {
  const current = await readMutedPids(dataKey, userId);
  let legacyRaw: string | null = null;
  try {
    legacyRaw = localStore.get(legacyKey(userId));
  } catch {
    legacyRaw = null;
  }
  if (!legacyRaw) return current;
  try {
    const parsed = JSON.parse(legacyRaw) as unknown;
    const adopted = sanitize(parsed);
    if (adopted.size > 0) {
      for (const pid of adopted) current.add(pid);
      await writeMutedPids(dataKey, userId, current);
    }
  } catch {
    // Unparseable legacy value: drop it below rather than crash the view.
  } finally {
    try {
      localStore.removePrefix(legacyKey(userId));
    } catch {
      // Storage is optional; the plaintext copy dies on the next wipe.
    }
  }
  return current;
}

/** Account-deletion hygiene (M-W3): the encrypted set must not outlive
 *  its account. */
export async function clearMutedPids(userId: string): Promise<void> {
  await kv.removeItem(storageKey(userId));
}
