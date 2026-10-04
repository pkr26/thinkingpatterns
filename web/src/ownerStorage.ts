/** Canonical registry for account-scoped durable browser storage.
 *
 * Every IndexedDB key that ends up associated with one account belongs
 * here. kvstore uses the policy to fence commits; localErasure uses the
 * same parser to enumerate deletion targets. Adding a new owner-scoped
 * store without registering it would otherwise let a late tab recreate
 * metadata after confirmed erasure.
 */

export interface AccountKeyPolicy { owner: string; keyBound: boolean }

/** Values authenticated/encrypted under the account data key. Producers
 * must carry a write-generation permit once a generation exists. */
export const KEY_BOUND_OWNER_PREFIXES = [
  "mindpattern.draft.active.",
  "mindpattern.safetyPlan.",
  "mindpattern.moodlog.",
  "mindpattern.feedback.",
  "mindpattern.pendingMeasure.",
  "mindpattern.patternMutes.v1.",
  "mindpattern.entryVersions.",
  "mindpattern.entryV2Bound.",
] as const;

/** Non-content/account-operation state. These writes do not require a
 * data-key permit, but every commit still checks the durable generation
 * and is rejected forever once that owner is marked deleted. */
export const METADATA_OWNER_PREFIXES = [
  "mindpattern.measureCadence.",
  "mindpattern.thresholdNotice.v1.",
  "mindpattern.stateSeq.",
  "mindpattern.localRotation.",
  "mindpattern.rotationSalt.",
  "mindpattern.rotationSeed.",
  "mindpattern.rotatePendingSalt.", // legacy alias; no new writes
  "mindpattern.rekeyHint.",
  "mindpattern.onboarding.v1.",
  "mindpattern.mutedPids.v1.", // legacy plaintext migration residue
] as const;

function queuePolicy(key: string): AccountKeyPolicy | null {
  const match = /^mindpattern\/queue\.v1\.(items|rejected|quarantine|evictions)\.([A-Za-z0-9_-]+)$/.exec(key);
  if (!match) return null;
  try {
    const binary = atob(match[2]!.replace(/-/g, "+").replace(/_/g, "/"));
    const scope = new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
    const owner = scope.includes("\0") ? scope.slice(scope.indexOf("\0") + 1) : "";
    return owner ? { owner, keyBound: match[1] !== "evictions" } : null;
  } catch {
    return null;
  }
}

export function accountKeyPolicy(key: string): AccountKeyPolicy | null {
  const keyBound = KEY_BOUND_OWNER_PREFIXES.find((prefix) => key.startsWith(prefix));
  if (keyBound) {
    const owner = key.slice(keyBound.length);
    return owner ? { owner, keyBound: true } : null;
  }
  const metadata = METADATA_OWNER_PREFIXES.find((prefix) => key.startsWith(prefix));
  if (metadata) {
    const owner = key.slice(metadata.length);
    return owner ? { owner, keyBound: false } : null;
  }
  return queuePolicy(key);
}

export function keyBelongsToOwner(key: string, owner: string): boolean {
  return accountKeyPolicy(key)?.owner === owner;
}
