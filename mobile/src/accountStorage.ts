/** Canonical inventory of durable state whose meaning is bound to one
 * account and API origin. Producers use these key factories; account
 * erasure and origin retirement use the same registry, so adding a family
 * cannot silently create a cleanup blind spot. */
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as FileSystem from "expo-file-system/legacy";
import { scrubAllVoiceScratchFiles } from "./audio/voiceScratch";

export const ACCOUNT_STORAGE_PREFIX = Object.freeze({
  salt: "@mindpattern/salt_",
  keyEnvelope: "@mindpattern/keyenvelope_",
  unlockProof: "@mindpattern/unlockproof_",
  recompute: "@mindpattern/last_recompute_",
  feedback: "@mindpattern/question_feedback.",
  moodLog: "mindpattern.moodlog.",
  crisisJournal: "@mindpattern/crisis_dialog_",
  crisisItem9: "@mindpattern/crisis_dialog_phq9_item9_",
  pendingMeasure: "@mindpattern/pending_measure_",
  safetyPlan: "@mindpattern/safety_plan_",
  safetyPlanDraft: "@mindpattern/safety_plan_draft_",
  stateSequence: "mindpattern.stateSeq.",
  entryVersions: "mindpattern.entryVersions.",
  entryV2Bound: "mindpattern.entryV2Bound.",
  onboardingSeen: "@mindpattern/onboarding_seen_",
  onboardingPanel: "@mindpattern/onboarding_panel_",
  keyShipmentConsent: "@mindpattern/keyship_consent_",
  reminders: "@mindpattern/reminders_",
  measureReminders: "@mindpattern/measure_reminders_",
  lastMeasure: "@mindpattern/last_measure_",
  healthMirror: "@mindpattern/mirror_mood_to_health_",
  thresholdNotice: "@mindpattern/threshold_notice_",
  pendingRotationSalt: "mindpattern.rotatePendingSalt.",
  biometricLegacyDisabled: "@mindpattern/biometric.legacy-disabled.",
  biometricOwner: "@mindpattern/biometric.owner.",
  unlockFailure: "mindpattern.unlockFail.",
  localRekey: "@mindpattern/local-rekey.",
  journalDraft: "@mindpattern/journal-draft.v1.",
  erasure: "@mindpattern/erasure.v1.",
  queue: "@mindpattern/queue.v2",
  audioQueue: "@mindpattern/audioqueue.v1:",
  audioErase: "@mindpattern/audioqueue.erase.",
} as const);

const scoped = (origin: string, userId: string): string =>
  Buffer.from(`${origin}\0${userId}`, "utf8").toString("base64url");

export const accountStorageKey = Object.freeze({
  unlockProof: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.unlockProof}${userId}`,
  recompute: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.recompute}${userId}`,
  feedback: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.feedback}${userId}`,
  moodLog: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.moodLog}${userId}`,
  crisisJournal: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.crisisJournal}${userId}`,
  crisisItem9: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.crisisItem9}${userId}`,
  pendingMeasure: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.pendingMeasure}${userId}`,
  safetyPlan: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.safetyPlan}${userId}`,
  safetyPlanDraft: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.safetyPlanDraft}${userId}`,
  stateSequence: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.stateSequence}${userId}`,
  entryVersions: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.entryVersions}${userId}`,
  entryV2Bound: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.entryV2Bound}${userId}`,
  onboardingSeen: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.onboardingSeen}${userId}`,
  onboardingPanel: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.onboardingPanel}${userId}`,
  keyShipmentConsent: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.keyShipmentConsent}${userId}`,
  reminders: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.reminders}${userId}`,
  measureReminders: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.measureReminders}${userId}`,
  lastMeasure: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.lastMeasure}${userId}`,
  healthMirror: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.healthMirror}${userId}`,
  thresholdNotice: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.thresholdNotice}${userId}`,
  pendingRotationSalt: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.pendingRotationSalt}${userId}`,
  biometricLegacyDisabled: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.biometricLegacyDisabled}${userId}`,
  biometricOwner: (userId: string) => `${ACCOUNT_STORAGE_PREFIX.biometricOwner}${userId}`,
  unlockFailure: (username: string) => `${ACCOUNT_STORAGE_PREFIX.unlockFailure}${username}`,
  localRekey: (origin: string, userId: string) => `${ACCOUNT_STORAGE_PREFIX.localRekey}${scoped(origin, userId)}`,
  journalDraft: (origin: string, userId: string) => `${ACCOUNT_STORAGE_PREFIX.journalDraft}${scoped(origin, userId)}`,
  erasure: (origin: string, userId: string) => `${ACCOUNT_STORAGE_PREFIX.erasure}${scoped(origin, userId)}`,
});

/** Legacy global queue/onboarding slots are included only as retirement
 * targets. Current producers never write account data there. */
export const LEGACY_ORIGIN_BOUND_KEYS = new Set([
  "@mindpattern/queue",
  "@mindpattern/queue_rejected",
  "@mindpattern/queue_quarantine",
  "@mindpattern/queue.legacy-unscoped.v1",
  "@mindpattern/onboarding_panel",
]);

const DIRECT_OWNER_PREFIXES = [
  ACCOUNT_STORAGE_PREFIX.crisisItem9,
  ACCOUNT_STORAGE_PREFIX.safetyPlanDraft,
  ACCOUNT_STORAGE_PREFIX.unlockProof,
  ACCOUNT_STORAGE_PREFIX.recompute,
  ACCOUNT_STORAGE_PREFIX.feedback,
  ACCOUNT_STORAGE_PREFIX.moodLog,
  ACCOUNT_STORAGE_PREFIX.crisisJournal,
  ACCOUNT_STORAGE_PREFIX.pendingMeasure,
  ACCOUNT_STORAGE_PREFIX.safetyPlan,
  ACCOUNT_STORAGE_PREFIX.stateSequence,
  ACCOUNT_STORAGE_PREFIX.entryVersions,
  ACCOUNT_STORAGE_PREFIX.entryV2Bound,
  ACCOUNT_STORAGE_PREFIX.onboardingSeen,
  ACCOUNT_STORAGE_PREFIX.onboardingPanel,
  ACCOUNT_STORAGE_PREFIX.keyShipmentConsent,
  ACCOUNT_STORAGE_PREFIX.reminders,
  ACCOUNT_STORAGE_PREFIX.measureReminders,
  ACCOUNT_STORAGE_PREFIX.lastMeasure,
  ACCOUNT_STORAGE_PREFIX.healthMirror,
  ACCOUNT_STORAGE_PREFIX.thresholdNotice,
  ACCOUNT_STORAGE_PREFIX.pendingRotationSalt,
  ACCOUNT_STORAGE_PREFIX.biometricLegacyDisabled,
  ACCOUNT_STORAGE_PREFIX.biometricOwner,
] as const;

const ENCODED_SCOPE_PREFIXES = [
  ACCOUNT_STORAGE_PREFIX.localRekey,
  ACCOUNT_STORAGE_PREFIX.journalDraft,
  ACCOUNT_STORAGE_PREFIX.erasure,
  ACCOUNT_STORAGE_PREFIX.audioErase,
] as const;

const ALL_ORIGIN_PREFIXES = new Set<string>([
  ...DIRECT_OWNER_PREFIXES,
  ...ENCODED_SCOPE_PREFIXES,
  ACCOUNT_STORAGE_PREFIX.salt,
  ACCOUNT_STORAGE_PREFIX.keyEnvelope,
  ACCOUNT_STORAGE_PREFIX.unlockFailure,
  ACCOUNT_STORAGE_PREFIX.queue,
  ACCOUNT_STORAGE_PREFIX.audioQueue,
]);

function decodedScopeOwner(encoded: string): string | null {
  try {
    const decoded = Buffer.from(encoded, "base64url").toString("utf8");
    const separator = decoded.indexOf("\0");
    return separator >= 0 && decoded.slice(separator + 1) ? decoded.slice(separator + 1) : null;
  } catch {
    return null;
  }
}

export function storageKeyOwner(key: string): string | null {
  for (const prefix of DIRECT_OWNER_PREFIXES) {
    if (key.startsWith(prefix)) return key.slice(prefix.length) || null;
  }
  for (const prefix of ENCODED_SCOPE_PREFIXES) {
    if (key.startsWith(prefix)) {
      const encoded = key.slice(prefix.length).split(".chunk.", 1)[0]!;
      return decodedScopeOwner(encoded);
    }
  }
  const queue = /^@mindpattern\/queue\.v2\.(?:items|rejected|quarantine)\.([A-Za-z0-9_-]+)$/.exec(key);
  if (queue) return decodedScopeOwner(queue[1]!);
  // The origin is an authority (including an optional port/IPv6 literal).
  // Entry ids may contain colons; never consume owner/id segments as part
  // of a greedy origin and infer a different account from an entry id.
  const audio = /^@mindpattern\/audioqueue\.v1:https?:\/\/(?:\[[^\]]+\]|[^\/:]+)(?::\d{1,5})?:([^:]+):[\s\S]*$/.exec(key);
  return audio?.[1] ?? null;
}

export function isOriginBoundStorageKey(key: string): boolean {
  if (LEGACY_ORIGIN_BOUND_KEYS.has(key)) return true;
  for (const prefix of ALL_ORIGIN_PREFIXES) if (key.startsWith(prefix)) return true;
  return false;
}

export function accountStorageKeysForOwner(keys: readonly string[], userId: string): string[] {
  return keys.filter((key) => storageKeyOwner(key) === userId);
}

export function accountOwnersFromStorageKeys(keys: readonly string[]): string[] {
  return [...new Set(keys.map(storageKeyOwner).filter((owner): owner is string => owner !== null))];
}

/** Audio descriptors can point at files, and interrupted migrations can
 * leave unindexed files. An origin switch retires every account, so remove
 * the entire encrypted-audio root and plaintext voice scratch before dropping
 * the descriptor registry. Attempt both roots even if one deletion fails. */
export async function purgeAllOriginBoundAccountFiles(): Promise<void> {
  const tasks: Array<Promise<unknown>> = [scrubAllVoiceScratchFiles()];
  if (FileSystem.documentDirectory) {
    tasks.push(FileSystem.deleteAsync(`${FileSystem.documentDirectory}mindpattern-audio/`, { idempotent: true }));
  }
  const results = await Promise.allSettled(tasks);
  if (results.some((result) => result.status === "rejected")) {
    throw new Error("Origin-bound file cleanup failed");
  }
}

export async function originBoundStorageInventory(): Promise<string[]> {
  return (await AsyncStorage.getAllKeys()).filter(isOriginBoundStorageKey);
}
