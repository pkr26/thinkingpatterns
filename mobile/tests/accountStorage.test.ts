import { describe, expect, it } from "vitest";
import {
  ACCOUNT_STORAGE_PREFIX,
  LEGACY_ORIGIN_BOUND_KEYS,
  accountStorageKey,
  accountStorageKeysForOwner,
  isOriginBoundStorageKey,
  storageKeyOwner,
} from "../src/accountStorage";

const USER = "11111111111111111111111111111111";
const ORIGIN = "https://old.example";
const SCOPE = Buffer.from(`${ORIGIN}\0${USER}`).toString("base64url");

function everyFamily(): string[] {
  return [
    `${ACCOUNT_STORAGE_PREFIX.salt}YWxpY2U`,
    `${ACCOUNT_STORAGE_PREFIX.keyEnvelope}YWxpY2U`,
    accountStorageKey.unlockProof(USER),
    accountStorageKey.recompute(USER),
    accountStorageKey.feedback(USER),
    accountStorageKey.moodLog(USER),
    accountStorageKey.crisisJournal(USER),
    accountStorageKey.crisisItem9(USER),
    accountStorageKey.pendingMeasure(USER),
    accountStorageKey.safetyPlan(USER),
    accountStorageKey.safetyPlanDraft(USER),
    accountStorageKey.stateSequence(USER),
    accountStorageKey.entryVersions(USER),
    accountStorageKey.entryV2Bound(USER),
    accountStorageKey.onboardingSeen(USER),
    accountStorageKey.onboardingPanel(USER),
    accountStorageKey.keyShipmentConsent(USER),
    accountStorageKey.reminders(USER),
    accountStorageKey.measureReminders(USER),
    accountStorageKey.lastMeasure(USER),
    accountStorageKey.healthMirror(USER),
    accountStorageKey.thresholdNotice(USER),
    accountStorageKey.pendingRotationSalt(USER),
    accountStorageKey.biometricLegacyDisabled(USER),
    accountStorageKey.biometricOwner(USER),
    accountStorageKey.unlockFailure("alice"),
    accountStorageKey.localRekey(ORIGIN, USER),
    `${accountStorageKey.localRekey(ORIGIN, USER)}.chunk.revision.0`,
    accountStorageKey.journalDraft(ORIGIN, USER),
    accountStorageKey.erasure(ORIGIN, USER),
    `${ACCOUNT_STORAGE_PREFIX.queue}.items.${SCOPE}`,
    `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${SCOPE}`,
    `${ACCOUNT_STORAGE_PREFIX.queue}.quarantine.${SCOPE}`,
    `${ACCOUNT_STORAGE_PREFIX.audioQueue}${ORIGIN}:${USER}:recording`,
    `${ACCOUNT_STORAGE_PREFIX.audioErase}${SCOPE}`,
    ...LEGACY_ORIGIN_BOUND_KEYS,
  ];
}

describe("canonical account storage registry", () => {
  it("classifies a representative of every registered family as origin-bound", () => {
    const keys = everyFamily();
    for (const prefix of Object.values(ACCOUNT_STORAGE_PREFIX)) {
      expect(keys.some(key => key.startsWith(prefix)), `missing fixture for ${prefix}`).toBe(true);
    }
    for (const key of keys) expect(isOriginBoundStorageKey(key), key).toBe(true);
    expect(isOriginBoundStorageKey("@mindpattern/theme.mode")).toBe(false);
  });

  it("recovers the owner for every user-id-scoped direct, encoded, queue, and audio family", () => {
    const keys = everyFamily();
    const owned = accountStorageKeysForOwner(keys, USER);
    const expectedOwned = keys.filter(key =>
      !key.startsWith(ACCOUNT_STORAGE_PREFIX.salt)
      && !key.startsWith(ACCOUNT_STORAGE_PREFIX.keyEnvelope)
      && !key.startsWith(ACCOUNT_STORAGE_PREFIX.unlockFailure)
      && !LEGACY_ORIGIN_BOUND_KEYS.has(key),
    );
    expect(new Set(owned)).toEqual(new Set(expectedOwned));
    for (const key of expectedOwned) expect(storageKeyOwner(key), key).toBe(USER);
  });
});
