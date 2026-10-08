import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ACCOUNT_STORAGE_PREFIX,
  LEGACY_ORIGIN_BOUND_KEYS,
  accountStorageKey,
  accountStorageKeysForOwner,
  isOriginBoundStorageKey,
  storageKeyOwner,
  accountOwnersFromStorageKeys,
  originBoundStorageInventory,
  purgeAllOriginBoundAccountFiles,
} from "../src/accountStorage";
import storage from "./helpers/storageMock";
import * as fs from "./helpers/expoFsMock";

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
    "@mindpattern/queue",
    "@mindpattern/queue_rejected",
    "@mindpattern/queue_quarantine",
    "@mindpattern/queue.legacy-unscoped.v1",
    "@mindpattern/onboarding_panel",
  ];
}

describe("canonical account storage registry", () => {
  beforeEach(() => { storage.__reset(); fs.__resetFiles(); });
  afterEach(() => vi.restoreAllMocks());
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
  it("does not infer owners from lookalike or extended queue keys", () => {
    const queue = `@mindpattern/queue.v2.items.${SCOPE}`;
    expect(storageKeyOwner(`unrelated.${queue}`)).toBeNull();
    expect(storageKeyOwner(`${queue}.foreign`)).toBeNull();
    const audio = `@mindpattern/audioqueue.v1:http://old.example:${USER}:recording`;
    expect(storageKeyOwner(audio)).toBe(USER);
    expect(storageKeyOwner(`unrelated.${audio}`)).toBeNull();
    expect(storageKeyOwner(`${audio}:foreign`)).toBe(USER);
    expect(storageKeyOwner(`@mindpattern/audioqueue.v1:https://old.example:8443:${USER}:recording:extra`)).toBe(USER);
    expect(storageKeyOwner(`@mindpattern/audioqueue.v1:http://[::1]:8000:${USER}:recording:extra`)).toBe(USER);
    expect(storageKeyOwner(`@mindpattern/audioqueue.v1:https://old.example:${USER}:recording with spaces`)).toBe(USER);
    const emptyOrigin = Buffer.from(`\0${USER}`).toString("base64url");
    expect(storageKeyOwner(`@mindpattern/queue.v2.items.${emptyOrigin}`)).toBe(USER);
    const emptyOwner = Buffer.from(`${ORIGIN}\0`).toString("base64url");
    expect(storageKeyOwner(`@mindpattern/queue.v2.items.${emptyOwner}`)).toBeNull();
    expect(storageKeyOwner("@mindpattern/queue.v2.items.bm8tc2NvcGU")).toBeNull();
  });
  it("reports no owner when the platform buffer decoder fails", () => {
    vi.spyOn(Buffer, "from").mockImplementation(() => { throw new Error("native buffer allocation failed"); });
    expect(storageKeyOwner(`@mindpattern/queue.v2.items.${SCOPE}`)).toBeNull();
  });
  it("scrubs native voice scratch even when the platform has no document directory", async () => {
    vi.resetModules();
    vi.doMock("expo-file-system/legacy", () => ({ ...fs, documentDirectory: null }));
    try {
      const { purgeAllOriginBoundAccountFiles: purge } = await import("../src/accountStorage");
      fs.deleteAsync.mockClear();
      await purge();
      expect(fs.deleteAsync.mock.calls.some(([uri]) => String(uri).includes("mindpattern-audio/"))).toBe(false);
      expect(fs.deleteAsync).toHaveBeenCalledWith(`${fs.cacheDirectory}ExpoAudio/`, { idempotent: true });
    } finally {
      vi.doUnmock("expo-file-system/legacy");
      vi.resetModules();
    }
  });
  it("discovers distinct owners and filters unknown keys from account inventory", async () => {
    const keys = [accountStorageKey.moodLog(USER), accountStorageKey.safetyPlan(USER), accountStorageKey.moodLog("other"), "@mindpattern/theme.mode", "unrelated"];
    expect(accountOwnersFromStorageKeys(keys).sort()).toEqual([USER, "other"].sort());
    expect(accountOwnersFromStorageKeys(["unrelated"])).toEqual([]);
    for (const key of keys) await storage.setItem(key, "stored");
    expect((await originBoundStorageInventory()).sort()).toEqual(keys.slice(0, 3).sort());
  });
  it("retires encrypted audio and voice scratch while preserving unrelated files", async () => {
    const audio = `${fs.documentDirectory}mindpattern-audio/entry.enc`;
    const recording = `${fs.cacheDirectory}ExpoAudio/recording.m4a`;
    const unrelated = `${fs.documentDirectory}unrelated/file.bin`;
    for (const file of [audio, recording, unrelated]) fs.__seedFile(file);
    await purgeAllOriginBoundAccountFiles();
    expect(fs.__hasFile(audio)).toBe(false); expect(fs.__hasFile(recording)).toBe(false); expect(fs.__hasFile(unrelated)).toBe(true);
    // All roots are now absent: idempotent cleanup must still succeed.
    await expect(purgeAllOriginBoundAccountFiles()).resolves.toBeUndefined();
  });
  it("attempts both audio and scratch roots and reports each failure", async () => {
    const original = fs.deleteAsync.getMockImplementation()!;
    for (const failedRoot of [`${fs.documentDirectory}mindpattern-audio/`, `${fs.cacheDirectory}ExpoAudio/`]) {
      fs.deleteAsync.mockClear();
      fs.deleteAsync.mockImplementation(async (uri, options) => { if (uri === failedRoot) throw new Error("disk blocked"); await original(uri, options); });
      await expect(purgeAllOriginBoundAccountFiles()).rejects.toThrow("Origin-bound file cleanup failed");
      expect(fs.deleteAsync).toHaveBeenCalledWith(`${fs.documentDirectory}mindpattern-audio/`, { idempotent: true });
      expect(fs.deleteAsync).toHaveBeenCalledWith(`${fs.cacheDirectory}ExpoAudio/`, { idempotent: true });
    }
    fs.deleteAsync.mockImplementation(original);
  });
});
