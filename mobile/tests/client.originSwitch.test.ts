import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, DEFAULT_BASE_URL, getBaseUrl, setBaseUrl, setOriginChangeHandler } from "../src/api/client";
import { ACCOUNT_STORAGE_PREFIX, LEGACY_ORIGIN_BOUND_KEYS, accountStorageKey, isOriginBoundStorageKey } from "../src/accountStorage";
import * as nativeFeatures from "../src/nativeFeatures";
import * as FileSystem from "./helpers/expoFsMock";
import * as Keychain from "react-native-keychain";
import * as keychainMock from "./helpers/keychainMock";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { setSecureStoreBackend } from "../src/secureStore";
import { createPlaybackScratchUri } from "../src/audio/voiceScratch";

const response = (body: unknown, url: string) => {
  const result = new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  Object.defineProperty(result, "url", { value: url });
  return result;
};

beforeEach(() => {
  storage.__reset();
  FileSystem.__resetFiles();
  keychainMock.__reset();
  __resetLocalKeyLifecycleForTests();
  setSecureStoreBackend(null);
  setOriginChangeHandler(null);
  vi.stubGlobal("fetch", vi.fn(async () => response({}, DEFAULT_BASE_URL)));
});

afterEach(() => {
  setOriginChangeHandler(null);
  vi.unstubAllGlobals();
});

describe("API-origin changes", () => {
  it("rejects cleartext non-loopback URLs even if an obsolete caller passes allowInsecure", async () => {
    await expect(setBaseUrl("http://journal.example.test", { allowInsecure: true })).resolves.toMatch(/plain HTTP/);
    expect(await api.isLoggedIn()).toBe(false);
  });

  it("allows loopback HTTP for local development without granting it to look-alike hosts", async () => {
    expect(await setBaseUrl("http://127.0.0.1:8000")).toBeNull();
    expect(await setBaseUrl("http://localhost.evil.test:8000")).toMatch(/plain HTTP/);
  });

  it("enforces the HTTPS boundary again at send time if persisted settings are tampered", async () => {
    await api.setSession("live-token", "abababababababababababababababab", "alice");
    await storage.setItem("@mindpattern/base_url", "http://remote.example.test:8000");
    await expect(api.meta()).rejects.toMatchObject({ status: 0 });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("erases session material and locks the app hook before a new origin is persisted", async () => {
    await api.setSession("live-token", "abababababababababababababababab", "alice");
    const transitions: string[] = [];
    setOriginChangeHandler(() => transitions.push("locked"));

    await expect(setBaseUrl("https://remote.example.test")).resolves.toBeNull();
    expect(transitions).toEqual(["locked"]);
    expect(await api.isLoggedIn()).toBe(false);

    vi.mocked(fetch).mockResolvedValue(response({}, "https://remote.example.test/api/v1/meta"));
    await api.meta();
    const [, options] = vi.mocked(fetch).mock.calls[0]!;
    expect((options?.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(options?.redirect).toBe("error");
  });

  it("retains a session for a path-only change on the same origin", async () => {
    await setBaseUrl("https://same.example.test");
    await api.setSession("live-token", "abababababababababababababababab");
    expect(await setBaseUrl("https://same.example.test/base-path")).toBeNull();
    expect(await api.isLoggedIn()).toBe(true);
  });

  it("retires every registered account family, native file/key, and old-origin notification", async () => {
    const user = "abababababababababababababababab";
    const other = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const oldOrigin = "http://127.0.0.1:8000";
    const scope = (owner: string) => Buffer.from(`${oldOrigin}\0${owner}`).toString("base64url");
    await api.setSession("old-token", user, "alice");

    const keys = [
      `${ACCOUNT_STORAGE_PREFIX.salt}YWxpY2U`, `${ACCOUNT_STORAGE_PREFIX.keyEnvelope}YWxpY2U`,
      accountStorageKey.unlockProof(user), accountStorageKey.recompute(user), accountStorageKey.feedback(user),
      accountStorageKey.moodLog(user), accountStorageKey.crisisJournal(user), accountStorageKey.crisisItem9(user),
      accountStorageKey.pendingMeasure(user), accountStorageKey.safetyPlan(user), accountStorageKey.safetyPlanDraft(user),
      accountStorageKey.stateSequence(user), accountStorageKey.entryVersions(user), accountStorageKey.entryV2Bound(user),
      accountStorageKey.onboardingSeen(user), accountStorageKey.onboardingPanel(user), accountStorageKey.keyShipmentConsent(user),
      accountStorageKey.reminders(user), accountStorageKey.measureReminders(user), accountStorageKey.lastMeasure(user),
      accountStorageKey.healthMirror(user), accountStorageKey.thresholdNotice(user), accountStorageKey.pendingRotationSalt(user),
      accountStorageKey.biometricLegacyDisabled(user), accountStorageKey.biometricOwner(user),
      accountStorageKey.unlockFailure("alice"), accountStorageKey.localRekey(oldOrigin, user),
      `${accountStorageKey.localRekey(oldOrigin, user)}.chunk.r.0`, accountStorageKey.journalDraft(oldOrigin, user),
      accountStorageKey.erasure(oldOrigin, user),
      `${ACCOUNT_STORAGE_PREFIX.queue}.items.${scope(user)}`, `${ACCOUNT_STORAGE_PREFIX.queue}.rejected.${scope(user)}`,
      `${ACCOUNT_STORAGE_PREFIX.queue}.quarantine.${scope(other)}`,
      `${ACCOUNT_STORAGE_PREFIX.audioQueue}${oldOrigin}:${user}:take`, `${ACCOUNT_STORAGE_PREFIX.audioErase}${scope(user)}`,
      accountStorageKey.reminders(other), ...LEGACY_ORIGIN_BOUND_KEYS,
    ];
    await storage.multiSet(keys.map(key => [key, "old-origin-private-state"]));
    await storage.setItem("@mindpattern/theme.mode", "dark");
    await Keychain.setGenericPassword(user, "wrapped-key", { service: `com.mindpattern.biometric-unlock.v1.${user}` });
    await Keychain.setGenericPassword("legacy", "wrapped-key", { service: "com.mindpattern.biometric-unlock.v1" });
    const orphanFile = `${FileSystem.documentDirectory}mindpattern-audio/orphan/private.enc`;
    FileSystem.__seedFile(orphanFile, "ciphertext");
    const playbackScratch = await createPlaybackScratchUri(user, "audio/m4a");
    const nativeScratch = `${FileSystem.cacheDirectory}Audio/recording-interrupted.m4a`;
    const unrelatedCache = `${FileSystem.cacheDirectory}unrelated/keep.bin`;
    FileSystem.__seedFile(playbackScratch, "plaintext playback");
    FileSystem.__seedFile(nativeScratch, "plaintext recording");
    FileSystem.__seedFile(unrelatedCache, "unrelated");
    const notifications = vi.spyOn(nativeFeatures, "cancelOriginNotifications").mockResolvedValue(true);

    await expect(setBaseUrl("https://new.example.test")).resolves.toBeNull();

    const remaining = await storage.getAllKeys();
    expect(remaining.filter(isOriginBoundStorageKey)).toEqual([]);
    expect(await storage.getItem("@mindpattern/theme.mode")).toBe("dark");
    expect(await api.isLoggedIn()).toBe(false);
    expect(await Keychain.hasGenericPassword({ service: `com.mindpattern.biometric-unlock.v1.${user}` })).toBe(false);
    expect(await Keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1" })).toBe(false);
    expect(FileSystem.__hasFile(orphanFile)).toBe(false);
    expect(FileSystem.__hasFile(playbackScratch)).toBe(false);
    expect(FileSystem.__hasFile(nativeScratch)).toBe(false);
    expect(FileSystem.__hasFile(unrelatedCache)).toBe(true);
    expect(notifications).toHaveBeenCalledTimes(1);

    // A colliding id on the new origin sees no old-origin preference.
    await api.setSession("new-token", user, "alice");
    expect(await storage.getItem(accountStorageKey.reminders(user))).toBeNull();
  });

  it("retires the unattributable legacy biometric slot even when no user id survives", async () => {
    await storage.setItem(`${ACCOUNT_STORAGE_PREFIX.salt}YWxpY2U`, "old-salt");
    await Keychain.setGenericPassword("legacy", "wrapped-key", {
      service: "com.mindpattern.biometric-unlock.v1",
    });

    await expect(setBaseUrl("https://new.example.test")).resolves.toBeNull();

    expect(await Keychain.hasGenericPassword({ service: "com.mindpattern.biometric-unlock.v1" })).toBe(false);
    expect(await storage.getItem(`${ACCOUNT_STORAGE_PREFIX.salt}YWxpY2U`)).toBeNull();
  });

  it("does not publish the new origin when old-origin notification retirement cannot be verified", async () => {
    await api.setSession("old-token", "abababababababababababababababab", "alice");
    vi.spyOn(nativeFeatures, "cancelOriginNotifications").mockResolvedValue(false);

    await expect(setBaseUrl("https://new.example.test")).rejects.toThrow(
      "Old-origin notification cancellation could not be verified",
    );

    expect(await getBaseUrl()).toBe(DEFAULT_BASE_URL);
    expect(await api.isLoggedIn()).toBe(false);
  });
});
