import { runTestControl } from "../helpers/testControl";
/**
 * SettingsScreen: server-URL policy (now under "Advanced") with the
 * explicit insecure-HTTP consent dialog, re-authenticated LLM consent
 * toggle, encrypted export (incl. share-sheet dismissal), the three-stage
 * destructive delete, the recovered-entries surface, and the About section.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, AppState, Platform, Share, Switch, TextInput } from "react-native";
import * as Keychain from "react-native-keychain";
import { emitAppState } from "../helpers/rnMock";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock } = await import("../helpers/apiMock");
  return {
    ...actual,
    api: makeApiMock(),
    getBaseUrl: vi.fn(async () => "http://localhost:8000"),
    getInsecureConsentUrl: vi.fn(async () => null),
    setBaseUrl: vi.fn(async () => null),
  };
});

const authKeyB64 = () => authKey.toString("base64");
const verifyPasswordForVault = vi.fn(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
vi.mock("../../src/reauth", async (importOriginal) => {
  // The error classifiers stay REAL: the screen branches 403-vs-401 on them.
  const actual = await importOriginal<typeof import("../../src/reauth")>();
  return {
    ...actual,
    verifyPasswordForVault: (...args: unknown[]) => verifyPasswordForVault(...(args as [string])),
  };
});

vi.mock("../../src/offlineQueue", () => ({
  prepareQueueRekey: vi.fn(async () => []),
  pendingEntryIds: vi.fn(async () => []),
  abortInFlightFlush: vi.fn(),
  flushQueue: vi.fn(async () => 0),
  clearQueue: vi.fn(async () => {}),
  rejectedEntryCount: vi.fn(async () => 0),
  requeueRejected: vi.fn(async () => 0),
  quarantinedQueueExists: vi.fn(async () => false),
  hasLegacyQueueRecovery: vi.fn(async () => false),
  // independent audit 2026-09-27 (P2): the rotation's queue discipline —
  // the drain reports an empty queue by default so rotations proceed.
  drainPendingQueueForRotation: vi.fn(async () => 0),
  rewrapQueue: vi.fn(async () => {}),
}));

// The rotation flow derives keys four times per attempt; the node tests
// mock the derivation (loginScreen/unlockScreen idiom) so the flow runs
// without the real 600k-iteration PBKDF2.
vi.mock("../../src/crypto/journalCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/journalCrypto")>();
  return {
    ...actual,
    deriveKeysAsync: vi.fn(async () => ({
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.alloc(32, 5),
      dataKey: Buffer.alloc(32, 6),
    })),
  };
});

// 2026-09-26 audit M-M5: controllable rotation seam. The default delegates
// to the REAL rotatePassword (the self-completion test below runs it); the
// throw-path test rejects once to pin the new catch.
const rotatePasswordMock = vi.hoisted(() => vi.fn());
vi.mock("../../src/rotation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/rotation")>();
  const real = actual.rotatePassword;
  rotatePasswordMock.mockImplementation((...args: Parameters<typeof real>) => real(...args));
  return { ...actual, rotatePassword: (...args: Parameters<typeof real>) => rotatePasswordMock(...args) };
});
const upgradeKeyProtectionMock = vi.hoisted(() => vi.fn());
vi.mock("../../src/envelopeUpgrade", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/envelopeUpgrade")>();
  const real = actual.upgradeKeyProtection;
  upgradeKeyProtectionMock.mockImplementation((...args: Parameters<typeof real>) => real(...args));
  return { ...actual, upgradeKeyProtection: (...args: Parameters<typeof real>) => upgradeKeyProtectionMock(...args) };
});

const signOut = vi.fn(async () => {});
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ signOut, touchActivity }) };
});

// The reminder seam (2026-09-19): controllable per test. Default matches
// this build — module absent. SettingsScreen AND reminderSync both import
// from nativeFeatures, so the mock makes the sync observable here.
const reminderCapabilityResult = { available: false, reason: "notification module not linked in this build" };
const reminderCapability = vi.fn(() => reminderCapabilityResult);
const scheduleDailyReminder = vi.fn(async () => true);
const cancelDailyReminder = vi.fn(async () => true);
const scheduleMeasureReminder = vi.fn(async () => true);
vi.mock("../../src/nativeFeatures", () => ({
  reminderCapability: () => reminderCapability(),
  scheduleDailyReminder: (...args: unknown[]) => scheduleDailyReminder(...(args as [number, number])),
  cancelDailyReminder: (...args: unknown[]) => cancelDailyReminder(...(args as [])),
  // 2026-09-27 clinical wave: the opt-in check-in reminder rides the same
  // nativeFeatures seam (own stable id); deletion cancels both schedules.
  cancelMeasureReminder: async () => true,
  scheduleMeasureReminder: (...args: unknown[]) => scheduleMeasureReminder(...(args as [Date])),
  // L-9 (2026-09-28): the one-time orphan sweep runs inside every
  // syncReminderSchedule; stubbed to a no-op here (its own seam is covered
  // in tests/nativeFeatures.test.ts against the real module).
  migrateOrphanedReminderNotifications: async () => {},
}));

// The HealthKit State of Mind seam (2026-09-19): controllable per test,
// defaulting to this build's state — module absent. The PREFERENCE layer
// (getMoodMirrorPref/setMoodMirrorPref/clearMoodMirrorPref) stays REAL so
// the per-account record round-trips through storage exactly as shipped.
const healthKitCapabilityResult = { available: false, reason: "health module not linked in this build" };
const healthKitCapability = vi.fn(() => healthKitCapabilityResult);
const ensureStateOfMindWriteAccess = vi.fn(async () => true);
vi.mock("../../src/healthkit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/healthkit")>();
  return {
    ...actual,
    healthKitCapability: () => healthKitCapability(),
    ensureStateOfMindWriteAccess: (...args: unknown[]) => ensureStateOfMindWriteAccess(...(args as [])),
  };
});

const { api, getBaseUrl, getInsecureConsentUrl, setBaseUrl } = await import("../../src/api/client");
const { flushQueue, clearQueue, rejectedEntryCount, requeueRejected, quarantinedQueueExists } = await import(
  "../../src/offlineQueue"
);
const { recordFeedbackTap } = await import("../../src/questionFeedback");
const { SettingsScreen } = await import("../../src/screens/SettingsScreen");
const { vault } = await import("../../src/vault");
const {
  render,
  flush,
  textOf,
  pressLabel,
  typeInto,
  pressAlertButton,
  lastAlert,
  touchableByLabel,
  inputByPlaceholder,
  act,
  firePress,
} = await import("../helpers/rtr");
const { resetApi, SALT_B64 } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const authKey = Buffer.alloc(32, 2);
const keys = { masterKey: Buffer.alloc(32), authKey, dataKey: Buffer.alloc(32, 3) };
const nav = { popToTop: vi.fn(), navigate: vi.fn() };
const keychainMock = Keychain as unknown as {
  __reset: () => void;
  __setBiometryType: (v: string | null) => void;
};

beforeEach(async () => {
  upgradeKeyProtectionMock.mockClear();
  runTestControl((await import("../../src/localRekey")).__resetLocalKeyLifecycleForTests);
  resetApi(api as never);
  storage.__reset();
  keychainMock.__reset();
  reminderCapability.mockReset();
  reminderCapability.mockReturnValue({ available: false, reason: "notification module not linked in this build" });
  scheduleDailyReminder.mockReset();
  scheduleDailyReminder.mockResolvedValue(true);
  cancelDailyReminder.mockReset();
  cancelDailyReminder.mockResolvedValue(true);
  scheduleMeasureReminder.mockReset();
  scheduleMeasureReminder.mockResolvedValue(true);
  healthKitCapability.mockReset();
  healthKitCapability.mockReturnValue({ available: false, reason: "health module not linked in this build" });
  ensureStateOfMindWriteAccess.mockReset();
  ensureStateOfMindWriteAccess.mockResolvedValue(true);
  vi.mocked(clearQueue).mockClear();
  vi.mocked(getBaseUrl).mockReset();
  vi.mocked(getBaseUrl).mockImplementation(async () => "http://localhost:8000");
  vi.mocked(getInsecureConsentUrl).mockReset();
  vi.mocked(getInsecureConsentUrl).mockImplementation(async () => null);
  vi.mocked(setBaseUrl).mockReset();
  vi.mocked(setBaseUrl).mockImplementation(async () => null);
  vi.mocked(flushQueue).mockClear();
  vi.mocked(flushQueue).mockImplementation(async () => 0);
  vi.mocked(rejectedEntryCount).mockReset();
  vi.mocked(rejectedEntryCount).mockImplementation(async () => 0);
  vi.mocked(requeueRejected).mockReset();
  vi.mocked(requeueRejected).mockImplementation(async () => 0);
  vi.mocked(quarantinedQueueExists).mockReset();
  vi.mocked(quarantinedQueueExists).mockImplementation(async () => false);
  touchActivity.mockClear();
  signOut.mockClear();
  nav.popToTop.mockClear();
  nav.navigate.mockClear();
  Alert.alert.mockClear();
  vi.mocked(Share.share).mockReset();
  vi.mocked(Share.share).mockImplementation(async () => ({}));
  vault.lock();
  vault.unlock({ masterKey: Buffer.from(keys.masterKey), authKey: Buffer.from(keys.authKey), dataKey: Buffer.from(keys.dataKey) }, "user-1");
  verifyPasswordForVault.mockClear();
  verifyPasswordForVault.mockImplementation(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
});

describe("reminder control admission ownership", () => {
  for (const kind of ["daily", "measure"] as const) {
    const label = kind === "daily" ? "Daily reminder" : "Check-in reminders";
    const slot = kind === "daily" ? "@mindpattern/reminders_" : "@mindpattern/measure_reminders_";
    const schedule = kind === "daily" ? scheduleDailyReminder : scheduleMeasureReminder;
    it(`${kind}: a late identity read cannot revive an older enable after a newer disable`, async () => {
      reminderCapability.mockReturnValue({ available: true, reason: "" });
      const root = await render(<SettingsScreen navigation={nav} />);
      await flush();
      let release!: (owner: string) => void;
      vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
      const toggle = () => root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === label)!;
      await act(async () => { toggle().props.onValueChange(true); });
      await act(async () => { toggle().props.onValueChange(false); });
      await flush();
      await act(async () => { release("user-1"); });
      await flush();
      expect(JSON.parse((await storage.getItem(`${slot}user-1`))!).enabled).toBe(false);
      expect(toggle().props.value).toBe(false);
      expect(schedule).not.toHaveBeenCalled();
      await act(async () => { root.unmount(); });
    });

    for (const retirement of ["unmount", "account", "key"] as const) {
      it(`${kind}: a pending identity read cannot write after ${retirement} retirement`, async () => {
        reminderCapability.mockReturnValue({ available: true, reason: "" });
        const root = await render(<SettingsScreen navigation={nav} />);
        await flush();
        let release!: (owner: string) => void;
        vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
        const toggle = root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === label)!;
        await act(async () => { toggle.props.onValueChange(true); });
        if (retirement !== "key") await act(async () => { root.unmount(); });
        if (retirement === "account") {
          const { changeLocalSessionOwner } = await import("../../src/localWriteGuard");
          changeLocalSessionOwner(null); vault.lock(); changeLocalSessionOwner("user-2");
          vault.unlock({ masterKey: Buffer.alloc(32, 7), authKey: Buffer.alloc(32, 8), dataKey: Buffer.alloc(32, 9) }, "user-2");
        } else if (retirement === "key") {
          vault.unlock({ masterKey: Buffer.alloc(32, 7), authKey: Buffer.alloc(32, 8), dataKey: Buffer.alloc(32, 9) }, "user-1");
        }
        await act(async () => { release(retirement === "account" ? "user-2" : "user-1"); });
        await flush();
        expect(await storage.getItem(`${slot}user-1`)).toBeNull();
        expect(await storage.getItem(`${slot}user-2`)).toBeNull();
        expect(schedule).not.toHaveBeenCalled();
        if (retirement === "key") await act(async () => { root.unmount(); });
      });
    }
  }

  it.each(["daily time", "measure interval"] as const)("the latest %s choice wins when the older identity read finishes last", async kind => {
    reminderCapability.mockReturnValue({ available: true, reason: "" });
    await storage.setItem("@mindpattern/reminders_user-1", JSON.stringify({ enabled: true, hour: 20, minute: 0 }));
    await storage.setItem("@mindpattern/measure_reminders_user-1", JSON.stringify({ enabled: true, intervalWeeks: 4 }));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    let release!: (owner: string) => void;
    vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    await pressLabel(root, kind === "daily time" ? "Morning" : "2 weeks");
    await pressLabel(root, kind === "daily time" ? "Midday" : "8 weeks");
    await flush();
    await act(async () => { release("user-1"); });
    await flush();
    const prefs = JSON.parse((await storage.getItem(kind === "daily time" ? "@mindpattern/reminders_user-1" : "@mindpattern/measure_reminders_user-1"))!);
    expect(kind === "daily time" ? prefs.hour : prefs.intervalWeeks).toBe(kind === "daily time" ? 12 : 8);
    await act(async () => { root.unmount(); });
  });
});

/** Drive the in-screen password re-auth card for a pending action. */
async function reauth(root: Awaited<ReturnType<typeof render>>, password = "correct horse"): Promise<void> {
  await typeInto(root, "password", password);
  await pressLabel(root, "Confirm with password");
  await flush();
}

describe("therapist-sharing availability copy", () => {
  it("offers the sharing button only when the server advertises it", async () => {
    vi.mocked(api.meta).mockResolvedValue({ sharing_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(textOf(root)).toContain("Share with my therapist");
    expect(textOf(root)).not.toContain("not available on this server");
    expect(textOf(root)).not.toContain("Can’t reach the server");
  });

  it("an explicit server 'disabled' answer never blames connectivity", async () => {
    vi.mocked(api.meta).mockResolvedValue({ sharing_available: false } as never);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(textOf(root)).toContain("Therapist sharing is not available on this server");
    expect(textOf(root)).not.toContain("Can’t reach the server");
    expect(textOf(root)).not.toContain("Share with my therapist");
  });

  it("an unreachable server says so instead of claiming the server disabled sharing", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("network down"));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(textOf(root)).toContain("Can’t reach the server to confirm therapist-sharing availability");
    expect(textOf(root)).not.toContain("not available on this server");
    expect(textOf(root)).not.toContain("Share with my therapist");
  });
});

describe("saved recording custody controls", () => {
  async function seedRecording(): Promise<void> {
    const { enqueueAudio } = await import("../../src/audioQueue");
    const { encryptAudio } = await import("../../src/crypto/journalCrypto");
    await enqueueAudio({ userId: "user-1", clientEntryId: "recording:one", ...encryptAudio({ dataKey: vault.get().dataKey }, "user-1", "recording:one", Buffer.from("private voice")), mime: "audio/m4a", durationSeconds: 5 });
  }

  it("an export pressed on the old list cannot adopt a replacement account after its owner lookup", async () => {
    const sharing = await import("../helpers/expoSharingMock"); sharing.shareAsync.mockClear();
    await seedRecording();
    const root = await render(<SettingsScreen navigation={nav as never} />); await flush();
    let release!: (value: string) => void;
    vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    await firePress(root, "Export encrypted recording 1"); await flush();
    const { enqueueAudio } = await import("../../src/audioQueue"), { encryptAudio } = await import("../../src/crypto/journalCrypto");
    const replacementKey = Buffer.alloc(32, 9);
    await enqueueAudio({ userId: "replacement-account", clientEntryId: "recording:one", ...encryptAudio({ dataKey: replacementKey }, "replacement-account", "recording:one", Buffer.from("replacement account's private voice")), mime: "audio/m4a", durationSeconds: 5 });
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: replacementKey }, "replacement-account");
    await act(async () => release("replacement-account")); await flush();
    expect(sharing.shareAsync).not.toHaveBeenCalled();
  });

  it("exports ciphertext without deleting it, and deletes only after explicit confirmation", async () => {
    const fs = await import("../helpers/expoFsMock");
    const sharing = await import("../helpers/expoSharingMock");
    sharing.shareAsync.mockClear();
    await seedRecording();
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(textOf(root)).toContain("1 encrypted recordings saved");
    await pressLabel(root, "Export encrypted recording 1");
    const uri = sharing.shareAsync.mock.calls.at(-1)![0];
    const exported = await fs.readAsStringAsync(uri);
    expect(exported).not.toContain("private voice");
    expect(JSON.parse(exported)).toMatchObject({ version: 2, username: "alice", audio: [expect.objectContaining({ client_entry_id: "recording:one" })] });
    expect(textOf(root)).toContain("1 encrypted recordings saved");
    await pressLabel(root, "Remove saved recording 1");
    await pressAlertButton("Cancel");
    expect(textOf(root)).toContain("1 encrypted recordings saved");
    await pressLabel(root, "Remove saved recording 1");
    await pressAlertButton("Remove recording");
    await flush();
    expect(textOf(root)).not.toContain("1 encrypted recordings saved");
    expect(fs.__hasFile(uri)).toBe(false);
  });

  it("keeps a failed upload available and exposes a usable encrypted export failure", async () => {
    await seedRecording();
    vi.mocked(api.uploadAudioAttachment).mockRejectedValue(new Error("network unavailable"));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Retry saved recordings");
    expect(api.uploadAudioAttachment).toHaveBeenCalledOnce();
    expect(textOf(root)).toContain("1 encrypted recordings saved");
    const sharing = await import("../helpers/expoSharingMock");
    sharing.isAvailableAsync.mockResolvedValueOnce(false);
    await pressLabel(root, "Export encrypted recording 1");
    expect(lastAlert()[0]).toBe("Export failed");
    expect(textOf(root)).toContain("1 encrypted recordings saved");
  });
});

describe("fresh recovery-kit verification and secret lifetime", () => {
  it.each(["recovery", "delete"])("refuses a %s mutation when the fresh password proof settles after account replacement", async action => {
    const { changeLocalSessionOwner } = await import("../../src/localWriteGuard");
    const root = await render(<SettingsScreen navigation={nav as never} />); await flush();
    if (action === "recovery") await pressLabel(root, "Create recovery kit");
    else {
      await pressLabel(root, "Delete my account and data"); await pressAlertButton("Continue"); await pressAlertButton("Continue to password");
    }
    await typeInto(root, "password", "correct horse"); let release!: () => void;
    verifyPasswordForVault.mockImplementationOnce(async () => { await new Promise<void>(resolve => { release = resolve; }); return { ok: true as const, verifierB64: authKeyB64() }; });
    await firePress(root, "Confirm with password"); await flush(); expect(release).toBeTypeOf("function");
    changeLocalSessionOwner("user-2"); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 9) }, "user-2");
    await act(async () => release()); await flush();
    expect(api.setupRecoveryKit).not.toHaveBeenCalled(); expect(api.deleteAccount).not.toHaveBeenCalled(); expect(signOut).not.toHaveBeenCalled();
    expect(vault.ownerUserId()).toBe("user-2");
  });
  it("creates a versioned kit only after fresh proof, confirms storage, and removes it with another proof", async () => {
    // Controlled entropy keeps the displayed kit reproducible while the
    // real recovery seal/verifier and disclosure flow execute below.
    const { engine } = await import("../helpers/nodeEngine");
    const random = vi.spyOn(engine, "randomBytes").mockImplementation(size => Buffer.alloc(size, 9));
    try {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Create recovery kit");
    expect(api.setupRecoveryKit).not.toHaveBeenCalled();
    await reauth(root);
    expect(vi.mocked(api.setupRecoveryKit).mock.calls[0]?.slice(0, 4)).toEqual([authKeyB64(), expect.any(String), expect.any(String), "v2"]);
    expect(textOf(root)).toContain("mindpattern-recovery:v2:");
    await pressLabel(root, "I saved the key");
    expect(textOf(root)).not.toContain("mindpattern-recovery:v2:");
    await pressLabel(root, "Remove kit");
    expect(api.removeRecoveryKit).not.toHaveBeenCalled();
    await reauth(root);
    expect(vi.mocked(api.removeRecoveryKit).mock.calls[0]?.[0]).toBe(authKeyB64());
    expect(textOf(root)).toContain("No recovery kit.");
    } finally { random.mockRestore(); }
  });

  it("requires a replacement warning and never reveals a late setup key after backgrounding", async () => {
    vi.mocked(api.recoveryStatus).mockResolvedValue({ enabled: true, set_at: "2026-10-01" } as never);
    let finish!: () => void;
    vi.mocked(api.setupRecoveryKit).mockImplementationOnce(() => new Promise(resolve => { finish = () => resolve({} as never); }));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Replace kit key");
    await pressAlertButton("Cancel");
    expect(api.setupRecoveryKit).not.toHaveBeenCalled();
    await pressLabel(root, "Replace kit key");
    await pressAlertButton("Replace kit key");
    await typeInto(root, "password", "correct horse");
    await firePress(root, "Confirm with password");
    await flush();
    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)![1];
    await act(async () => { listener("background"); finish(); });
    await flush();
    expect(textOf(root)).not.toContain("mindpattern-recovery:v2:");
    expect(textOf(root)).not.toContain("Confirm with password");
  });

  it("reports a refused recovery-kit mutation without showing a key", async () => {
    vi.mocked(api.setupRecoveryKit).mockRejectedValueOnce(new Error("service unavailable"));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Create recovery kit");
    await reauth(root);
    expect(textOf(root)).not.toContain("mindpattern-recovery:v2:");
    expect(lastAlert()[1]).toContain("could not be created");
  });
});

describe("SettingsScreen chrome", () => {
  it("loads the stored URL, insecure consent and LLM state on mount", async () => {
    vi.mocked(getBaseUrl).mockImplementation(async () => "https://sync.example.com");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.getLlmConsent).mockResolvedValue({ enabled: true, active_for_current_policy: true } as never);

    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();

    expect((inputByPlaceholder(root, "https://your-server:8000").props as { value: string }).value).toBe(
      "https://sync.example.com",
    );
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation");
    expect(sw).toBeDefined();
    expect(sw.props.value).toBe(true);
    expect(sw.props.trackColor).toEqual({ true: "#b7d5b2", false: "#232019" });
  });

  it("renders an empty, idle form before the stored URL resolves", async () => {
    let resolveUrl!: (v: string) => void;
    vi.mocked(getBaseUrl).mockImplementation(
      () => new Promise((resolve) => (resolveUrl = resolve as (v: string) => void)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    // First paint: blank URL field, buttons enabled (not busy).
    expect((inputByPlaceholder(root, "https://your-server:8000").props as { value: string }).value).toBe("");
    expect(textOf(root)).toContain("Why export is unavailable");
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveUrl("http://localhost:8000");
    });
    await flush();
  });

  it("pins the visual language of the screen", async () => {
    // Design-system pass: theme-composed styles; the footnote moved off the
    // failing #5c6370 onto muted #a29a8c; the button fill is AA-passing.
    const { expectStyle } = await import("../helpers/rtr");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expectStyle(root, { flex: 1 }); // container base
    expectStyle(root, { backgroundColor: "#211e1a", padding: 24, gap: 14 }); // container themed
    expectStyle(root, { color: "#a29a8c", fontSize: 12, fontWeight: "700", letterSpacing: 1, marginTop: 8 }); // label
    expectStyle(root, { backgroundColor: "#2a2620", color: "#ede8df", borderRadius: 10, padding: 14, fontSize: 15 }); // input
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton
    expectStyle(root, { backgroundColor: "#a9cba4", minHeight: 44 }); // primary fill (AA fix)
    expectStyle(root, { backgroundColor: "#d98a80", minHeight: 44 }); // danger fill
    expectStyle(root, { padding: 12 }); // GhostButton base
    expectStyle(root, { color: "#a29a8c", fontSize: 14 }); // ghostText
    expectStyle(root, { color: "#1e1c17", fontSize: 16 }); // buttonText (dark onPrimary)
    expectStyle(root, { flexDirection: "row", alignItems: "center", gap: 12, padding: 14 }); // row base
    expectStyle(root, { backgroundColor: "#2a2620", borderRadius: 10 }); // row themed
    expectStyle(root, { color: "#cfc7ba", fontSize: 13, flex: 1, lineHeight: 18 }); // rowText
    expectStyle(root, { color: "#a29a8c", fontSize: 12, lineHeight: 18 }); // footnote (contrast fix)
    expectStyle(root, { backgroundColor: "#1c1915", borderRadius: 10, minHeight: 44 }); // help surface
  });

  it("hands cleartext URLs directly to the fail-closed client without a consent dialog", async () => {
    vi.mocked(setBaseUrl).mockResolvedValue("This server uses plain HTTP. Use HTTPS.");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    expect(setBaseUrl).toHaveBeenCalledWith("http://nas.lan:8000");
    expect(Alert.alert).toHaveBeenCalledWith("Could not save server", expect.stringContaining("plain HTTP"));
    expect(Alert.alert).not.toHaveBeenCalledWith("Insecure server", expect.any(String), expect.anything());
  });

  it("shows the LLM switch off before the stored consent resolves", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    let resolveConsent!: (v: unknown) => void;
    vi.mocked(api.getLlmConsent).mockImplementation(
      () => new Promise((resolve) => (resolveConsent = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.value).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveConsent({ enabled: true, active_for_current_policy: true });
    });
    await flush();
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.value).toBe(true);
  });

  it("treats legacy LLM v1 consent as inactive until a fresh v2 opt-in", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.getLlmConsent).mockResolvedValue({
      enabled: true,
      active_for_current_policy: false,
      llm_consent_disclosure: "v1",
    } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!;
    expect(sw.props.value).toBe(false);
    expect(textOf(root)).toContain("earlier choice no longer authorizes transcript translation");
    expect(textOf(root)).toContain("Translation is off");
  });

  it("disables the switch and buttons while the verified consent save is busy, and resets after", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    let resolveSave!: (v: unknown) => void;
    vi.mocked(api.setLlmConsent).mockImplementation(
      () => new Promise((resolve) => (resolveSave = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { act, firePress } = await import("../helpers/rtr");
    const sw0 = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!;
    await act(async () => {
      (sw0.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await typeInto(root, "password", "correct horse");
    await firePress(root, "Confirm with password");
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.disabled).toBe(true);
    await act(async () => {
      resolveSave?.({ enabled: true, active_for_current_policy: true });
    });
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.disabled).toBe(false);

    // busy reset in finally: a second toggle round-trip works.
    vi.mocked(api.setLlmConsent).mockResolvedValue({ enabled: false, active_for_current_policy: false } as never);
    const sw1 = root.root.findAllByType(Switch)[0];
    await act(async () => {
      (sw1.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    await reauth(root);
    expect(api.setLlmConsent).toHaveBeenCalledTimes(2);
  });

  it("hides the third-party section when the server has no LLM configured", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party transcript translation"),
    ).toHaveLength(0);
    expect(textOf(root)).not.toContain("Third-party transcript translation");
  });

  it("keeps defaults when the server is unreachable on mount", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("offline"));
    vi.mocked(api.getLlmConsent).mockRejectedValue(new Error("offline"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party transcript translation"),
    ).toHaveLength(0);
    expect(textOf(root)).toContain("Save server URL");
  });
});

describe("server URL policy", () => {
  it("rejects malformed URLs before saving", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "garbage");
    await pressLabel(root, "Save server URL");
    expect(Alert.alert).toHaveBeenCalledWith("Invalid URL", expect.stringContaining("https://your-server:8000"));
    expect(setBaseUrl).not.toHaveBeenCalled();
  });

  it("delegates remote plain-HTTP rejection to the client with no consent bypass", async () => {
    vi.mocked(setBaseUrl).mockResolvedValue("This server uses plain HTTP. Use HTTPS.");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");

    expect(setBaseUrl).toHaveBeenCalledWith("http://nas.lan:8000");
    expect(lastAlert()[0]).toBe("Could not save server");
    expect(lastAlert()[1]).toContain("plain HTTP");
    expect(Alert.alert).not.toHaveBeenCalledWith("Insecure server", expect.any(String), expect.anything());
  });

  it("reports a cleartext rejection from the client", async () => {
    vi.mocked(setBaseUrl).mockImplementation(async () => "Enter a full URL like https://your-server:8000");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    expect(Alert.alert).toHaveBeenCalledWith("Could not save server", expect.stringContaining("full URL"));
  });

  it("reports save errors from the direct save of a secure URL", async () => {
    vi.mocked(setBaseUrl).mockImplementation(async () => "connection refused");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://sync.example.com");
    await pressLabel(root, "Save server URL");
    await flush();
    expect(setBaseUrl).toHaveBeenCalledWith("https://sync.example.com");
    expect(Alert.alert).toHaveBeenCalledWith("Could not save server", "connection refused");
  });

  it("saves secure URLs without any warning", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://api.example.com");
    await pressLabel(root, "Save server URL");
    expect(setBaseUrl).toHaveBeenCalledWith("https://api.example.com");
    expect(Alert.alert).toHaveBeenCalledWith("Saved", expect.any(String));
  });

  it("does not revive a stored insecure-consent exception", async () => {
    vi.mocked(getInsecureConsentUrl).mockImplementation(async () => "http://nas.lan:8000");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    expect(setBaseUrl).toHaveBeenCalledWith("http://nas.lan:8000");
    expect(Alert.alert).not.toHaveBeenCalledWith("Insecure server", expect.any(String), expect.anything());
  });

  it("treats empty meta/consent payloads as feature-off", async () => {
    vi.mocked(api.meta).mockResolvedValue({} as never);
    vi.mocked(api.getLlmConsent).mockResolvedValue(undefined as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party transcript translation"),
    ).toHaveLength(0);
  });
});

describe("LLM consent toggle", () => {
  async function renderWithLlm(): Promise<Awaited<ReturnType<typeof render>>> {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    return root;
  }

  // H2: the toggle alone does nothing — the PASSWORD must be typed and
  // verified against the vault's key before the consent request is sent.
  it("requires the typed password and publishes the server's answer", async () => {
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    expect(sw.props.value).toBe(false);

    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    // Nothing was sent yet: the re-auth card is up, not a network call.
    expect(api.setLlmConsent).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Enter your password to enable");

    await reauth(root);

    expect(verifyPasswordForVault).toHaveBeenCalledWith("correct horse");
    expect(vi.mocked(api.setLlmConsent).mock.calls[0]?.slice(0, 2)).toEqual([true, authKey.toString("base64")]);
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.value).toBe(true);
  });

  it("a wrong password never reaches the server", async () => {
    verifyPasswordForVault.mockImplementation(async () => ({ ok: false as const, reason: "wrong-password" as const }));
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root, "wrong guess");
    expect(api.setLlmConsent).not.toHaveBeenCalled();
    expect(Alert.alert).toHaveBeenCalledWith("Could not verify", "Wrong password.");
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.value).toBe(false);
  });

  it("reports failures and keeps the old state", async () => {
    vi.mocked(api.setLlmConsent).mockRejectedValue(new Error("invalid credentials"));
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    // Calm fallback copy — no raw error text in the dialog (audit fix).
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "Something went wrong — try again.");
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.value).toBe(false);
  });

  it("falls back to calm copy for non-Error consent failures", async () => {
    vi.mocked(api.setLlmConsent).mockRejectedValue("nope" as never);
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "Something went wrong — try again.");
  });
});

describe("export safety gate", () => {
  it("fails closed before fetching or sharing a potentially large account", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Why export is unavailable");
    expect(Alert.alert).toHaveBeenCalledWith(
      "Export unavailable in this build",
      expect.stringContaining("sign in to the Fathom web app on a trusted computer"),
    );
    expect(api.exportAccount).not.toHaveBeenCalled();
    expect(flushQueue).not.toHaveBeenCalled();
    expect(Share.share).not.toHaveBeenCalled();
  });
});

describe("destructive delete", () => {
  it("requires two confirmations and the sign-in key", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");

    expect(lastAlert()[0]).toBe("Delete everything?");
    await pressAlertButton("Cancel");
    expect(api.deleteAccount).not.toHaveBeenCalled();

    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    expect(lastAlert()[0]).toBe("Final confirmation");
    await pressAlertButton("Cancel");
    expect(api.deleteAccount).not.toHaveBeenCalled();

    // H2: the final stage is the PASSWORD PROMPT — nothing is deleted
    // until the typed password re-derives the vault's own key.
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(api.deleteAccount).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    await reauth(root);

    expect(verifyPasswordForVault).toHaveBeenCalledWith("correct horse");
    expect(vi.mocked(api.deleteAccount).mock.calls[0]?.[0]).toBe(authKey.toString("base64"));
    expect(vault.isUnlocked()).toBe(false);
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it("the crisis-help button navigates to Crisis without any confirmation", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("Confirm with no typed password is a no-op even if the disabled press leaks through", async () => {
    // The native button suppresses this press; the guard inside
    // confirmWithPassword is the second line of defense.
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    // Password field left empty: the Confirm press must not even attempt re-auth.
    await pressLabel(root, "Confirm with password");
    await flush();
    expect(verifyPasswordForVault).not.toHaveBeenCalled();
    expect(api.deleteAccount).not.toHaveBeenCalled();
    // The card is still up — nothing was cancelled by accident.
    expect(textOf(root)).toContain("Enter your password to delete everything");
  });

  it("Cancel on the password card abandons the pending action", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    await typeInto(root, "password", "half-typed");
    await pressLabel(root, "Cancel");
    await flush();
    // The pending action and the half-typed password are both discarded.
    expect(textOf(root)).not.toContain("Enter your password to delete everything");
    expect(() => inputByPlaceholder(root, "password")).toThrow();
    expect(verifyPasswordForVault).not.toHaveBeenCalled();
    expect(api.deleteAccount).not.toHaveBeenCalled();
  });

  // M11: deletion is the destructive path — everything this account left on
  // the device goes too: queue, mood log, recompute stamp, cached salt.
  it("deletion also wipes the mood log, recompute stamp, cached salt and queue", async () => {
    await storage.setItem("@mindpattern/queue", "[]");
    await storage.setItem("mindpattern.moodlog.user-1", "[{\"date\":\"2026-09-01\",\"value\":0.5}]");
    await storage.setItem("@mindpattern/last_recompute_user-1", "2026-09-04");
    await storage.setItem("@mindpattern/salt_alice", "c2FsdA==");
    // Per-account acknowledgments die with the account too.
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    await storage.setItem("@mindpattern/onboarding_seen_user-1", "1");
    // …the reminder opt-in and the biometric data-key wrap as well (2026-09-19).
    await storage.setItem("@mindpattern/reminders_user-1", JSON.stringify({ enabled: true, hour: 20, minute: 0 }));
    // …the Health mirror opt-in dies with the account too (2026-09-19).
    await storage.setItem(
      "@mindpattern/mirror_mood_to_health_user-1",
      JSON.stringify({ enabled: true }),
    );
    const { enableBiometricUnlock } = await import("../../src/biometricUnlock");
    await enableBiometricUnlock("user-1", keys.dataKey);
    // …and so does the pending question-feedback record (encrypted locally,
    // written through the real module so the key format is the real one).
    await recordFeedbackTap(Buffer.alloc(32, 3), "user-1", "pid-1", true);

    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);

    expect(clearQueue).toHaveBeenCalledTimes(1); // the queue wipe itself
    expect(await storage.getItem("mindpattern.moodlog.user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/last_recompute_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/keyship_consent_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/onboarding_seen_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/question_feedback.user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/mirror_mood_to_health_user-1")).toBeNull();
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1); // a deleted account is never nudged
    expect(api.clearCachedSalt).toHaveBeenCalledWith("alice");
  });

  it("keeps the session intact when the server refuses, so retry is possible", async () => {
    vi.mocked(api.deleteAccount).mockRejectedValue(new Error("invalid credentials"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);

    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "Something went wrong — try again.");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("falls back to calm copy for non-Error delete failures", async () => {
    vi.mocked(api.deleteAccount).mockRejectedValue("nope" as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "Something went wrong — try again.");
  });

  // H2: a wrong password must never delete anything.
  it("a wrong password blocks the delete entirely", async () => {
    verifyPasswordForVault.mockImplementation(async () => ({ ok: false as const, reason: "wrong-password" as const }));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root, "wrong guess");
    expect(api.deleteAccount).not.toHaveBeenCalled();
    expect(signOut).not.toHaveBeenCalled();
    expect(Alert.alert).toHaveBeenCalledWith("Could not verify", "Wrong password.");
  });

  // M8: the server deletion is irreversible — a LATER local-cleanup failure
  // must not be reported as a failed delete (a retry could never work).
  it("a local cleanup failure after a successful server delete still reports success", async () => {
    vi.mocked(clearQueue).mockRejectedValue(new Error("storage corrupted"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(api.deleteAccount).toHaveBeenCalledTimes(1);
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(Alert.alert).toHaveBeenCalledWith("Deleted", expect.stringContaining("deleted from the server"));
    expect(Alert.alert).not.toHaveBeenCalledWith("Delete failed", expect.any(String));
  });
});

describe("sign out", () => {
  it("locks the vault, signs out and pops to the top", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Sign out");
    expect(vault.isUnlocked()).toBe(false);
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(nav.popToTop).toHaveBeenCalledTimes(1);
  });

  // M2: unsynced offline entries must survive sign-out — only deletion wipes.
  it("plain sign-out does NOT clear the offline queue", async () => {
    await storage.setItem("@mindpattern/queue", "[]");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Sign out");
    expect(clearQueue).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/queue")).toBe("[]");
  });

  it("keeps destructive controls available while the export safety explanation is shown", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Why export is unavailable");
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
  });
});

describe("verification-failure branching (403 vs 401)", () => {
  it("a 403 on the LLM toggle keeps the card up for a retry (NOT a session death)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.setLlmConsent).mockRejectedValue(new ApiError(403, "verification_failed", "verification_failed"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("That password didn't match", expect.stringContaining("try again"));
    // The card stays: pending is intact, the password field is cleared.
    expect(textOf(root)).toContain("Enter your password to enable");
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("a 401 on the LLM toggle reports the dead session (vault already locked by the hook)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.setLlmConsent).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Session expired", "Please unlock again.");
    // The flow concluded — the card is gone (there is nothing to retry here).
    expect(textOf(root)).not.toContain("Enter your password to enable");
  });

  it("a 403 on account deletion keeps the session AND the password card up for retry (L-62)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.deleteAccount).mockRejectedValue(new ApiError(403, "verification_failed", "verification_failed"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    // The verifier rejection rethrows to the outer handler: the shared
    // retry contract now covers the DELETE path too (the inner catch used
    // to swallow it and clear the card).
    expect(Alert.alert).toHaveBeenCalledWith(
      "That password didn't match",
      "Check it and try again — nothing was changed.",
    );
    expect(textOf(root)).toContain("Enter your password to delete everything");
    expect(signOut).not.toHaveBeenCalled();
    expect(vault.isUnlocked()).toBe(true);
  });

  it("a 401 on account deletion reports the dead session honestly", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.deleteAccount).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", expect.stringContaining("Session expired"));
    expect(signOut).not.toHaveBeenCalled();
  });
});

describe("theme radio initial value", () => {
  /** The radio touchable for a theme mode. L-64: the a11y label
   *  interpolates the LOCALIZED mode name ("Theme: Dark"), never the raw
   *  enum token — a Spanish screen reader heard "Tema: dark" before. */
  const MODE_LABEL: Record<string, string> = { system: "System", dark: "Dark", light: "Light" };
  function radioOf(root: Awaited<ReturnType<typeof render>>, mode: string) {
    const node = root.root
      .findAll((n) => n.props.accessibilityLabel === `Theme: ${MODE_LABEL[mode]}`)
      .find(() => true);
    if (!node) throw new Error(`no radio for ${JSON.stringify(mode)}`);
    return node;
  }

  it("shows the provider default while the persisted read is in flight — never a palette-derived value", async () => {
    // Dark OS palette + persisted "system": the old derived init selected
    // "Dark" on the first paint, as if the user had pinned an override.
    const { useColorScheme } = await import("react-native");
    useColorScheme.mockReturnValue("dark");
    let resolveStored!: (v: string | null) => void;
    const original = storage.getItem;
    storage.getItem = vi.fn(async (k: string) =>
      k === "@mindpattern/theme.mode" ? new Promise((resolve) => (resolveStored = resolve)) : original(k),
    ) as never;
    try {
      const root = await render(<SettingsScreen navigation={nav} />);
      expect(radioOf(root, "system").props.accessibilityState).toEqual({ selected: true });
      expect(radioOf(root, "dark").props.accessibilityState).toEqual({ selected: false });
      // The read lands: the persisted preference takes over.
      const { act } = await import("../helpers/rtr");
      await act(async () => {
        resolveStored("dark");
      });
      await flush();
      expect(radioOf(root, "dark").props.accessibilityState).toEqual({ selected: true });
      expect(radioOf(root, "system").props.accessibilityState).toEqual({ selected: false });
    } finally {
      storage.getItem = original;
    }
  });

  it("takes the persisted 'light' preference from storage", async () => {
    await storage.setItem("@mindpattern/theme.mode", "light");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(radioOf(root, "light").props.accessibilityState).toEqual({ selected: true });
    expect(radioOf(root, "dark").props.accessibilityState).toEqual({ selected: false });
    expect(radioOf(root, "system").props.accessibilityState).toEqual({ selected: false });
  });

  it("with nothing persisted the radio rests on System (the provider default)", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(radioOf(root, "system").props.accessibilityState).toEqual({ selected: true });
    expect(radioOf(root, "dark").props.accessibilityState).toEqual({ selected: false });
  });
});

describe("recovered entries surface", () => {
  it("is hidden when the rejected store is empty", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("couldn't sync");
    expect(textOf(root)).not.toContain("Try syncing them again");
  });

  it("offers one-tap recovery when rejected entries exist (requeue + flush)", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(2);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("2 entries couldn't sync and were kept safely on this device.");
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(requeueRejected).toHaveBeenCalledTimes(1);
    expect(flushQueue).toHaveBeenCalledWith("user-1");
    expect(Alert.alert).toHaveBeenCalledWith("Recovered entries", expect.stringContaining("moved back into the sync queue"));
  });

  it("singular wording for a single recovered entry", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("1 entry couldn't sync and was kept safely on this device.");
  });

  it("reports honestly when nothing could be moved yet", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    vi.mocked(requeueRejected).mockResolvedValue(0);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Recovered entries", expect.stringContaining("stay safely stored"));
  });

  it("a requeue failure reassures instead of alarming", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    vi.mocked(requeueRejected).mockRejectedValue(new Error("disk gone"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not retry", expect.stringContaining("still safe"));
  });

  it("shows the quarantine notice when a corrupt queue payload was set aside", async () => {
    vi.mocked(quarantinedQueueExists).mockResolvedValue(true);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("damaged piece of the offline queue was set aside instead of deleted");
  });
});

describe("About and Advanced sections", () => {
  it("shows the app version and the honest privacy note", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: false, version: "0.9.1" } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("About");
    expect(textOf(root)).toContain("Fathom 1.0.0 · server 0.9.1");
    expect(textOf(root)).toContain("encrypted on this device before it leaves");
    expect(textOf(root)).toContain("single-use session");
  });

  it("the privacy policy is one tap from About", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Privacy policy");
    expect(nav.navigate).toHaveBeenCalledWith("Privacy");
  });

  it("the daily-reminder section is honest when the module is absent: disabled switch, real reason, no fake scheduling", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    // Honest section copy — local only, nothing sent anywhere.
    expect(textOf(root)).toContain("A gentle daily nudge — local only, nothing is sent anywhere.");
    // The switch EXISTS (the preference is real) but is disabled, with the
    // capability reason as muted text — never a control that pretends.
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder");
    expect(sw).toBeDefined();
    expect(sw!.props.value).toBe(false);
    expect(sw!.props.disabled).toBe(true);
    expect(textOf(root)).toContain("notification module not linked in this build");
    // Off means no time chips yet.
    expect(textOf(root)).not.toContain("Morning 9:00");
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
    expect(cancelDailyReminder).not.toHaveBeenCalled();
  });

  it("a stored preference still READS while the module is absent (custom time chip included)", async () => {
    await storage.setItem("@mindpattern/reminders_user-1", JSON.stringify({ enabled: true, hour: 21, minute: 30 }));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder");
    expect(sw!.props.value).toBe(true);
    expect(sw!.props.disabled).toBe(true);
    // The three presets plus the custom time as its own chip, selected.
    expect(textOf(root)).toContain("Morning 9:00");
    expect(textOf(root)).toContain("Midday 12:00");
    expect(textOf(root)).toContain("Evening 20:00");
    expect(textOf(root)).toContain("21:30");
    const custom = root.root.findAll((n) => n.props.accessibilityLabel === "Reminder time: 21:30")[0];
    expect(custom.props.accessibilityState).toEqual({ selected: true });
  });

  it("renders the version without the server part when meta has none", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Fathom 1.0.0");
    expect(textOf(root)).not.toContain("server undefined");
  });

  it("the developer server-URL setting sits in Advanced, after About", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const texts = (await import("../helpers/rtr")).allText(root);
    const iAbout = texts.findIndex((t) => t === "About");
    const iAdvanced = texts.findIndex((t) => t === "Advanced");
    const iSaveUrl = texts.findIndex((t) => t.includes("Save server URL"));
    expect(iAbout).toBeGreaterThanOrEqual(0);
    expect(iAdvanced).toBeGreaterThan(iAbout);
    expect(iSaveUrl).toBeGreaterThan(iAdvanced);
    // The safe export explanation remains with consumer actions before About.
    expect(texts.findIndex((t) => t.includes("Why export is unavailable"))).toBeLessThan(iAbout);
  });
});

describe("daily reminder section (module linked)", () => {
  /** Render with the notification module present (the seam's "linked" side). */
  async function renderWithReminders(): Promise<Awaited<ReturnType<typeof render>>> {
    reminderCapability.mockReturnValue({ available: true });
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    return root;
  }

  it("toggling on persists the per-account opt-in and schedules at the stored time", async () => {
    const root = await renderWithReminders();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder")!;
    expect(sw.props.disabled).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toContain("\"enabled\":true");
    expect(scheduleDailyReminder).toHaveBeenCalledWith(20, 0, expect.any(Object)); // the default time
    expect(cancelDailyReminder).not.toHaveBeenCalled();
    expect(
      root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder")!.props.value,
    ).toBe(true);
    // Time chips appear once enabled.
    expect(textOf(root)).toContain("Morning 9:00");
    expect(textOf(root)).toContain("Evening 20:00");
  });

  it("toggling off persists it and cancels the schedule", async () => {
    await storage.setItem("@mindpattern/reminders_user-1", JSON.stringify({ enabled: true, hour: 9, minute: 0 }));
    const root = await renderWithReminders();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder")!;
    expect(sw.props.value).toBe(true);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toContain("\"enabled\":false");
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
  });

  it("choosing a preset time persists it and selects exactly that chip", async () => {
    await storage.setItem("@mindpattern/reminders_user-1", JSON.stringify({ enabled: true, hour: 20, minute: 0 }));
    const root = await renderWithReminders();
    await pressLabel(root, "Morning 9:00");
    await flush();
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toContain("\"hour\":9");
    const morning = root.root.findAll((n) => n.props.accessibilityLabel === "Reminder time: Morning 9:00")[0];
    const evening = root.root.findAll((n) => n.props.accessibilityLabel === "Reminder time: Evening 20:00")[0];
    expect(morning.props.accessibilityState).toEqual({ selected: true });
    expect(evening.props.accessibilityState).toEqual({ selected: false });
    // A preset that matches leaves no duplicate custom chip.
    expect(textOf(root)).not.toContain("9:00\n"); // no second 9:00 chip beyond the preset
  });

  it("a scheduling that lands on denied permission explains itself honestly", async () => {
    reminderCapability.mockReturnValue({ available: true });
    scheduleDailyReminder.mockResolvedValue(false);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder")!;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Reminder not scheduled", expect.stringContaining("device settings"));
    // The preference itself still saved — honest "not scheduled", not amnesia.
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toContain("\"enabled\":true");
  });

  it("no account id: the toggle does nothing and nothing is written", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await renderWithReminders();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder")!;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/reminders_user-1")).toBeNull();
    expect(scheduleDailyReminder).not.toHaveBeenCalled();
  });
});

describe("Health mirror section (module absent — this build)", () => {
  /** The row's switch, by its accessibility label. */
  function mirrorSwitch(root: Awaited<ReturnType<typeof render>>) {
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app");
    if (!sw) throw new Error("no Health mirror switch rendered");
    return sw;
  }

  it("is always visible: honest write-only disclosure, disabled switch, the capability reason", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = mirrorSwitch(root);
    expect(sw.props.value).toBe(false);
    expect(sw.props.disabled).toBe(true);
    expect(sw.props.accessibilityState).toEqual({ checked: false, disabled: true });
    // The disclosure states all three facts: what is written, that
    // Fathom never READS from Health, and what off means.
    expect(textOf(root)).toContain("written to the Health app on this device");
    expect(textOf(root)).toContain("Fathom never reads anything from Health");
    expect(textOf(root)).toContain("Turning this off stops future writes; what the Health app already holds stays there.");
    expect(textOf(root)).toContain("health module not linked in this build");
  });

  it("a stored ON preference still READS while the module is absent", async () => {
    await storage.setItem("@mindpattern/mirror_mood_to_health_user-1", JSON.stringify({ enabled: true }));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(mirrorSwitch(root).props.value).toBe(true);
    expect(mirrorSwitch(root).props.disabled).toBe(true); // still can't flip it here
  });
});

describe("Health mirror toggle (module linked)", () => {
  async function renderWithHealth(): Promise<Awaited<ReturnType<typeof render>>> {
    healthKitCapability.mockReturnValue({ available: true });
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    return root;
  }

  it("toggling on persists the per-account opt-in and asks for Health WRITE access here, not later", async () => {
    const root = await renderWithHealth();
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!;
    expect(sw.props.disabled).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/mirror_mood_to_health_user-1")).toBe('{"enabled":true}');
    // The access ask happened at the switch, where the user just acted.
    expect(ensureStateOfMindWriteAccess).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled(); // granted: quiet success
    expect(
      root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!.props.value,
    ).toBe(true);
  });

  it("a denied Health grant explains itself honestly while the preference stays saved", async () => {
    ensureStateOfMindWriteAccess.mockResolvedValue(false);
    const root = await renderWithHealth();
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Health access not granted", expect.stringContaining("privacy settings"));
    expect(await storage.getItem("@mindpattern/mirror_mood_to_health_user-1")).toBe('{"enabled":true}');
  });

  it("toggling off persists OFF and asks Health for nothing", async () => {
    await storage.setItem("@mindpattern/mirror_mood_to_health_user-1", JSON.stringify({ enabled: true }));
    const root = await renderWithHealth();
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!;
    expect(sw.props.value).toBe(true);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/mirror_mood_to_health_user-1")).toBe('{"enabled":false}');
    expect(ensureStateOfMindWriteAccess).not.toHaveBeenCalled();
  });

  it("a failed preference save is reported honestly and flips nothing", async () => {
    const original = storage.setItem;
    storage.setItem = vi.fn(async () => {
      throw new Error("disk full");
    }) as never;
    try {
      const root = await renderWithHealth();
      const sw = root.root
        .findAllByType(Switch)
        .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!;
      const { act } = await import("../helpers/rtr");
      await act(async () => {
        (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
      });
      await flush();
      expect(Alert.alert).toHaveBeenCalledWith("Could not save", "The Health preference wasn't saved — try again.");
      expect(ensureStateOfMindWriteAccess).not.toHaveBeenCalled(); // nothing else happened
    } finally {
      storage.setItem = original;
    }
  });

  it("no account id: the toggle does nothing and nothing is written", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await renderWithHealth();
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Mirror mood check-ins to the Health app")!;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(await storage.getItem("@mindpattern/mirror_mood_to_health_user-1")).toBeNull();
    expect(ensureStateOfMindWriteAccess).not.toHaveBeenCalled();
  });
});

describe("biometric unlock toggle", () => {
  it("stays hidden on a device without biometrics", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Biometric unlock"),
    ).toHaveLength(0);
    expect(textOf(root)).not.toContain("BIOMETRIC UNLOCK");
  });

  it("appears on a supported device, off by default, and enabling shows the honest trade before storing", async () => {
    keychainMock.__setBiometryType("FaceID");
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Biometric unlock")!;
    expect(sw.props.value).toBe(false);
    expect(textOf(root)).toContain("Your password always keeps working.");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    // The confirmation states the trade BEFORE anything is stored.
    expect(Alert.alert).toHaveBeenCalledWith("Use biometric unlock?", expect.stringContaining("wrapped under your fingerprint or face"), expect.anything());
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
    await pressAlertButton("Enable");
    await flush();
    // M-4 (2026-09-20): the explainer is only step one — the password card
    // appears and NOTHING is stored until the typed password verifies.
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
    expect(textOf(root)).toContain("Enter your password to enable biometric unlock");
    const passwordField = root.root
      .findAllByType(TextInput)
      .find((n) => n.props.accessibilityLabel === "Password confirmation")!;
    await act(async () => {
      (passwordField.props as { onChangeText: (t: string) => void }).onChangeText("correct horse battery staple");
    });
    await pressLabel(root, "Confirm with password");
    await flush();
    // The wrap stored the vault's own data key for this account — after the
    // password proof, not before.
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toEqual({
      username: "user-1",
      password: keys.dataKey.toString("base64"),
    });
    expect(
      root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Biometric unlock")!.props.value,
    ).toBe(true);
  });

  it("cancel on the confirmation stores nothing", async () => {
    keychainMock.__setBiometryType("FaceID");
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Biometric unlock")!;
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await pressAlertButton("Cancel");
    await flush();
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
  });

  it("reflects an existing wrap on mount, and turning it off removes it", async () => {
    keychainMock.__setBiometryType("FaceID");
    const { enableBiometricUnlock } = await import("../../src/biometricUnlock");
    await enableBiometricUnlock("user-1", keys.dataKey);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Biometric unlock")!;
    expect(sw.props.value).toBe(true);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
    expect(
      root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Biometric unlock")!.props.value,
    ).toBe(false);
  });
});

describe("therapist sharing entry point", () => {
  it("navigates to the share screen", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Share with my therapist");
    expect(nav.navigate).toHaveBeenCalledWith("TherapistShare");
  });
});

describe("accessibility", () => {
  it("labels the LLM switch and reports checked/disabled state", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    expect(sw.props.accessibilityLabel).toBe("Allow third-party transcript translation");
    expect(sw.props.accessibilityState).toEqual({ checked: false, disabled: false });
  });

  it("labels the inputs explicitly", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(inputByPlaceholder(root, "https://your-server:8000").props.accessibilityLabel).toBe("Server URL");
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(inputByPlaceholder(root, "password").props.accessibilityLabel).toBe("Password confirmation");
  });
});

describe("recovered entries surface — edge branches", () => {
  it("singular moved-count and nothing-left copy", async () => {
    // Mount read → 1; the post-recovery read → 0 left.
    vi.mocked(rejectedEntryCount).mockResolvedValueOnce(1).mockResolvedValue(0);
    vi.mocked(requeueRejected).mockResolvedValue(1);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Recovered entries",
      "1 entry moved back into the sync queue — they upload on the next sync.",
    );
  });

  it("some still waiting after the move", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(3);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Recovered entries",
      "2 entries moved back into the sync queue — 3 still waiting.",
    );
  });

  it("ignores a second recovery tap while recovery is already busy", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    let resolveRequeue: ((v: number) => void) | undefined;
    vi.mocked(requeueRejected).mockImplementation(
      () => new Promise((resolve) => (resolveRequeue = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { firePress, act } = await import("../helpers/rtr");
    await firePress(root, "Try syncing them again");
    await firePress(root, "Try syncing them again");
    expect(requeueRejected).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveRequeue?.(1);
    });
    await flush();
  });
});

describe("change-password rotation self-completes (audit fix 7, 2026-09-21)", () => {
  it.each(["getUserId", "getUsername"] as const)("refuses a replacement account during the initial %s lookup", async lookup => {
    const { changeLocalSessionOwner } = await import("../../src/localWriteGuard");
    const root = await render(<SettingsScreen navigation={nav as never} />); await flush();
    await pressLabel(root, "Change password"); await typeInto(root, "password", "correct old password");
    await typeInto(root, "New password (12+ characters)", "a strong new passphrase 42!");
    rotatePasswordMock.mockClear(); let release!: () => void;
    vi.mocked(api[lookup]).mockImplementationOnce(async () => { await new Promise<void>(resolve => { release = resolve; }); return lookup === "getUserId" ? "user-2" : "replacement"; });
    await firePress(root, "Rotate keys and sign in again"); await flush(); expect(release).toBeTypeOf("function");
    changeLocalSessionOwner("user-2"); vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 9) }, "user-2");
    await act(async () => release()); await flush();
    expect(rotatePasswordMock).not.toHaveBeenCalled(); expect(api.changePassword).not.toHaveBeenCalled(); expect(api.rekeyStoredData).not.toHaveBeenCalled();
  });
  it("locks the vault and drops the biometric wrap BEFORE the alert — even when the alert is dismissed without OK", async () => {
    const { enableBiometricUnlock, hasBiometricUnlock } = await import("../../src/biometricUnlock");
    // A biometric wrap exists for this account — the stale-key hazard the
    // fix exists for (a wrap sealed under the OLD data key).
    await enableBiometricUnlock("user-1", Buffer.alloc(32, 7));
    expect(await hasBiometricUnlock("user-1")).toBe(true);

    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Change password");
    await typeInto(root, "password", "correct old password");
    await typeInto(root, "New password (12+ characters)", "a strong new passphrase 42!");
    await pressLabel(root, "Rotate keys and sign in again");
    await flush(6);

    // The success alert IS up: the rotation finished server-side. Deliberately
    // DO NOT press OK — Android can dismiss an alert without firing its
    // button, and the cleanup must not depend on it.
    expect(Alert.alert).toHaveBeenCalledWith("Password changed", expect.any(String), expect.anything());
    // The vault no longer holds the OLD data key…
    expect(vault.isUnlocked()).toBe(false);
    // …and the biometric wrap (which still sealed the old key) is gone.
    expect(await hasBiometricUnlock("user-1")).toBe(false);
    // The OK-button-only signOut never ran — proving none of the security
    // cleanup hung off the alert.
    expect(signOut).not.toHaveBeenCalled();
  });

  // 2026-09-26 audit M-M5: runRotate had no catch — an unexpected throw
  // became an unhandled rejection with zero user feedback while the finally
  // cleared the typed passwords. The catch must surface the calm failed
  // rotation title + generic copy (the confirmWithPassword idiom).
  it("an unexpected rotation throw surfaces calm feedback instead of an unhandled rejection", async () => {
    rotatePasswordMock.mockRejectedValueOnce(new Error("unexpected local failure"));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Change password");
    await typeInto(root, "password", "correct old password");
    await typeInto(root, "New password (12+ characters)", "a strong new passphrase 42!");
    await pressLabel(root, "Rotate keys and sign in again");
    await flush(6);

    expect(Alert.alert).toHaveBeenCalledWith("Could not change password", "Something went wrong — try again.");
    // The finally still ran: busy cleared and both fields wiped (the retry
    // starts from empty inputs, never from a stale password).
    expect((inputByPlaceholder(root, "password")?.props as { value?: string })?.value ?? "").toBe("");
    expect(touchableByLabel(root, "Rotate keys and sign in again").props.disabled).toBe(true);
  });

  // 2026-09-26 audit LOW: the rotation card's current-password field is no
  // longer the re-auth card's shared state — a password typed for rotation
  // must never silently satisfy a later destructive re-auth prompt.
  it("the rotation card's password never leaks into the destructive re-auth card", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Change password");
    await typeInto(root, "password", "rotation-only secret");
    // Close the rotation card without running it…
    await pressLabel(root, "Cancel");
    expect(textOf(root)).not.toContain("Rotate keys and sign in again");
    // …then open the DELETE flow's password card.
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    // The re-auth field starts EMPTY — before the split it carried
    // "rotation-only secret", one tap away from deleting the account.
    const reauthInput = inputByPlaceholder(root, "password");
    expect((reauthInput.props as { value: string }).value).toBe("");
    expect(touchableByLabel(root, "Confirm with password").props.disabled).toBe(true);
  });
});

// --- v1 → v2 key-envelope upgrade + scheme-aware copy (2026-09-26) -----------
describe("key-envelope upgrade card", () => {
  it("appears ONLY when the server says the account is v1", async () => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Upgrade key protection");
    expect(textOf(root)).toContain("today your password directly derives your encryption key");

    const v2 = await render(<SettingsScreen navigation={nav} />);
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: SALT_B64, kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, wrapped_data_key: Buffer.alloc(60, 7).toString("base64") } as never);
    const root2 = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root2)).not.toContain("Upgrade key protection");
    void v2;
  });

  it("runs the upgrade after the typed password: session key proof + honest success copy", async () => {
    // The upgrade requires the vault to be bound to THIS account (the
    // key-shipping ownership rule); the suite's default unlock has no id.
    vault.lock();
    vault.unlock({ masterKey: Buffer.from(keys.masterKey), authKey: Buffer.from(keys.authKey), dataKey: Buffer.from(keys.dataKey) }, "user-1");
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Upgrade now");
    await flush();
    expect(textOf(root)).toContain("Enter your password to upgrade key protection");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Confirm with password");
    await flush();

    // Both proofs shipped: the processing session carried the vault's data
    // key, and the wrap is a real 60-byte envelope over THAT key.
    expect(api.upgradeKeyEnvelope).toHaveBeenCalledTimes(1);
    const [params, wrappedB64, token] = vi.mocked(api.upgradeKeyEnvelope).mock.calls[0] as unknown as [
      Record<string, unknown>,
      string,
      string,
    ];
    expect(params).toEqual({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 });
    expect(Buffer.from(wrappedB64, "base64")).toHaveLength(60);
    expect(token).toBe("st"); // the mocked processing session token
    expect(lastAlert()[0]).toBe("Key protection upgraded");
    // The card is gone — the account is v2 on this screen now.
    expect(textOf(root)).not.toContain("Upgrade key protection");
    // The vault survived untouched (same data key, still unlocked).
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.get().dataKey).toEqual(keys.dataKey);
  });

  it("a 403 envelope_key_mismatch gets the dedicated honest copy, never a raw error", async () => {
    const { ApiError } = await import("../../src/api/client");
    vault.lock();
    vault.unlock({ masterKey: Buffer.from(keys.masterKey), authKey: Buffer.from(keys.authKey), dataKey: Buffer.from(keys.dataKey) }, "user-1");
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    vi.mocked(api.upgradeKeyEnvelope).mockRejectedValue(
      new ApiError(403, "the processing session's key did not authenticate stored ciphertext", "envelope_key_mismatch"),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Upgrade now");
    await flush();
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Confirm with password");
    await flush();
    expect(lastAlert()[0]).toBe("Could not upgrade key protection");
    expect(lastAlert()[1]).toContain("does not match the data stored on the server");
    expect(lastAlert()[1]).not.toContain("processing session");
  });
});

describe("scheme-aware change-password copy", () => {
  it("v1 accounts keep the rekey disclosure; v2 accounts get the honest O(1) copy", async () => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    const v1Root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(v1Root, "Change password");
    await flush();
    expect(textOf(v1Root)).toContain("re-encrypts your journal under a new encryption key");
    expect(textOf(v1Root)).toContain("Rotate keys and sign in again");

    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: SALT_B64, kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, wrapped_data_key: Buffer.alloc(60, 7).toString("base64") } as never);
    const v2Root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(v2Root, "Change password");
    await flush();
    expect(textOf(v2Root)).toContain("Your journal is not re-encrypted");
    expect(textOf(v2Root)).toContain("Change password and sign in again");
  });
});

// --- independent audit 2026-09-27 (coverage): the appearance, reminder,
// check-in cadence, sign-out, and navigation sections — the behavioral
// branches the functions gate needs.
const { Switch } = await import("../helpers/rnMock");

/** independent audit 2026-09-27 (coverage): find a Switch by its
 *  accessibilityLabel — the reminder/biometrics/haptics rows each carry
 *  one, and value-based lookup is ambiguous across sections. */
function switchByA11y(root: Awaited<ReturnType<typeof render>>, label: string) {
  const node = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === label);
  if (!node) throw new Error(`no Switch labeled ${label}`);
  return node;
}

describe("appearance and haptics (independent audit 2026-09-27)", () => {
  it("a theme radio tap selects the mode and persists the preference", async () => {
    const { ThemeProvider } = await import("../../src/theme");
    const root = await render(
      <ThemeProvider>
        <SettingsScreen navigation={nav as never} />
      </ThemeProvider>,
    );
    await flush();
    await pressLabel(root, "Dark");
    await flush();
    expect(touchActivity).toHaveBeenCalled();
    // The persisted preference follows the tap (the storage-backed radio).
    const AsyncStorage = (await import("@react-native-async-storage/async-storage")).default;
    expect(await AsyncStorage.getItem("@mindpattern/theme.mode")).toBe("dark");
    // Selecting is visible in the a11y state of the tapped radio.
    const radios = root.root.findAll((n) => n.props.accessibilityRole === "radio");
    const dark = radios.find((n) => String(n.props.accessibilityLabel).includes("Dark"));
    expect(dark?.props.accessibilityState).toMatchObject({ selected: true });
  });

  it("the haptics switch persists through its own preference lane", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      switchByA11y(root, "Haptics").props.onValueChange(false);
    });
    await flush();
    const AsyncStorage = (await import("@react-native-async-storage/async-storage")).default;
    expect(await AsyncStorage.getItem("@mindpattern/haptics.enabled")).toBe("off");
    expect(switchByA11y(root, "Haptics").props.value).toBe(false);
  });
});

describe("daily reminder and check-in cadence (independent audit 2026-09-27)", () => {
  it("toggling the daily reminder ON schedules at the stored time and shows the time chips", async () => {
    reminderCapability.mockReturnValue({ available: true });
    const { setReminderTime } = await import("../../src/reminders");
    await setReminderTime("user-1", 12, 0);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    expect(switchByA11y(root, "Daily reminder").props.value).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      switchByA11y(root, "Daily reminder").props.onValueChange(true);
    });
    await flush(5);
    // The sync scheduled at the STORED preference time (the reconciliation
    // contract: preference is the direction of truth).
    expect(scheduleDailyReminder).toHaveBeenCalledWith(12, 0, expect.any(Object));
    expect(switchByA11y(root, "Daily reminder").props.value).toBe(true);
    // The time chips render with the current one selected.
    const chips = root.root.findAll((n) => n.props.accessibilityRole === "radio");
    const midday = chips.find((n) => String(n.props.accessibilityLabel).includes("Midday"));
    expect(midday?.props.accessibilityState).toMatchObject({ selected: true });
  });

  it("a custom stored time renders as its own chip; tapping a preset re-schedules", async () => {
    reminderCapability.mockReturnValue({ available: true });
    const { setReminderEnabled, setReminderTime } = await import("../../src/reminders");
    await setReminderEnabled("user-1", true);
    await setReminderTime("user-1", 6, 45);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    expect(textOf(root)).toContain("6:45");
    await pressLabel(root, "6:45"); // the custom chip exists and is tappable
    await flush(5);
    scheduleDailyReminder.mockClear();
    await pressLabel(root, "Evening");
    await flush(5);
    expect(scheduleDailyReminder).toHaveBeenCalledWith(20, 0, expect.any(Object));
    const { getReminderPrefs } = await import("../../src/reminders");
    expect((await getReminderPrefs("user-1")).hour).toBe(20);
  });

  it("toggling the daily reminder OFF cancels the native schedule", async () => {
    reminderCapability.mockReturnValue({ available: true });
    const { setReminderEnabled } = await import("../../src/reminders");
    await setReminderEnabled("user-1", true);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      switchByA11y(root, "Daily reminder").props.onValueChange(false);
    });
    await flush(5);
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
    expect(switchByA11y(root, "Daily reminder").props.value).toBe(false);
  });

  it("toggling check-in reminders ON schedules the nudge; the interval chips persist the cadence", async () => {
    reminderCapability.mockReturnValue({ available: true });
    // The nudge only schedules when the cadence is DUE: the last completed
    // measure is seeded 5 weeks back through the encrypted stamp lane.
    const { secureStore } = await import("../../src/secureStore");
    await secureStore.setItem("@mindpattern/last_measure_user-1", new Date(Date.now() - 63 * 86_400_000).toISOString().slice(0, 10));
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      switchByA11y(root, "Check-in reminders").props.onValueChange(true);
    });
    await flush(5);
    expect(scheduleMeasureReminder).toHaveBeenCalledTimes(1);
    // The cadence chips render; choosing 8 weeks persists and re-syncs.
    scheduleMeasureReminder.mockClear();
    await pressLabel(root, "8 weeks");
    await flush(5);
    const { getMeasureReminderPrefs } = await import("../../src/measureReminders");
    expect((await getMeasureReminderPrefs("user-1")).intervalWeeks).toBe(8);
    expect(scheduleMeasureReminder).toHaveBeenCalledTimes(1);
  });

  it("with the module absent the toggles persist the preference but schedule nothing", async () => {
    // reminderCapability defaults to unavailable in this file's beforeEach.
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    expect(textOf(root)).toContain("notification module not linked in this build");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      const { Switch } = await import("../helpers/rnMock");
      const node = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Daily reminder");
      node!.props.onValueChange(true);
    });
    await flush(5);
    const { getReminderPrefs } = await import("../../src/reminders");
    expect((await getReminderPrefs("user-1")).enabled).toBe(true);
    // The switch is disabled — the OS-level honest state for this build.
    expect(switchByA11y(root, "Daily reminder").props.disabled).toBe(true);
  });
});

describe("navigation rows and sign-out hygiene (independent audit 2026-09-27)", () => {
  it("the section rows navigate to Measures, the safety plan, and Privacy", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Wellbeing measures");
    await pressLabel(root, "Make a safety plan");
    await pressLabel(root, "Privacy policy");
    expect(nav.navigate).toHaveBeenCalledWith("Measures");
    expect(nav.navigate).toHaveBeenCalledWith("SafetyPlan");
    expect(nav.navigate).toHaveBeenCalledWith("Privacy");
  });

  it("sign-out locks the vault FIRST, then signs the session out and pops to top", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    await pressLabel(root, "Sign out");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(nav.popToTop).toHaveBeenCalledTimes(1);
  });

  it("'Why can't I export my journal?' explains the honest export stance", async () => {
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush();
    await pressLabel(root, "Why export is unavailable");
    await flush();
    expect(Alert.alert).toHaveBeenCalledTimes(1);
    expect(Alert.alert.mock.calls[0]![1]).toContain("sign in to the Fathom web app on a trusted computer");
  });

  it("the re-auth card's Cancel retires the pending action and clears the field", async () => {
    vi.mocked(api.getLlmConsent).mockResolvedValue({ enabled: false } as never);
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true, sharing_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav as never} />);
    await flush(5);
    const { Switch } = await import("../helpers/rnMock");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      const node = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party transcript translation");
      node!.props.onValueChange(true);
    });
    await flush();
    expect(textOf(root)).toContain("Confirm with password");
    await typeInto(root, "password", "typed-then-cancelled");
    await pressLabel(root, "Cancel");
    await flush();
    expect(textOf(root)).not.toContain("Confirm with password");
  });
});

describe("voice journaling consent (VOICE_PLAN 2026-09-29, audit C5)", () => {
  it("shows the section with the provider note and the stored consent state", async () => {
    vi.mocked(api.meta).mockResolvedValue({ audio_available: true, stt_provider_name: "Whisper Medical" } as never);
    vi.mocked(api.getVoiceConsent).mockResolvedValue({ enabled: true, active_for_current_policy: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling");
    expect(sw).toBeDefined();
    expect(sw!.props.value).toBe(true);
    expect(textOf(root)).toContain("Whisper Medical");
    // Current policy: no stale note.
    expect(textOf(root)).not.toContain("earlier choice no longer authorizes uploads");
  });

  it("treats legacy voice v1 consent as inactive until a fresh v2 opt-in", async () => {
    vi.mocked(api.meta).mockResolvedValue({ audio_available: true } as never);
    vi.mocked(api.getVoiceConsent).mockResolvedValue({ enabled: true, active_for_current_policy: false } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling")!;
    expect(sw.props.value).toBe(false);
    expect(textOf(root)).toContain("earlier choice no longer authorizes uploads");
    expect(textOf(root)).toContain("Voice journaling is off");
  });

  it("the toggle demands the typed password; the verifier, not the bearer, changes the consent", async () => {
    vi.mocked(api.meta).mockResolvedValue({ audio_available: true } as never);
    vi.mocked(api.getVoiceConsent).mockResolvedValue({ enabled: false, active_for_current_policy: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { act } = await import("../helpers/rtr");
    const sw = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling")!;
    expect(sw.props.value).toBe(false);
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    // The password card names the action; nothing was sent yet.
    expect(textOf(root)).toContain("Enter your password to enable voice journaling");
    expect(api.setVoiceConsent).not.toHaveBeenCalled();
    await reauth(root);
    expect(vi.mocked(api.setVoiceConsent).mock.calls[0]?.slice(0, 2)).toEqual([true, authKeyB64()]);
    expect(
      root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling")!.props.value,
    ).toBe(true);
  });

  it("a server without voice says so; an unreachable server guesses nothing", async () => {
    vi.mocked(api.meta).mockResolvedValue({ audio_available: false } as never);
    const off = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(off)).toContain("Voice journaling is not offered by this server.");
    expect(off.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling")).toBeUndefined();

    vi.mocked(api.meta).mockRejectedValue(new Error("network down"));
    const unknown = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(unknown)).not.toContain("Voice journaling is not offered by this server.");
    expect(unknown.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow voice journaling")).toBeUndefined();
  });
});


describe("Settings metadata, consent, and completion contracts", () => {
  it.each([null, undefined])("an absent native metadata response %s explains unavailable voice and sharing", async meta => {
    vi.mocked(api.meta).mockResolvedValue(meta as never);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    expect(textOf(root)).toContain("Voice journaling is not offered by this server.");
    expect(root.root.findAllByType(Switch).find(node => node.props.accessibilityLabel === "Allow voice journaling")).toBeUndefined();
    expect(textOf(root)).toContain("not offered by this server"); await act(async () => root.unmount());
  });
  it.each(["valid", "missing", "null", "object", "number"])("renders disclosed provider policy and safely handles %s metadata", async kind => {
    const value = (text: string) => kind === "valid" ? text : kind === "missing" ? undefined : kind === "null" ? null : kind === "object" ? { unsafe: "remote object" } : 37;
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true, audio_available: true, sharing_available: true,
      llm_provider_name: value("Reviewed LLM Provider"), llm_data_retention: value("LLM retained for30days"), llm_policy_fingerprint: value("reviewed-llm-policy"),
      stt_provider_name: value("Reviewed Voice Provider"), stt_data_retention: value("Voice retained for7days"), stt_policy_fingerprint: value("reviewed-voice-policy") } as never);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    if (kind === "valid") for (const copy of ["Reviewed LLM Provider", "LLM retained for30days", "reviewed-llm-policy", "Reviewed Voice Provider", "Voice retained for7days", "reviewed-voice-policy"]) expect(textOf(root)).toContain(copy);
    else { expect(textOf(root)).toContain("not disclosed by this server"); expect(textOf(root)).not.toContain("remote object"); }
  });
  for (const kind of ["llm", "voice"] as const) {
    const label = kind === "llm" ? "Allow third-party transcript translation" : "Allow voice journaling";
    const method = kind === "llm" ? "getLlmConsent" : "getVoiceConsent";
    for (const enabled of [true, false, undefined]) for (const active of [true, false]) {
      it(`${kind} shows only current explicitly enabled consent enabled=${enabled}, active=${active}`, async () => {
        vi.mocked(api.meta).mockResolvedValue({ llm_available: true, audio_available: true } as never);
        vi.mocked(api[method]).mockResolvedValue({ enabled, active_for_current_policy: active } as never);
        const root = await render(<SettingsScreen navigation={nav} />); await flush();
        const control = root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === label)!;
        expect(control).toBeDefined(); expect(control.props.value).toBe(enabled === true && active === true);
        expect(control.props.accessibilityState.checked).toBe(enabled === true && active === true);
      });
    }
    for (const enabled of [true, false]) for (const active of [true, false]) {
      it(`${kind} renders the acknowledged consent enabled=${enabled}, active=${active}`, async () => {
        vi.mocked(api.meta).mockResolvedValue({ llm_available: true, audio_available: true } as never);
        const setter = kind === "llm" ? "setLlmConsent" : "setVoiceConsent";
        vi.mocked(api[setter]).mockResolvedValueOnce({ enabled, active_for_current_policy: active } as never);
        const root = await render(<SettingsScreen navigation={nav} />); await flush();
        await act(async () => root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === label)!.props.onValueChange(true));
        await reauth(root); await flush();
        const control = root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === label)!;
        expect(control.props.value).toBe(enabled && active); expect(control.props.accessibilityState.checked).toBe(enabled && active);
      });
    }
  }
  async function rotate(root: Awaited<ReturnType<typeof render>>, password = "a strong new passphrase 42!") {
    await pressLabel(root, "Change password"); await typeInto(root, "password", "correct old password");
    await typeInto(root, "New password (12+ characters)", password); await pressLabel(root, "Rotate keys and sign in again"); await flush();
  }
  it.each(["wrong-password", "queue-blocked", "offline", "server"] as const)("renders the typed rotation failure %s and clears both password fields", async reason => {
    rotatePasswordMock.mockResolvedValueOnce({ ok: false, stage: "rekey", reason });
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); await rotate(root);
    const expected = reason === "wrong-password" ? "The current password was not accepted. Nothing was changed." : reason === "queue-blocked" ? "Entries are still waiting to upload from this device, sealed under your current password — changing it now would leave them unreadable. Save them first (keep the app open while online until the queue is empty), then try again." : reason === "offline" ? "Cannot verify your password offline right now — try again when online." : "Something went wrong — try again.";
    expect(lastAlert().slice(0, 2)).toEqual(["Could not change password", expected]);
    expect(inputByPlaceholder(root, "password").props.value).toBe(""); expect(inputByPlaceholder(root, "New password (12+ characters)").props.value).toBe("");
  });
  it.each(["v1", "v2"] as const)("describes the completed %s rotation and preserves its grant scope", async scheme => {
    rotatePasswordMock.mockResolvedValueOnce({ ok: true, scheme, counts: { entries: 1, insights: 2, measures: 3 }, rewrapped: 0, rewrapFailures: ["Therapist A", "Therapist B"] });
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); await rotate(root);
    const text = scheme === "v2" ? "Your password now unlocks a freshly wrapped copy of your encryption key; the key itself did not change, so your journal and sharing are exactly as they were. Sign in again on this device and on any other device you use." : "Your journal is now encrypted under your new password. Sign in again on this device and on any other device you use.\n\nThese sharing grants could not be re-wrapped and must be re-paired from the therapist's pairing code: Therapist A, Therapist B\n\nA legacy data-key change invalidates the previous recovery kit. Create and save a new recovery kit after signing in.";
    expect(lastAlert().slice(0, 2)).toEqual(["Password changed", text]);
    expect(signOut).not.toHaveBeenCalled(); await pressAlertButton("OK"); expect(signOut).toHaveBeenCalledTimes(1);
  });
  it.each(["short", "variety"])("explains the rejected %s password policy before rotation", async kind => {
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); rotatePasswordMock.mockClear();
    await rotate(root, kind === "short" ? "short123!" : "abcdefghijkl");
    expect(lastAlert()[0]).toBe(kind === "short" ? "Password too short" : "Password needs more variety"); expect(rotatePasswordMock).not.toHaveBeenCalled();
  });
  it.each(["inactive", "background"])("clears a typed pending proof through the actual native %s event", async state => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    await act(async () => root.root.findAllByType(Switch).find(n => n.props.accessibilityLabel === "Allow third-party transcript translation")!.props.onValueChange(true));
    await typeInto(root, "password", "secret typed Native proof");
    await act(async () => emitAppState("active")); expect(inputByPlaceholder(root, "password").props.value).toBe("secret typed Native proof");
    await act(async () => emitAppState(state)); await flush(); expect(textOf(root)).not.toContain("Confirm with password"); expect(api.setLlmConsent).not.toHaveBeenCalled();
  });
  it("shows a custom saved reminder minute with two digits and its selected accessibility state", async () => {
    const reminders = await import("../../src/reminders"); await reminders.setReminderEnabled("user-1", true); await reminders.setReminderTime("user-1", 6, 7);
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); expect(textOf(root)).toContain("6:07");
    const chip = root.root.findAll(n => n.props.accessibilityRole === "radio" && n.props.accessibilityLabel?.includes("6:07"))[0]!;
    expect(chip.props.accessibilityState.selected).toBe(true);
  });
});

describe("Settings durable preference and upgrade result contracts", () => {
  it.each(["daily-enabled", "daily-time", "measure-enabled", "measure-interval"] as const)("a native %s write refusal preserves the displayed saved preference", async kind => {
    reminderCapability.mockReturnValue({ available: true });
    const daily = await import("../../src/reminders"), measure = await import("../../src/measureReminders");
    if (kind === "daily-time") await daily.setReminderEnabled("user-1", true);
    if (kind === "measure-interval") await measure.setMeasureReminderEnabled("user-1", true);
    const slot = kind.startsWith("daily") ? "@mindpattern/reminders_user-1" : "@mindpattern/measure_reminders_user-1";
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    const saved = await storage.getItem(slot), nativeWrite = storage.setItem.bind(storage);
    const write = vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { if (key === slot) throw new Error("Native preference write unavailable"); await nativeWrite(key, value); });
    Alert.alert.mockClear();
    try {
      if (kind.endsWith("enabled")) await act(async () => switchByA11y(root, kind.startsWith("daily") ? "Daily reminder" : "Check-in reminders").props.onValueChange(true));
      else await pressLabel(root, kind === "daily-time" ? "Morning" : "2 weeks");
      await flush();
      expect(lastAlert().slice(0, 2)).toEqual(["Could not save", "The reminder preference wasn't saved — try again."]);
      expect(await storage.getItem(slot)).toBe(saved);
      if (kind.endsWith("enabled")) expect(switchByA11y(root, kind.startsWith("daily") ? "Daily reminder" : "Check-in reminders").props.value).toBe(false);
      else {
        const label = kind === "daily-time" ? "Evening" : "4 weeks";
        expect(root.root.findAll(n => n.props.accessibilityRole === "radio" && String(n.props.accessibilityLabel).includes(label)).some(n => n.props.accessibilityState.selected)).toBe(true);
      }
    } finally { write.mockRestore(); await act(async () => root.unmount()); }
  });

  const upgradeCases = [
    [{ ok: true, already: false }, "Key protection upgraded", "Your journal is unchanged and still opens as before. From now on, changing your password no longer re-encrypts it.", false],
    [{ ok: true, already: true }, "Already upgraded", "This account already uses the newer key protection. Nothing needed to change.", false],
    [{ ok: false, stage: "upgrade", reason: "wrong-password" }, "That password didn't match", "Check it and try again — nothing was changed.", true],
    [{ ok: false, stage: "upgrade", reason: "session-expired" }, "Session expired", "Please unlock again.", false],
    [{ ok: false, stage: "upgrade", reason: "key-mismatch" }, "Could not upgrade key protection", "The encryption key on this device does not match the data stored on the server, so nothing was changed. Lock the app and unlock it again with your current password first, then retry.", false],
    [{ ok: false, stage: "verify", reason: "offline" }, "Could not upgrade key protection", "Cannot verify your password offline right now — try again when online.", false],
    [{ ok: false, stage: "verify", reason: "server" }, "Could not upgrade key protection", "Something went wrong — try again.", false],
    [{ ok: false, stage: "wrap", reason: "server", detail: "The native wrapping provider could not finish" }, "Could not upgrade key protection", "The native wrapping provider could not finish", false],
  ] as const;
  it.each(upgradeCases)("displays the acknowledged upgrade outcome %j and preserves its retry state", async (outcome, title, body, retry) => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    upgradeKeyProtectionMock.mockResolvedValueOnce(outcome);
    await pressLabel(root, "Upgrade now"); await typeInto(root, "password", "typed password for Native upgrade"); await pressLabel(root, "Confirm with password"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual([title, body]); expect(textOf(root).includes("Confirm with password")).toBe(retry);
    expect(upgradeKeyProtectionMock).toHaveBeenCalledWith({ username: "alice", userId: "user-1", password: "typed password for Native upgrade", verifierB64: authKeyB64() });
    if (retry) expect(inputByPlaceholder(root, "password").props.value).toBe("");
    if (outcome.ok) expect(textOf(root)).not.toContain("Upgrade key protection");
    await act(async () => root.unmount());
  });

  it.each(["upgrade", "rotation"] as const)("a missing native saved username stops %s with the account recovery message", async action => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    vi.mocked(api.getUsername).mockResolvedValueOnce(null);
    upgradeKeyProtectionMock.mockClear(); rotatePasswordMock.mockClear();
    if (action === "upgrade") { await pressLabel(root, "Upgrade now"); await typeInto(root, "password", "typed Native proof"); await pressLabel(root, "Confirm with password"); }
    else { await pressLabel(root, "Change password"); await typeInto(root, "password", "old Native proof"); await typeInto(root, "New password (12+ characters)", "a strong new passphrase 42!"); await pressLabel(root, "Rotate keys and sign in again"); }
    await flush(); expect(lastAlert()[0]).toBe("No saved account on this device — sign in again.");
    expect(upgradeKeyProtectionMock).not.toHaveBeenCalled(); expect(rotatePasswordMock).not.toHaveBeenCalled();
    if (action === "upgrade") expect(textOf(root)).toContain("Confirm with password");
    await act(async () => root.unmount());
  });
});

describe("Settings native saved-recording completion and recovery visibility", () => {
  async function savedRecording() {
    const { enqueueAudio } = await import("../../src/audioQueue"), { encryptAudio } = await import("../../src/crypto/journalCrypto");
    await enqueueAudio({ userId: "user-1", clientEntryId: "visible-native-recording", ...encryptAudio({ dataKey: vault.get().dataKey }, "user-1", "visible-native-recording", Buffer.from("native recorded private speech")), mime: "audio/m4a", durationSeconds: 5 });
  }
  it("a native retry acknowledgement removes the recording from the visible saved list", async () => {
    await savedRecording(); const root = await render(<SettingsScreen navigation={nav} />); await flush(); expect(textOf(root)).toContain("1 encrypted recordings saved");
    await pressLabel(root, "Retry saved recordings"); await flush(); expect(textOf(root)).not.toContain("1 encrypted recordings saved");
    expect(api.uploadAudioAttachment).toHaveBeenCalledWith("visible-native-recording", expect.any(String), "audio/m4a", 5, expect.any(String), expect.any(Object));
    await act(async () => root.unmount());
  });
  it("a corrupted native recording is displayed with an unavailable date and retained for repair", async () => {
    await savedRecording(); const slot = (await storage.getAllKeys()).find(key => key.endsWith(":visible-native-recording"))!; await storage.setItem(slot, "unreadable native descriptor");
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    expect(textOf(root)).toContain("Recording 1 · date unavailable"); expect(textOf(root)).toContain("1 encrypted recordings saved on this device; 1 need attention");
    expect(textOf(root)).toContain("Upload needs attention. Retry, export an encrypted copy, or remove it when you are ready.");
    await pressLabel(root, "Export encrypted recording 1"); await flush(); expect(lastAlert().slice(0, 2)).toEqual(["Export failed", "This saved recording could not be read"]);
    expect(await storage.getItem(slot)).toBe("unreadable native descriptor"); await act(async () => root.unmount());
  });
  it("the native removal failure keeps the saved recording and displays the local recovery message", async () => {
    await savedRecording(); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    const files = await import("../helpers/expoFsMock"); files.deleteAsync.mockRejectedValueOnce(new Error("Native saved recording is still in use"));
    await pressLabel(root, "Remove saved recording 1"); await pressAlertButton("Remove recording"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual(["Could not retry", "Native saved recording is still in use"]); expect(textOf(root)).toContain("1 encrypted recordings saved");
    await act(async () => root.unmount());
  });
  it("a removal confirmation cannot delete the newer recording replacing its displayed revision", async () => {
    await savedRecording(); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    await pressLabel(root, "Remove saved recording 1"); await savedRecording(); await pressAlertButton("Remove recording"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual(["Could not retry", "The saved recording changed; refresh before removing it"]);
    const { listSavedAudio } = await import("../../src/audioQueue"); expect(await listSavedAudio("user-1")).toHaveLength(1); await act(async () => root.unmount());
  });
  it.each([null, "different-native-account"])("an export with native saved identity %s reports the damaged session before touching any recording", async owner => {
    await savedRecording(); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    const sharing = await import("../helpers/expoSharingMock"); sharing.shareAsync.mockClear();
    vi.mocked(api.getUserId).mockResolvedValueOnce(owner);
    await pressLabel(root, "Export encrypted recording 1"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual(["Export failed", "Session damaged"]); expect(sharing.shareAsync).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("1 encrypted recordings saved"); await act(async () => root.unmount());
  });
  it.each(["ios", "android"])("the %s recovery disclosure uses its native font and is cleared by navigation blur", async platform => {
    const previous = Platform.OS; Object.assign(Platform, { OS: platform });
    const { engine } = await import("../helpers/nodeEngine"); const entropy = vi.spyOn(engine, "randomBytes").mockImplementation(size => Buffer.alloc(size, 9));
    let blur!: () => void; const unsubscribe = vi.fn(); const navigation = { ...nav, addListener: vi.fn((event: string, listener: () => void) => { if (event === "blur") blur = listener; return unsubscribe; }) };
    let root: Awaited<ReturnType<typeof render>> | undefined;
    try {
      root = await render(<SettingsScreen navigation={navigation} />); await flush(); await pressLabel(root, "Create recovery kit"); await reauth(root);
      expect(textOf(root)).toContain("mindpattern-recovery:v2:");
      const key = root.root.findAllByType((await import("react-native")).Text).find(node => node.props.selectable && String(node.props.children).startsWith("mindpattern-recovery:v2:"))!;
      expect(key.props.style.fontFamily).toBe(platform === "ios" ? "Menlo" : "monospace");
      await act(async () => blur()); await flush(); expect(textOf(root)).not.toContain("mindpattern-recovery:v2:");
      await act(async () => root!.unmount()); root = undefined; expect(unsubscribe).toHaveBeenCalledOnce();
    } finally { if (root) await act(async () => root!.unmount()); entropy.mockRestore(); Object.assign(Platform, { OS: previous }); }
  });
});

describe("Settings native biometric persistence failures", () => {
  it("a refused native biometric write keeps the switch off and explains that nothing was stored", async () => {
    const controls = await import("../helpers/keychainMock"); controls.__setBiometryType("FaceID");
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    controls.__failWrites(true);
    try {
      await act(async () => switchByA11y(root, "Biometric unlock").props.onValueChange(true)); await pressAlertButton("Enable"); await reauth(root);
      expect(lastAlert().slice(0, 2)).toEqual(["Could not turn on", "Nothing was stored — your password keeps working."]);
      expect(switchByA11y(root, "Biometric unlock").props.value).toBe(false);
      expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toBe(false);
    } finally { controls.__failWrites(false); await act(async () => root.unmount()); }
  });
  it("a refused native biometric removal preserves the enabled wrap and its visible switch", async () => {
    keychainMock.__setBiometryType("FaceID"); const { enableBiometricUnlock } = await import("../../src/biometricUnlock"); await enableBiometricUnlock("user-1", vault.get().dataKey);
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    const remove = vi.spyOn(Keychain, "resetGenericPassword").mockRejectedValueOnce(new Error("Native biometric item is temporarily unavailable"));
    try {
      await act(async () => switchByA11y(root, "Biometric unlock").props.onValueChange(false)); await flush();
      expect(lastAlert().slice(0, 2)).toEqual(["Could not turn off", "Try again — your password keeps working either way."]);
      expect(switchByA11y(root, "Biometric unlock").props.value).toBe(true);
      expect(await Keychain.getGenericPassword({ service: "com.mindpattern.biometric-unlock.v1.user-1" })).toEqual({ username: "user-1", password: keys.dataKey.toString("base64") });
    } finally { remove.mockRestore(); await act(async () => root.unmount()); }
  });
  it("an absent native account after the password proof preserves the retry card for biometric enablement", async () => {
    keychainMock.__setBiometryType("FaceID"); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    await act(async () => switchByA11y(root, "Biometric unlock").props.onValueChange(true)); await pressAlertButton("Enable"); await typeInto(root, "password", "Native biometric proof");
    vi.mocked(api.getUserId).mockResolvedValueOnce(null); await pressLabel(root, "Confirm with password"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual(["Could not verify", "No saved account on this device — sign in again."]);
    expect(textOf(root)).toContain("Confirm with password"); expect(inputByPlaceholder(root, "password").props.value).toBe(""); expect(switchByA11y(root, "Biometric unlock").props.value).toBe(false);
    await act(async () => root.unmount());
  });
});

describe("Settings native recovery-key custody", () => {
  it.each(["status-pending", "setup-failure"] as const)("erases actual native provider-held recovery allocations after %s", async phase => {
    const { engine } = await import("../helpers/nodeEngine");
    const entropy = vi.spyOn(engine, "randomBytes").mockImplementation(size => Buffer.alloc(size, 9));
    const hkdf = engine.hkdfSync.bind(engine), heldInputs: Buffer[] = [], heldOutputs: ArrayBuffer[] = [];
    const provider = vi.spyOn(engine, "hkdfSync").mockImplementation((digest, input, salt, info, size) => {
      heldInputs.push(input); const derived = hkdf(digest, input, salt, info, size); heldOutputs.push(derived as ArrayBuffer); return derived;
    });
    let release!: () => void, entered = false;
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    if (phase === "setup-failure") vi.mocked(api.setupRecoveryKit).mockRejectedValueOnce(new Error("Native recovery upload failed"));
    else vi.mocked(api.recoveryStatus).mockImplementationOnce(async () => { entered = true; await new Promise<void>(resolve => { release = resolve; }); return { enabled: true, set_at: "2026-10-01" } as never; });
    try {
      await pressLabel(root, "Create recovery kit"); await typeInto(root, "password", "typed Native recovery proof");
      await firePress(root, "Confirm with password"); await flush();
      expect(heldInputs).toHaveLength(2); expect(heldOutputs).toHaveLength(2);
      for (const allocation of heldInputs) expect(allocation.every(byte => byte === 0)).toBe(true);
      for (const allocation of heldOutputs) expect(new Uint8Array(allocation).every(byte => byte === 0)).toBe(true);
      if (phase === "status-pending") { expect(entered).toBe(true); expect(textOf(root)).toContain("mindpattern-recovery:v2:"); }
      else { expect(textOf(root)).not.toContain("mindpattern-recovery:v2:"); expect(lastAlert()[1]).toContain("could not be created"); }
    } finally {
      if (release) await act(async () => release()); await flush(); await act(async () => root.unmount()); provider.mockRestore(); entropy.mockRestore();
    }
  });
});

describe("Settings native permission, dialog, and acknowledged cleanup boundaries", () => {
  it("a native Health permission failure preserves the preference and explains the denied access", async () => {
    healthKitCapability.mockReturnValue({ available: true }); ensureStateOfMindWriteAccess.mockRejectedValueOnce(new Error("Native Health authorization failed"));
    const root = await render(<SettingsScreen navigation={nav} />); await flush();
    await act(async () => switchByA11y(root, "Mirror mood check-ins to the Health app").props.onValueChange(true)); await flush();
    expect(await (await import("../../src/healthkit")).getMoodMirrorPref("user-1")).toBe(true); expect(switchByA11y(root, "Mirror mood check-ins to the Health app").props.value).toBe(true);
    expect(lastAlert().slice(0, 2)).toEqual(["Health access not granted", "The Health app hasn't granted write access. You can change that in the Health app's privacy settings; the preference stays saved and nothing else changes."]);
    await act(async () => root.unmount());
  });
  it("a missing identity while retrying displayed entries gives the sign-in instruction", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(2); const root = await render(<SettingsScreen navigation={nav} />); await flush(); vi.mocked(api.getUserId).mockResolvedValueOnce(null);
    await pressLabel(root, "Try syncing them again"); await flush(); expect(lastAlert().slice(0, 2)).toEqual(["Sign in required", "Sign in again before retrying saved entries."]); expect(textOf(root)).toContain("2 entries"); await act(async () => root.unmount());
  });
  it("the legacy recovery disclosure renders when an older native queue is detected", async () => {
    vi.mocked((await import("../../src/offlineQueue")).hasLegacyQueueRecovery).mockResolvedValueOnce(true); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    expect(textOf(root)).toContain("Older offline entries need recovery"); expect(root.root.findAll(node => node.props.accessibilityRole === "alert").length).toBeGreaterThan(0); await act(async () => root.unmount());
  });
  it("a full server recovery timestamp is displayed as its calendar date", async () => {
    vi.mocked(api.recoveryStatus).mockResolvedValue({ enabled: true, set_at: "2026-10-01T17:45:00Z" } as never); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    expect(textOf(root)).toContain("2026-10-01"); expect(textOf(root)).not.toContain("T17:45:00Z"); await act(async () => root.unmount());
  });
  it("a refused recovery-kit removal keeps the enabled kit and gives a retry explanation", async () => {
    vi.mocked(api.recoveryStatus).mockResolvedValue({ enabled: true, set_at: "2026-10-01" } as never); vi.mocked(api.removeRecoveryKit).mockRejectedValueOnce(new Error("Native connection was lost"));
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); await pressLabel(root, "Remove kit"); await reauth(root);
    expect(lastAlert().slice(0, 2)).toEqual(["Recovery kit", "The kit could not be removed — try again."]); expect(textOf(root)).toContain("2026-10-01"); expect(textOf(root)).toContain("Remove kit"); await act(async () => root.unmount());
  });
  it("an acknowledged upgrade selects the newer password-change disclosure", async () => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    upgradeKeyProtectionMock.mockResolvedValueOnce({ ok: true, already: false }); await pressLabel(root, "Upgrade now"); await reauth(root); await pressLabel(root, "Change password"); await flush();
    expect(textOf(root)).toContain("Change password and sign in again"); expect(textOf(root)).not.toContain("Rotate keys and sign in again"); await act(async () => root.unmount());
  });
  it("a legacy rotation without failed grants omits the re-pairing warning", async () => {
    vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: SALT_B64, kdf_params: null, wrapped_data_key: null } as never); const root = await render(<SettingsScreen navigation={nav} />); await flush();
    rotatePasswordMock.mockResolvedValueOnce({ ok: true, scheme: "v1", rewrapFailures: [], sessionScope: (await import("../../src/localWriteGuard")).localWriteScopeEpoch() });
    await pressLabel(root, "Change password"); await typeInto(root, "password", "old Native proof"); await typeInto(root, "New password (12+ characters)", "a strong new passphrase 42!"); await pressLabel(root, "Rotate keys and sign in again"); await flush();
    expect(lastAlert().slice(0, 2)).toEqual(["Password changed", "Your journal is now encrypted under your new password. Sign in again on this device and on any other device you use.\n\nA legacy data-key change invalidates the previous recovery kit. Create and save a new recovery kit after signing in."]); await act(async () => root.unmount());
  });
  it("native destructive confirmations distinguish cancellation from deletion", async () => {
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); await pressLabel(root, "Delete my account and data");
    expect(lastAlert()[2].map(({ text, style }: { text: string; style?: string }) => ({ text, style }))).toEqual([{ text: "Cancel", style: "cancel" }, { text: "Continue", style: "destructive" }]); await pressAlertButton("Continue");
    expect(lastAlert()[2].map(({ text, style }: { text: string; style?: string }) => ({ text, style }))).toEqual([{ text: "Cancel", style: "cancel" }, { text: "Continue to password", style: "destructive" }]); await act(async () => root.unmount());
  });
  it("the native biometric explanation gives cancellation its native role", async () => {
    keychainMock.__setBiometryType("FaceID"); const root = await render(<SettingsScreen navigation={nav} />); await flush(); await act(async () => switchByA11y(root, "Biometric unlock").props.onValueChange(true)); await flush();
    expect(lastAlert()[2].map(({ text, style }: { text: string; style?: string }) => ({ text, style }))).toEqual([{ text: "Cancel", style: "cancel" }, { text: "Enable", style: undefined }]); await act(async () => root.unmount());
  });
  it("the replacement recovery confirmation marks its native cancel button", async () => {
    vi.mocked(api.recoveryStatus).mockResolvedValue({ enabled: true, set_at: "2026-10-01" } as never); const root = await render(<SettingsScreen navigation={nav} />); await flush(); await pressLabel(root, "Replace kit key");
    expect(lastAlert()[2].map(({ text, style }: { text: string; style?: string }) => ({ text, style }))).toEqual([{ text: "Cancel", style: "cancel" }, { text: "Replace kit key", style: undefined }]); await act(async () => root.unmount());
  });
  it.each(["native inventory", "sign-out"] as const)("confirmed server deletion reports incomplete %s cleanup", async failure => {
    const root = await render(<SettingsScreen navigation={nav} />); await flush(); const nativeInventory = failure === "native inventory" ? vi.spyOn(storage, "getAllKeys").mockRejectedValue(new Error("Native storage unavailable")) : null;
    if (failure === "sign-out") signOut.mockRejectedValueOnce(new Error("Native credential cleanup unavailable"));
    try { await pressLabel(root, "Delete my account and data"); await pressAlertButton("Continue"); await pressAlertButton("Continue to password"); await reauth(root);
      expect(lastAlert()[0]).toBe("Deleted"); expect(lastAlert()[1]).toContain("Your server account is deleted. Some device cleanup remains; Fathom will retry it on the next start."); expect(vault.isUnlocked()).toBe(false);
    } finally { nativeInventory?.mockRestore(); await act(async () => root.unmount()); }
  });
});
