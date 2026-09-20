/**
 * The HealthKit State of Mind seam in src/healthkit.ts (2026-09-19): the
 * capability probe fails closed to unavailable (the module is not linked
 * in this JS-only build, and a linked-but-too-old module gets its own
 * reason), the continuous [-1, 1] valence quantizes onto HealthKit's five
 * discrete levels with clamped bounds, writeStateOfMind is a quiet false
 * when the module is absent / access denied / the native call fails, and
 * the per-account mirrorMoodToHealth preference round-trips with the
 * reminders.ts hygiene (validated reads, per-account isolation, deletion
 * wipe). The module is injected through the seam's dynamic import exactly
 * the way tests/nativeFeatures.test.ts injects @notifee/react-native.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// The seam resolves the module through a dynamic import (require fails in
// a node build), which vi.mock intercepts — see probeAsync in healthkit.
const requestAuthorization = vi.fn(async () => true);
const getAuthorizationStatus = vi.fn(async () => ({ stateOfMind: 2 }));
const saveStateOfMind = vi.fn(async () => true);

vi.mock("react-native-health", () => ({
  default: { requestAuthorization, getAuthorizationStatus, saveStateOfMind },
}));

const {
  healthKitCapability,
  writeStateOfMind,
  ensureStateOfMindWriteAccess,
  stateOfMindKind,
  getMoodMirrorPref,
  setMoodMirrorPref,
  clearMoodMirrorPref,
  mirrorMoodCheckIn,
} = await import("../src/healthkit");
const storage = (await import("./helpers/storageMock")).default;

const PREF_KEY = (userId: string) => `@mindpattern/mirror_mood_to_health_${userId}`;

beforeEach(() => {
  storage.__reset();
  requestAuthorization.mockReset();
  requestAuthorization.mockResolvedValue(true);
  getAuthorizationStatus.mockReset();
  getAuthorizationStatus.mockResolvedValue({ stateOfMind: 2 });
  saveStateOfMind.mockReset();
  saveStateOfMind.mockResolvedValue(true);
});

describe("healthKitCapability (fail-closed)", () => {
  it("reads unavailable with an honest reason when the module is not linked (this build)", () => {
    // The sync require probe cannot resolve the module under a node test
    // build even with vi.mock registered (vi.mock intercepts import(),
    // not require()) — which is exactly the "not linked" production state.
    expect(healthKitCapability()).toEqual({
      available: false,
      reason: "health module not linked in this build",
    });
  });

  it("never throws for any caller — it is a plain synchronous record", () => {
    const cap = healthKitCapability();
    expect(typeof cap.available).toBe("boolean");
  });
});

describe("stateOfMindKind (valence → discrete level, PURE)", () => {
  // The five check-in picks (-1, -0.5, 0, 0.5, 1 — src/mood.ts) land on
  // HealthKit's five discrete levels one-to-one.
  it.each([
    [-1, "very_unpleasant"],
    [-0.5, "unpleasant"],
    [0, "neutral"],
    [0.5, "pleasant"],
    [1, "very_pleasant"],
  ] as const)("pick %i → %s", (valence, kind) => {
    expect(stateOfMindKind(valence)).toBe(kind);
  });

  it.each([
    [-5, "very_unpleasant"],
    [-1.0001, "very_unpleasant"],
    [5, "very_pleasant"],
    [1.0001, "very_pleasant"],
  ] as const)("out-of-range %i clamps to the end (%s)", (valence, kind) => {
    expect(stateOfMindKind(valence)).toBe(kind);
  });

  it("values between picks round to the nearer label (halves toward pleasant)", () => {
    expect(stateOfMindKind(-0.8)).toBe("very_unpleasant"); // -1.6 → -2
    expect(stateOfMindKind(-0.3)).toBe("unpleasant"); // -0.6 → -1
    expect(stateOfMindKind(0.25)).toBe("pleasant"); // 0.5 → 1 (half rounds up)
    expect(stateOfMindKind(0.3)).toBe("pleasant"); // 0.6 → 1
  });

  it("a non-finite valence is not a mood at all", () => {
    expect(stateOfMindKind(Number.NaN)).toBeNull();
    expect(stateOfMindKind(Number.POSITIVE_INFINITY)).toBeNull();
    expect(stateOfMindKind(Number.NEGATIVE_INFINITY)).toBeNull();
  });
});

describe("writeStateOfMind (module linked via the dynamic-import seam)", () => {
  it("quantizes and writes the sample with HealthKit's discrete valence", async () => {
    expect(await writeStateOfMind(-0.5, "2026-09-19")).toBe(true);
    expect(saveStateOfMind).toHaveBeenCalledTimes(1);
    expect(saveStateOfMind).toHaveBeenCalledWith({
      kind: "unpleasant",
      valence: -1,
      date: "2026-09-19",
    });
    // The ONLY scope ever passed asks for State of Mind WRITE — never read.
    expect(requestAuthorization).toHaveBeenCalledWith({ stateOfMind: { write: true } });
  });

  it("each of the five picks maps to its own discrete sample", async () => {
    const cases: Array<[number, string, number]> = [
      [-1, "very_unpleasant", -2],
      [1, "very_pleasant", 2],
      [0, "neutral", 0],
    ];
    for (const [valence, kind, level] of cases) {
      saveStateOfMind.mockClear();
      expect(await writeStateOfMind(valence, "2026-09-19")).toBe(true);
      expect(saveStateOfMind).toHaveBeenCalledWith({ kind, valence: level, date: "2026-09-19" });
    }
  });

  it("a non-finite valence declines to write (no authorization ask either)", async () => {
    expect(await writeStateOfMind(Number.NaN, "2026-09-19")).toBe(false);
    expect(requestAuthorization).not.toHaveBeenCalled();
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });

  it("an explicit authorization refusal (false) writes nothing and reports false", async () => {
    requestAuthorization.mockResolvedValue(false);
    expect(await writeStateOfMind(0.5, "2026-09-19")).toBe(false);
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });

  it("HealthKit's sharingDenied status reads as refusal even when the request resolves", async () => {
    // The HealthKit quirk the contract documents: requestAuthorization
    // resolves on denial too — only the status tells the truth.
    requestAuthorization.mockResolvedValue(true);
    getAuthorizationStatus.mockResolvedValue({ stateOfMind: 1 }); // sharingDenied
    expect(await writeStateOfMind(0.5, "2026-09-19")).toBe(false);
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });

  it("a notDetermined status fails TOWARD the write attempt (the save decides)", async () => {
    getAuthorizationStatus.mockResolvedValue({ stateOfMind: 0 });
    expect(await writeStateOfMind(0.5, "2026-09-19")).toBe(true);
    expect(saveStateOfMind).toHaveBeenCalledTimes(1);
  });

  it("a native save failure is a false, never a throw", async () => {
    saveStateOfMind.mockRejectedValue(new Error("HealthKit exploded"));
    expect(await writeStateOfMind(1, "2026-09-19")).toBe(false);
  });

  it("an authorization call failure is a false, never a throw", async () => {
    requestAuthorization.mockRejectedValue(new Error("no bridge"));
    expect(await writeStateOfMind(1, "2026-09-19")).toBe(false);
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });

  it("a save that answers false reports false (the bridge's own refusal)", async () => {
    saveStateOfMind.mockResolvedValue(false);
    expect(await writeStateOfMind(1, "2026-09-19")).toBe(false);
  });
});

describe("module ABSENT (this build)", () => {
  it("the write path is a quiet false when the module exposes no State of Mind API", async () => {
    // Simulate an unlinked (or pre-State-of-Mind) module: the dynamic
    // import resolves to something unusable for this seam.
    const health = (await import("react-native-health")) as unknown as {
      default: Record<string, unknown>;
    };
    const original = health.default.saveStateOfMind;
    delete health.default.saveStateOfMind;
    try {
      expect(await writeStateOfMind(0.5, "2026-09-19")).toBe(false);
      expect(await ensureStateOfMindWriteAccess()).toBe(false);
      expect(saveStateOfMind).not.toHaveBeenCalled();
    } finally {
      health.default.saveStateOfMind = original;
    }
  });
});

describe("ensureStateOfMindWriteAccess (Settings' toggle-on probe)", () => {
  it("grants when the module answers and the status is not denied", async () => {
    expect(await ensureStateOfMindWriteAccess()).toBe(true);
  });

  it("is a false on refusal, on status denial, and never throws on failure", async () => {
    requestAuthorization.mockResolvedValue(false);
    expect(await ensureStateOfMindWriteAccess()).toBe(false);
    requestAuthorization.mockResolvedValue(true);
    getAuthorizationStatus.mockResolvedValue({ stateOfMind: 1 });
    expect(await ensureStateOfMindWriteAccess()).toBe(false);
    requestAuthorization.mockRejectedValue(new Error("bridge gone"));
    expect(await ensureStateOfMindWriteAccess()).toBe(false);
  });
});

describe("the mirrorMoodToHealth preference (reminders.ts idiom)", () => {
  it("defaults OFF — the app never writes to Health unasked", async () => {
    expect(await getMoodMirrorPref("user-1")).toBe(false);
  });

  it("round-trips per account, and one account's opt-in is not another's", async () => {
    await setMoodMirrorPref("user-1", true);
    expect(await getMoodMirrorPref("user-1")).toBe(true);
    expect(await getMoodMirrorPref("user-2")).toBe(false);
    expect(await storage.getItem(PREF_KEY("user-1"))).toBe('{"enabled":true}');
    await setMoodMirrorPref("user-1", false);
    expect(await getMoodMirrorPref("user-1")).toBe(false);
  });

  it.each([
    ["garbage", "not JSON"],
    ['{"enabled":"yes"}', "wrong-typed flag"],
    ['{"hour":20}', "wrong shape"],
    ["null", "JSON null"],
  ])("a hostile/corrupt record (%s: %s) fails toward OFF", async (raw) => {
    await storage.setItem(PREF_KEY("user-1"), raw);
    expect(await getMoodMirrorPref("user-1")).toBe(false);
  });

  it("a throwing storage read still answers OFF instead of crashing the caller", async () => {
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("storage fault");
    }) as never;
    try {
      expect(await getMoodMirrorPref("user-1")).toBe(false);
    } finally {
      storage.getItem = original;
    }
  });

  it("clearMoodMirrorPref removes the record (and only that account's) — deletion hygiene", async () => {
    await setMoodMirrorPref("user-1", true);
    await setMoodMirrorPref("user-2", true);
    await clearMoodMirrorPref("user-1");
    expect(await storage.getItem(PREF_KEY("user-1"))).toBeNull();
    expect(await getMoodMirrorPref("user-1")).toBe(false);
    expect(await getMoodMirrorPref("user-2")).toBe(true);
  });
});

describe("mirrorMoodCheckIn (the entry save path's one call)", () => {
  it("pref OFF: a quiet false, and the native write path is never touched", async () => {
    expect(await mirrorMoodCheckIn("user-1", 0.5, "2026-09-19")).toBe(false);
    expect(requestAuthorization).not.toHaveBeenCalled();
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });

  it("pref ON: delegates the quantized write to the seam", async () => {
    await setMoodMirrorPref("user-1", true);
    expect(await mirrorMoodCheckIn("user-1", -1, "2026-09-19")).toBe(true);
    expect(saveStateOfMind).toHaveBeenCalledWith({
      kind: "very_unpleasant",
      valence: -2,
      date: "2026-09-19",
    });
  });

  it("a non-finite valence is refused even with the pref on", async () => {
    await setMoodMirrorPref("user-1", true);
    expect(await mirrorMoodCheckIn("user-1", Number.NaN, "2026-09-19")).toBe(false);
    expect(saveStateOfMind).not.toHaveBeenCalled();
  });
});
