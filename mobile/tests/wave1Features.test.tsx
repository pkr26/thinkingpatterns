/**
 * Wave-1 feature units (2026-09-17): haptics, theme override, native-feature
 * seams, the string catalog, and prompt chips.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";



const { Platform, Vibration } = (await import("react-native")) as unknown as {
  Platform: { OS: string };
  Vibration: { vibrate: (ms: number) => void };
};

const { lightHaptic, loadHapticsSetting, setHapticsEnabled } = await import("../src/haptics");
const { t } = await import("../src/strings");
const { promptChipsFor, PROMPT_CHIPS } = await import("../src/promptChips");
const { reminderCapability, biometricCapability } = await import("../src/nativeFeatures");

const storage = (await import("./helpers/storageMock")).default;

beforeEach(() => {
  storage.__reset();
  vi.clearAllMocks();
  Platform.OS = "ios"; // the rnMock default; haptics tests flip it per case
});

describe("haptics", () => {
  it("Android: vibrates 10ms by default (the lightest selection pulse)", () => {
    Platform.OS = "android";
    void loadHapticsSetting();
    lightHaptic();
    expect(Vibration.vibrate).toHaveBeenCalledWith(10);
  });

  it("L-71: iOS stays silent — the core API's fixed ~400ms buzz is the opposite of quiet haptics", () => {
    Platform.OS = "ios";
    void loadHapticsSetting();
    lightHaptic();
    // Duration is IGNORED on iOS (always ~400ms), so the sensory-anxious
    // direction is silence until a real haptics module is linked.
    expect(Vibration.vibrate).not.toHaveBeenCalled();
  });

  it("disabling silences every call and persists (storage receives 'off')", async () => {
    Platform.OS = "android";
    await setHapticsEnabled(false);
    lightHaptic();
    expect(Vibration.vibrate).not.toHaveBeenCalled();
    await setHapticsEnabled(true);
    lightHaptic();
    expect(Vibration.vibrate).toHaveBeenCalledWith(10);
  });

  it("a stored 'off' loads as disabled", async () => {
    Platform.OS = "android";
    await storage.setItem("@mindpattern/haptics.enabled", "off");
    expect(await loadHapticsSetting()).toBe(false);
  });
});

describe("strings catalog", () => {
  it("every crisis key resolves to non-empty copy (safety-critical: no key bleed)", () => {
    for (const key of [
      "crisis.title", "crisis.call988", "crisis.call988.detail", "crisis.call988.fallback",
      "crisis.text741741", "crisis.emergency", "crisis.emergency.detail", "crisis.findhelpline",
    ] as const) {
      const value = t(key);
      expect(value.length).toBeGreaterThan(8);
      expect(value).not.toContain("crisis.");
    }
  });

  it("the 988 fallback copy states free + 24/7 (safe-messaging tone)", () => {
    const copy = t("crisis.call988.fallback");
    expect(copy).toMatch(/free/i);
    expect(copy).toMatch(/24\/7/);
  });
});

describe("prompt chips", () => {
  it("deterministic per LOCAL calendar day: same local day, same chips, in pool order (L-70)", () => {
    // Local-calendar fields, so the assertion holds on any runner timezone.
    const earlyMorning = new Date(2026, 8, 17, 0, 30);
    const lateEvening = new Date(2026, 8, 17, 23, 30);
    const a = promptChipsFor(earlyMorning);
    const b = promptChipsFor(lateEvening);
    expect(a).toEqual(b);
    expect(a).toHaveLength(3);
    expect(PROMPT_CHIPS).toContain(a[0]);
  });

  it("E-3 (2026-09-21): the chips localize — es serves the Spanish pool, position-parity", async () => {
    const { PROMPT_CHIPS_ES } = await import("../src/promptChips");
    expect(PROMPT_CHIPS_ES.length).toBe(PROMPT_CHIPS.length);
    const day = new Date(2026, 8, 17, 12, 0);
    const en = promptChipsFor(day);
    const es = promptChipsFor(day, 3, "es");
    expect(es).toHaveLength(3);
    for (const chip of es) {
      expect(PROMPT_CHIPS_ES).toContain(chip);
      expect(PROMPT_CHIPS).not.toContain(chip);
    }
    // Parity of position: chip j of each locale sits at the same pool index.
    for (let j = 0; j < en.length; j++) {
      expect(PROMPT_CHIPS_ES.indexOf(es[j]!)).toBe(PROMPT_CHIPS.indexOf(en[j]!));
    }
    // Deterministic within the day for es too.
    expect(promptChipsFor(new Date(2026, 8, 17, 23, 30), 3, "es")).toEqual(es);
  });

  it("L-70: the chips rotate at LOCAL midnight, not UTC midnight", () => {
    // Two instants inside the same UTC day can be different LOCAL days
    // (the pre-fix bug: rotation happened at the UTC boundary).
    const beforeMidnight = new Date(2026, 8, 17, 23, 59);
    const afterMidnight = new Date(2026, 8, 18, 0, 1);
    expect(promptChipsFor(beforeMidnight)).not.toEqual(promptChipsFor(afterMidnight));
  });

  it("different days rotate through the pool", () => {
    const seen = new Set<string>();
    for (let d = 1; d <= 20; d++) {
      for (const chip of promptChipsFor(new Date(2026, 8, d))) seen.add(chip);
    }
    expect(seen.size).toBeGreaterThan(6);
  });
});

describe("native-feature seams", () => {
  it("both capabilities degrade to unavailable without their native modules", () => {
    expect(reminderCapability().available).toBe(false);
    expect(reminderCapability().reason).toContain("notification module");
    expect(biometricCapability().available).toBe(false);
    expect(biometricCapability().reason).toContain("biometric module");
  });
});
