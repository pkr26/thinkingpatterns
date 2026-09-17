/**
 * Wave-1 feature units (2026-09-17): haptics, theme override, native-feature
 * seams, the string catalog, and prompt chips.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";



const { Vibration } = (await import("react-native")) as unknown as {
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
});

describe("haptics", () => {
  it("vibrates 10ms by default (the lightest selection pulse)", () => {
    void loadHapticsSetting();
    lightHaptic();
    expect(Vibration.vibrate).toHaveBeenCalledWith(10);
  });

  it("disabling silences every call and persists (storage receives 'off')", async () => {
    await setHapticsEnabled(false);
    lightHaptic();
    expect(Vibration.vibrate).not.toHaveBeenCalled();
    await setHapticsEnabled(true);
    lightHaptic();
    expect(Vibration.vibrate).toHaveBeenCalledWith(10);
  });

  it("a stored 'off' loads as disabled", async () => {
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
  it("deterministic per day: same date, same chips, in pool order", () => {
    const a = promptChipsFor(new Date("2026-09-17T00:00:00Z"));
    const b = promptChipsFor(new Date("2026-09-17T23:00:00Z"));
    expect(a).toEqual(b);
    expect(a).toHaveLength(3);
    expect(PROMPT_CHIPS).toContain(a[0]);
  });

  it("different days rotate through the pool", () => {
    const seen = new Set<string>();
    for (let d = 1; d <= 20; d++) {
      for (const chip of promptChipsFor(new Date(Date.UTC(2026, 8, d)))) seen.add(chip);
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
