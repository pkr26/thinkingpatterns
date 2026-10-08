/** Observe the Native vibration provider and actual saved preference,
 * including a retired startup read and native write/read failures. */
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { Platform, Vibration } from "react-native";
import storage from "./helpers/storageMock";
import { lightHaptic, loadHapticsSetting, setHapticsEnabled, hapticsEnabled } from "../src/haptics";
const key = "@mindpattern/haptics.enabled"; let pulses: unknown[];
const originalPlatform = Platform.OS;
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); pulses = []; Object.defineProperty(Platform, "OS", { configurable: true, value: "android" }); vi.mocked(Vibration.vibrate).mockImplementation(value => { pulses.push(value); }); });
afterEach(async () => { vi.restoreAllMocks(); Object.defineProperty(Platform, "OS", { configurable: true, value: originalPlatform }); await setHapticsEnabled(true); });
it("cold Native Android feedback uses the advertised ten-millisecond tap before startup reading", () => { lightHaptic(); expect(pulses).toEqual([10]); });
it.each([null, "on", "off", "unexpected"])("Native stored preference %j drives actual Android feedback", async value => {
  if (value !== null) await storage.setItem(key, value); expect(await loadHapticsSetting()).toBe(value !== "off");
  expect(hapticsEnabled()).toBe(value !== "off"); lightHaptic(); expect(pulses).toEqual(value === "off" ? [] : [10]);
});
it.each([true, false])("Native saving %s preserves the actual disk and physical feedback choice", async enabled => {
  await setHapticsEnabled(enabled); expect(await storage.getItem(key)).toBe(enabled ? "on" : "off"); lightHaptic(); expect(pulses).toEqual(enabled ? [10] : []);
});
it("a failed Native preference write preserves the effective current opt-out", async () => {
  vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native preference writes unavailable")); await expect(setHapticsEnabled(false)).resolves.toBeUndefined(); expect(hapticsEnabled()).toBe(false); lightHaptic(); expect(pulses).toEqual([]);
});
it.each(["value", "failure"])("a held Native startup %s cannot revive an acknowledged opt-out", async outcome => {
  let release!: () => void, entered = false; const held = new Promise<void>(resolve => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementationOnce(async () => { entered = true; await held; if (outcome === "failure") throw new Error("Native read unavailable"); return "on"; });
  const pending = loadHapticsSetting(); expect(entered).toBe(true); await setHapticsEnabled(false); release(); expect(await pending).toBe(false); lightHaptic(); expect(pulses).toEqual([]);
});
it("an unavailable Native startup read uses the documented enabled default", async () => { await setHapticsEnabled(false); vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("Native read unavailable")); expect(await loadHapticsSetting()).toBe(true); lightHaptic(); expect(pulses).toEqual([10]); });
it("Native iOS does not substitute its longer vibration for the short tap", async () => { await setHapticsEnabled(true); Object.defineProperty(Platform, "OS", { configurable: true, value: "ios" }); lightHaptic(); expect(pulses).toEqual([]); });
it("Native vibration failure never interrupts the public tap operation", async () => { await setHapticsEnabled(true); vi.mocked(Vibration.vibrate).mockImplementationOnce(() => { throw new Error("Native vibrator unavailable"); }); expect(() => lightHaptic()).not.toThrow(); });
