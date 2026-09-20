/**
 * Quiet haptics (2026-09-17) — the app felt like a form, not a companion;
 * a 10ms selection pulse makes the check-in and the save land physically
 * without adding visual noise.
 *
 * Custody rules:
 *  - Vibration is a React Native CORE API (no native dependency to add).
 *  - OFF by setting: users who find haptics aversive (common in sensory
 *    anxiety) disable them once in Settings and every call becomes a no-op.
 *  - Fails silent everywhere: a missing/unsupported vibration API must
 *    never crash a save. 10ms is the lightest Android selection pulse.
 *  - iOS (audit L-71, 2026-09-20): the core Vibration API IGNORES the
 *    duration argument and always plays the fixed ~400ms system buzz —
 *    the exact opposite of "quiet haptics" for the sensory-anxious users
 *    this setting exists for. There is no short iOS pulse in the core
 *    API (it needs a native haptics module, e.g. UIImpactFeedbackGenerator).
 *    Until one is linked, iOS stays deliberately SILENT: nothing is
 *    better than the aversive buzz. The Settings toggle remains honest —
 *    it governs the Android pulse and any future iOS haptics module.
 */
import { Platform, Vibration } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";

const HAPTICS_KEY = "@mindpattern/haptics.enabled";
let enabled = true;
let loaded = false;

export async function loadHapticsSetting(): Promise<boolean> {
  try {
    const stored = await AsyncStorage.getItem(HAPTICS_KEY);
    enabled = stored !== "off";
  } catch {
    enabled = true;
  }
  loaded = true;
  return enabled;
}

export async function setHapticsEnabled(on: boolean): Promise<void> {
  enabled = on;
  try {
    await AsyncStorage.setItem(HAPTICS_KEY, on ? "on" : "off");
  } catch {
    // Persistence failure leaves the setting effective for this session.
  }
}

export function hapticsEnabled(): boolean {
  return enabled;
}

/** The one pulse the app uses: a 10ms tap. No patterns, no alerts. */
export function lightHaptic(): void {
  if (!enabled) return;
  try {
    // L-71: Android honors the 10ms duration; iOS would ignore it and buzz
    // the fixed ~400ms system vibration, so non-Android platforms stay
    // silent until a real haptics module is linked (see the header).
    if (Platform.OS !== "android") return;
    Vibration.vibrate(10);
  } catch {
    // Unsupported platform or permission: silence is fine.
  }
}
