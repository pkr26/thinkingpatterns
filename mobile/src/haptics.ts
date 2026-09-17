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
 *    never crash a save. 10ms is the lightest iOS selection pulse.
 */
import { Vibration } from "react-native";
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
    Vibration.vibrate(10);
  } catch {
    // Unsupported platform or permission: silence is fine.
  }
}
