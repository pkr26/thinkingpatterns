/**
 * Optional 10 ms feedback through React Native's Android Vibration API.
 * The persisted preference applies to all pulses; unsupported APIs fail
 * silently so feedback cannot interrupt a save.
 *
 * iOS ignores the requested duration and uses a longer system vibration.
 * It stays silent until a native short-pulse implementation is available.
 */
import { Platform, Vibration } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";

const HAPTICS_KEY = "@mindpattern/haptics.enabled";
let enabled = true;
let preferenceRevision = 0;

export async function loadHapticsSetting(): Promise<boolean> {
  const revision = preferenceRevision;
  try {
    const stored = await AsyncStorage.getItem(HAPTICS_KEY);
    if (revision === preferenceRevision) enabled = stored !== "off";
  } catch {
    if (revision === preferenceRevision) enabled = true;
  }
  return enabled;
}

export async function setHapticsEnabled(on: boolean): Promise<void> {
  preferenceRevision++;
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
    // Only Android honors the short duration; other platforms remain silent.
    if (Platform.OS !== "android") return;
    Vibration.vibrate(10);
  } catch {
    // Unsupported platform or permission: silence is fine.
  }
}
