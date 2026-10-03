/** Protected credential reads prompt even without an accessControl option.
 * Presence checks use native metadata APIs; only an explicit unlock reads keys. */
import * as Keychain from "react-native-keychain";
import AsyncStorage from "@react-native-async-storage/async-storage";
const SERVICE = "com.mindpattern.biometric-unlock.v1";
const serviceFor = (userId: string): string => `${SERVICE}.${userId}`;
const legacyDisabled = (userId: string): string => `@mindpattern/biometric.legacy-disabled.${userId}`;
const authenticatedLegacyOwners = new Set<string>();
async function exists(service: string): Promise<boolean> {
  try { return await Keychain.hasGenericPassword({ service }); } catch { return false; }
}
async function legacyAllowed(userId: string): Promise<boolean> {
  try { return (await AsyncStorage.getItem(legacyDisabled(userId))) !== "1"; } catch { return false; }
}
export async function biometricsSupported(): Promise<boolean> {
  try { return (await Keychain.getSupportedBiometryType()) !== null; } catch { return false; }
}
export async function enableBiometricUnlock(userId: string, dataKey: Buffer): Promise<void> {
  if (dataKey.length !== 32) throw new Error("Invalid biometric data key");
  const result = await Keychain.setGenericPassword(userId, dataKey.toString("base64"), {
    service: serviceFor(userId), accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
  });
  if (!result) throw new Error("biometric secure storage rejected the data-key wrap");
  await AsyncStorage.setItem(legacyDisabled(userId), "1");
  if (authenticatedLegacyOwners.has(userId)) await Keychain.resetGenericPassword({ service: SERVICE });
}
export async function disableBiometricUnlock(userId: string): Promise<void> {
  // A legacy slot cannot be attributed without authenticating. Suppress its
  // fallback for this account without reading/deleting another owner's key.
  await AsyncStorage.setItem(legacyDisabled(userId), "1");
  await Keychain.resetGenericPassword({ service: serviceFor(userId) });
  if (authenticatedLegacyOwners.has(userId)) {
    await Keychain.resetGenericPassword({ service: SERVICE });
    authenticatedLegacyOwners.delete(userId);
  }
}
export async function hasBiometricUnlock(userId: string): Promise<boolean> {
  return (await exists(serviceFor(userId))) || ((await legacyAllowed(userId)) && (await exists(SERVICE)));
}
export async function unwrapBiometricDataKey(userId: string): Promise<Buffer | null> {
  const service = (await exists(serviceFor(userId))) ? serviceFor(userId)
    : ((await legacyAllowed(userId)) && (await exists(SERVICE))) ? SERVICE : null;
  if (!service) return null;
  try {
    const creds = await Keychain.getGenericPassword({ service, accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET });
    if (!creds || creds.username !== userId || !/^[A-Za-z0-9+/]{43}=$/.test(creds.password)) return null;
    const key = Buffer.from(creds.password, "base64");
    if (key.length !== 32) { key.fill(0); return null; }
    if (service === SERVICE) authenticatedLegacyOwners.add(userId);
    return key;
  } catch { return null; }
}
