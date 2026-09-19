/**
 * Node-test replacement for react-native-keychain. Production imports the
 * native module; this mock intentionally keeps the device key out of the
 * AsyncStorage mock so tests exercise the same custody boundary.
 */
const credentials = new Map<string, { username: string; password: string }>();
let failWrites = false;

export const ACCESSIBLE = {
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: "AccessibleWhenUnlockedThisDeviceOnly",
} as const;

export async function getGenericPassword(options?: { service?: string }): Promise<false | { username: string; password: string }> {
  return credentials.get(options?.service ?? "") ?? false;
}

export async function setGenericPassword(
  username: string,
  password: string,
  options?: { service?: string },
): Promise<false | { service: string }> {
  const service = options?.service ?? "";
  if (failWrites) return false; // the real module's failure contract
  credentials.set(service, { username, password });
  return { service };
}

export async function resetGenericPassword(options?: { service?: string }): Promise<boolean> {
  return credentials.delete(options?.service ?? "");
}

/** Force setGenericPassword to report failure, as the native module does
 * when the keystore rejects the write. Cleared by __reset. */
export function __failWrites(value: boolean): void {
  failWrites = value;
}

export function __reset(): void {
  credentials.clear();
  failWrites = false;
}
