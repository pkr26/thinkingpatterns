/**
 * Node-test replacement for react-native-keychain. Production imports the
 * native module; this mock intentionally keeps the device key out of the
 * AsyncStorage mock so tests exercise the same custody boundary.
 *
 * The biometric-unlock surface (2026-09-19) is mocked here too — same
 * approach as tests/secureStore.test.ts: the vitest alias routes every
 * `import "react-native-keychain"` (src and tests alike) to this module,
 * so one shared custody boundary is exercised instead of per-file vi.mocks.
 */
const credentials = new Map<string, { username: string; password: string }>();
let failWrites = false;
let failReads = false;
/** null = "no biometry enrolled/available" — the honest default in node. */
let biometryType: string | null = null;
/** Options seen on every getGenericPassword call (assert the prompt-forcing
 *  accessControl read vs the quiet metadata read). */
const getCalls: Array<{ service?: string; accessControl?: string }> = [];
/** username/options seen on every setGenericPassword call. */
const setCalls: Array<{ username: string; options?: Record<string, unknown> }> = [];

export const ACCESSIBLE = {
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: "AccessibleWhenUnlockedThisDeviceOnly",
  WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: "AccessibleWhenPasscodeSetThisDeviceOnly",
} as const;

export const ACCESS_CONTROL = {
  BIOMETRY_CURRENT_SET: "BiometryCurrentSet",
} as const;

export async function getSupportedBiometryType(): Promise<string | null> {
  return biometryType;
}

export async function getGenericPassword(options?: { service?: string; accessControl?: string }): Promise<false | { username: string; password: string }> {
  getCalls.push({ service: options?.service, accessControl: options?.accessControl });
  if (failReads) throw new Error("keychain unavailable");
  return credentials.get(options?.service ?? "") ?? false;
}

export async function setGenericPassword(
  username: string,
  password: string,
  options?: { service?: string; accessControl?: string; accessible?: string },
): Promise<false | { service: string }> {
  const service = options?.service ?? "";
  setCalls.push({ username, options: options as Record<string, unknown> });
  if (failWrites) return false; // the real module's failure contract
  credentials.set(service, { username, password });
  return { service };
}

export async function resetGenericPassword(options?: { service?: string }): Promise<boolean> {
  return credentials.delete(options?.service ?? "");
}

/** Force setGenericPassword to report failure, as the native module does
 *  when the keystore rejects the write. Cleared by __reset. */
export function __failWrites(value: boolean): void {
  failWrites = value;
}

/** Force getGenericPassword to throw (biometry lockout / keychain dead). */
export function __failReads(value: boolean): void {
  failReads = value;
}

/** Pretend a biometry type is (or is not) enrolled on this "device". */
export function __setBiometryType(value: string | null): void {
  biometryType = value;
}

/** The most recent getGenericPassword options, for prompt-path asserts. */
export function __lastGetOptions(): { service?: string; accessControl?: string } | undefined {
  return getCalls[getCalls.length - 1];
}

/** The most recent setGenericPassword call (username + options). */
export function __lastSetCall(): { username: string; options?: Record<string, unknown> } | undefined {
  return setCalls[setCalls.length - 1];
}

export function __reset(): void {
  credentials.clear();
  failWrites = false;
  failReads = false;
  biometryType = null;
  getCalls.length = 0;
  setCalls.length = 0;
}
