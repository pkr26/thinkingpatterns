/**
 * Biometric unlock for the DERIVED data key (2026-09-19).
 *
 * SECURITY TRADE — deliberate, and stated plainly: enabling stores the data
 * key (base64) in the iOS Keychain / Android Keystore under the service
 * below, sealed with BIOMETRY_CURRENT_SET + WHEN_PASSCODE_SET_THIS_DEVICE
 * ONLY. The data key now rests on this device wrapped under the user's
 * biometrics: a read of the item prompts for the living finger/face, and a
 * re-enrolled biometry invalidates the seal. This trades "type the password
 * after every restart" for "the key is recoverable on this one device with
 * the user's biometrics" — it does NOT touch the password path (always
 * intact, always the fallback), does not enable server re-authentication
 * (the auth key is never stored), and disabling deletes the item outright.
 * It is distinct from the secureStore device-key custody item
 * (com.mindpattern.session-device-key.v1), which is a random per-install
 * key with no biometric binding.
 *
 * Prompt behavior, so the UI never surprises anyone:
 *  - hasBiometricUnlock performs a QUIET metadata read — passing NO
 *    accessControl option means the Keychain answers without a biometric
 *    prompt; only the stored username is inspected.
 *  - unwrapBiometricDataKey passes accessControl on the read, which is
 *    what forces the system biometric prompt; cancel/failure returns null.
 */
import * as Keychain from "react-native-keychain";

const SERVICE = "com.mindpattern.biometric-unlock.v1";

/** True when this device has face/fingerprint hardware with a biometry
 *  enrolled. Never throws — unsupported reads as false. */
export async function biometricsSupported(): Promise<boolean> {
  try {
    return (await Keychain.getSupportedBiometryType()) !== null;
  } catch {
    return false;
  }
}

/** Store the data key wrapped under the user's biometrics for this
 *  account. Throws on a Keychain refusal (the caller says so honestly —
 *  "could not turn on" — rather than pretending the wrap exists). */
export async function enableBiometricUnlock(userId: string, dataKey: Buffer): Promise<void> {
  const result = await Keychain.setGenericPassword(userId, dataKey.toString("base64"), {
    service: SERVICE,
    accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
  });
  if (!result) throw new Error("biometric secure storage rejected the data-key wrap");
}

/** Remove the wrap. Sign-out hygiene and the Settings toggle both land
 *  here; a missing item is already gone (success). */
export async function disableBiometricUnlock(userId: string): Promise<void> {
  await Keychain.resetGenericPassword({ service: SERVICE });
}

/** Does a biometric wrap exist for this account? The read passes NO
 *  accessControl option, so it answers from item metadata and NEVER
 *  prompts — prompting on a mount-time existence check would be hostile. */
export async function hasBiometricUnlock(userId: string): Promise<boolean> {
  try {
    const creds = await Keychain.getGenericPassword({ service: SERVICE });
    if (!creds || typeof creds !== "object") return false;
    return creds.username === userId;
  } catch {
    return false;
  }
}

/**
 * Prompt for the biometric and return the unwrapped data key, or null on
 * cancel/failure — never a throw (the password path must stay reachable no
 * matter what the Keychain does). The accessControl option on this read is
 * what triggers the prompt; anything the Keychain hands back is validated
 * like any storage input: a username mismatch or a value that is not
 * exactly 32 bytes is corrupt/hostile and fails to null, never unlocks
 * under garbage bytes.
 */
export async function unwrapBiometricDataKey(userId: string): Promise<Buffer | null> {
  try {
    const creds = await Keychain.getGenericPassword({
      service: SERVICE,
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    });
    if (!creds || typeof creds !== "object" || creds.username !== userId) return null;
    const key = Buffer.from(creds.password, "base64");
    if (key.length !== 32) return null;
    return key;
  } catch {
    return null;
  }
}
