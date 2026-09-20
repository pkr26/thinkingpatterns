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
 * (the auth key is never stored), and disabling deletes only THIS
 * account's item (per-account services — see serviceFor below).
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

/** L-50: the wrap slot is PER ACCOUNT. The old single service meant
 *  enabling account B OVERWROTE account A's wrap (one Keychain item per
 *  service) and disabling B (or A) wiped the whole service — feature loss
 *  only (the username check below still bound reads to the owner; no
 *  cross-account key exposure), but two accounts on one device could never
 *  both keep biometric unlock. The userId is already stored as the item's
 *  username, so including it in the service name exposes nothing new. */
const serviceFor = (userId: string): string => `${SERVICE}.${userId}`;

/** Best-effort removal of the pre-per-account SHARED slot when THIS account
 *  owns it — otherwise a legacy wrap would keep answering
 *  hasBiometricUnlock after a disable, or hold a stale key forever after a
 *  re-enable. Another account's legacy wrap is deliberately untouched;
 *  failures are swallowed (the per-account item is authoritative now). */
async function removeLegacyWrapIfOwned(userId: string): Promise<void> {
  try {
    const creds = await Keychain.getGenericPassword({ service: SERVICE });
    if (creds && typeof creds === "object" && creds.username === userId) {
      await Keychain.resetGenericPassword({ service: SERVICE });
    }
  } catch {
    /* a missing/unreadable legacy item is already gone for our purposes */
  }
}

/** Read one wrap slot and validate ownership. `prompt` decides whether the
 *  read carries the accessControl option (the system biometric prompt);
 *  without it the Keychain answers from item metadata. Any refusal,
 *  mismatch or corrupt shape fails to null — never a throw, never an
 *  unlock under garbage bytes. */
async function readWrap(
  service: string,
  userId: string,
  prompt: boolean,
): Promise<{ username: string; password: string } | null> {
  try {
    const creds = await Keychain.getGenericPassword(
      prompt ? { service, accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET } : { service },
    );
    if (!creds || typeof creds !== "object" || creds.username !== userId) return null;
    return creds;
  } catch {
    return null;
  }
}

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
    service: serviceFor(userId),
    accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
  });
  if (!result) throw new Error("biometric secure storage rejected the data-key wrap");
  // Retire THIS account's pre-per-account wrap so a later disable can never
  // resurrect it (the shared slot is never written again).
  await removeLegacyWrapIfOwned(userId);
}

/** Remove THIS account's wrap. Sign-out hygiene and the Settings toggle
 *  both land here; a missing item is already gone (success). Another
 *  account's wrap — per-account slot or legacy — is not touched. */
export async function disableBiometricUnlock(userId: string): Promise<void> {
  await Keychain.resetGenericPassword({ service: serviceFor(userId) });
  await removeLegacyWrapIfOwned(userId);
}

/** Does a biometric wrap exist for this account? The reads pass NO
 *  accessControl option, so they answer from item metadata and NEVER
 *  prompt — prompting on a mount-time existence check would be hostile.
 *  The per-account slot first, then the legacy shared slot an older
 *  install may still hold (still ownership-checked, never prompted). */
export async function hasBiometricUnlock(userId: string): Promise<boolean> {
  return (
    (await readWrap(serviceFor(userId), userId, false)) !== null ||
    (await readWrap(SERVICE, userId, false)) !== null
  );
}

/**
 * Prompt for the biometric and return the unwrapped data key, or null on
 * cancel/failure — never a throw (the password path must stay reachable no
 *  matter what the Keychain does). The accessControl option on these reads
 * is what triggers the prompt; the per-account slot is read first and the
 * legacy shared slot (an upgrade-era wrap) is consulted only when the
 * per-account item is absent, so an old wrap keeps unlocking until it is
 * re-enabled or disabled. Anything the Keychain hands back is validated
 * like any storage input: a username mismatch or a value that is not
 * exactly 32 bytes is corrupt/hostile and fails to null.
 */
export async function unwrapBiometricDataKey(userId: string): Promise<Buffer | null> {
  const creds =
    (await readWrap(serviceFor(userId), userId, true)) ?? (await readWrap(SERVICE, userId, true));
  if (creds === null) return null;
  const key = Buffer.from(creds.password, "base64");
  if (key.length !== 32) return null;
  return key;
}
