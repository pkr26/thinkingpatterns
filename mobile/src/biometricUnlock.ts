/** Protected credential reads prompt even without an accessControl option.
 * Presence checks use native metadata APIs; only an explicit unlock reads keys. */
import * as Keychain from "react-native-keychain";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { captureLocalWritePermit, assertLocalWritePermit, commitLocalWrite, commitLocalErasureWrite, commitOriginErasureWrite, localWriteScopeEpoch } from "./localWriteGuard";
import { accountStorageKey } from "./accountStorage";
const SERVICE = "com.mindpattern.biometric-unlock.v1";
const serviceFor = (userId: string): string => `${SERVICE}.${userId}`;
const legacyDisabled = accountStorageKey.biometricLegacyDisabled;
const ownerMarker = accountStorageKey.biometricOwner;
const authenticatedLegacyOwners = new Set<string>();
let mutations: Promise<unknown> = Promise.resolve();
function serialized<T>(run: () => Promise<T>): Promise<T> {
  const pending = mutations.then(run, run); mutations = pending.catch(() => {}); return pending;
}
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
  const permit = captureLocalWritePermit(userId, dataKey), encoded = dataKey.toString("base64");
  // Keychain calls are physical key publications too. Track the entire
  // admitted mutation so deletion/rotation cannot finish before it drains.
  await commitLocalWrite(permit, () => serialized(async () => {
    assertLocalWritePermit(permit);
    // Publish the non-secret owner inventory before the native key. A crash
    // after Keychain accepts the wrap must never leave an unenumerable
    // per-owner service that a later origin retirement cannot discover.
    await AsyncStorage.setItem(ownerMarker(userId), "1");
    const result = await Keychain.setGenericPassword(userId, encoded, {
      service: serviceFor(userId), accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
      accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    });
    if (!result) throw new Error("biometric secure storage rejected the data-key wrap");
    // A prompting legacy read is the only safe way to attribute the shared
    // upgrade-era slot. If it was not authenticated as this user, leave it
    // protected and tombstone fallback for this account; it may belong to a
    // different account that still uses this installation.
    if (authenticatedLegacyOwners.has(userId)) {
      await Keychain.resetGenericPassword({ service: SERVICE });
      authenticatedLegacyOwners.delete(userId);
      await AsyncStorage.removeItem(legacyDisabled(userId));
    } else {
      await AsyncStorage.setItem(legacyDisabled(userId), "1");
    }
  }));
}
export async function disableBiometricUnlock(userId: string): Promise<void> {
  // A legacy slot cannot be attributed without authenticating. Suppress its
  // fallback for this account without reading/deleting another owner's key.
  const epoch = localWriteScopeEpoch();
  // Administrative removal is also used after the account is tombstoned
  // and while rekey freezes producers, so it does not require an active key.
  await commitLocalErasureWrite(userId, epoch, () => serialized(async () => {
    if (epoch !== localWriteScopeEpoch()) throw new Error("The biometric removal belongs to a retired session");
    await AsyncStorage.setItem(legacyDisabled(userId), "1");
    await Keychain.resetGenericPassword({ service: serviceFor(userId) });
    if (authenticatedLegacyOwners.has(userId)) {
      await Keychain.resetGenericPassword({ service: SERVICE });
      authenticatedLegacyOwners.delete(userId);
    }
    await AsyncStorage.removeItem(ownerMarker(userId));
  }));
}

/** Irreversible account/origin retirement. Unlike the user-facing disable
 * operation above, this lane retires the un-attributable legacy singleton
 * as well: keeping it would leave a raw data-key wrap orphaned after the
 * owning origin is gone. It also removes the temporary compatibility
 * tombstone so no account-labelled metadata survives erasure. */
export async function eraseBiometricUnlock(userId: string): Promise<void> {
  const epoch = localWriteScopeEpoch();
  await commitLocalErasureWrite(userId, epoch, () => serialized(async () => {
    if (epoch !== localWriteScopeEpoch()) throw new Error("The biometric erasure belongs to a retired session");
    await Keychain.resetGenericPassword({ service: serviceFor(userId) });
    await Keychain.resetGenericPassword({ service: SERVICE });
    authenticatedLegacyOwners.delete(userId);
    await AsyncStorage.multiRemove([legacyDisabled(userId), ownerMarker(userId)]);
  }));
}
/** Retire every biometric slot owned by the old API origin. The shared v1
 * slot has no recoverable owner label, so it must be erased even when the
 * credential tuple is already missing and the storage inventory contains
 * only username-scoped caches. */
export async function eraseOriginBiometricUnlocks(userIds: readonly string[]): Promise<void> {
  const epoch = localWriteScopeEpoch();
  const owners = [...new Set(userIds)];
  await commitOriginErasureWrite(epoch, () => serialized(async () => {
    if (epoch !== localWriteScopeEpoch()) throw new Error("The biometric erasure belongs to a retired origin");
    for (const owner of owners) {
      await Keychain.resetGenericPassword({ service: serviceFor(owner) });
    }
    await Keychain.resetGenericPassword({ service: SERVICE });
    authenticatedLegacyOwners.clear();
    const markers = owners.flatMap((owner) => [legacyDisabled(owner), ownerMarker(owner)]);
    if (markers.length > 0) await AsyncStorage.multiRemove(markers);
    if (epoch !== localWriteScopeEpoch()) throw new Error("The biometric erasure belongs to a retired origin");
  }));
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
