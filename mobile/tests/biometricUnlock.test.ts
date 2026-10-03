/**
 * Biometric unlock custody (src/biometricUnlock.ts) over the shared
 * keychainMock — the same approach as tests/secureStore.test.ts: the
 * vitest alias routes every react-native-keychain import to one custody
 * boundary. Covers the wrap options, the quiet-vs-prompting read split,
 * hostile/corrupt stores failing to the password path, hygiene, and the
 * PER-ACCOUNT wrap slots (L-50) including the legacy shared-slot fallback.
 */
import { beforeEach, describe, expect, it } from "vitest";
import * as Keychain from "react-native-keychain";
import storage from "./helpers/storageMock";
import {
  biometricsSupported,
  disableBiometricUnlock,
  enableBiometricUnlock,
  hasBiometricUnlock,
  unwrapBiometricDataKey,
} from "../src/biometricUnlock";

const SERVICE = "com.mindpattern.biometric-unlock.v1";
/** L-50: each account owns its own Keychain service slot. */
const serviceFor = (userId: string): string => `${SERVICE}.${userId}`;
const mock = Keychain as unknown as {
  __reset: () => void;
  __failWrites: (v: boolean) => void;
  __failReads: (v: boolean) => void;
  __setBiometryType: (v: string | null) => void;
  __getReadCount: () => number;
  __lastGetOptions: () => { service?: string; accessControl?: string };
  __lastSetCall: () => { username: string; options?: Record<string, unknown> };
};

const DATA_KEY = Buffer.alloc(32, 7);
const DATA_KEY_B = Buffer.alloc(32, 11);

beforeEach(() => {
  mock.__reset();
  storage.__reset();
});

describe("biometricsSupported", () => {
  it("false when no biometry is enrolled, true when the Keychain reports one", async () => {
    await expect(biometricsSupported()).resolves.toBe(false);
    mock.__setBiometryType("FaceID");
    await expect(biometricsSupported()).resolves.toBe(true);
  });
});

describe("enable / has / disable round-trip", () => {
  it("stores the wrap under the ACCOUNT'S service with the biometry-current-set, this-device-only seal", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    const call = mock.__lastSetCall();
    expect(call.username).toBe("user-1");
    expect(call.options).toMatchObject({
      service: serviceFor("user-1"),
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
      accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    });
    // The stored value is the base64 data key under the dedicated service.
    const stored = await Keychain.getGenericPassword({ service: serviceFor("user-1") });
    expect(stored).toEqual({ username: "user-1", password: DATA_KEY.toString("base64") });
  });

  it("presence/enable/disable do not retrieve protected credentials", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    expect(mock.__getReadCount()).toBe(0);
    // A different account (or no wrap at all) reads false.
    await expect(hasBiometricUnlock("user-2")).resolves.toBe(false);
    await disableBiometricUnlock("user-1");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
    expect(mock.__getReadCount()).toBe(0);
  });

  it("enable fails honestly when the Keychain refuses the write", async () => {
    mock.__failWrites(true);
    await expect(enableBiometricUnlock("user-1", DATA_KEY)).rejects.toThrow("rejected the data-key wrap");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
  });

  it("disable removes the item (and a second disable is fine)", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await disableBiometricUnlock("user-1");
    await expect(disableBiometricUnlock("user-1")).resolves.toBeUndefined();
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
  });
});

describe("per-account wrap slots (L-50)", () => {
  it("enabling account B no longer overwrites account A's wrap", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await enableBiometricUnlock("user-2", DATA_KEY_B);

    // Both wraps coexist under their own services…
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    await expect(hasBiometricUnlock("user-2")).resolves.toBe(true);
    // …and each unwraps to ITS OWN key (the prompting read).
    expect((await unwrapBiometricDataKey("user-1"))!.equals(DATA_KEY)).toBe(true);
    expect((await unwrapBiometricDataKey("user-2"))!.equals(DATA_KEY_B)).toBe(true);
  });

  it("disabling account B leaves account A's wrap intact", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await enableBiometricUnlock("user-2", DATA_KEY_B);
    await disableBiometricUnlock("user-2");
    await expect(hasBiometricUnlock("user-2")).resolves.toBe(false);
    await expect(unwrapBiometricDataKey("user-2")).resolves.toBeNull();
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    expect((await unwrapBiometricDataKey("user-1"))!.equals(DATA_KEY)).toBe(true);
  });

  it("an upgrade-era wrap in the legacy SHARED slot still answers (fallback read)", async () => {
    await Keychain.setGenericPassword("user-1", DATA_KEY.toString("base64"), { service: SERVICE });
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    const key = await unwrapBiometricDataKey("user-1");
    expect(key).toEqual(DATA_KEY);
    // The prompting fallback read carries the accessControl option too.
    expect(mock.__lastGetOptions()).toEqual({
      service: SERVICE,
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    });
    // Metadata cannot attribute a legacy shared item without a prompt.
    // Availability is only an unlock affordance; the explicit unwrap checks ownership.
    await expect(hasBiometricUnlock("user-2")).resolves.toBe(true);
    await expect(unwrapBiometricDataKey("user-2")).resolves.toBeNull();
  });

  it("disable removes a legacy shared wrap only when THIS account owns it", async () => {
    await Keychain.setGenericPassword("user-1", DATA_KEY.toString("base64"), { service: SERVICE });
    // user-2 disabling must NOT destroy user-1's legacy wrap.
    await disableBiometricUnlock("user-2");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    // Without authenticating user-1, disable suppresses fallback for that
    // account without retrieving/deleting a possibly foreign shared item.
    await disableBiometricUnlock("user-1");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
  });

  it("re-enabling suppresses an unowned legacy fallback without prompting", async () => {
    await Keychain.setGenericPassword("user-1", DATA_KEY.toString("base64"), { service: SERVICE });
    const rotated = Buffer.alloc(32, 21);
    await enableBiometricUnlock("user-1", rotated);
    // The per-account slot answers with the NEW key…
    expect((await unwrapBiometricDataKey("user-1"))!.equals(rotated)).toBe(true);
    // …and the unverified shared slot remains protected. A later disable
    // cannot resurrect this account's old key because its fallback is tombstoned.
    expect(await Keychain.hasGenericPassword({ service: SERVICE })).toBe(true);
    await disableBiometricUnlock("user-1");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
  });
});

describe("legacy ownership cleanup", () => {
  it("only explicit owner authentication permits removing the shared slot", async () => {
    await Keychain.setGenericPassword("legacy-owner", DATA_KEY.toString("base64"), { service: SERVICE });
    await expect(hasBiometricUnlock("legacy-owner")).resolves.toBe(true);
    expect(mock.__getReadCount()).toBe(0);
    expect(await unwrapBiometricDataKey("legacy-owner")).toEqual(DATA_KEY);
    await disableBiometricUnlock("legacy-owner");
    await expect(Keychain.hasGenericPassword({ service: SERVICE })).resolves.toBe(false);
  });
});

describe("unwrapBiometricDataKey (the prompting read)", () => {
  it("unwraps to the exact 32 bytes and forces the prompt via the accessControl option", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    const key = await unwrapBiometricDataKey("user-1");
    expect(mock.__lastGetOptions()).toEqual({
      service: serviceFor("user-1"),
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    });
    expect(key).toEqual(DATA_KEY);
  });

  it("null on cancel/failure — never a throw — when the Keychain read explodes", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    mock.__failReads(true);
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false); // quiet read fails the same way
  });

  it("null when no wrap exists", async () => {
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
  });

  it("null when the stored item belongs to a DIFFERENT account", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await expect(unwrapBiometricDataKey("user-2")).resolves.toBeNull();
  });

  it("a corrupt store (not 32 bytes) fails to null — never unlocks under garbage", async () => {
    await Keychain.setGenericPassword("user-1", Buffer.alloc(16, 9).toString("base64"), {
      service: serviceFor("user-1"),
    });
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
    // Even a hostile 32-byte-length base64 of the wrong key is just bytes —
    // but a non-base64 password decodes to wrong-length bytes and fails too.
    await Keychain.setGenericPassword("user-1", "not-base64-@#$%", { service: serviceFor("user-1") });
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
    // The same corruption in the legacy fallback slot fails identically.
    await Keychain.setGenericPassword("user-1", Buffer.alloc(16, 9).toString("base64"), { service: SERVICE });
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
  });
});
