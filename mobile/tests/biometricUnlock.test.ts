/**
 * Biometric unlock custody (src/biometricUnlock.ts) over the shared
 * keychainMock — the same approach as tests/secureStore.test.ts: the
 * vitest alias routes every react-native-keychain import to one custody
 * boundary. Covers the wrap options, the quiet-vs-prompting read split,
 * hostile/corrupt stores failing to the password path, and hygiene.
 */
import { beforeEach, describe, expect, it } from "vitest";
import * as Keychain from "react-native-keychain";
import {
  biometricsSupported,
  disableBiometricUnlock,
  enableBiometricUnlock,
  hasBiometricUnlock,
  unwrapBiometricDataKey,
} from "../src/biometricUnlock";

const SERVICE = "com.mindpattern.biometric-unlock.v1";
const mock = Keychain as unknown as {
  __reset: () => void;
  __failWrites: (v: boolean) => void;
  __failReads: (v: boolean) => void;
  __setBiometryType: (v: string | null) => void;
  __lastGetOptions: () => { service?: string; accessControl?: string };
  __lastSetCall: () => { username: string; options?: Record<string, unknown> };
};

const DATA_KEY = Buffer.alloc(32, 7);

beforeEach(() => {
  mock.__reset();
});

describe("biometricsSupported", () => {
  it("false when no biometry is enrolled, true when the Keychain reports one", async () => {
    await expect(biometricsSupported()).resolves.toBe(false);
    mock.__setBiometryType("FaceID");
    await expect(biometricsSupported()).resolves.toBe(true);
  });
});

describe("enable / has / disable round-trip", () => {
  it("stores the wrap with the biometry-current-set, this-device-only seal", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    const call = mock.__lastSetCall();
    expect(call.username).toBe("user-1");
    expect(call.options).toMatchObject({
      service: SERVICE,
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
      accessible: Keychain.ACCESSIBLE.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    });
    // The stored value is the base64 data key under the dedicated service.
    const stored = await Keychain.getGenericPassword({ service: SERVICE });
    expect(stored).toEqual({ username: "user-1", password: DATA_KEY.toString("base64") });
  });

  it("hasBiometricUnlock is a QUIET read (no accessControl option) bound to the account", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(true);
    expect(mock.__lastGetOptions()).toEqual({ service: SERVICE, accessControl: undefined });
    // A different account (or no wrap at all) reads false.
    await expect(hasBiometricUnlock("user-2")).resolves.toBe(false);
    await disableBiometricUnlock("user-1");
    await expect(hasBiometricUnlock("user-1")).resolves.toBe(false);
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

describe("unwrapBiometricDataKey (the prompting read)", () => {
  it("unwraps to the exact 32 bytes and forces the prompt via the accessControl option", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    const key = await unwrapBiometricDataKey("user-1");
    expect(mock.__lastGetOptions()).toEqual({
      service: SERVICE,
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
    });
    expect(key).toEqual(DATA_KEY);
  });

  it("null on cancel/failure — never a throw — when the Keychain read explodes", async () => {
    await enableBiometricUnlock("user-1", DATA_KEY);
    mock.__failReads(true);
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
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
      service: SERVICE,
    });
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
    // Even a hostile 32-byte-length base64 of the wrong key is just bytes —
    // but a non-base64 password decodes to wrong-length bytes and fails too.
    await Keychain.setGenericPassword("user-1", "not-base64-@#$%", { service: SERVICE });
    await expect(unwrapBiometricDataKey("user-1")).resolves.toBeNull();
  });
});
