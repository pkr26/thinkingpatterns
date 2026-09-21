/**
 * UnlockScreen: cold-restart gate. Re-derives keys from the password,
 * re-verifies via login (refreshing the token), and fails with honest
 * messages — 401 means wrong password.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

vi.mock("../../src/unlockProof", () => ({
  storeUnlockProof: vi.fn(async () => {}),
  verifyUnlockProof: vi.fn(async (): Promise<"ok" | "wrong" | "absent"> => "ok"),
  clearUnlockProof: vi.fn(async () => {}),
  unlockProofExists: vi.fn(async () => false),
}));

// Biometric unlock (2026-09-19): defaults to "unsupported device" so every
// pre-existing test sees the plain password gate.
const biometricsSupported = vi.fn(async () => false);
const hasBiometricUnlock = vi.fn(async () => false);
const unwrapBiometricDataKey = vi.fn(async (): Promise<Buffer | null> => null);
const disableBiometricUnlock = vi.fn(async () => {});
vi.mock("../../src/biometricUnlock", () => ({
  biometricsSupported: () => biometricsSupported(),
  hasBiometricUnlock: (userId: string) => hasBiometricUnlock(userId),
  unwrapBiometricDataKey: (userId: string) => unwrapBiometricDataKey(userId),
  disableBiometricUnlock: (userId: string) => disableBiometricUnlock(userId),
}));

vi.mock("../../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>();
  return {
    ...actual,
    deriveKeysAsync: vi.fn(async () => ({
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.alloc(32, 2),
      dataKey: Buffer.alloc(32, 3),
    })),
  };
});

const signOut = vi.fn(async () => {});
const refreshActiveDays = vi.fn(async () => {});
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return {
    ...actual,
    useSession: () => ({ signOut, refreshActiveDays }),
  };
});

const { api, ApiError } = await import("../../src/api/client");
const { storeUnlockProof, verifyUnlockProof } = await import("../../src/unlockProof");
const { deriveKeysAsync } = await import("../../src/crypto/MindPatternCrypto");
const { UnlockScreen } = await import("../../src/screens/UnlockScreen");
const { vault } = await import("../../src/vault");
const {
  render,
  flush,
  textOf,
  pressLabel,
  typeInto,
  touchableByLabel,
  submitInput,
  act,
  inputByPlaceholder,
} = await import("../helpers/rtr");
const { resetApi, SALT_B64 } = await import("../helpers/apiMock");

/** The most recent keys the mocked deriveKeys produced, for zeroization asserts. */
let lastDerived: { masterKey: Buffer; authKey: Buffer; dataKey: Buffer } | null = null;

beforeEach(() => {
  resetApi(api as never);
  lastDerived = null;
  biometricsSupported.mockReset();
  biometricsSupported.mockImplementation(async () => false);
  hasBiometricUnlock.mockReset();
  hasBiometricUnlock.mockImplementation(async () => false);
  unwrapBiometricDataKey.mockReset();
  unwrapBiometricDataKey.mockImplementation(async () => null);
  disableBiometricUnlock.mockReset();
  disableBiometricUnlock.mockImplementation(async () => {});
  vi.mocked(deriveKeysAsync).mockReset();
  vi.mocked(deriveKeysAsync).mockImplementation(async () => {
    lastDerived = {
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.alloc(32, 2),
      dataKey: Buffer.alloc(32, 3),
    };
    return lastDerived;
  });
  vi.mocked(storeUnlockProof).mockClear();
  vi.mocked(verifyUnlockProof).mockClear();
  vi.mocked(verifyUnlockProof).mockImplementation(async () => "ok");
  signOut.mockClear();
  refreshActiveDays.mockClear();
  Alert.alert.mockClear();
  vault.lock();
});

describe("UnlockScreen", () => {
  it("renders the locked gate with a disabled unlock button until a password is typed", async () => {
    const root = await render(<UnlockScreen />);
    await flush();
    expect(textOf(root)).toContain("Locked");
    expect(textOf(root)).toContain("Re-enter your password");
    // The honest copy: keys only you hold + the one bounded exception.
    expect(textOf(root)).toContain("Your journal is encrypted with keys only you hold");
    expect(textOf(root)).toContain("held in memory, then destroyed");
    expect(textOf(root)).not.toContain("never leave this device");
    expect(touchableByLabel(root, "Unlock").props.disabled).toBe(true);

    await typeInto(root, "password", "something");
    expect(touchableByLabel(root, "Unlock").props.disabled).toBe(false);
  });

  it("re-derives keys, re-verifies and unlocks the vault", async () => {
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();

    expect(api.getUsername).toHaveBeenCalledTimes(1);
    expect(api.saltFor).toHaveBeenCalledWith("alice");
    expect(vi.mocked(deriveKeysAsync)).toHaveBeenCalledWith("correct horse", Buffer.from(SALT_B64, "base64"));
    expect(api.login).toHaveBeenCalledTimes(1);
    expect(api.setSession).toHaveBeenCalledWith("tok", "user-1", "alice");
    expect(vault.isUnlocked()).toBe(true);
    expect(refreshActiveDays).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled();
    // The password field is scrubbed after a successful unlock.
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
    // busy was reset: a second press runs the flow again.
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(api.login).toHaveBeenCalledTimes(2);
  });

  it("caches the salt on a successful online unlock", async () => {
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(api.cacheSalt).toHaveBeenCalledWith("alice", SALT_B64);
  });

  // M7: unlocking the vault must not require the network.
  it("unlocks OFFLINE using the cached salt — no login round-trip, no token", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();

    expect(api.login).not.toHaveBeenCalled();
    expect(api.setSession).not.toHaveBeenCalled();
    expect(vi.mocked(deriveKeysAsync)).toHaveBeenCalledWith("correct horse", Buffer.from(SALT_B64, "base64"));
    expect(vault.isUnlocked()).toBe(true);
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(refreshActiveDays).toHaveBeenCalledTimes(1);
  });

  // C1: the offline path must VERIFY the password — any string must no
  // longer unlock the vault.
  it("REFUSES a wrong password offline (sealed proof fails)", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    vi.mocked(verifyUnlockProof).mockResolvedValue("wrong");
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "any guess");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Wrong password.");
    expect(verifyUnlockProof).toHaveBeenCalledTimes(1);
  });

  it("refuses offline unlock when no proof was ever sealed (first-run device)", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    vi.mocked(verifyUnlockProof).mockResolvedValue("absent");
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "anything");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", expect.stringContaining("sign in once while online"));
  });

  it("an online unlock refreshes the sealed proof", async () => {
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(storeUnlockProof).toHaveBeenCalledTimes(1);
  });

  it("a non-401 login failure falls back to the sealed proof (not to blind trust)", async () => {
    vi.mocked(api.login).mockRejectedValue(new ApiError(500, "server exploded"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    vi.mocked(verifyUnlockProof).mockResolvedValue("wrong");
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "guess");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(verifyUnlockProof).toHaveBeenCalledTimes(1);
  });

  it("unlocks offline when the network dies between salt fetch and login", async () => {
    vi.mocked(api.login).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
  });

  it("offline with no cached salt: honest error, locked vault, crisis still reachable", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    // Calm mapped copy, not raw server text.
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Couldn't reach the server — check your connection.");
    expect(textOf(root)).toContain("Need help now? Crisis resources");
  });

  it("offers crisis resources from the locked state without unlocking", async () => {
    const nav = { navigate: vi.fn() };
    const root = await render(<UnlockScreen navigation={nav as never} />);
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
    expect(vault.isUnlocked()).toBe(false);
  });

  it("pins the visual language of the screen", async () => {
    // Design-system pass: theme-composed styles; primary fill is the
    // AA-passing #3b5bdb; the crisis affordance keeps its own surface.
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<UnlockScreen />);
    await flush();
    expectStyle(root, { flex: 1, justifyContent: "center" }); // container base
    expectStyle(root, { backgroundColor: "#0f1115", padding: 32, gap: 12 }); // container themed
    expectStyle(root, { fontSize: 34, fontWeight: "700", textAlign: "center" }); // title base
    expectStyle(root, { color: "#e8eaf0" }); // title themed
    expectStyle(root, { textAlign: "center", marginBottom: 24, lineHeight: 20 }); // subtitle base
    expectStyle(root, { color: "#8a91a3", fontSize: 14 }); // subtitle themed
    expectStyle(root, { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 16 });
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton
    expectStyle(root, { backgroundColor: "#3b5bdb", minHeight: 44 }); // primary fill (AA fix)
    expectStyle(root, { color: "#ffffff", fontSize: 16 }); // button text
    expectStyle(root, { backgroundColor: "#242a38", borderRadius: 10, minHeight: 44 }); // help surface
  });

  it("supports submitting from the keyboard", async () => {
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await submitInput(root, "password");
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);
  });

  it("refuses to unlock when no saved account exists", async () => {
    vi.mocked(api.getUsername).mockResolvedValue(null);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "anything");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith(
      "Unlock failed",
      "no saved account on this device — please sign in",
    );
  });

  it("says 'Wrong password.' specifically on 401", async () => {
    vi.mocked(api.login).mockRejectedValue(new ApiError(401, "invalid credentials"));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "nope");
    await pressLabel(root, "Unlock");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Wrong password.");
  });

  it("maps server errors to calm copy (no raw technical text)", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Couldn't reach the server — check your connection.");
    expect(Alert.alert).not.toHaveBeenCalledWith("Unlock failed", "server unreachable");
  });

  // A non-Error login rejection (hostile proxy garbage) is NOT trusted as
  // success either: the sealed proof decides.
  it("a non-Error login rejection falls to the sealed proof", async () => {
    vi.mocked(api.login).mockRejectedValue("boom" as never);
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(verifyUnlockProof).toHaveBeenCalledTimes(1);
    expect(vault.isUnlocked()).toBe(true); // proof said ok
    Alert.alert.mockClear();
    // Now go fully offline with a wrong password: the proof must refuse.
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(verifyUnlockProof).mockResolvedValue("wrong");
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Wrong password.");
  });

  it("offline path with no saved account id: honest error, locked vault", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith(
      "Unlock failed",
      "no saved account on this device — please sign in",
    );
  });

  it("a successful online unlock tolerates a missing stored user id", async () => {
    // The vault's account binding is best-effort metadata: a null id must
    // not block an unlock the server already verified.
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("a non-Error failure in the outer flow reports calm fallback copy", async () => {
    vi.mocked(api.getUsername).mockRejectedValue("boom" as never);
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "Something went wrong — try again.");
  });

  it("ignores a second unlock press while one is in flight", async () => {
    let resolveLogin!: (v: unknown) => void;
    vi.mocked(api.login).mockImplementation(() => new Promise((resolve) => (resolveLogin = resolve)));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Unlock");
    // While busy the button label is a spinner — a second attempt arrives
    // through the keyboard submit path instead.
    await submitInput(root, "password");
    expect(api.login).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveLogin?.({ token: "tok", user_id: "u" });
    });
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);
    expect(vault.isUnlocked()).toBe(true);
  });

  it("uses the padding keyboard behavior on iOS and none on Android", async () => {
    const reactNative = await import("react-native");
    const rtr = await import("../helpers/rtr");
    const root = await render(<UnlockScreen />);
    const keyboard = root.root.findByType(reactNative.KeyboardAvoidingView);
    expect(keyboard.props.behavior).toBe("padding");
    expect(keyboard.props.style).toEqual(
      [{ flex: 1, justifyContent: "center" }, { backgroundColor: "#0f1115", padding: 32, gap: 12 }],
    );

    const original = reactNative.Platform.OS;
    (reactNative.Platform as { OS: string }).OS = "android";
    try {
      const androidRoot = await rtr.render(<UnlockScreen />);
      const androidKeyboard = androidRoot.root.findByType(reactNative.KeyboardAvoidingView);
      expect(androidKeyboard.props.behavior).toBeUndefined();
    } finally {
      (reactNative.Platform as { OS: string }).OS = original;
    }
  });

  it("offers sign-out instead", async () => {
    const root = await render(<UnlockScreen />);
    await pressLabel(root, "Sign out instead");
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it("renders the android keyboard behavior when the platform differs", async () => {
    const { Platform } = await import("react-native");
    const original = Platform.OS;
    (Platform as { OS: string }).OS = "android";
    try {
      const root = await render(<UnlockScreen />);
      await typeInto(root, "password", "pw");
      await pressLabel(root, "Unlock");
      await flush();
      expect(vault.isUnlocked()).toBe(true);
    } finally {
      (Platform as { OS: string }).OS = original;
    }
  });

  it("zeroizes keys that failed to unlock and stays locked", async () => {
    vi.mocked(api.login).mockRejectedValue(new ApiError(401, "invalid credentials"));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "nope");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("Sign out instead");
    // The failed attempt's key material is scrubbed before the retry.
    expect(lastDerived).not.toBeNull();
    expect(lastDerived!.masterKey.equals(Buffer.alloc(32))).toBe(true);
    expect(lastDerived!.authKey.equals(Buffer.alloc(32))).toBe(true);
    expect(lastDerived!.dataKey.equals(Buffer.alloc(32))).toBe(true);
  });
});

describe("UnlockScreen biometric unlock (offered only when a wrap exists)", () => {
  it("no biometric button on an unsupported device — the password gate is unchanged", async () => {
    const root = await render(<UnlockScreen />);
    await flush();
    expect(textOf(root)).not.toContain("Unlock with biometrics");
    expect(textOf(root)).not.toContain("Biometric unlock didn't work");
  });

  it("no button when the device is supported but no wrap was ever stored", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => false);
    const root = await render(<UnlockScreen />);
    await flush();
    expect(textOf(root)).not.toContain("Unlock with biometrics");
    expect(hasBiometricUnlock).toHaveBeenCalledWith("user-1");
  });

  it("no button when the quiet probe finds no session account", async () => {
    biometricsSupported.mockImplementation(async () => true);
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<UnlockScreen />);
    await flush();
    expect(textOf(root)).not.toContain("Unlock with biometrics");
    expect(hasBiometricUnlock).not.toHaveBeenCalled();
  });

  it("a wrap on a supported device shows the button above the password field", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => true);
    const root = await render(<UnlockScreen />);
    await flush();
    const { TextInput: RNInput } = await import("react-native");
    const passwordField = root.root.findAllByType(RNInput)[0];
    expect(passwordField).toBeDefined();
    // Document order: the biometric button renders BEFORE the password field.
    const order = root.root.findAll(() => true);
    const bioIdx = order.findIndex(
      (n) => n.props.accessibilityLabel === "Unlock with biometrics" && n.props.accessibilityRole === "button",
    );
    const passIdx = order.findIndex((n) => n === passwordField);
    expect(bioIdx).toBeGreaterThanOrEqual(0);
    expect(bioIdx).toBeLessThan(passIdx);
    // The quiet probe never prompted: hasBiometricUnlock ran without an
    // accessControl read (asserted at the module level in
    // tests/biometricUnlock.test.ts).
    expect(hasBiometricUnlock).toHaveBeenCalledTimes(1);
  });

  it("success: unwraps and unlocks the vault WITHOUT a login round-trip", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => true);
    unwrapBiometricDataKey.mockImplementation(async () => Buffer.alloc(32, 9));
    const root = await render(<UnlockScreen />);
    await flush();
    await pressLabel(root, "Unlock with biometrics");
    await flush();
    expect(unwrapBiometricDataKey).toHaveBeenCalledWith("user-1");
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("user-1");
    // H-2: the authKey slot is honestly marked UNKNOWN (placeholder zeros)
    // — reauth.ts must verify online rather than compare against zeros.
    expect(vault.get().authKeyKnown).toBe(false);
    expect(vault.get().authKey.equals(Buffer.alloc(32))).toBe(true);
    expect(refreshActiveDays).toHaveBeenCalledTimes(1);
    // Biometric unlock restores LOCAL decryption — no server login, no
    // token refresh, no proof rewrite (those belong to the password path).
    expect(api.login).not.toHaveBeenCalled();
    expect(api.setSession).not.toHaveBeenCalled();
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(textOf(root)).not.toContain("Biometric unlock didn't work");
  });

  it("failure: one calm inline line, no dialog, and the password still unlocks", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => true);
    unwrapBiometricDataKey.mockImplementation(async () => null); // cancelled
    const root = await render(<UnlockScreen />);
    await flush();
    await pressLabel(root, "Unlock with biometrics");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("Biometric unlock didn't work — your password always works below.");
    expect(Alert.alert).not.toHaveBeenCalled();
    // The password path is fully intact right after the failure. Submit
    // from the keyboard: the literal label "Unlock" is now a substring of
    // "Unlock with biometrics", so this exercises the password flow
    // unambiguously.
    await typeInto(root, "password", "correct horse");
    await submitInput(root, "password");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(api.login).toHaveBeenCalledTimes(1);
    expect(textOf(root)).not.toContain("Biometric unlock didn't work");
  });

  it("ignores a second biometric press while one is in flight (busy guard)", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => true);
    let resolveUnwrap!: (v: Buffer | null) => void;
    unwrapBiometricDataKey.mockImplementation(
      () => new Promise((resolve) => (resolveUnwrap = resolve as (v: Buffer | null) => void)),
    );
    const root = await render(<UnlockScreen />);
    await flush();
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Unlock with biometrics");
    await firePress(root, "Unlock with biometrics"); // swallowed: busy
    expect(unwrapBiometricDataKey).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveUnwrap(Buffer.alloc(32, 9));
    });
    await flush();
    expect(vault.isUnlocked()).toBe(true);
  });

  // Audit fix 8 (2026-09-21): the biometric path must VERIFY the unwrapped
  // key against the sealed proof — a stale wrap (rotation / re-enrollment
  // left the OLD key sealed) otherwise unlocks under the wrong key and the
  // journal reads as tamper failures.
  it("a STALE wrap fails the proof, is DELETED, and the password path takes over", async () => {
    biometricsSupported.mockImplementation(async () => true);
    hasBiometricUnlock.mockImplementation(async () => true);
    unwrapBiometricDataKey.mockImplementation(async () => Buffer.alloc(32, 9)); // unwrap succeeds…
    vi.mocked(verifyUnlockProof).mockResolvedValue("wrong"); // …but under the WRONG key
    const root = await render(<UnlockScreen />);
    await flush();
    await pressLabel(root, "Unlock with biometrics");
    await flush();

    // The same proof check the password path runs, on the unwrapped key.
    expect(verifyUnlockProof).toHaveBeenCalledWith(Buffer.alloc(32, 9), "user-1");
    // The stale wrap is deleted — the next visit cannot offer it again.
    expect(disableBiometricUnlock).toHaveBeenCalledWith("user-1");
    // The vault NEVER unlocked under the wrong key.
    expect(vault.isUnlocked()).toBe(false);
    // The biometric offer retracts and the calm line points at the password.
    expect(textOf(root)).not.toContain("Unlock with biometrics");
    expect(textOf(root)).toContain("Biometric unlock didn't work — your password always works below.");
    expect(Alert.alert).not.toHaveBeenCalled();

    // Fall back to the password path: it still unlocks (verified online).
    await typeInto(root, "password", "correct horse");
    await submitInput(root, "password");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
  });
});
