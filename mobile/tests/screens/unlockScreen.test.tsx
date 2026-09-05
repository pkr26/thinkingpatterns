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
  return { ApiError, api: makeApiMock() };
});

vi.mock("../../src/unlockProof", () => ({
  storeUnlockProof: vi.fn(async () => {}),
  verifyUnlockProof: vi.fn(async (): Promise<"ok" | "wrong" | "absent"> => "ok"),
  clearUnlockProof: vi.fn(async () => {}),
  unlockProofExists: vi.fn(async () => false),
}));

vi.mock("../../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>();
  return {
    ...actual,
    deriveKeys: vi.fn(() => ({
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
const { deriveKeys } = await import("../../src/crypto/MindPatternCrypto");
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
  vi.mocked(deriveKeys).mockReset();
  vi.mocked(deriveKeys).mockImplementation(() => {
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
    expect(vi.mocked(deriveKeys)).toHaveBeenCalledWith("correct horse", Buffer.from(SALT_B64, "base64"));
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
    expect(vi.mocked(deriveKeys)).toHaveBeenCalledWith("correct horse", Buffer.from(SALT_B64, "base64"));
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
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "server unreachable");
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
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<UnlockScreen />);
    await flush();
    expectStyle(root, { flex: 1, justifyContent: "center", padding: 32, gap: 12, backgroundColor: "#0f1115" });
    expectStyle(root, { fontSize: 34, fontWeight: "700", color: "#e8eaf0", textAlign: "center" });
    expectStyle(root, {
      fontSize: 14, color: "#8a91a3", textAlign: "center", marginBottom: 24, lineHeight: 20,
    });
    expectStyle(root, { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 16 });
    expectStyle(root, { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 8 });
    expectStyle(root, { color: "#fff", fontSize: 16, fontWeight: "600" });
    expectStyle(root, { color: "#7f9bff", textAlign: "center", marginTop: 16 });
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

  it("surfaces other error messages verbatim", async () => {
    vi.mocked(api.saltFor).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "pw");
    await pressLabel(root, "Unlock");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Unlock failed", "server unreachable");
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
      { flex: 1, justifyContent: "center", padding: 32, gap: 12, backgroundColor: "#0f1115" },
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
