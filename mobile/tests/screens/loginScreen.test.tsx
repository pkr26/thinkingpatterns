/**
 * LoginScreen: register/login flows, short-password gate, key custody on
 * failure (derived buffers zeroized, vault locked), the mode toggle, and
 * registration honesty (no-reset warning, confirm password, strength hint).
 * Keys derive via deriveKeysAsync (no JS-thread freeze) — the mock is async.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

vi.mock("../../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>();
  return {
    ...actual,
    deriveKeysAsync: vi.fn(async (password: string, salt: Buffer) => ({
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.from(`${password}|${salt.toString("base64")}`.padEnd(32, "\0")),
      dataKey: Buffer.alloc(32, 3),
    })),
  };
});

const markLoggedIn = vi.fn();
const refreshActiveDays = vi.fn(async () => {});
let sessionState: Record<string, unknown>;
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => sessionState };
});

const { api, ApiError } = await import("../../src/api/client");
const { deriveKeysAsync } = await import("../../src/crypto/MindPatternCrypto");
const { LoginScreen } = await import("../../src/screens/LoginScreen");
const { takePendingOnboarding } = await import("../../src/onboarding");
const { vault } = await import("../../src/vault");
const { render, flush, textOf, pressLabel, typeInto, inputByPlaceholder, pressAlertButton } = await import("../helpers/rtr");
const { resetApi, SALT_B64 } = await import("../helpers/apiMock");

/** The most recent keys the mocked deriveKeys produced, for zeroization asserts. */
let lastDerived: { masterKey: Buffer; authKey: Buffer; dataKey: Buffer } | null = null;

beforeEach(() => {
  resetApi(api as never);
  lastDerived = null;
  vi.mocked(deriveKeysAsync).mockReset();
  vi.mocked(deriveKeysAsync).mockImplementation(async (password: string, salt: Buffer) => {
    lastDerived = {
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.from(`${password}|${salt.toString("base64")}`.padEnd(32, "\0")),
      dataKey: Buffer.alloc(32, 3),
    };
    return lastDerived;
  });
  markLoggedIn.mockClear();
  refreshActiveDays.mockClear();
  Alert.alert.mockClear();
  vault.lock();
  takePendingOnboarding(); // drain leftovers so one test cannot leak into the next
  sessionState = { markLoggedIn, refreshActiveDays };
});

describe("LoginScreen chrome", () => {
  it("renders the sign-in form and the register toggle", async () => {
    const root = await render(<LoginScreen />);
    await flush();
    expect(textOf(root)).toContain("MindPattern");
    expect(textOf(root)).toContain("Sign in");
    expect(textOf(root)).toContain("New here? Create an account");
    // Editors start empty and idle (no busy spinner, fields blank).
    const { inputByPlaceholder } = await import("../helpers/rtr");
    expect((inputByPlaceholder(root, "username").props as { value: string }).value).toBe("");
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
  });

  it("pins the visual language of the screen", async () => {
    // Design-system pass: theme-composed styles; the button fill moved to
    // the AA-passing #3b5bdb and the switch link is a themed GhostButton.
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<LoginScreen />);
    await flush();
    expectStyle(root, { flex: 1, justifyContent: "center" }); // container base
    expectStyle(root, { backgroundColor: "#0f1115", padding: 32, gap: 12 }); // container themed
    expectStyle(root, { fontSize: 34, fontWeight: "700", textAlign: "center" }); // title base
    expectStyle(root, { color: "#e8eaf0" }); // title themed
    expectStyle(root, { textAlign: "center", marginBottom: 24 }); // subtitle base
    expectStyle(root, { color: "#8a91a3", fontSize: 14 }); // subtitle themed
    expectStyle(root, { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 16 });
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton
    expectStyle(root, { backgroundColor: "#3b5bdb", minHeight: 44 }); // primary fill (AA fix)
    expectStyle(root, { color: "#ffffff", fontSize: 16 }); // button text
    expectStyle(root, { padding: 12 }); // GhostButton base
    expectStyle(root, { color: "#8a91a3", fontSize: 14 }); // ghost text
    // The crisis affordance keeps its distinct surface.
    expectStyle(root, { backgroundColor: "#242a38", borderRadius: 10, minHeight: 44 });
  });

  it("switches to register mode and back", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    expect(textOf(root)).toContain("Create account");
    expect(textOf(root)).toContain("Already have an account? Sign in");
    await pressLabel(root, "Already have an account? Sign in");
    // The BUTTON label is exactly "Sign in" again (not just present in the
    // switch link text).
    const { allText } = await import("../helpers/rtr");
    expect(allText(root)).toContain("Sign in");
  });

  it("does nothing without both fields", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await pressLabel(root, "Sign in");
    expect(api.saltFor).not.toHaveBeenCalled();
  });
});

describe("registration", () => {
  it("rejects passwords shorter than 8 characters before any network call", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "short");
    await pressLabel(root, "New here? Create an account");
    await pressLabel(root, "Create account");
    expect(Alert.alert).toHaveBeenCalledWith(
      "Password too short",
      expect.stringContaining("8 characters"),
    );
    expect(api.register).not.toHaveBeenCalled();
  });

  it("accepts a password of exactly 8 characters (the boundary)", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "12345678");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "12345678");
    await pressLabel(root, "Create account");
    await flush();
    expect(api.register).toHaveBeenCalledTimes(1);
    expect(vault.isUnlocked()).toBe(true);
  });

  it("derives keys locally, registers, stores the session and unlocks the vault", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", " alice ");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "correct horse");
    await pressLabel(root, "Create account");
    await flush();

    expect(deriveKeysAsync).toHaveBeenCalledWith("correct horse", expect.any(Buffer));
    expect(api.register).toHaveBeenCalledWith("alice", expect.any(String), expect.any(String));
    expect(api.setSession).toHaveBeenCalledWith("tok", "user-1", "alice");
    expect(vault.isUnlocked()).toBe(true);
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
    expect(refreshActiveDays).toHaveBeenCalledTimes(1);
    // The password field is cleared after success.
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
  });

  it("a successful REGISTRATION queues first-run onboarding (the navigator consumes it once)", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "correct horse");
    await pressLabel(root, "Create account");
    await flush();
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
    expect(takePendingOnboarding()).toBe(true);
    // One-shot: the pending flag is consumed, not sticky.
    expect(takePendingOnboarding()).toBe(false);
  });

  it("a failed registration queues NO onboarding", async () => {
    vi.mocked(api.register).mockRejectedValue(new ApiError(409, "username already taken"));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "correct horse");
    await pressLabel(root, "Create account");
    await flush();
    expect(markLoggedIn).not.toHaveBeenCalled();
    expect(takePendingOnboarding()).toBe(false);
  });

  it("a plain LOGIN never queues onboarding", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
    expect(takePendingOnboarding()).toBe(false);
  });

  it("zeroizes derived keys and keeps the vault locked when registration fails", async () => {
    vi.mocked(api.register).mockRejectedValue(new ApiError(409, "username already taken"));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "correct horse");
    await pressLabel(root, "Create account");
    await flush();

    expect(vault.isUnlocked()).toBe(false);
    // Calm mapped copy — no raw server detail in the dialog (audit fix).
    expect(Alert.alert).toHaveBeenCalledWith(
      "Couldn't create account",
      "That username is already taken. Try another, or sign in instead.",
    );
    expect(markLoggedIn).not.toHaveBeenCalled();
    // The failed attempt's key material is scrubbed, not left in memory.
    expect(lastDerived).not.toBeNull();
    expect(lastDerived!.masterKey.equals(Buffer.alloc(32))).toBe(true);
    expect(lastDerived!.authKey.equals(Buffer.alloc(lastDerived!.authKey.length))).toBe(true);
    expect(lastDerived!.dataKey.equals(Buffer.alloc(32))).toBe(true);
  });

  it("clears the busy flag after a completed attempt (a retry is possible)", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);

    // Second attempt goes through — busy was reset in the finally block.
    vi.mocked(api.login).mockClear();
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);
  });
});

describe("login", () => {
  it("fetches the salt, derives keys, logs in and unlocks", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();

    expect(api.saltFor).toHaveBeenCalledWith("alice");
    expect(deriveKeysAsync).toHaveBeenCalledWith("correct horse", Buffer.from(SALT_B64, "base64"));
    const expectedAuthKey = Buffer.from(`correct horse|${SALT_B64}`.padEnd(32, "\0")).toString("base64");
    expect(api.login).toHaveBeenCalledWith("alice", expectedAuthKey);
    expect(api.setSession).toHaveBeenCalledWith("tok", "user-1", "alice");
    expect(vault.isUnlocked()).toBe(true);
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
  });

  it("tolerates an empty user_id in the login response (vault binding is best-effort)", async () => {
    // A server that verifies the password but returns a blank id must not
    // block the unlock — the vault simply records no account binding.
    vi.mocked(api.login).mockResolvedValue({ token: "tok", user_id: "" } as never);
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("unlocks via the keyboard submit action too", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    const { submitInput } = await import("../helpers/rtr");
    await submitInput(root, "password");
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);
  });

  // M10: the disabled button alone is not enough — the keyboard submit path
  // still fires and must be a no-op while an attempt is in flight.
  it("ignores a keyboard submit while an attempt is already in flight (M10)", async () => {
    let resolveLogin!: (v: unknown) => void;
    vi.mocked(api.login).mockImplementation(() => new Promise((resolve) => (resolveLogin = resolve)));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    const { firePress, submitInput, act } = await import("../helpers/rtr");
    await firePress(root, "Sign in");
    await submitInput(root, "password"); // keyboard submit while busy
    expect(api.login).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveLogin?.({ token: "tok", user_id: "user-1" });
    });
    await flush();
    expect(api.login).toHaveBeenCalledTimes(1);
    expect(vault.isUnlocked()).toBe(true);
  });

  it("caches the salt after a successful login (enables offline unlock)", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(api.cacheSalt).toHaveBeenCalledWith("alice", SALT_B64);
  });

  it("offers crisis resources without an account", async () => {
    const nav = { navigate: vi.fn() };
    const root = await render(<LoginScreen navigation={nav as never} />);
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("reports wrong credentials without unlocking", async () => {
    vi.mocked(api.login).mockRejectedValue(new ApiError(401, "invalid credentials"));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "wrong password");
    await pressLabel(root, "Sign in");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Sign in failed", "That username or password didn't match.");
  });

  it("locks a previously unlocked vault when a new sign-in fails", async () => {
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.alloc(32, 9) });
    vi.mocked(api.login).mockRejectedValue(new ApiError(401, "invalid credentials"));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "whatever-long");
    await pressLabel(root, "Sign in");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
  });

  it("uses the padding keyboard behavior on iOS and none on Android", async () => {
    const reactNative = await import("react-native");
    const rtr = await import("../helpers/rtr");
    const root = await render(<LoginScreen />);
    const keyboard = root.root.findByType(reactNative.KeyboardAvoidingView);
    expect(keyboard.props.behavior).toBe("padding");
    expect(keyboard.props.style).toEqual(
      [{ flex: 1, justifyContent: "center" }, { backgroundColor: "#0f1115", padding: 32, gap: 12 }],
    );

    const original = reactNative.Platform.OS;
    (reactNative.Platform as { OS: string }).OS = "android";
    try {
      const androidRoot = await rtr.render(<LoginScreen />);
      const androidKeyboard = androidRoot.root.findByType(reactNative.KeyboardAvoidingView);
      expect(androidKeyboard.props.behavior).toBeUndefined();
    } finally {
      (reactNative.Platform as { OS: string }).OS = original;
    }
  });

  it("cleans up when key derivation itself fails", async () => {
    vi.mocked(deriveKeysAsync).mockImplementation(async () => {
      throw new Error("salt must be at least 8 bytes");
    });
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "whatever-long");
    await pressLabel(root, "Sign in");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(Alert.alert).toHaveBeenCalledWith("Sign in failed", "salt must be at least 8 bytes");
    // Nothing was derived, so nothing needed zeroizing — and the flow ended
    // cleanly (busy reset: another attempt is accepted).
    await typeInto(root, "password", "whatever-long");
    await pressLabel(root, "Sign in");
    await flush();
    expect(Alert.alert).toHaveBeenCalledTimes(2);
  });
});

describe("register-mode edge cases", () => {
  it("trims the username and requires a password even in register mode", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "  ");
    await pressLabel(root, "New here? Create an account");
    await pressLabel(root, "Create account");
    expect(api.register).not.toHaveBeenCalled();
  });

  it("uses exactly 16 random salt bytes", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "long enough pw");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "long enough pw");
    await pressLabel(root, "Create account");
    await flush();
    const saltB64 = vi.mocked(api.register).mock.calls[0][1];
    expect(Buffer.from(saltB64, "base64")).toHaveLength(16);
  });

  it("keeps the register alert path unused for non-register failures", async () => {
    // Sanity: the short-password alert only fires in register mode.
    vi.mocked(api.login).mockRejectedValue(new ApiError(0, "offline"));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "tiny");
    await pressLabel(root, "Sign in");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Sign in failed", "Couldn't reach the server — check your connection.");
  });

  it("falls back to calm copy for non-Error failures", async () => {
    vi.mocked(api.login).mockRejectedValue("nope" as never);
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    // Was "unknown error"; the error-copy pass made the fallback a sentence.
    expect(Alert.alert).toHaveBeenCalledWith("Sign in failed", "Something went wrong — try again.");
  });

  it("renders the android keyboard behavior when the platform differs", async () => {
    const { Platform } = await import("react-native");
    const original = Platform.OS;
    (Platform as { OS: string }).OS = "android";
    try {
      const root = await render(<LoginScreen />);
      await flush();
      expect(textOf(root)).toContain("Sign in");
    } finally {
      (Platform as { OS: string }).OS = original;
    }
  });

  it("shows the busy spinner instead of the button label while signing in", async () => {
    let resolveLogin!: (v: unknown) => void;
    vi.mocked(api.login).mockImplementation(() => new Promise((resolve) => (resolveLogin = resolve)));
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Sign in");
    expect(textOf(root)).not.toContain("Sign in");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveLogin?.({ token: "tok", user_id: "user-1" });
    });
    await flush();
    expect(vault.isUnlocked()).toBe(true);
  });
});

describe("registration honesty (audit fix)", () => {
  it("shows the no-reset warning only in register mode", async () => {
    const root = await render(<LoginScreen />);
    await flush();
    expect(textOf(root)).not.toContain("There is no password reset.");
    await pressLabel(root, "New here? Create an account");
    expect(textOf(root)).toContain(
      "There is no password reset. If you forget this password, no one — including us — can recover your journal.",
    );
  });

  it("requires the confirmation to match before any network call", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "correct HORSE");
    // Live inline mismatch hint…
    expect(textOf(root)).toContain("Passwords don't match.");
    // …and a gate at submit.
    await pressLabel(root, "Create account");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Passwords don't match", expect.stringContaining("no reset"));
    expect(api.register).not.toHaveBeenCalled();
    // Fixing the typo clears the hint.
    await typeInto(root, "confirm password", "correct horse");
    expect(textOf(root)).not.toContain("Passwords don't match.");
  });

  it("shows the strength hint as the password improves (never shaming)", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "password", "abc");
    expect(textOf(root)).toContain("Password strength: weak.");
    expect(textOf(root)).toContain("aim for a short sentence");
    await typeInto(root, "password", "abcDEF12");
    expect(textOf(root)).toContain("Password strength: fair.");
    await typeInto(root, "password", "a very long passphrase with mixed Case and 123 !");
    expect(textOf(root)).toContain("Password strength: strong.");
    expect(textOf(root)).not.toContain("aim for a short sentence");
    // Login mode shows no hint.
    await pressLabel(root, "Already have an account? Sign in");
    expect(textOf(root)).not.toContain("Password strength:");
  });

  it("marks fields for password managers (new-password on register)", async () => {
    const root = await render(<LoginScreen />);
    await flush();
    expect(inputByPlaceholder(root, "password").props.textContentType).toBe("password");
    expect(inputByPlaceholder(root, "password").props.autoComplete).toBe("current-password");
    expect(inputByPlaceholder(root, "username").props.textContentType).toBe("username");
    await pressLabel(root, "New here? Create an account");
    expect(inputByPlaceholder(root, "password").props.textContentType).toBe("newPassword");
    expect(inputByPlaceholder(root, "password").props.autoComplete).toBe("new-password");
    expect(inputByPlaceholder(root, "confirm password").props.textContentType).toBe("newPassword");
  });

  it("every field has an explicit accessibilityLabel (not placeholder-only)", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    expect(inputByPlaceholder(root, "username").props.accessibilityLabel).toBe("Username");
    expect(inputByPlaceholder(root, "password").props.accessibilityLabel).toBe("Password");
    expect(inputByPlaceholder(root, "confirm password").props.accessibilityLabel).toBe("Confirm password");
  });
});

describe("passwordStrength heuristic", () => {
  it("scores length and variety without any library", async () => {
    const { passwordStrength } = await import("../../src/screens/LoginScreen");
    expect(passwordStrength("").label).toBe("weak");
    expect(passwordStrength("short").label).toBe("weak");
    expect(passwordStrength("eightchr").label).toBe("weak");
    expect(passwordStrength("Eightchr1").label).toBe("fair");
    expect(passwordStrength("a quite long lowercase sentence").label).toBe("fair");
    expect(passwordStrength("a Quite long sentence, with 5 things!").label).toBe("strong");
    expect(passwordStrength("weak").hint).toContain("Longer is stronger");
    expect(passwordStrength("a Quite long sentence, with 5 things!").hint).toBe("");
  });
});
