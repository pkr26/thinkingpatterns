/**
 * Deep-mutation pins for LoginScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class:
 *  - passwordStrength boundary vectors: the score<=2 / score<=4 band edges,
 *    the length-8/14 points, every Regex character-class mutation, and the
 *    case-variety && gate (|| mutant),
 *  - signInFailureCopy's `instanceof ApiError` gate (a non-ApiError object
 *    carrying status 401 must get the generic fallback, not the 401 copy),
 *  - the confirm-field lifecycle: absent in login mode, no mismatch hint
 *    while confirm is empty, cleared on mode toggle and after success,
 *  - the strength-hint gate (register mode + NON-empty password),
 *  - the vault's ownerUserId binding after login and registration,
 *  - node-exact style overlays (subtitle / strength / mismatch / no-reset):
 *    the global expectStyle matcher hits ANY node, and GhostButton's text
 *    shares {color: muted, fontSize: 14} — so overlays are pinned to their
 *    own Text nodes here.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Text, TextInput } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
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

const { api } = await import("../../src/api/client");
const { deriveKeysAsync } = await import("../../src/crypto/MindPatternCrypto");
const { LoginScreen, passwordStrength } = await import("../../src/screens/LoginScreen");
const { takePendingOnboarding } = await import("../../src/onboarding");
const { vault } = await import("../../src/vault");
const { render, flush, textOf, allText, pressLabel, typeInto, inputByPlaceholder } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

/** Flatten a Text node's children (they may be arrays) to its exact string. */
const flat = (children: unknown): string => {
  if (typeof children === "string") return children;
  if (typeof children === "number") return String(children);
  if (Array.isArray(children)) return children.map(flat).join("");
  return "";
};

/** The Text node whose flattened content satisfies the match (string = exact). */
function textNode(root: Awaited<ReturnType<typeof render>>, match: string | ((s: string) => boolean)) {
  const pred = typeof match === "string" ? (s: string) => s === match : match;
  const node = root.root.findAllByType(Text).find((n) => pred(flat(n.props.children)));
  if (!node) throw new Error(`no matching Text node for ${String(match)}: ${allText(root).join(" | ")}`);
  return node;
}

beforeEach(() => {
  resetApi(api as never);
  vi.mocked(deriveKeysAsync).mockReset();
  vi.mocked(deriveKeysAsync).mockImplementation(async (password: string, salt: Buffer) => ({
    masterKey: Buffer.alloc(32, 1),
    authKey: Buffer.from(`${password}|${salt.toString("base64")}`.padEnd(32, "\0")),
    dataKey: Buffer.alloc(32, 3),
  }));
  markLoggedIn.mockClear();
  refreshActiveDays.mockClear();
  Alert.alert.mockClear();
  vault.lock();
  takePendingOnboarding(); // drain leftovers so one test cannot leak into the next
  sessionState = { markLoggedIn, refreshActiveDays };
});

describe("LoginScreen pins: passwordStrength boundary vectors", () => {
  it("a 2-score password is weak at every variety combination (band edge score <= 2)", async () => {
    // Each vector scores exactly 2 with no length points; every condition,
    // regex, and the `score < 2` boundary flip it to fair (3).
    expect(passwordStrength("aB1").label).toBe("weak"); // case + digit, len 3 (length>=8 → true mutant)
    expect(passwordStrength("1!").label).toBe("weak"); // digit + symbol, no letters (case cond → true)
    expect(passwordStrength("a1!").label).toBe("weak"); // lowercase present, no upper (&& → || mutant)
    expect(passwordStrength("ABC1!").label).toBe("weak"); // uppercase-only (/[a-z]/ → /[^a-z]/ mutant)
    expect(passwordStrength("abc1!").label).toBe("weak"); // lowercase-only (/[A-Z]/ → /[^A-Z]/ mutant)
    expect(passwordStrength("aB!").label).toBe("weak"); // case + symbol, no digit (digit cond → true)
    expect(passwordStrength("aB12").label).toBe("weak"); // case + digit, no symbol (symbol cond → true AND /[^a-zA-Z0-9]/ → /[a-zA-Z0-9]/ mutant)
  });

  it("length points are exact: the 8/14 boundaries and the digit class", async () => {
    // 8 chars, all four varieties + len8 = 4 → fair, with its exact hint.
    expect(passwordStrength("aB1!efgh").label).toBe("fair");
    expect(passwordStrength("aB1!efgh").hint).toBe("Good start — more length or a symbol makes it stronger.");
    // Exactly 14 chars with all five varieties → strong (>= 14 → > 14 drops it to fair).
    expect(passwordStrength("abcdeABCDE123!").label).toBe("strong");
    // 14 digits: len8 + len14 + digit = 3 → fair (/\d/ → /\D/ loses the digit point → weak).
    expect(passwordStrength("12345678901234").label).toBe("fair");
  });
});

describe("LoginScreen pins: signInFailureCopy instanceof gate", () => {
  it("a non-ApiError object carrying status 401 gets the generic fallback, never the 401 copy", async () => {
    // `err instanceof ApiError → true` would read .status off ANY rejection;
    // only real ApiErrors may map to the calm status copy.
    vi.mocked(api.login).mockRejectedValue({ status: 401 } as never);
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Sign in failed", "Something went wrong — try again.");
    expect(Alert.alert).not.toHaveBeenCalledWith("Sign in failed", "That username or password didn't match.");
  });
});

describe("LoginScreen pins: confirm-field lifecycle", () => {
  it("login mode renders no confirm input at all", async () => {
    const root = await render(<LoginScreen />);
    await flush();
    expect(root.root.findAllByType(TextInput)).toHaveLength(2);
    expect(
      root.root.findAllByType(TextInput).some((n) => n.props.placeholder === "confirm password"),
    ).toBe(false);
  });

  it("an empty confirm never shows the mismatch hint — even with a password typed", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    // Register mode, nothing typed: no hint (|| / cond→true mutants render one).
    expect(textOf(root)).not.toContain("Passwords don't match.");
    // Password typed, confirm still empty: still no hint (confirm.length > 0
    // cond / >= 0 / whole-condition mutants all render one here).
    await typeInto(root, "password", "correct horse");
    expect(textOf(root)).not.toContain("Passwords don't match.");
    // And login mode with a password typed never shows it either.
    await pressLabel(root, "Already have an account? Sign in");
    await typeInto(root, "password", "another one");
    expect(textOf(root)).not.toContain("Passwords don't match.");
  });

  it("register mode with an EMPTY password shows no strength hint", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    expect(textOf(root)).not.toContain("Password strength:");
  });

  it("toggling modes clears the confirm field", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "confirm password", "abc");
    await pressLabel(root, "Already have an account? Sign in");
    await pressLabel(root, "New here? Create an account");
    expect((inputByPlaceholder(root, "confirm password").props as { value: string }).value).toBe("");
  });

  it("a successful registration clears the confirm field too", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "password", "Correct horse!");
    await typeInto(root, "confirm password", "Correct horse!");
    await pressLabel(root, "Create account");
    await flush();
    expect((inputByPlaceholder(root, "confirm password").props as { value: string }).value).toBe("");
  });
});

describe("LoginScreen pins: vault account binding", () => {
  it("a successful login binds the vault to the server-verified user id", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Sign in");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("user-1");
  });

  it("a successful registration binds the vault to the new user id", async () => {
    const root = await render(<LoginScreen />);
    await typeInto(root, "username", "alice");
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "password", "Correct horse!");
    await typeInto(root, "confirm password", "Correct horse!");
    await pressLabel(root, "Create account");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("user-1");
  });
});

describe("LoginScreen pins: node-exact style overlays", () => {
  it("the subtitle carries its themed overlay on its own node", async () => {
    const root = await render(<LoginScreen />);
    await flush();
    const node = textNode(root, (s) => s.includes("Your patterns, from your words."));
    expect(node.props.style).toEqual(
      [{ textAlign: "center", marginBottom: 24 }, { color: "#8a91a3", fontSize: 14 }],
    );
  });

  it("the strength line: exact style and exact node text with no hint fragment", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "password", "abc");
    const weakNode = textNode(root, (s) => s.startsWith("Password strength:"));
    expect(weakNode.props.style).toEqual({ color: "#8a91a3", fontSize: 12 });
    // Strong band: hint is "" — the node text must end at the period.
    await typeInto(root, "password", "a Quite long sentence, with 5 things!");
    expect(allText(root)).toContain("Password strength: strong.");
  });

  it("the mismatch line is error-colored on its own node", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    await typeInto(root, "password", "correct horse");
    await typeInto(root, "confirm password", "correct HORSE");
    const node = textNode(root, "Passwords don't match.");
    expect(node.props.style).toEqual({ color: "#ff6b6b", fontSize: 12 });
  });

  it("the no-reset warning carries the body overlay on its own node", async () => {
    const root = await render(<LoginScreen />);
    await pressLabel(root, "New here? Create an account");
    const node = textNode(root, (s) => s.includes("There is no password reset."));
    expect(node.props.style).toEqual({ color: "#b6bdc9", fontSize: 13, lineHeight: 19 });
  });
});
