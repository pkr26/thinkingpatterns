/** LoginView: the zero-knowledge sign-in/register flows, the honest error
 *  mapping, the therapist-account rejection, and key hygiene on every
 *  failure path. Uses REAL crypto (the fixed salt makes keys
 *  deterministic; PBKDF2-600k runs in ~40 ms). */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactTestRenderer } from "react-test-renderer";
import { LoginView, passwordPolicyError } from "../src/views/LoginView";
import { hasSession } from "../src/api/client";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, typeInto } from "./helpers/rtr";

const SALT_B64 = "AAECAwQFBgcICQoLDA0ODw=="; // 16 bytes, from the shared vectors
const GOOD_PASSWORD = "correct horse battery staple";
/** Server account ids are 32-hex (uuid4().hex) — the contract adoptSession
 *  now enforces (W-5); fixtures must match it. */
const TEST_USER_ID = "0123456789abcdef0123456789abcdef";

const tokenResponse = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  token: "tok-1",
  user_id: TEST_USER_ID,
  expires_in: 86400,
  role: "user",
  ...overrides,
});

function authRoutes(overrides: { login?: Record<string, unknown>; register?: Record<string, unknown> } = {}): ReturnType<typeof stubFetch> {
  return stubFetch((url) => {
    if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
    if (url.endsWith("/auth/login")) {
      return jsonResponse(overrides.login ?? tokenResponse(), { status: (overrides.login?.__status as number) ?? 200 });
    }
    if (url.endsWith("/auth/register")) {
      return jsonResponse(overrides.register ?? tokenResponse(), { status: (overrides.register?.__status as number) ?? 200 });
    }
    return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
  });
}

beforeEach(() => {
  resetTestState();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("password policy", () => {
  it("requires 12+ characters and class variety below 16", () => {
    expect(passwordPolicyError("short")).toContain("at least 12");
    expect(passwordPolicyError("abcdefghijkl")).toContain("three of");
    expect(passwordPolicyError("abcdefghijkl99!")).toBeNull();
    expect(passwordPolicyError("aA1!aaaaaaaaaaaaaaaaa")).toBeNull();
  });

  it("L-6 shape rules (mobile parity, W-3): blocklisted words are rejected even with passing variety", () => {
    // 17 chars, three classes — passes length+variety, dies on "password":
    expect(passwordPolicyError("passwordpassword1!")).toContain("too common");
    expect(passwordPolicyError("MyJournal2026!x")).toContain("too common"); // "journal"
    expect(passwordPolicyError("correct-horse-MindPattern-7")).toContain("too common"); // "mindpattern"
    expect(passwordPolicyError("welcome-to-the-Jungle99")).toContain("too common"); // "welcome"
    expect(passwordPolicyError("qwerty123456!X")).toContain("too common"); // keyboard walk "qwer"
    expect(passwordPolicyError("12345678abcd!Q")).toContain("too common"); // keyboard walk "1234"
    expect(passwordPolicyError("zzzzzzzzzzzz!9Q")).toBeNull(); // repeated run, not the whole password
  });

  it("L-6: an entire-password single-character run is rejected", () => {
    // Only reachable above the variety floor with one class + 16+ chars:
    expect(passwordPolicyError("aaaaaaaaaaaaaaaa")).toContain("too common");
  });

  it("L-6: honest strong passphrases still pass", () => {
    expect(passwordPolicyError("correct horse battery staple")).toBeNull();
    expect(passwordPolicyError("quiet-morning-lantern-42")).toBeNull();
  });
});

describe("sign in", () => {
  it("derives keys, adopts the session, unlocks the vault, and reports success", async () => {
    authRoutes();
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "alice");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "alice" });
    expect(hasSession()).toBe(true);
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe(TEST_USER_ID);
  });

  it("wrong credentials show the server message and leave nothing behind", async () => {
    authRoutes({ login: { __status: 401, detail: "username or password is incorrect", code: "invalid_credentials" } });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "alice");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("username or password is incorrect");
  });

  it("a therapist account is refused — no session, no keys", async () => {
    authRoutes({ login: tokenResponse({ role: "therapist" }) });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "dr.smith");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("therapist portal");
  });

  it("W-5: a malformed server user_id is refused fail-closed — no session, no keys", async () => {
    // A hostile server can put anything in user_id; it must never reach
    // the vault owner binding, AAD contexts, or storage keys.
    authRoutes({ login: tokenResponse({ user_id: "user-7" }) });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "alice");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("invalid response");
  });

  it("W-5: a user_id carrying storage-key/AAD injection payloads is refused", async () => {
    for (const hostile of [
      `a".repeat(1)+"`, // JSON-array AAD smuggle attempt
      "../../etc/passwd",
      "x".repeat(64),
      "0123456789ABCDEF0123456789ABCDEF", // uppercase is outside the hex contract
      "",
    ]) {
      authRoutes({ login: tokenResponse({ user_id: hostile }) });
      const onSuccess = vi.fn();
      const root = await render(<LoginView onSuccess={onSuccess} />);
      await typeInto(root, "Username", "alice");
      await typeInto(root, "Password", GOOD_PASSWORD);
      await press(root, "Sign in");
      await settle();
      expect(onSuccess).not.toHaveBeenCalled();
      expect(hasSession()).toBe(false);
    }
  });

  it("rate limiting renders the retry window", async () => {
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      return jsonResponse({ detail: "too many", code: "rate_limited" }, { status: 429, headers: { "Retry-After": "30" } });
    });
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await typeInto(root, "Username", "alice");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(textOf(root)).toContain("about 30s");
  });

  it("client-side validation rejects a malformed username without a request", async () => {
    const mock = authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await typeInto(root, "Username", "no spaces allowed");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(textOf(root)).toContain("Username");
    expect(mock).not.toHaveBeenCalled();
  });
});

describe("register", () => {
  async function registerMode(root: ReactTestRenderer): Promise<void> {
    await press(root, "Create an account");
  }

  it("creates the account, unlocks, and reports success", async () => {
    authRoutes();
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await press(root, "Create journal");
    await settle();
    expect(onSuccess).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "newuser" });
    expect(vault.isUnlocked()).toBe(true);
  });

  it("W-5: a malformed user_id from register is refused fail-closed too", async () => {
    authRoutes({ register: tokenResponse({ user_id: "not-hex" }) });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await press(root, "Create journal");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("invalid response");
  });

  it("shows the policy error for a weak password", async () => {
    const mock = authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", "short");
    await typeInto(root, "Confirm password", "short");
    await press(root, "Create journal");
    await settle();
    expect(textOf(root)).toContain("at least 12");
    expect(mock).not.toHaveBeenCalled();
  });

  it("shows a mismatch error when the confirm differs", async () => {
    const mock = authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", "different-but-long-enough");
    await press(root, "Create journal");
    await settle();
    expect(textOf(root)).toContain("do not match");
    expect(mock).not.toHaveBeenCalled();
  });

  it("a taken name surfaces the conflict honestly", async () => {
    authRoutes({ register: { __status: 409, detail: "that username is taken", code: "conflict" } });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await registerMode(root);
    await typeInto(root, "Username", "taken");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await press(root, "Create journal");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("that username is taken");
  });
});
