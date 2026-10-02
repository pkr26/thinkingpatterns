/** LoginView: the zero-knowledge sign-in/register flows, the honest error
 *  mapping, the therapist-account rejection, and key hygiene on every
 *  failure path. Uses REAL crypto (the fixed salt makes keys
 *  deterministic; PBKDF2-600k runs in ~40 ms). The v2 describe block
 *  covers the 2026-09-26 key envelope: registration default, the
 *  register→login→unlock roundtrip, the unchanged v1 path, response
 *  tolerance, and both fail-closed envelope failures. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactTestRenderer } from "react-test-renderer";
import { LoginView, passwordPolicyError } from "../src/views/LoginView";
import { hasSession } from "../src/api/client";
import { deriveMasterKey, fromBase64, toBase64 } from "../src/crypto/core";
import { createRegistrationEnvelope } from "../src/crypto/envelope";
import { derivePatientKeys } from "../src/crypto/keys";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { isDisabled, press, render, setCheckbox, settle, textOf, typeInto } from "./helpers/rtr";

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

/** The DPIA age gate (clinical review 2026-09-27): registration requires
 *  the honest 18+ self-declaration before the register action enables —
 *  every register-flow test ticks it after filling the fields. */
async function confirmAge(root: ReactTestRenderer): Promise<void> {
  await setCheckbox(root, "I am 18 or older", true);
}

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
    expect(passwordPolicyError("correct-horse-Fathom-7")).toContain("too common"); // "mindpattern"
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
    await confirmAge(root);
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
    await confirmAge(root);
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
    await confirmAge(root);
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
    await confirmAge(root);
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
    await confirmAge(root);
    await press(root, "Create journal");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("that username is taken");
  });
});

/** The DPIA-required age gate (clinical review 2026-09-27): an honest
 *  18+ self-declaration — the register action stays disabled until the
 *  box is ticked, the guard holds under synthetic submits, sign-in is
 *  unaffected, and NOTHING extra is stored or sent. */
describe("age gate (DPIA control, 2026-09-27)", () => {
  async function registerMode(root: Awaited<ReturnType<typeof render>>): Promise<void> {
    await press(root, "Create an account");
  }

  it("the register button stays disabled until the 18+ declaration is ticked, then enables", async () => {
    authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    expect(textOf(root)).toContain("I am 18 or older");
    expect(isDisabled(root, "Create journal")).toBe(true);
    await setCheckbox(root, "I am 18 or older", true);
    expect(isDisabled(root, "Create journal")).toBe(false);
  });

  it("a submit path that skips the disabled button (Enter / synthetic) is stopped by the guard, with no request", async () => {
    const mock = authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "newuser");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    // The form's own onSubmit (what Enter fires) must not bypass the gate.
    const form = root.root.findAllByType("form")[0]!;
    await form.props.onSubmit({ preventDefault: () => undefined });
    await settle();
    expect(textOf(root)).toContain("18 or older");
    expect(mock).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
  });

  it("sign-in never carries the gate — no checkbox, button enabled", async () => {
    authRoutes();
    const root = await render(<LoginView onSuccess={() => undefined} />);
    expect(root.root.findAllByType("input").some((n) => n.props.type === "checkbox")).toBe(false);
    expect(isDisabled(root, "Sign in")).toBe(false);
  });
});

/** v2 key-envelope flows (2026-09-26): registration defaults to the random
 *  data key + wrap; sign-in branches on key_scheme; v1 accounts keep the
 *  exact pre-wave derivation and NEVER pay the envelope round trip. Real
 *  crypto against stubbed fetch (the api-client seam, like the suites
 *  above). */
describe("v2 key envelope (2026-09-26)", () => {
  const decodeB64Length = (text: string): number => atob(text).length;

  async function registerMode(root: Awaited<ReturnType<typeof render>>): Promise<void> {
    await press(root, "Create an account");
  }

  it("registration DEFAULTS to v2: random data key + kdf_params + 60-byte wrapped_data_key", async () => {
    const bodies: Record<string, unknown> = {};
    stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/register")) {
        bodies.register = JSON.parse(String(init.body));
        return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "v2user");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await confirmAge(root);
    await press(root, "Create journal");
    await settle();
    const body = bodies.register as Record<string, unknown>;
    // Both-or-neither on the wire, the documented canonical params blob,
    // and the exact 60-byte envelope.
    expect(body.kdf_params).toEqual({ algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 });
    expect(decodeB64Length(String(body.wrapped_data_key))).toBe(60);
    // The vault holds a RANDOM key, not the v1 password-derived label.
    expect(vault.isUnlocked()).toBe(true);
    const v1 = await derivePatientKeys(await deriveMasterKey(GOOD_PASSWORD, fromBase64(String(body.salt))));
    expect(toBase64(vault.get().dataKey)).not.toBe(toBase64(v1.dataKey));
  });

  it("register → login → unlock ROUNDTRIP: the same random key comes back through the envelope", async () => {
    // Pin the registration salt: a fresh sign-in derives its master from
    // /auth/salt, and the envelope must name the SAME salt (the production
    // invariant — the account has exactly one salt).
    const platform = await import("../src/platform");
    const fixedSalt = fromBase64(SALT_B64);
    const randomSpy = vi.spyOn(platform, "randomBytes").mockImplementation((length: number) => {
      const out = new Uint8Array(new ArrayBuffer(length));
      out.set(fixedSalt.subarray(0, length));
      return out;
    });
    let registerBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/register")) {
        registerBody = JSON.parse(String(init.body));
        return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      }
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        return jsonResponse({
          key_scheme: "v2",
          salt: registerBody.salt,
          kdf_params: registerBody.kdf_params,
          wrapped_data_key: registerBody.wrapped_data_key,
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    // Register and snapshot the key this session holds.
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await registerMode(root);
    await typeInto(root, "Username", "v2user");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await confirmAge(root);
    await press(root, "Create journal");
    await settle();
    const registeredKey = toBase64(vault.get().dataKey);

    // A fresh sign-in on the same stubbed account: login says v2 → the
    // envelope is fetched → unwrapped locally → the vault ends up holding
    // the IDENTICAL random key the registration drew.
    const onLogin = vi.fn();
    const root2 = await render(<LoginView onSuccess={onLogin} />);
    await typeInto(root2, "Username", "v2user");
    await typeInto(root2, "Password", GOOD_PASSWORD);
    await press(root2, "Sign in");
    await settle();
    expect(onLogin).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "v2user" });
    expect(vault.isUnlocked()).toBe(true);
    expect(toBase64(vault.get().dataKey)).toBe(registeredKey);
    randomSpy.mockRestore();
  });

  it("C-1 (2026-09-28): v2 sign-in on FRESH module state installs the session BEFORE the envelope fetch", async () => {
    // The roundtrip test above cannot catch the fresh-page-load bug: its
    // register half leaves the module session installed, so the sign-in
    // half's key-envelope fetch was already authenticated by accident.
    // This test resets the module registry first — session, vault, and
    // view all come from virgin module state, the exact world of every
    // real page load. Before the fix, the envelope fetch threw "not
    // signed in" before any HTTP request left the tab and the sign-in
    // dead-ended on login.envelopeUnlockWeb.
    const saltBytes = fromBase64(SALT_B64);
    const master = await deriveMasterKey(GOOD_PASSWORD, saltBytes);
    const envelope = await createRegistrationEnvelope(master, saltBytes, "v2user");
    const envelopeAuth: (string | undefined)[] = [];
    stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        envelopeAuth.push((init.headers as Record<string, string>)?.["Authorization"]);
        return jsonResponse({
          key_scheme: "v2",
          salt: SALT_B64,
          kdf_params: envelope.kdfParams,
          wrapped_data_key: envelope.wrappedDataKeyB64,
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });

    vi.resetModules();
    const { LoginView: FreshLoginView } = await import("../src/views/LoginView");
    const { hasSession: freshHasSession } = await import("../src/api/client");
    const { vault: freshVault } = await import("../src/vault");
    expect(freshHasSession()).toBe(false); // the fresh-page-load world

    const onLogin = vi.fn();
    const root = await render(<FreshLoginView onSuccess={onLogin} />);
    await typeInto(root, "Username", "v2user");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();

    // The envelope fetch left the tab AUTHENTICATED with the fresh token.
    expect(envelopeAuth).toEqual(["Bearer tok-1"]);
    expect(onLogin).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "v2user" });
    expect(freshVault.isUnlocked()).toBe(true);
    expect(toBase64(freshVault.get().dataKey)).toBe(toBase64(envelope.dataKey));
  });

  it("C-1 rollback: a v2 sign-in whose envelope will not open leaves NO session behind", async () => {
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        // Names a DIFFERENT salt: the unwrap cannot succeed by construction.
        return jsonResponse({
          key_scheme: "v2",
          salt: toBase64(new Uint8Array(16).fill(7)),
          kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 100000 },
          wrapped_data_key: envelopeGarbage(),
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    vi.resetModules();
    const { LoginView: FreshLoginView } = await import("../src/views/LoginView");
    const { hasSession: freshHasSession } = await import("../src/api/client");

    const onLogin = vi.fn();
    const root = await render(<FreshLoginView onSuccess={onLogin} />);
    await typeInto(root, "Username", "v2user");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();

    expect(onLogin).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("key envelope could not be opened");
    expect(freshHasSession()).toBe(false); // the pre-installed session was rolled back
  });

  /** 60 bytes of base64 garbage shaped like a wrapped key. */
  function envelopeGarbage(): string {
    return toBase64(globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(60))));
  }

  it("V1 UNCHANGED: no key_scheme → the derived data key, and NO envelope request at all", async () => {
    const urls: string[] = [];
    stubFetch((url) => {
      urls.push(url);
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse());
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await typeInto(root, "Username", "legacy");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(vault.isUnlocked()).toBe(true);
    expect(urls.some((url) => url.endsWith("/auth/key-envelope"))).toBe(false);
    // And the key is exactly the pre-wave derivation (the shared contract).
    const expected = await derivePatientKeys(await deriveMasterKey(GOOD_PASSWORD, fromBase64(SALT_B64)));
    expect(toBase64(vault.get().dataKey)).toBe(toBase64(expected.dataKey));
    // key_scheme "v1" (an explicit wave-era server answer) behaves the same.
  });

  it("token/response tolerance: extra unknown fields (key_scheme, jti/purpose/ksv-like claims) adopt cleanly", async () => {
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) {
        return jsonResponse(tokenResponse({
          key_scheme: "v1",
          // A future backend may add token claims/metadata to the response;
          // the client treats the bearer as an opaque string and must not
          // care (2026-09-26 token tolerance pin).
          jti: "0123456789abcdef0123456789abcdef",
          purpose: "patient",
          ksv: 1,
          future_field: { nested: true },
        }));
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "tolerant");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "tolerant" });
    expect(vault.isUnlocked()).toBe(true);
  });

  it("a v2 account whose envelope cannot be fetched leaves NOTHING behind", async () => {
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) return jsonResponse({ detail: "server unhappy" }, { status: 500 });
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "v2broken");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("key envelope could not be opened");
  });

  it("a TAMPERED envelope fails closed the same way (no session, no keys)", async () => {
    // Build an envelope for this account, corrupt one ciphertext byte —
    // deterministic, before any UI mounts.
    const master = await deriveMasterKey(GOOD_PASSWORD, fromBase64(SALT_B64));
    const envelope = await createRegistrationEnvelope(master, fromBase64(SALT_B64), "v2tamper");
    const bytes = fromBase64(envelope.wrappedDataKeyB64);
    bytes[20]! ^= 0x01;
    const tamperedB64 = toBase64(bytes);
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        return jsonResponse({
          key_scheme: "v2",
          salt: SALT_B64,
          kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 },
          wrapped_data_key: tamperedB64,
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const onSuccess = vi.fn();
    const root = await render(<LoginView onSuccess={onSuccess} />);
    await typeInto(root, "Username", "v2tamper");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("key envelope could not be opened");
  });

  it("2026-09-28 audit (LOW): a v2 envelope declaring NON-default iterations is unwrapped at THOSE params", async () => {
    // Mobile keyScheme.ts parity: the params and the KEK come from one
    // source. The envelope below was wrapped under the 800k master; the
    // pre-fix unwrap always used the 600k login master and could never
    // open it.
    const saltBytes = fromBase64(SALT_B64);
    const master800 = await deriveMasterKey(GOOD_PASSWORD, saltBytes, 800_000);
    const envelope = await createRegistrationEnvelope(master800, saltBytes, "v2user", {
      algorithm: "pbkdf2-sha256",
      version: 1,
      iterations: 800_000,
    });
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        return jsonResponse({
          key_scheme: "v2",
          salt: SALT_B64,
          kdf_params: envelope.kdfParams,
          wrapped_data_key: envelope.wrappedDataKeyB64,
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const onLogin = vi.fn();
    const root = await render(<LoginView onSuccess={onLogin} />);
    await typeInto(root, "Username", "v2user");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onLogin).toHaveBeenCalledWith({ userId: TEST_USER_ID, username: "v2user" });
    expect(vault.isUnlocked()).toBe(true);
    expect(toBase64(vault.get().dataKey)).toBe(toBase64(envelope.dataKey));
  });

  it("2026-09-28 audit (LOW): an argon2id envelope fails with the explicit unsupported-parameters error", async () => {
    // This build derives PBKDF2 only (no native WebCrypto Argon2). The
    // honest verdict names THAT — never a misleading envelope/generic
    // invalid-credentials-shaped failure — and nothing is left behind.
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/login")) return jsonResponse(tokenResponse({ key_scheme: "v2" }));
      if (url.endsWith("/auth/key-envelope")) {
        return jsonResponse({
          key_scheme: "v2",
          salt: SALT_B64,
          kdf_params: { algorithm: "argon2id", version: 1, iterations: 3, memory_kib: 65536, parallelism: 1 },
          wrapped_data_key: toBase64(new Uint8Array(new ArrayBuffer(60))),
        });
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const onLogin = vi.fn();
    const root = await render(<LoginView onSuccess={onLogin} />);
    await typeInto(root, "Username", "argon");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await press(root, "Sign in");
    await settle();
    expect(onLogin).not.toHaveBeenCalled();
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("this browser cannot derive");
  });

  it("2026-09-28 audit (LOW): a register response that does NOT echo key_scheme v2 keeps the DERIVED v1 key", async () => {
    // The register response is the only authority on what was stored. A
    // backend that ignored the envelope pair stored no wrapped_data_key —
    // adopting the random key anyway would seal every entry under a key
    // no unlock path can ever reproduce (the login path's documented
    // ambiguity defense, mirrored).
    let registerBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT_B64 });
      if (url.endsWith("/auth/register")) {
        registerBody = JSON.parse(String(init.body));
        return jsonResponse(tokenResponse()); // NO key_scheme echo
      }
      return jsonResponse({ detail: "unmatched route", code: "not_found" }, { status: 404 });
    });
    const root = await render(<LoginView onSuccess={() => undefined} />);
    await press(root, "Create an account");
    await typeInto(root, "Username", "v1echo");
    await typeInto(root, "Password", GOOD_PASSWORD);
    await typeInto(root, "Confirm password", GOOD_PASSWORD);
    await setCheckbox(root, "I am 18 or older", true);
    await press(root, "Create journal");
    await settle();
    expect(vault.isUnlocked()).toBe(true);
    // v1 semantics: the vault holds the password-DERIVED label — the
    // envelope upload happened, but without the echo the random key the
    // server never stored is discarded, not adopted.
    const expected = await derivePatientKeys(await deriveMasterKey(GOOD_PASSWORD, fromBase64(String(registerBody.salt))));
    expect(toBase64(vault.get().dataKey)).toBe(toBase64(expected.dataKey));
    expect(registerBody.wrapped_data_key).toBeTruthy(); // the pair was still sent
  });
});
