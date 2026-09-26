/**
 * Therapist TOTP portal surface (2026-09-21 audit C-2/F-4, delivered
 * 2026-09-22): the LoginView second-factor step (totp_required → code
 * field → verified resend; the password survives ONLY inside that stage)
 * and the Account-security enrollment ladder (verifier-gated setup shows
 * the secret exactly once → confirm-with-code enable → disable with both
 * halves). Backend behavior is pinned end-to-end in
 * backend/tests/test_totp.py; these tests pin the PORTAL wiring.
 */
import { act } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    auth: {
      meta: vi.fn(async () => ({ sharing_available: true })),
      saltFor: vi.fn(async () => ({ salt: "QUJDREVGR0hJSktMTU5P" })),
      login: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
      registerTherapist: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
    },
    api: {
      me: vi.fn(async () => ({
        username: "drportal",
        display_name: "Dr. Portal",
        wrap_pub_key: "P".repeat(124),
        wrap_key_blob: "KQ==",
        totp_enabled: false,
      })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7 })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      accessLog: vi.fn(async () => []),
      totpSetup: vi.fn(async () => ({
        secret_base32: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        otpauth_uri: "otpauth://totp/MindPattern:drportal?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=MindPattern&algorithm=SHA1&digits=6&period=30",
      })),
      totpEnable: vi.fn(async () => null),
      totpDisable: vi.fn(async () => null),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({ state_seq: 7, stats: { patterns: [] } })),
    decryptMeasure: vi.fn(async () => null),
  };
});

const { auth, api } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const { ApiError } = await import("../src/api");
const { LoginView } = await import("../src/views/LoginView");
const { PatientsView } = await import("../src/views/PatientsView");
const { render, flush, textOf, press, typeInto } = await import("./helpers/rtr");

const session = {
  username: "drportal",
  userId: "therapist-1",
  noteKey: new Uint8Array(32),
  privateKey: {} as CryptoKey,
  publicKeyB64: "P".repeat(124),
};

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("LoginView TOTP step (2026-09-22)", () => {
  it("totp_required reveals the code field and resends with the code; the password survives only inside the stage", async () => {
    // First attempt: password half validates, server demands the code.
    mockedAuth.login.mockImplementationOnce(() => {
      throw Object.assign(new ApiError(401, "totp code required"), { code: "totp_required" });
    });
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    await press(root, "Sign in");
    await flush(6);
    // The code field appeared with the explanatory prompt…
    expect(textOf(root)).toContain("Enter the 6-digit code from your authenticator app.");
    expect(root.root.findAllByType("input").some((i) => i.props.placeholder === "123456")).toBe(true);
    // …and the first login went out WITHOUT a code.
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", expect.any(String), undefined);

    // Second attempt: a valid code completes the sign-in.
    await typeInto(root, "Authenticator code", "123456");
    await press(root, "Verify code");
    await flush(6);
    expect(mockedAuth.login).toHaveBeenLastCalledWith(expect.any(String), "drportal", expect.any(String), "123456");
    expect(onReady).toHaveBeenCalled();
  });

  it("a wrong code keeps the stage armed (retry without retyping the password); a wrong password never shows the code field", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    // Plain invalid credentials: no TOTP stage.
    mockedAuth.login.mockImplementationOnce(() => {
      throw Object.assign(new ApiError(401, "invalid credentials"), { code: "invalid_credentials" });
    });
    await press(root, "Sign in");
    await flush(6);
    expect(root.root.findAllByType("input").some((i) => i.props.placeholder === "123456")).toBe(false);
    expect(textOf(root)).toContain("invalid credentials");

    // Fresh mount: totp_required arms the stage…
    const root2 = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root2, "Username", "drportal");
    await typeInto(root2, "Password", "right-password");
    mockedAuth.login.mockImplementationOnce(() => {
      throw Object.assign(new ApiError(401, "totp code required"), { code: "totp_required" });
    });
    await press(root2, "Sign in");
    await flush(6);
    expect(root2.root.findAllByType("input").some((i) => i.props.placeholder === "123456")).toBe(true);
    // …a stale code keeps it armed with the honest message…
    await typeInto(root2, "Authenticator code", "111111");
    mockedAuth.login.mockImplementationOnce(() => {
      throw Object.assign(new ApiError(401, "invalid totp code"), { code: "totp_code_invalid" });
    });
    await press(root2, "Verify code");
    await flush(6);
    expect(textOf(root2)).toContain("That code was wrong or already used");
    expect(root2.root.findAllByType("input").some((i) => i.props.placeholder === "123456")).toBe(true);
    // …and the retry still sends the code-shaped login.
    expect(mockedAuth.login).toHaveBeenLastCalledWith(expect.any(String), "drportal", expect.any(String), "111111");
  });
});

describe("PatientsView TOTP enrollment (2026-09-22)", () => {
  const openSecurityPanel = async (root: Awaited<ReturnType<typeof render>>): Promise<void> => {
    await press(root, "Show account security");
    await flush();
  };

  it("setup shows the secret exactly once and enable confirms with the code", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    // The panel asked the server for the honest state.
    expect(mockedApi.me).toHaveBeenCalled();
    expect(textOf(root)).toContain("Two-factor authentication");

    await typeInto(root, "Current password (to authorize setup)", "deep-password-1");
    await press(root, "Set up authenticator");
    await flush(6);
    // The secret and otpauth URI are rendered exactly once…
    expect(textOf(root)).toContain("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    expect(textOf(root)).toContain("otpauth://totp/MindPattern:drportal");
    expect(mockedApi.totpSetup).toHaveBeenCalledTimes(1);
    // …not yet enabled: no enable call happened.
    expect(mockedApi.totpEnable).not.toHaveBeenCalled();

    await typeInto(root, "Current password (to authorize setup)", "deep-password-1");
    await typeInto(root, "6-digit code from the app", "123456");
    await press(root, "Enable two-factor");
    await flush(6);
    expect(mockedApi.totpEnable).toHaveBeenCalledWith(expect.any(String), "123456");
    expect(textOf(root)).toContain("Two-factor authentication is on");
    // The one-time secret is gone from the tree after enabling.
    expect(textOf(root)).not.toContain("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
  });

  it("an enabled account offers the both-halves disable flow", async () => {
    (mockedApi.me as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      username: "drportal",
      display_name: "Dr. Portal",
      wrap_pub_key: "P".repeat(124),
      wrap_key_blob: "KQ==",
      totp_enabled: true,
    }));
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    expect(textOf(root)).toContain("Enabled — sign-in requires your password and a current 6-digit code.");

    await typeInto(root, "Current password (to disable two-factor)", "deep-password-1");
    await typeInto(root, "6-digit code (to disable two-factor)", "654321");
    await press(root, "Disable two-factor");
    await flush(6);
    expect(mockedApi.totpDisable).toHaveBeenCalledWith(expect.any(String), "654321");
    expect(textOf(root)).toContain("Two-factor authentication is off");
  });
});
