/**
 * TherapistShareScreen: the patient-side sharing flow — consent list
 * rendering, pairing lookup (found / not found / expired session), the
 * re-authenticated grant (the wrap is the REAL shipping code; the produced
 * envelope is unwrapped in-test back to the vault's data key), revoke, and
 * the honest error branches.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import nodeCrypto from "node:crypto";
import { Alert } from "react-native";
import { deriveWrapKek, WRAP_CONTEXT } from "../../src/crypto/sharing";
import { buildAad, decrypt } from "../../src/crypto/envelope";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock } = await import("../helpers/apiMock");
  return { ...actual, api: makeApiMock() };
});

const authKey = Buffer.alloc(32, 2);
const authKeyB64 = () => authKey.toString("base64");
const verifyPasswordForVault = vi.fn(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
vi.mock("../../src/reauth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/reauth")>();
  return {
    ...actual,
    verifyPasswordForVault: (...args: unknown[]) => verifyPasswordForVault(...(args as [string])),
  };
});

const { api, ApiError: RealApiError } = await import("../../src/api/client");
const { TherapistShareScreen } = await import("../../src/screens/TherapistShareScreen");
const { vault } = await import("../../src/vault");
const {
  render,
  flush,
  textOf,
  pressLabel,
  typeInto,
  pressAlertButton,
  lastAlert,
  inputByPlaceholder,
  touchableByLabel,
} = await import("../helpers/rtr");
const { resetApi, ApiError } = await import("../helpers/apiMock");

// A REAL therapist keypair so the screen's genuine wrap path succeeds and
// the produced envelope can be unwrapped in-test.
const therapistPriv = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const THERAPIST_PUB = therapistPriv.publicKey.export({ format: "der", type: "spki" }).toString("base64");
const THERAPIST_ID = "t".repeat(32);

const dataKey = Buffer.alloc(32, 7);
const keys = { masterKey: Buffer.alloc(32), authKey, dataKey };
const nav = { popToTop: vi.fn(), navigate: vi.fn() };

const activeConsent = {
  id: "a".repeat(32),
  therapist_id: THERAPIST_ID,
  display_name: "Dr. Active",
  username: "dractive",
  status: "active",
  granted_at: "2026-09-01T10:00:00Z",
  revoked_at: null,
};
const revokedConsent = {
  ...activeConsent,
  id: "b".repeat(32),
  display_name: "Dr. Past",
  status: "revoked",
  revoked_at: "2026-09-10T10:00:00Z",
};

/** Unwrap a grant produced by the screen, therapist-side, in-test. */
function unwrapGrant(wrappedKeyB64: string, ephemeralPubB64: string): Buffer {
  const shared = nodeCrypto.diffieHellman({
    privateKey: therapistPriv.privateKey,
    publicKey: nodeCrypto.createPublicKey({
      key: Buffer.from(ephemeralPubB64, "base64"),
      format: "der",
      type: "spki",
    }),
  });
  const kek = deriveWrapKek(
    shared,
    Buffer.from(ephemeralPubB64, "base64"),
    Buffer.from(THERAPIST_PUB, "base64"),
  );
  return decrypt(kek, Buffer.from(wrappedKeyB64, "base64"), buildAad(WRAP_CONTEXT, "user-1", THERAPIST_ID));
}

beforeEach(() => {
  resetApi(api as never);
  vi.mocked(api.listConsents).mockResolvedValue([]);
  vi.mocked(api.pairingLookup).mockResolvedValue({
    therapist_id: THERAPIST_ID,
    display_name: "Dr. Real",
    wrap_pub_key: THERAPIST_PUB,
  });
  Alert.alert.mockClear();
  nav.navigate.mockClear();
  vault.lock();
  vault.unlock({ ...keys });
  verifyPasswordForVault.mockClear();
  verifyPasswordForVault.mockImplementation(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
});

async function reauth(root: Awaited<ReturnType<typeof render>>, password = "correct horse"): Promise<void> {
  await typeInto(root, "password", password);
  await pressLabel(root, "Confirm with password");
  await flush();
}

describe("consent list", () => {
  it("fails closed when the server has not enabled verified clinician sharing", async () => {
    vi.mocked(api.meta).mockResolvedValue({ sharing_available: false } as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Therapist sharing unavailable");
    expect(textOf(root)).not.toContain("Add your therapist");
    expect(vi.mocked(api.listConsents)).not.toHaveBeenCalled();
  });

  it("renders the empty state when nothing is shared", async () => {
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("You are not sharing with anyone");
    expect(textOf(root)).toContain("Add your therapist");
  });

  it("renders active and revoked consents; only active ones can be stopped", async () => {
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent, revokedConsent] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Dr. Active");
    expect(textOf(root)).toContain("Sharing since 2026-09-01");
    expect(textOf(root)).toContain("Dr. Past");
    expect(textOf(root)).toContain("Stopped 2026-09-10");
    expect(touchableByLabel(root, "Stop sharing")).toBeTruthy();
  });
});

describe("pairing lookup", () => {
  it("shows the therapist card on success and resets on cancel", async () => {
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await pressLabel(root, "Find my therapist");
    await flush();
    expect(textOf(root)).toContain("Dr. Real");
    await pressLabel(root, "Cancel");
    await flush();
    expect(textOf(root)).not.toContain("Dr. Real");
    expect(textOf(root)).toContain("Add your therapist");
  });

  it("a dead code explains itself without leaking anything", async () => {
    vi.mocked(api.pairingLookup).mockRejectedValue(new RealApiError(404, "pairing code not found"));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "ZZZZZZZZ");
    await pressLabel(root, "Find my therapist");
    await flush();
    expect(lastAlert()[0]).toBe("Code not found");
  });

  it("an expired session says so", async () => {
    vi.mocked(api.pairingLookup).mockRejectedValue(new RealApiError(401, "invalid token"));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await pressLabel(root, "Find my therapist");
    await flush();
    expect(lastAlert()[0]).toBe("Session expired");
  });
});

describe("grant", () => {
  async function driveToPasswordCard(root: Awaited<ReturnType<typeof render>>): Promise<void> {
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await pressLabel(root, "Find my therapist");
    await flush();
    await pressLabel(root, "Share with Dr. Real");
    await flush();
    expect(lastAlert()[0]).toBe("Share with Dr. Real?");
    await pressAlertButton("Continue to password");
    await flush();
  }

  it("wraps the vault data key and grants after password re-auth", async () => {
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await driveToPasswordCard(root);
    await reauth(root);

    expect(vi.mocked(api.grantConsent)).toHaveBeenCalledTimes(1);
    const [code, ephemeralPubB64, wrappedKeyB64, verifierB64] = vi.mocked(api.grantConsent).mock
      .calls[0] as [string, string, string, string];
    expect(code).toBe("7X2KQM4N");
    expect(verifierB64).toBe(authKeyB64());
    expect(ephemeralPubB64).toHaveLength(124);
    // The whole point of the feature: the shipped envelope carries the
    // vault's data key, recoverable only with the therapist's private key.
    expect(unwrapGrant(wrappedKeyB64, ephemeralPubB64).equals(dataKey)).toBe(true);
    expect(lastAlert()[0]).toBe("Sharing started");
    expect(vi.mocked(api.listConsents)).toHaveBeenCalledTimes(2); // mount + refresh
  });

  it("a wrong password keeps the card up for retry", async () => {
    verifyPasswordForVault.mockImplementation(async () => ({ ok: false as const, reason: "wrong-password" }));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await driveToPasswordCard(root);
    await reauth(root, "wrong");
    expect(lastAlert()[0]).toBe("Could not verify");
    expect(vi.mocked(api.grantConsent)).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Enter your password to share with Dr. Real");
  });

  it("a server-side verifier rejection (403) stays retryable", async () => {
    vi.mocked(api.grantConsent).mockRejectedValue(
      new RealApiError(403, "invalid credentials", "verification_failed"),
    );
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await driveToPasswordCard(root);
    await reauth(root);
    expect(lastAlert()[0]).toBe("That password didn't match");
    expect(textOf(root)).toContain("Enter your password to share with Dr. Real");
  });

  it("an ordinary failure ends the flow honestly", async () => {
    vi.mocked(api.grantConsent).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await driveToPasswordCard(root);
    await reauth(root);
    expect(lastAlert()[0]).toBe("Could not complete");
    expect(textOf(root)).not.toContain("Enter your password to share");
  });

  it("refuses to wrap without a saved account", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await driveToPasswordCard(root);
    await reauth(root);
    expect(lastAlert()[0]).toBe("Could not complete");
    expect(vi.mocked(api.grantConsent)).not.toHaveBeenCalled();
  });
});

describe("revoke", () => {
  it("stops sharing after password re-auth", async () => {
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Stop sharing");
    await flush();
    expect(lastAlert()[0]).toBe("Stop sharing with Dr. Active?");
    await pressAlertButton("Stop sharing");
    await flush();
    expect(textOf(root)).toContain("Enter your password to stop sharing");
    await reauth(root);
    expect(vi.mocked(api.revokeConsent)).toHaveBeenCalledWith(activeConsent.id, authKeyB64());
    expect(lastAlert()[0]).toBe("Sharing stopped");
    expect(vi.mocked(api.listConsents)).toHaveBeenCalledTimes(2);
  });

  it("an expired session during revoke says so", async () => {
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent] as never);
    vi.mocked(api.revokeConsent).mockRejectedValue(new RealApiError(401, "invalid token"));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Stop sharing");
    await flush();
    await pressAlertButton("Stop sharing");
    await flush();
    await reauth(root);
    expect(lastAlert()[0]).toBe("Session expired");
  });
});

describe("guard rails", () => {
  it("an empty code cannot start a lookup", async () => {
    const { firePress } = await import("../helpers/rtr");
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await firePress(root, "Find my therapist"); // disabled: empty code
    expect(vi.mocked(api.pairingLookup)).not.toHaveBeenCalled();
  });

  it("a second lookup press while one is in flight is ignored", async () => {
    let resolveLookup!: (v: unknown) => void;
    vi.mocked(api.pairingLookup).mockImplementation(
      () => new Promise((resolve) => (resolveLookup = resolve)),
    );
    const { firePress } = await import("../helpers/rtr");
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await firePress(root, "Find my therapist");
    await firePress(root, "Looking up…"); // busy: the guard arm
    expect(vi.mocked(api.pairingLookup)).toHaveBeenCalledTimes(1);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveLookup?.({ therapist_id: THERAPIST_ID, display_name: "Dr. Real", wrap_pub_key: THERAPIST_PUB });
    });
    await flush();
  });

  it("an empty password cannot start the re-auth action", async () => {
    const { firePress } = await import("../helpers/rtr");
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Stop sharing");
    await flush();
    await pressAlertButton("Stop sharing");
    await flush();
    await firePress(root, "Confirm with password"); // disabled: no password
    expect(verifyPasswordForVault).not.toHaveBeenCalled();
  });

  it("a second confirm press while verifying is ignored, and revoke is blocked while busy", async () => {
    let resolveGrant!: (v: unknown) => void;
    vi.mocked(api.grantConsent).mockImplementation(
      () => new Promise((resolve) => (resolveGrant = resolve)),
    );
    const { firePress, act } = await import("../helpers/rtr");
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await pressLabel(root, "Find my therapist");
    await flush();
    await pressLabel(root, "Share with Dr. Real");
    await flush();
    await pressAlertButton("Continue to password");
    await flush();
    await typeInto(root, "password", "correct horse");
    await firePress(root, "Confirm with password");
    await firePress(root, "Verifying…"); // busy: the confirm guard arm
    await firePress(root, "Stop sharing"); // busy: the revoke guard arm
    expect(vi.mocked(api.grantConsent)).toHaveBeenCalledTimes(1);
    expect(lastAlert()[0]).not.toBe("Stop sharing with Dr. Active?");
    await act(async () => {
      resolveGrant?.({ id: "a".repeat(32) });
    });
    await flush();
  });

  it("a revoked consent without a timestamp renders an honest stopped line", async () => {
    vi.mocked(api.listConsents).mockResolvedValue([
      { ...revokedConsent, revoked_at: null },
    ] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Stopped ");
    // touchableByLabel throws when absent — absence is exactly the claim.
    expect(() => touchableByLabel(root, "Stop sharing")).toThrow(/no Text node/);
  });
});

describe("availability gate copy", () => {
  it("explains honestly when the server cannot be reached (nothing sent)", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("offline"));
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Can’t reach the server");
    expect(textOf(root)).toContain("No pairing code or journal data is sent until it is");
    expect(textOf(root)).not.toContain("has not enabled verified clinician sharing");
    expect(vi.mocked(api.pairingLookup)).not.toHaveBeenCalled();
  });

  it("keeps the distinct, authoritative message for a server that disabled sharing", async () => {
    vi.mocked(api.meta).mockResolvedValue({ sharing_available: false } as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("This server has not enabled verified clinician sharing");
    expect(textOf(root)).not.toContain("Can’t reach the server");
  });
});

describe("cancel paths", () => {
  it("cancelling the confirm dialog shares nothing", async () => {
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await typeInto(root, "e.g. 7X2KQM4N", "7X2KQM4N");
    await pressLabel(root, "Find my therapist");
    await flush();
    await pressLabel(root, "Share with Dr. Real");
    await flush();
    await pressAlertButton("Cancel");
    await flush();
    expect(vi.mocked(api.grantConsent)).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Dr. Real"); // still on the lookup card
  });

  it("the password card can be cancelled", async () => {
    vi.mocked(api.listConsents).mockResolvedValue([activeConsent] as never);
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Stop sharing");
    await flush();
    await pressAlertButton("Stop sharing");
    await flush();
    await pressLabel(root, "Cancel");
    await flush();
    expect(vi.mocked(api.revokeConsent)).not.toHaveBeenCalled();
  });

  it("crisis help stays one tap away", async () => {
    const root = await render(<TherapistShareScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });
});
