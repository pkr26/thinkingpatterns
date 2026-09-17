/**
 * App shell state machine: login -> unlock -> patients -> patient, and the
 * honest failure paths (role rejection at login is in views.test; here the
 * unlock failure and sign-out loop).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    auth: {
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
      })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null })),
      patientEntries: vi.fn(async () => []),
      notes: vi.fn(async () => []),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    derivePortalKeys: vi.fn(async () => ({
      authKeyB64: "AUTHKEY==",
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      privateKeyPkcs8B64: "PRIV==",
      privateKey: {},
    })),
    sealPrivateKeyForUpload: vi.fn(async () => "SEALED=="),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } })),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptInsights: vi.fn(async () => ({ stats: { patterns: [] } })),
    decryptEntry: vi.fn(async () => ({ text: "" })),
    encryptNote: vi.fn(async () => ({ blobB64: "S==" })),
    decryptNote: vi.fn(async () => ""),
  };
});

const { api, clearSession } = await import("../src/api");
const { App } = await import("../src/App");
const { render, flush, textOf, press, typeInto } = await import("./helpers/rtr");

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  clearSession();
});

async function login() {
  const root = await render(<App />);
  await typeInto(root, "Username", "drportal");
  await typeInto(root, "Password", "pw");
  await press(root, "Sign in");
  await flush();
  return root;
}

describe("App", () => {
  it("logs in, unlocks the sharing key, and lands on Patients", async () => {
    const root = await login();
    expect(textOf(root)).toContain("Patients — Dr. Portal");
    expect(textOf(root)).toContain("No patients are sharing with you yet");
  });

  it("a failed key unlock returns to login with an honest message", async () => {
    const { unlockWrapPrivateKey } = vi.mocked(await import("../src/crypto"));
    const err = new Error("blob failed authentication");
    err.name = "TamperError";
    unlockWrapPrivateKey.mockRejectedValueOnce(err);
    const root = await login();
    await flush();
    expect(textOf(root)).toContain("could not be unlocked with this password");
    expect(textOf(root)).toContain("Sign in");
  });

  it("a non-tamper unlock failure reports the raw message", async () => {
    const { unlockWrapPrivateKey } = vi.mocked(await import("../src/crypto"));
    unlockWrapPrivateKey.mockRejectedValueOnce(new Error("network down"));
    const root = await login();
    await flush();
    expect(textOf(root)).toContain("network down");
  });

  it("opens a patient and comes back; sign out returns to login", async () => {
    vi.mocked(api.patients).mockResolvedValue([
      {
        user_id: "user-1",
        username: "patienta",
        status: "active",
        granted_at: "2026-09-01T00:00:00Z",
        revoked_at: null,
        ephemeral_pub: "E".repeat(124),
        wrapped_key: "W==",
      },
    ]);
    const root = await login();
    await flush();
    await press(root, "Open patterns");
    await flush();
    expect(textOf(root)).toContain("patienta");
    expect(textOf(root)).toContain("read-only");
    await press(root, "Back to patients");
    await flush();
    expect(textOf(root)).toContain("Connect a new patient");
    await press(root, "Sign out");
    await flush();
    expect(textOf(root)).toContain("Create a therapist account instead");
  });

  it("a 401 locks the app down, and a same-tab re-login re-arms the expiry hook", async () => {
    // The mock above replaces the api object only — setSession and the
    // 401 latch are the real module state, so drive a genuine 401 through
    // the real request core to exercise App's registered lockDown.
    const { api: actualApi } = await vi.importActual<typeof import("../src/api")>("../src/api");
    const expire = async (): Promise<void> => {
      vi.stubGlobal("fetch", vi.fn(async () =>
        new Response(JSON.stringify({ detail: "unauthorized", code: "unauthorized" }), { status: 401 })));
      await act(async () => {
        await actualApi.patients().catch(() => {});
      });
      vi.unstubAllGlobals();
    };

    const root = await login();
    await expire();
    expect(textOf(root)).toContain("Session expired — please sign in again.");

    // Sign back in on the same rendered app — no reload, no re-registration.
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "pw");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("Patients — Dr. Portal");
    expect(textOf(root)).not.toContain("Session expired");

    await expire();
    expect(textOf(root)).toContain("Session expired — please sign in again.");
  });
});
