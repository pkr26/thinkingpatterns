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
      })),
      // 2026-09-26 audit M-P1: lockDown fires this best-effort before the
      // local teardown on every lock route (sign-out, idle, 401, bfcache).
      logout: vi.fn(async () => null),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({
        phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null, state_seq: 0,
      })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
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
    // Audit fix P-1 (2026-09-20): the verifier is raw bytes (base64 derived
    // only at the send); key generation returns the sealed blob directly.
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } })),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptInsights: vi.fn(async () => ({ stats: { patterns: [] } })),
    decryptEntry: vi.fn(async () => ({ text: "" })),
    encryptNote: vi.fn(async () => ({ blobB64: "S==" })),
    decryptNote: vi.fn(async () => ""),
  };
});

const { api, clearSession, hasSession } = await import("../src/api");
const { App } = await import("../src/App");
const { render, flush, textOf, press, typeInto } = await import("./helpers/rtr");

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
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
    // 2026-09-26 follow-up (portal N-3): this path runs AFTER a fresh 24 h
    // bearer was minted — dropping it from memory must also revoke it
    // server-side, like every other session end.
    expect(api.logout).toHaveBeenCalledTimes(1);
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

  it("sign-out aborts the portal session, wipes raw keys, and keeps the session-backed delta anchor (L-75)", async () => {
    const crypto = vi.mocked(await import("../src/crypto"));
    const wrapKek = new Uint8Array(32).fill(7);
    const noteKey = new Uint8Array(32).fill(9);
    crypto.derivePortalKeys.mockResolvedValueOnce({ authKey: new Uint8Array(32), wrapKek, noteKey });
    vi.mocked(api.patients).mockResolvedValueOnce([
      {
        user_id: "user-1", username: "patienta", status: "active",
        granted_at: "2026-09-01T00:00:00Z", revoked_at: null,
        ephemeral_pub: "E".repeat(124), wrapped_key: "W==",
      },
    ]);
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-01T00:00:00.000Z");
    const root = await login();
    await press(root, "Open patterns");
    await flush();
    // The wrap KEK's only job is the one-time unwrap of the private key:
    // it must be zeroed the moment that succeeds (2026-09-18 audit), not
    // retained in the session until sign-out.
    expect([...wrapKek]).toEqual(new Array(32).fill(0));
    expect([...noteKey]).not.toEqual(new Array(32).fill(0)); // still live for note decryption
    await press(root, "Sign out");
    await flush();

    expect(hasSession()).toBe(false);
    expect([...noteKey]).toEqual(new Array(32).fill(0));
    // L-75 decision (2026-09-20): visit-date stamps are date-only anchors
    // in per-tab sessionStorage, so a sign-out / idle lock / expiry no
    // longer scrubs them — the clinician keeps the "new since reviewed"
    // delta within the browser session, and the session's end clears it.
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBe("2026-09-01T00:00:00.000Z");
    expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBeNull();
    expect(textOf(root)).toContain("Your in-memory keys were cleared");
  });

  it("2026-09-26 audit M-P1: sign-out revokes the bearer server-side before the local teardown", async () => {
    // A copied bearer used to stay valid for its full 24h TTL after "sign
    // out" — lockDown now fires POST /auth/logout (token-epoch bump) as
    // part of every lock boundary.
    const root = await login();
    await press(root, "Sign out");
    await flush();
    expect(vi.mocked(api.logout)).toHaveBeenCalledTimes(1);
    expect(hasSession()).toBe(false);
    expect(textOf(root)).toContain("Signed out. Your in-memory keys were cleared.");
  });

  it("M-P1: a FAILING logout never blocks the local lockdown", async () => {
    // The revocation is best-effort by contract: an unreachable backend at
    // sign-out must not leave decrypted keys on screen waiting for it.
    vi.mocked(api.logout).mockRejectedValueOnce(new Error("offline backend"));
    const root = await login();
    await press(root, "Sign out");
    await flush();
    expect(vi.mocked(api.logout)).toHaveBeenCalledTimes(1);
    expect(hasSession()).toBe(false);
    expect(textOf(root)).toContain("Signed out. Your in-memory keys were cleared.");
    expect(textOf(root)).toContain("Sign in");
  });

  it("M-P1: the idle lock also revokes the bearer server-side", async () => {
    vi.useFakeTimers();
    try {
      const root = await login();
      await act(async () => { await vi.advanceTimersByTimeAsync(10 * 60 * 1000); });
      expect(textOf(root)).toContain("Locked after inactivity");
      expect(vi.mocked(api.logout)).toHaveBeenCalledTimes(1);
      expect(hasSession()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("L-75 fallback: without sessionStorage the old scrub-on-lock contract returns", async () => {
    // Some privacy modes expose no (or a dead) sessionStorage; the anchor
    // store then falls back to localStorage, which MUST keep the old
    // behavior of being removed at every lock boundary.
    const windowShim = (window as unknown as { sessionStorage?: Storage }).sessionStorage;
    delete (window as unknown as { sessionStorage?: Storage }).sessionStorage;
    try {
      vi.mocked(api.patients).mockResolvedValueOnce([
        {
          user_id: "user-1", username: "patienta", status: "active",
          granted_at: "2026-09-01T00:00:00Z", revoked_at: null,
          ephemeral_pub: "E".repeat(124), wrapped_key: "W==",
        },
      ]);
      window.localStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-01T00:00:00.000Z");
      const root = await login();
      await press(root, "Open patterns");
      await flush();
      await press(root, "Sign out");
      await flush();
      expect(hasSession()).toBe(false);
      expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBeNull();
    } finally {
      (window as unknown as { sessionStorage?: Storage }).sessionStorage = windowShim;
    }
  });

  it("component teardown keeps the session-backed anchor and never touches localStorage (L-75)", async () => {
    const root = await login();
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-01T00:00:00.000Z");
    window.sessionStorage.setItem("mindpattern.lastVisit.other-therapist.user-1", "2026-09-01T00:00:00.000Z");

    await act(async () => { root.unmount(); });

    // Session-backed anchors survive teardown (the browser session owns
    // their lifetime) and localStorage was never involved.
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBeTruthy();
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.other-therapist.user-1")).toBeTruthy();
    expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBeNull();
  });

  it("2026-09-19: a FAILED key unlock wipes the password-derived wrap KEK too", async () => {
    // The audit path: login succeeds, the unlock (me() or TamperError)
    // fails, onLoginReady catches its own error — so LoginView's finally
    // wipeKeys never ran and the wrap KEK (the key that decrypts the
    // therapist's stored private key) stayed live in the heap until GC.
    const crypto = vi.mocked(await import("../src/crypto"));
    const wrapKek = new Uint8Array(32).fill(7);
    const noteKey = new Uint8Array(32).fill(9);
    const authKey = new Uint8Array(32).fill(5);
    crypto.derivePortalKeys.mockResolvedValueOnce({ authKey, wrapKek, noteKey });
    crypto.unlockWrapPrivateKey.mockRejectedValueOnce(new Error("network down"));
    const root = await login();
    await flush();
    expect(textOf(root)).toContain("network down");
    expect([...wrapKek]).toEqual(new Array(32).fill(0));
    expect([...noteKey]).toEqual(new Array(32).fill(0));
    // P-1 (2026-09-20): the password-equivalent verifier bytes do not survive
    // the flow either — wiped at the login send, before the unlock failure.
    expect([...authKey]).toEqual(new Array(32).fill(0));
  });

  it("2026-09-19: a bfcache restore (persisted pageshow) locks the app down", async () => {
    // Navigating away and pressing Back past the idle window restores the
    // tab from the back/forward cache with the decrypted DOM frozen in it;
    // the overdue idle timer only fires AFTER restore. A persisted
    // pageshow must lock down synchronously, before paint.
    const root = await login();
    expect(textOf(root)).toContain("Patients — Dr. Portal");
    const pageshow = { type: "pageshow", persisted: true };
    await act(async () => { window.dispatchEvent(pageshow as unknown as Event); });
    expect(textOf(root)).toContain("Restored from the browser cache");
    expect(textOf(root)).toContain("Sign in");
    // 2026-09-26 follow-up: the fourth lock path revokes server-side too
    // (the M-P1 test coverage gap — the lockdown was pinned, the logout
    // fire was not).
    expect(api.logout).toHaveBeenCalledTimes(1);
  });

  it("a normal (non-persisted) pageshow does NOT lock the app", async () => {
    const root = await login();
    const initial = { type: "pageshow", persisted: false };
    await act(async () => { window.dispatchEvent(initial as unknown as Event); });
    expect(textOf(root)).toContain("Patients — Dr. Portal");
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
    // M-P1 (2026-09-26): the 401 latch teardown fires the same best-effort
    // revocation while the dying session still exists — an already-dead
    // token's 401 answer is swallowed like any other logout failure.
    expect(vi.mocked(api.logout)).toHaveBeenCalledTimes(1);

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
