/**
 * Frontend mutation campaign 2026-09-22 — App-shell survivor pins.
 *
 * Companion to mutation_2026_09_22_frontend.pins.test.tsx: the idle auto-lock
 * clock (10 minutes, re-armed by real interaction) and the unmount teardown
 * (session cleared, raw keys wiped) were genuine survivors of the fresh
 * full-src Stryker run.
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
      patients: vi.fn(async () => []),
      // 2026-09-26 audit M-P1: lockDown fires this on every lock route.
      logout: vi.fn(async () => null),
      patientInsights: vi.fn(async () => ({ phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null, state_seq: 0 })),
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
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } } as unknown as CryptoKey)),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptInsights: vi.fn(async () => ({ stats: { patterns: [] } })),
    decryptEntry: vi.fn(async () => ({ text: "" })),
    encryptNote: vi.fn(async () => ({ blobB64: "S==" })),
    decryptNote: vi.fn(async () => ""),
  };
});

const { clearSession, hasSession } = await import("../src/api");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const { App } = await import("../src/App");
const { render, flush, textOf, press, typeInto } = await import("./helpers/rtr");

beforeEach(() => {
  vi.clearAllMocks();
  mockedCrypto.derivePortalKeys.mockReset().mockResolvedValue({
    authKey: new Uint8Array(32), wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32),
  });
  mockedCrypto.unlockWrapPrivateKey.mockReset().mockResolvedValue({ algorithm: { name: "ECDH" } } as unknown as CryptoKey);
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

describe("mutation pins 2026-09-22: App idle auto-lock", () => {
  it("locks at exactly ten minutes of inactivity with the honest notice", async () => {
    vi.useFakeTimers();
    try {
      const root = await login();
      expect(textOf(root)).toContain("Patients — Dr. Portal");
      await act(async () => { await vi.advanceTimersByTimeAsync(10 * 60 * 1000 - 1); });
      expect(textOf(root)).toContain("Patients — Dr. Portal"); // one tick early: still unlocked
      await act(async () => { await vi.advanceTimersByTimeAsync(1); });
      expect(textOf(root)).toContain("Locked after inactivity — sign in again to continue.");
      expect(hasSession()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("real interaction re-arms the clock", async () => {
    vi.useFakeTimers();
    try {
      const root = await login();
      await act(async () => { await vi.advanceTimersByTimeAsync(9 * 60 * 1000); });
      window.dispatchEvent({ type: "click" } as Event); // the clinician is still working
      await act(async () => { await vi.advanceTimersByTimeAsync(9 * 60 * 1000); });
      expect(textOf(root)).toContain("Patients — Dr. Portal"); // 18 min since start, 9 since the click
      await act(async () => { await vi.advanceTimersByTimeAsync(60 * 1000 + 1); });
      expect(textOf(root)).toContain("Locked after inactivity");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("mutation pins 2026-09-22: App unmount teardown", () => {
  it("unmount clears the session and wipes the raw key material", async () => {
    const keys = { authKey: new Uint8Array(32).fill(1), wrapKek: new Uint8Array(32).fill(2), noteKey: new Uint8Array(32).fill(3) };
    mockedCrypto.derivePortalKeys.mockResolvedValue(keys);
    const root = await login();
    expect(textOf(root)).toContain("Patients — Dr. Portal");
    await act(async () => { root.unmount(); });
    expect(hasSession()).toBe(false);
    expect(keys.noteKey.every((b) => b === 0)).toBe(true);
    expect(keys.wrapKek.every((b) => b === 0)).toBe(true);
  });
});
