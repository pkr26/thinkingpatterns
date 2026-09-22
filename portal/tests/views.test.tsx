/**
 * View behavior with mocked api/crypto layers (the crypto itself is
 * pinned by tests/crypto.test.ts against the real WebCrypto): login and
 * registration flows, the patients list + pairing code, and the patient
 * view — pattern cards, the sensitive non-quoting card, the evidence
 * drill-down, and notes.
 */
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
      })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==" })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => []),
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
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({
      stats: {
        patterns: [
          { kind: "temporal", label: "work", occurrences: 9, confidence: 0.8, detail: { day: "Sunday", pattern_pid: "temporal:work", pattern_state: "confirmed", evidence_dates: ["2026-09-01", "2026-09-08"], first_seen: "2026-08-20", last_seen: "2026-09-08" } },
          { kind: "recurring_phrase", label: "can't sleep", occurrences: 4, confidence: 0.5, detail: { sensitive: true, pattern_pid: "recurring_phrase:x", evidence_dates: ["2026-09-02"] } },
          { kind: "mood_correlation", label: "family", occurrences: 6, confidence: 0.7, detail: { direction: "higher", mood_delta: -0.3, pattern_pid: "mood_correlation:family", evidence_dates: ["2026-09-03"] } },
          { kind: "link", label: "sleep", occurrences: 5, confidence: 0.6, detail: { lag_days: 2, direction: "lower", pattern_pid: "link:sleep", evidence_dates: ["2026-09-04"] } },
          { kind: "temporal", label: "gym", occurrences: 4, confidence: 0.4, detail: { pattern_pid: "temporal:gym", evidence_dates: ["2026-09-05"] } },
          { kind: "mood_shift", label: "", occurrences: 1, confidence: 0.3, detail: { direction: "lower", pattern_pid: "mood_shift:lower", evidence_dates: ["2026-09-06"] } },
        ],
      },
    })),
    decryptEntry: vi.fn(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
      text: `decrypted ${entry.client_entry_id}`,
      sentiment: entry.client_entry_id === "e-1" ? 0.25 : null,
    })),
    encryptNote: vi.fn(async () => ({ blobB64: "SEALEDNOTE==" })),
    decryptNote: vi.fn(async () => "existing note text"),
  };
});

const { auth, api, ApiError } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const { LoginView, passwordPolicyError } = await import("../src/views/LoginView");
const { PatientsView } = await import("../src/views/PatientsView");
const { PatientView } = await import("../src/views/PatientView");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const rtr = await import("./helpers/rtr");
const { render, flush, textOf, press, buttonByLabel, typeInto, typeTextarea } = rtr;
const { act } = await import("react-test-renderer");
const joinedLabel = (n: { props: { children?: unknown } }): string => {
  const parts: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") parts.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
  };
  walk(n.props.children);
  return parts.join("");
};

const patient = {
  user_id: "user-1",
  username: "patienta",
  status: "active",
  granted_at: "2026-09-01T10:00:00Z",
  revoked_at: null,
  ephemeral_pub: "E".repeat(124),
  wrapped_key: "W==",
};
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
  // L-75 (2026-09-20): delta anchors now live in per-tab sessionStorage
  // (the shim provides it), so tests that pin anchor behavior seed it there.
  window.sessionStorage.clear();
});

describe("LoginView", () => {
  it("requires a genuinely strong registration password while allowing a long passphrase", async () => {
    expect(passwordPolicyError("one")).toContain("12");
    expect(passwordPolicyError("alllowercase12")).toContain("three character types");
    expect(passwordPolicyError("four correct horse battery staple")).toBe("");
    expect(passwordPolicyError("Strong!pass123")).toBe("");

    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "one");
    await typeInto(root, "Repeat password", "one");
    expect(buttonByLabel(root, "Create account")).toBe(true);
    const create = root.root.findAllByType("button").find((n) => joinedLabel(n) === "Create account");
    expect(create?.props.disabled).toBe(true);
  });

  it("fails closed with an administrative explanation when the server disables clinician enrollment", async () => {
    mockedAuth.meta.mockResolvedValueOnce({ sharing_available: false });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    expect(textOf(root)).toContain("New clinician enrollment is unavailable on this server");
    const create = root.root.findAllByType("button").find((n) => joinedLabel(n) === "Create account");
    expect(create?.props.disabled).toBe(true);
  });

  it("signs in: salt -> derive -> login -> onReady", async () => {
    const onReady = vi.fn();
    // P-1 (2026-09-20): the verifier is derived as raw bytes and its base64
    // exists only inside the login request; the bytes are wiped right after.
    const authKey = new Uint8Array(32).map((_, i) => i + 1);
    const expectedVerifier = mockedCrypto.toBase64(authKey);
    mockedCrypto.derivePortalKeys.mockResolvedValueOnce({ authKey, wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) });
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    await press(root, "Sign in");
    await flush();
    expect(mockedAuth.saltFor).toHaveBeenCalled();
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", expectedVerifier);
    expect([...authKey]).toEqual(new Array(32).fill(0));
    expect(onReady).toHaveBeenCalledWith(
      expect.objectContaining({ username: "drportal", userId: "therapist-1" }),
      expect.objectContaining({ token: "tok" }),
      expect.any(String),
    );
    expect(textOf(root)).toContain("cannot be changed from the sign-in screen");
  });

  it("refuses a patient-role account", async () => {
    mockedAuth.login.mockResolvedValueOnce({ token: "t", user_id: "u", expires_in: 1, role: "user" });
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "plainuser");
    await typeInto(root, "Password", "pw");
    await press(root, "Sign in");
    await flush();
    expect(onReady).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("patient account");
  });

  it("surfaces a failed sign-in without crashing", async () => {
    mockedAuth.login.mockRejectedValueOnce(new Error("invalid credentials"));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "wrong");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("invalid credentials");
  });

  it("a non-Error sign-in failure shows the generic fallback, and Back-to-sign-in works", async () => {
    mockedAuth.login.mockRejectedValueOnce("offline");
    let root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "pw");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("sign-in failed");
    // register mode's Back button returns to sign-in
    root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await press(root, "Back to sign in");
    expect(textOf(root)).toContain("Sign in");
  });

  it("an Error registration failure surfaces its message", async () => {
    mockedAuth.registerTherapist.mockRejectedValueOnce(new Error("username already taken"));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("username already taken");
  });

  it("a non-Error registration failure shows the generic fallback", async () => {
    mockedAuth.registerTherapist.mockRejectedValueOnce("nope");
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("registration failed");
  });

  it("registers: mismatched passwords blocked; happy path seals the key", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Your name", "Dr. New");
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "two");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("passwords do not match");

    await typeInto(root, "Repeat password", "Strong!pass123");
    await press(root, "Create account");
    await flush();
    // P-1 (2026-09-20): sealing happens inside generateTherapistKeyPair now —
    // the flow hands the registration only the sealed blob.
    expect(mockedCrypto.generateTherapistKeyPair).toHaveBeenCalledWith(expect.any(Uint8Array), "drnew");
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ username: "drnew", display_name: "Dr. New", wrap_pub_key: "P".repeat(124), wrap_key_blob: "SEALED==" }),
    );
    expect(onReady).toHaveBeenCalled();
  });

  it("P-1 (2026-09-20): registration derives the verifier at the send and wipes the raw bytes", async () => {
    const authKey = new Uint8Array(32).fill(9);
    const expectedVerifier = mockedCrypto.toBase64(authKey);
    mockedCrypto.derivePortalKeys.mockResolvedValueOnce({ authKey, wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    await press(root, "Create account");
    await flush();
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ verifier: expectedVerifier }),
    );
    // The password-equivalent verifier bytes do not outlive the flow — the
    // success path transfers the other keys, so this wipe must be eager.
    expect([...authKey]).toEqual(new Array(32).fill(0));
  });

  it("forwards an organization-issued enrollment token only during registration", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    await typeInto(root, "Clinician enrollment token", "managed-enrollment-token");
    await press(root, "Create account");
    await flush();
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ username: "drnew" }),
      "managed-enrollment-token",
    );
  });
});

describe("PatientsView", () => {
  it("shows the empty state and generates pairing codes", async () => {
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("No patients are sharing with you yet");
    await press(root, "Generate pairing code");
    await flush();
    expect(mockedApi.newPairingCode).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toContain("7X2KQM4N");
  });

  it("lists active and stopped patients; open hands the patient up", async () => {
    const onOpen = vi.fn();
    mockedApi.patients.mockResolvedValueOnce([
      patient,
      { ...patient, user_id: "user-2", username: "patientb", status: "revoked", revoked_at: "2026-09-10T00:00:00Z" },
    ]);
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={onOpen} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("patienta");
    expect(textOf(root)).toContain("sharing since 2026-09-01");
    expect(textOf(root)).toContain("patientb");
    expect(textOf(root)).toContain("access ended 2026-09-10");
    expect(buttonByLabel(root, "Open patterns")).toBe(true);
    await press(root, "Open patterns");
    expect(onOpen).toHaveBeenCalledWith(patient);
  });

  it("reports a failed patient load, including non-Error rejections", async () => {
    mockedApi.patients.mockRejectedValueOnce(new Error("boom"));
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("boom");
    mockedApi.patients.mockRejectedValueOnce("just a string");
    const root2 = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root2)).toContain("could not load patients");
  });

  it("a stopped patient without a timestamp says 'recently'", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, user_id: "user-3", username: "patientc", status: "revoked", revoked_at: null },
    ]);
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("access ended recently");
  });

  it("ignores a second generate press while one is in flight", async () => {
    let resolveCode!: (v: { code: string; expires_in: number }) => void;
    mockedApi.newPairingCode.mockImplementationOnce(
      () => new Promise((resolve) => (resolveCode = resolve)),
    );
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    await press(root, "Generate pairing code");
    await press(root, "Generating…"); // busy guard arm
    expect(mockedApi.newPairingCode).toHaveBeenCalledTimes(1);
    resolveCode?.({ code: "DONECODE", expires_in: 900 });
    await flush();
    expect(textOf(root)).toContain("DONECODE");
  });

  it("zeroizes each unwrapped patient key after a caseload scan", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      patient,
      { ...patient, user_id: "user-2", username: "patientb" },
    ]);
    const firstKey = new Uint8Array(32).fill(17);
    const secondKey = new Uint8Array(32).fill(23);
    mockedCrypto.unwrapPatientDataKey
      .mockResolvedValueOnce(firstKey)
      .mockResolvedValueOnce(secondKey);

    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session} />,
    );
    await flush();
    await press(root, "Scan caseload for triage");
    await flush(6);

    expect([...firstKey]).toEqual(new Array(32).fill(0));
    expect([...secondKey]).toEqual(new Array(32).fill(0));
  });
});

/** 2026-09-17: cards render in REVIEW ORDER (sensitive/down-shifts lead),
 *  so tests open a specific card by title fragment instead of position. */
async function openCard(root: Awaited<ReturnType<typeof render>>, titlePart: string): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const titles = root.root.findAllByType("h3").map((n) => String(n.props.children)).join("|");
    if (titles.includes(titlePart)) return;
    const buttons = root.root.findAllByType("button").filter((n) => joinedLabel(n) === "See the evidence");
    const target = buttons[attempt];
    if (!target) break;
    await act(async () => { target.props.onClick(); });
    await flush();
    const nowTitles = root.root.findAllByType("h3").map((n) => String(n.props.children)).join("|");
    if (!nowTitles.includes(titlePart)) {
      const back = root.root.findAllByType("button").find((n) => joinedLabel(n) === "Back to all patterns");
      if (back) {
        await act(async () => { back.props.onClick(); });
        await flush();
      }
    }
  }
}

describe("PatientView", () => {
  it("renders pattern cards, the sensitive card non-quoting, and the drill-down", async () => {
    // Persistent (not Once): review-ordered cards mean openCard may open a
    // leading card before the temporal:work one — every drill-down sees rows.
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-08", received_at: "x" },
        { id: "3", client_entry_id: "e-3", blob: "b", entry_date: "2026-09-09", received_at: "x" }, // outside evidence
        { id: "4", client_entry_id: "e-4", blob: "b", entry_date: "2026-09-08", received_at: "x" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(mockedApi.patientInsights).toHaveBeenCalledWith("user-1");
    expect(textOf(root)).toContain("work");
    // Sensitive cards never quote the phrase.
    expect(textOf(root)).toContain("A difficult thought has been returning");
    expect(textOf(root)).not.toContain("can't sleep");
    expect(textOf(root)).toContain("read higher on days 'family' appears");
    expect(textOf(root)).toContain("About 2 day(s) after 'sleep'");
    expect(textOf(root)).toContain("concentrates on certain days");
    expect(textOf(root)).toContain("read lower than the patient's own baseline");

    await openCard(root, "temporal — work");
    await flush();
    expect(mockedApi.patientEntries).toHaveBeenCalledWith(
      "user-1",
      expect.objectContaining({ since: "2026-09-01", until: "2026-09-08" }),
    );
    // Only the pattern's evidence dates are kept (2026-09-09 dropped).
    expect(textOf(root)).toContain("decrypted e-1");
    expect(textOf(root)).toContain("decrypted e-2");
    expect(textOf(root)).toContain("decrypted e-4"); // same calendar day: distinct row keys
    expect(textOf(root)).not.toContain("decrypted e-3");
    expect(textOf(root)).toContain("mood 0.25");
    await press(root, "Back to all patterns");
    expect(textOf(root)).toContain("See the evidence");
  });

  it("shows the baseline phase note without unwrapping", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("baseline phase");
    expect(mockedCrypto.unwrapPatientDataKey).not.toHaveBeenCalled();
  });

  it("loads private notes page-by-page during baseline and explains their scope", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    // A byte-bound server page can be shorter than the 100-row request while
    // still having more notes. The header, not the short length, drives the
    // next request.
    const firstPage = [{
      id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    }];
    const secondPage = [{
      id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b",
      created_at: "2026-09-17T00:00:00Z", updated_at: "2026-09-17T00:00:00Z",
    }];
    mockedApi.notes
      .mockResolvedValueOnce({ notes: firstPage, nextOffset: 1 })
      .mockResolvedValueOnce({ notes: secondPage, nextOffset: null });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    expect(mockedApi.notes).toHaveBeenNthCalledWith(1, "user-1", { offset: 0 });
    expect(mockedApi.notes).toHaveBeenNthCalledWith(2, "user-1", { offset: 1 });
    expect(textOf(root)).toContain("private clinician notes remain available below");
    expect(textOf(root)).toContain("not shared with the patient");
    expect(textOf(root)).toContain("may remain in your account after the patient stops sharing");
  });

  it("restarts the entire note traversal after a collection_changed snapshot conflict", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    const stale = {
      id: "stale-note", client_note_id: "stale-client", pattern_pid: null, blob: "stale",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    };
    const fresh = {
      id: "fresh-note", client_note_id: "fresh-client", pattern_pid: null, blob: "fresh",
      created_at: "2026-09-17T00:00:00Z", updated_at: "2026-09-17T00:00:00Z",
    };
    mockedApi.notes
      .mockResolvedValueOnce({ notes: [stale], nextOffset: 1, revision: "41" })
      .mockRejectedValueOnce(new ApiError(409, "notes changed while paging; retry the request", "collection_changed"))
      .mockResolvedValueOnce({ notes: [fresh], nextOffset: 1, revision: "42" })
      .mockResolvedValueOnce({ notes: [], nextOffset: null, revision: "42" });

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);

    expect(mockedApi.notes).toHaveBeenNthCalledWith(1, "user-1", { offset: 0 });
    expect(mockedApi.notes).toHaveBeenNthCalledWith(2, "user-1", { offset: 1, expectedRevision: "41" });
    expect(mockedApi.notes).toHaveBeenNthCalledWith(3, "user-1", { offset: 0 });
    expect(mockedApi.notes).toHaveBeenNthCalledWith(4, "user-1", { offset: 1, expectedRevision: "42" });
    // The failed snapshot's encrypted note never reaches the decryption/UI
    // stage; restarting must not merge stale and fresh pages.
    expect(vi.mocked(mockedCrypto.decryptNote).mock.calls.map((call) => call[3])).toEqual(["fresh-client"]);
    expect(textOf(root)).toContain("existing note text");
  });

  it("shows an honest placeholder for notes it cannot decrypt", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptNote).mockRejectedValueOnce(new Error("TamperError"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("(note could not be decrypted with this account's key)");
  });

  it("creates a note bound to the open pattern and deletes one", async () => {
    mockedApi.createNote.mockResolvedValueOnce({
      id: "n1", client_note_id: "c1", pattern_pid: "temporal:work", blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    // 2026-09-17: cards are review-ordered (sensitive/down-shifts lead),
    // so open the temporal:work card specifically — find its drill-down
    // button among the "See the evidence" buttons by card position.
    await openCard(root, "temporal — work");
    await flush();
    await typeTextarea(root, "Note about this pattern…", "Discuss Sunday dread next session.");
    await press(root, "Save note");
    await flush();
    expect(mockedApi.createNote).toHaveBeenCalledWith(
      "user-1",
      expect.objectContaining({ pattern_pid: "temporal:work", blob: "SEALEDNOTE==" }),
    );
    expect(textOf(root)).toContain("Discuss Sunday dread next session.");

    mockedApi.deleteNote.mockResolvedValueOnce(null);
    // M-23 (2026-09-20): deletion is two-step — the first press arms the
    // confirmation and must NOT reach the API.
    await press(root, "Delete");
    await flush();
    expect(mockedApi.deleteNote).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Permanently delete this note?");
    await press(root, "Confirm delete");
    await flush();
    expect(mockedApi.deleteNote).toHaveBeenCalledWith("n1");
    expect(textOf(root)).not.toContain("Discuss Sunday dread next session.");
  });

  it("reports failures with the generic fallback for non-Error rejections", async () => {
    // drill-down load
    mockedApi.patientEntries.mockRejectedValueOnce("offline");
    let root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(textOf(root)).toContain("could not load the evidence entries");

    // note save
    root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    mockedApi.createNote.mockRejectedValueOnce("offline");
    await typeTextarea(root, "Note about this patient…", "text");
    await press(root, "Save note");
    await flush();
    expect(textOf(root)).toContain("could not save the note");

    // note delete (two-step confirm first, M-23)
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "nd", client_note_id: "cd", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    mockedApi.deleteNote.mockRejectedValueOnce("offline");
    await press(root, "Delete");
    await press(root, "Confirm delete");
    await flush();
    expect(textOf(root)).toContain("could not delete the note");
  });

  it("follows validated evidence cursors and stops at the finite page cap", async () => {
    // The first review-ordered card is the sensitive pattern on 2026-09-02.
    // Supply eight retained pages plus a nonempty bounded probe. The view
    // must refuse that ninth page rather than accumulate an unbounded chart.
    for (let page = 0; page < 8; page += 1) {
      const offset = page * 25;
      mockedApi.patientEntries.mockResolvedValueOnce({
        entries: Array.from({ length: 25 }, (_, index) => ({
          id: `page-${page}-${index}`,
          client_entry_id: `entry-${page}-${index}`,
          blob: "b",
          entry_date: "2026-09-02",
          received_at: "x",
        })),
        nextOffset: offset + 25,
      });
    }
    mockedApi.patientEntries.mockResolvedValueOnce({
      entries: [{
        id: "overflow-entry", client_entry_id: "overflow-entry", blob: "b",
        entry_date: "2026-09-02", received_at: "x",
      }],
      nextOffset: 201,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush(12);
    expect(mockedApi.patientEntries).toHaveBeenCalledTimes(9);
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      1,
      "user-1",
      expect.objectContaining({ offset: 0 }),
    );
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      8,
      "user-1",
      expect.objectContaining({ offset: 175 }),
    );
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      9,
      "user-1",
      expect.objectContaining({ offset: 200 }),
    );
    expect(textOf(root)).toContain("evidence window exceeds this portal's safe page limit");
  });

  it("restarts the evidence traversal after a collection_changed snapshot conflict", async () => {
    // Review ordering makes the sensitive pattern (whose only evidence date
    // is 2026-09-02) the first drill-down action.
    const stale = {
      id: "stale-entry", client_entry_id: "stale-client", blob: "stale",
      entry_date: "2026-09-02", received_at: "2026-09-02T00:00:00Z",
    };
    const fresh = {
      id: "fresh-entry", client_entry_id: "fresh-client", blob: "fresh",
      entry_date: "2026-09-02", received_at: "2026-09-02T00:00:00Z",
    };
    mockedApi.patientEntries
      .mockResolvedValueOnce({ entries: [stale], nextOffset: 1, revision: "9007199254740993" })
      .mockRejectedValueOnce(new ApiError(409, "entries changed while paging; retry the request", "collection_changed"))
      .mockResolvedValueOnce({ entries: [fresh], nextOffset: 1, revision: "9007199254740994" })
      .mockResolvedValueOnce({ entries: [], nextOffset: null, revision: "9007199254740994" });

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush(12);

    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      1,
      "user-1",
      expect.objectContaining({ since: "2026-09-02", until: "2026-09-02", offset: 0 }),
    );
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      2,
      "user-1",
      expect.objectContaining({ offset: 1, expectedRevision: "9007199254740993" }),
    );
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      3,
      "user-1",
      expect.objectContaining({ offset: 0 }),
    );
    expect(mockedApi.patientEntries).toHaveBeenNthCalledWith(
      4,
      "user-1",
      expect.objectContaining({ offset: 1, expectedRevision: "9007199254740994" }),
    );
    expect(vi.mocked(mockedCrypto.decryptEntry).mock.calls.map((call) => call[2].client_entry_id)).toEqual(["fresh-client"]);
    expect(textOf(root)).toContain("decrypted fresh-client");
    expect(textOf(root)).not.toContain("decrypted stale-client");
  });

  it("stops note paging at the finite portal cap instead of accumulating a chart forever", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    for (let page = 0; page < 20; page += 1) {
      mockedApi.notes.mockResolvedValueOnce({
        notes: [{
          id: `cap-note-${page}`,
          client_note_id: `cap-client-${page}`,
          pattern_pid: null,
          blob: "b",
          created_at: "2026-09-16T00:00:00Z",
          updated_at: "2026-09-16T00:00:00Z",
        }],
        nextOffset: page + 1,
      });
    }
    mockedApi.notes.mockResolvedValueOnce({
      notes: [{
        id: "overflow-note", client_note_id: "overflow-note", pattern_pid: null, blob: "b",
        created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
      }],
      nextOffset: 21,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(24);
    expect(mockedApi.notes).toHaveBeenCalledTimes(21);
    expect(mockedApi.notes).toHaveBeenNthCalledWith(20, "user-1", { offset: 19 });
    expect(mockedApi.notes).toHaveBeenNthCalledWith(21, "user-1", { offset: 20 });
    expect(textOf(root)).toContain("note history exceeds this portal's safe page limit");
  });

  it("accepts an exactly capped evidence history after its empty terminal probe", async () => {
    for (let page = 0; page < 8; page += 1) {
      const offset = page * 25;
      mockedApi.patientEntries.mockResolvedValueOnce({
        entries: Array.from({ length: 25 }, (_, index) => ({
          id: `exact-${page}-${index}`,
          client_entry_id: `exact-entry-${page}-${index}`,
          blob: "b",
          entry_date: "2026-09-02",
          received_at: "x",
        })),
        nextOffset: offset + 25,
      });
    }
    mockedApi.patientEntries.mockResolvedValueOnce({ entries: [], nextOffset: null });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(24);
    await press(root, "See the evidence");
    await flush(28);
    expect(mockedApi.patientEntries).toHaveBeenCalledTimes(9);
    expect(textOf(root)).not.toContain("evidence window exceeds this portal's safe page limit");
  });

  it("accepts an exactly capped note history after its empty terminal probe", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    for (let page = 0; page < 20; page += 1) {
      mockedApi.notes.mockResolvedValueOnce({
        notes: [{
          id: `exact-note-${page}`,
          client_note_id: `exact-client-${page}`,
          pattern_pid: null,
          blob: "b",
          created_at: "2026-09-16T00:00:00Z",
          updated_at: "2026-09-16T00:00:00Z",
        }],
        nextOffset: page + 1,
      });
    }
    mockedApi.notes.mockResolvedValueOnce({ notes: [], nextOffset: null });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(28);
    expect(mockedApi.notes).toHaveBeenCalledTimes(21);
    expect(textOf(root)).not.toContain("note history exceeds this portal's safe page limit");
  });

  it("shows the honest empty-patterns card when nothing has surfaced yet", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({ stats: { patterns: [] } });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet");
  });

  it("covers the remaining describe arms: inertia, instability, topic, default, quoted phrase", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      stats: {
        patterns: [
          { kind: "inertia", label: "mood", occurrences: 2, confidence: 0.5, detail: { pattern_pid: "inertia:mood", evidence_dates: [] } },
          { kind: "instability", label: "mood", occurrences: 2, confidence: 0.5, detail: { pattern_pid: "instability:mood", evidence_dates: [] } },
          { kind: "topic", label: "guitar", occurrences: 5, confidence: 0.5, detail: { pattern_pid: "topic:guitar", evidence_dates: [] } },
          { kind: "mystery", label: "thing", occurrences: 3, confidence: 0.5, detail: { pattern_pid: "mystery:thing", evidence_dates: [] } },
          { kind: "recurring_phrase", label: "feeling better", occurrences: 3, confidence: 0.5, detail: { pattern_pid: "recurring_phrase:y", evidence_dates: [] } },
        ],
      },
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("carrying over day to day");
    expect(textOf(root)).toContain("swung more widely");
    expect(textOf(root)).toContain("taking up more space");
    expect(textOf(root)).toContain("3 mentions");
    expect(textOf(root)).toContain("'feeling better' has returned 3 times");
  });

  it("handles a non-insight phase without a blob, dead key material, and string failures", async () => {
    // Neither insight-phase nor a blob -> the honest no-data line.
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "locked", active_days: 40, streak: 0, days_remaining: 0, blob: null,
    });
    let root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("No pattern data has been computed yet");

    // A consent stripped of its key material cannot unwrap.
    root = await render(
      <PatientView patient={{ ...patient, ephemeral_pub: null, wrapped_key: null }} session={session} onBack={vi.fn()} />,
    );
    await flush();
    expect(textOf(root)).toContain("this consent carries no key material");

    // A non-Error load failure shows the generic fallback.
    mockedApi.patientInsights.mockRejectedValueOnce("offline");
    root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("could not load this patient");
  });

  it("a pattern with no evidence dates opens an empty drill-down", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      stats: {
        patterns: [
          { kind: "topic", label: "guitar", occurrences: 5, confidence: 0.5, detail: { pattern_pid: "topic:guitar" } },
        ],
      },
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(mockedApi.patientEntries).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("No decryptable entries behind this pattern");
  });

  it("flags patterns new since the last visit via the session anchor", async () => {
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-01T00:00:00.000Z");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    // first_seen 2026-08-20 is NOT newer than the stamp; refresh the stamp
    // to a date before first_seen to see the badge.
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-08-01T00:00:00.000Z");
    const root2 = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    // 2026-09-17: the delta anchor is explicit — the copy names the anchor
    // date instead of implying a per-open reset.
    expect(textOf(root2)).toContain("1 pattern new since you marked reviewed 2026-08-01");
    expect(textOf(root)).not.toContain("pattern new since");
  });
});

describe("PatientView 2026-09-17 wave", () => {
  it("the visit delta anchors only on the explicit Mark reviewed action", async () => {
    // Load with a stamp of 2026-08-01: one new pattern shows, and the
    // stamp itself is NOT rewritten by opening the chart.
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-08-01T00:00:00.000Z");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("since you marked reviewed 2026-08-01");
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBe("2026-08-01T00:00:00.000Z");

    await press(root, "Mark reviewed (update the delta anchor)");
    await flush();
    // L-80 (2026-09-20): the new anchor is the CLINICIAN-LOCAL calendar
    // date (YYYY-MM-DD), not a UTC instant — a plain date string here.
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(window.sessionStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).not.toBe("2026-08-01T00:00:00.000Z");
    expect(textOf(root)).not.toContain("pattern new since");
    // The anchor copy names the local-calendar basis explicitly (L-80).
    expect(textOf(root)).toContain("on this computer's calendar");
  });

  it("review ordering puts the sensitive card first", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    const titles = root.root.findAllByType("h3").map((n) => String(n.props.children));
    const sensitiveIdx = titles.findIndex((t) => t.includes("A difficult thought"));
    expect(sensitiveIdx).toBeGreaterThanOrEqual(0);
    // The first pattern-titled card in the list is the sensitive one.
    const patternTitles = titles.filter((t) => !t.includes("Account summary"));
    expect(String(patternTitles[0])).toContain("A difficult thought");
  });

  it("renders a print-only session summary and the print trigger", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(buttonByLabel(root, "Print session summary")).toBe(true);
    expect(textOf(root)).toContain("MindPattern session summary — patienta");
  });

  it("note editing round-trips through the PATCH endpoint", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    mockedApi.updateNote.mockResolvedValueOnce({
      id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-17T00:00:00Z",
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("existing note text");
    await press(root, "Edit");
    await typeTextarea(root, "Editing note…", "Edited session note.");
    await press(root, "Save edit");
    await flush();
    expect(mockedApi.updateNote).toHaveBeenCalledWith("n0", "SEALEDNOTE==");
    expect(textOf(root)).toContain("Edited session note.");
  });

  it("note templates and copy-forward seed the draft", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(buttonByLabel(root, "Copy forward last note")).toBe(true);
    expect(buttonByLabel(root, "Session focus")).toBe(true);
  });

  it("the drill-down renders the mood sparkline over decrypted sentiments", async () => {
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-08", received_at: "x" },
      ],
      nextOffset: null,
    });
    // H-13 (2026-09-20): the sparkline exists only over GENUINE mood picks.
    // Two numeric sentiments are needed for a line; nulls are dropped, not
    // fabricated as 0 (the old pin leaned on that fabrication).
    vi.mocked(mockedCrypto.decryptEntry)
      .mockResolvedValueOnce({ text: "decrypted e-1", sentiment: 0.25 })
      .mockResolvedValueOnce({ text: "decrypted e-2", sentiment: -0.4 });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await openCard(root, "temporal — work");
    await flush();
    const svg = root.root.findAllByType("svg");
    expect(svg.length).toBeGreaterThan(0);
  });
});

describe("PatientsView caseload summaries (2026-09-19)", () => {
  it("decrypts server summaries and shows the sensitive banner without opening charts", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==", summary_updated_at: "2026-09-19T00:00:00Z" },
      { ...patient, user_id: "user-2", username: "patientb", summary_blob: "SB2==", summary_eph_pub: "SE2==" },
    ]);
    const { decryptCaseloadSummary } = mockedCrypto;
    vi.mocked(decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: true, newest: "2026-09-18", forDate: "2026-09-19" })
      .mockResolvedValueOnce({ patterns: 0, sensitive: false, newest: null, forDate: "2026-09-19" });
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    // The banner: one patient flagged sensitive, wording never quoted.
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
    expect(textOf(root)).toContain("never echoed here");
    // The per-patient count comes from the O(1) summary, not a chart fetch.
    expect(textOf(root)).toContain("4 patterns");
    expect(mockedApi.patientInsights).not.toHaveBeenCalled();
  });

  it("no banner and no counts when no summaries decrypt", async () => {
    mockedApi.patients.mockResolvedValueOnce([{ ...patient }]);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    expect(textOf(root)).not.toContain("sensitive card");
    expect(textOf(root)).not.toContain(" · "); // no per-patient count line at all
    expect(mockedCrypto.decryptCaseloadSummary).not.toHaveBeenCalled();
  });

  it("a failed summary decrypt degrades to no summary (the scan stays the fallback)", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
    ]);
    vi.mocked(mockedCrypto.decryptCaseloadSummary).mockResolvedValueOnce(null);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    expect(textOf(root)).toContain("patienta");
    expect(textOf(root)).not.toContain("sensitive card");
    expect(textOf(root)).not.toContain(" · ");
  });
});

describe("PatientView recorded measures (MBC, 2026-09-19)", () => {
  it("renders decrypted measure scores with the interpretation-belongs-to-you copy", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "insight",
      active_days: 45,
      streak: 3,
      days_remaining: 0,
      blob: "BLOB==",
    } as never);
    mockedApi.patientMeasures.mockResolvedValueOnce([
      { id: "1", client_measure_id: "m-1", blob: "B1==", measure_date: "2026-09-04", received_at: "2026-09-04T00:00:00Z" },
      { id: "2", client_measure_id: "m-2", blob: "B2==", measure_date: "2026-09-11", received_at: "2026-09-11T00:00:00Z" },
    ] as never);
    vi.mocked(mockedCrypto.decryptMeasure)
      .mockResolvedValueOnce({ measure: "phq9", score: 14, completedAt: "2026-09-04", measureDate: "2026-09-04" })
      .mockResolvedValueOnce({ measure: "phq9", score: 9, completedAt: "2026-09-11", measureDate: "2026-09-11" });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).toContain("Recorded measures (2)");
    // L-76 (2026-09-20): the decrypted INSTRUMENT name renders beside its
    // readings — a bare number is only interpretable next to the scale
    // that produced it.
    expect(rtr.textOf(root)).toContain("PHQ-9 (depression): 2026-09-04: 14  ·  2026-09-11: 9");
    expect(rtr.textOf(root)).toContain("interpretation is yours");
  });

  it("no measures means no card", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "insight",
      active_days: 45,
      streak: 3,
      days_remaining: 0,
      blob: "BLOB==",
    } as never);
    mockedApi.patientMeasures.mockResolvedValueOnce([] as never);
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).not.toContain("Recorded measures");
  });
});

/** Audit-fix regressions (2026-09-20): H-13, M-21, M-22, M-23, L-76,
 *  L-77, L-78, L-79, L-81, L-82. */
describe("audit fixes 2026-09-20", () => {
  it("H-13: null-sentiment entries render but never fabricate sparkline points", async () => {
    // No entry carries a numeric sentiment (the normal case: mobile keeps
    // payload sentiment null without an explicit pick) — the sparkline must
    // disappear, not draw a fabricated mid-scale trend at 0.
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-a", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "2", client_entry_id: "e-b", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(textOf(root)).toContain("decrypted e-a");
    expect(textOf(root)).toContain("decrypted e-b");
    expect(root.root.findAllByType("svg")).toHaveLength(0);
  });

  it("H-13: the sparkline counts only mood-tagged entries, dropping nulls", async () => {
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "3", client_entry_id: "e-3", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptEntry)
      .mockResolvedValueOnce({ text: "decrypted e-1", sentiment: 0.25 })
      .mockResolvedValueOnce({ text: "decrypted e-2", sentiment: null })
      .mockResolvedValueOnce({ text: "decrypted e-3", sentiment: 0.7 });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    const svg = root.root.findAllByType("svg");
    expect(svg).toHaveLength(1);
    expect(String(svg[0]!.props["aria-label"])).toContain("2 mood-tagged evidence entries");
  });

  it("H-13: copy forward seeds the NEWEST note (notes arrive created_at ascending)", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
        { id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-17T00:00:00Z", updated_at: "2026-09-17T00:00:00Z" },
      ],
      nextOffset: null,
    });
    // Decrypts run in arrival order: oldest first, newest second.
    vi.mocked(mockedCrypto.decryptNote)
      .mockResolvedValueOnce("oldest session note")
      .mockResolvedValueOnce("newest session note");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "Copy forward last note");
    await flush();
    const draft = root.root.findAllByType("textarea").find((n) => n.props.placeholder === "Note about this patient…");
    expect(draft?.props.value).toBe("newest session note");
  });

  it("M-21: the summary count renders with its as-of date when no scan exists", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
    ]);
    vi.mocked(mockedCrypto.decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: false, newest: "2026-09-18", forDate: "2026-09-19" });
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    expect(textOf(root)).toContain("4 patterns as of 2026-09-19");
  });

  it("M-21: a completed scan row shadows the server summary, not the reverse", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
      { ...patient, user_id: "user-2", username: "patientb", summary_blob: "SB2==", summary_eph_pub: "SE2==" },
    ]);
    vi.mocked(mockedCrypto.decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: false, newest: "2026-09-18", forDate: "2026-09-19" })
      .mockResolvedValueOnce({ patterns: 3, sensitive: false, newest: "2026-09-17", forDate: "2026-09-19" });
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    await press(root, "Scan caseload for triage");
    await flush(8);
    // The scan just decrypted the live payloads (6 patterns in the mock);
    // the stale summary's count must not shadow it, and its undated "4
    // patterns" must not render either.
    expect(textOf(root)).toContain("6 patterns (scanned just now)");
    expect(textOf(root)).not.toContain("as of 2026-09-19");
  });

  it("M-22: a stopped consent opens notes-only — no insights or measures reads, notes stay", async () => {
    const stopped = {
      ...patient,
      status: "revoked",
      revoked_at: "2026-09-10T00:00:00Z",
      ephemeral_pub: null,
      wrapped_key: null,
    };
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={stopped} session={session} onBack={vi.fn()} />);
    await flush();
    expect(mockedApi.patientInsights).not.toHaveBeenCalled();
    expect(mockedApi.patientMeasures).not.toHaveBeenCalled();
    expect(mockedApi.notes).toHaveBeenCalledWith("user-1", { offset: 0 });
    expect(textOf(root)).toContain("sharing ended 2026-09-10");
    expect(textOf(root)).toContain("no longer reachable");
    expect(textOf(root)).toContain("existing note text");
    expect(textOf(root)).not.toContain("Loading decrypted patterns");
    expect(textOf(root)).not.toContain("Mark reviewed");
    // The therapist can still write against their own record.
    await typeTextarea(root, "Note about this patient…", "post-revoke follow-up");
    await press(root, "Save note");
    await flush();
    expect(mockedApi.createNote).toHaveBeenCalledWith("user-1", expect.objectContaining({ blob: "SEALEDNOTE==" }));
  });

  it("M-22: the stopped list row hands the revoked patient to the notes-only chart", async () => {
    const onOpen = vi.fn();
    const stopped = { ...patient, user_id: "user-9", status: "revoked", revoked_at: "2026-09-10T00:00:00Z" };
    mockedApi.patients.mockResolvedValueOnce([stopped]);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={onOpen} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    expect(buttonByLabel(root, "Open my notes")).toBe(true);
    expect(buttonByLabel(root, "Open patterns")).toBe(false);
    await press(root, "Open my notes");
    expect(onOpen).toHaveBeenCalledWith(stopped);
  });

  it("M-23: a single Delete press never reaches the API", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "nd", client_note_id: "cd", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "Delete");
    await flush();
    expect(mockedApi.deleteNote).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Permanently delete this note?");
    // Arming one note does not arm another note's delete button.
    expect(buttonByLabel(root, "Confirm delete")).toBe(true);
  });

  it("L-76: measures page through everything, render per instrument, and disclose the display slice", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==",
    } as never);
    const dateFor = (n: number): string =>
      new Date(Date.UTC(2026, 0, 1) + n * 86_400_000).toISOString().slice(0, 10);
    const rowFor = (n: number) => ({
      id: `m-${n}`,
      client_measure_id: `m-${n}`,
      blob: "B==",
      measure_date: dateFor(n),
      received_at: "x",
    });
    mockedApi.patientMeasures
      .mockResolvedValueOnce(Array.from({ length: 100 }, (_, i) => rowFor(i)) as never)
      .mockResolvedValueOnce(Array.from({ length: 50 }, (_, i) => rowFor(100 + i)) as never);
    vi.mocked(mockedCrypto.decryptMeasure).mockImplementation(
      async (_dataKey: Uint8Array<ArrayBuffer>, _userId: string, row: { client_measure_id: string }) => {
        const n = Number(row.client_measure_id.slice(2));
        return { measure: "phq9", score: n % 28, completedAt: null, measureDate: dateFor(n) };
      },
    );
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush(6);
    // Continuation is offset-based; the second page starts past the first.
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(1, "user-1", { offset: 0, limit: 100 });
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(2, "user-1", { offset: 100, limit: 100 });
    expect(mockedApi.patientMeasures).toHaveBeenCalledTimes(2);
    // ALL 150 rows were fetched, decrypted, and counted — not a silent 60.
    expect(vi.mocked(mockedCrypto.decryptMeasure)).toHaveBeenCalledTimes(150);
    expect(rtr.textOf(root)).toContain("Recorded measures (150)");
    expect(rtr.textOf(root)).toContain("PHQ-9 (depression):");
    // Newest reading renders; oldest is outside the 60-per-instrument window.
    expect(rtr.textOf(root)).toContain(`${dateFor(149)}: ${149 % 28}`);
    expect(rtr.textOf(root)).not.toContain(`${dateFor(0)}: 0`);
    expect(rtr.textOf(root)).toContain("+90 earlier measures not shown");
  });

  it("L-76: a second instrument renders as its own named trend line", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==",
    } as never);
    const dateFor = (n: number): string =>
      new Date(Date.UTC(2026, 0, 1) + n * 86_400_000).toISOString().slice(0, 10);
    mockedApi.patientMeasures.mockResolvedValueOnce([
      { id: "m-0", client_measure_id: "m-0", blob: "B==", measure_date: dateFor(0), received_at: "x" },
      { id: "m-1", client_measure_id: "m-1", blob: "B==", measure_date: dateFor(1), received_at: "x" },
      { id: "m-2", client_measure_id: "m-2", blob: "B==", measure_date: dateFor(2), received_at: "x" },
      { id: "m-3", client_measure_id: "m-3", blob: "B==", measure_date: dateFor(3), received_at: "x" },
    ] as never);
    vi.mocked(mockedCrypto.decryptMeasure)
      .mockResolvedValueOnce({ measure: "phq9", score: 12, completedAt: null, measureDate: dateFor(0) })
      .mockResolvedValueOnce({ measure: "gad7", score: 8, completedAt: null, measureDate: dateFor(1) })
      .mockResolvedValueOnce({ measure: "phq9", score: 10, completedAt: null, measureDate: dateFor(2) })
      .mockResolvedValueOnce({ measure: "gad7", score: 6, completedAt: null, measureDate: dateFor(3) });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).toContain("Recorded measures (4)");
    expect(rtr.textOf(root)).toContain("PHQ-9 (depression): ");
    expect(rtr.textOf(root)).toContain("GAD-7 (anxiety): ");
    expect(rtr.textOf(root)).not.toContain("not shown");
  });

  it("L-77: a failed insights load stops saying 'Loading decrypted patterns…'", async () => {
    mockedApi.patientInsights.mockRejectedValueOnce(new Error("insights down"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("insights down");
    expect(textOf(root)).not.toContain("Loading decrypted patterns");
  });

  it("L-78: one undecryptable entry degrades per row instead of discarding the drill-down", async () => {
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "3", client_entry_id: "e-3", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptEntry)
      .mockResolvedValueOnce({ text: "decrypted e-1", sentiment: null })
      .mockRejectedValueOnce(new Error("blob failed authentication"))
      .mockResolvedValueOnce({ text: "decrypted e-3", sentiment: null });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(textOf(root)).toContain("decrypted e-1");
    expect(textOf(root)).toContain("decrypted e-3");
    expect(textOf(root)).toContain("(entry could not be decrypted with this consent's key)");
    expect(textOf(root)).not.toContain("could not load the evidence entries");
  });

  it("L-79: a legacy 409 code 'conflict' restarts the traversal once like collection_changed", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null,
    });
    const stale = {
      id: "stale-note", client_note_id: "stale-client", pattern_pid: null, blob: "stale",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    };
    const fresh = {
      id: "fresh-note", client_note_id: "fresh-client", pattern_pid: null, blob: "fresh",
      created_at: "2026-09-17T00:00:00Z", updated_at: "2026-09-17T00:00:00Z",
    };
    mockedApi.notes
      .mockResolvedValueOnce({ notes: [stale], nextOffset: 1, revision: "41" })
      .mockRejectedValueOnce(new ApiError(409, "notes changed while paging; retry the request", "conflict"))
      .mockResolvedValueOnce({ notes: [fresh], nextOffset: 1, revision: "42" })
      .mockResolvedValueOnce({ notes: [], nextOffset: null, revision: "42" });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);
    expect(mockedApi.notes).toHaveBeenNthCalledWith(3, "user-1", { offset: 0 });
    expect(vi.mocked(mockedCrypto.decryptNote).mock.calls.map((call) => call[3])).toEqual(["fresh-client"]);
    expect(textOf(root)).toContain("existing note text");
  });

  it("L-81: note draft and edit textareas carry programmatic labels", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    const draft = root.root.findAllByType("textarea").find((n) => n.props.placeholder === "Note about this patient…");
    expect(draft?.props["aria-label"]).toBe("New note about this patient");
    await press(root, "Edit");
    const edit = root.root.findAllByType("textarea").find((n) => n.props.placeholder === "Editing note…");
    expect(String(edit?.props["aria-label"])).toBe("Edit note from 2026-09-16");
  });

  it("L-82: mood_correlation without a direction renders the honest unknown", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      stats: {
        patterns: [
          { kind: "mood_correlation", label: "family", occurrences: 6, confidence: 0.7, detail: { mood_delta: -0.3, pattern_pid: "mood_correlation:family", evidence_dates: [] } },
        ],
      },
    } as never);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("read ? on days 'family' appears");
    expect(textOf(root)).not.toContain("read higher on days 'family' appears");
  });
});

// --- Audit round 2 (2026-09-21): F-8 banner fold + F-11 unpinned fixes --------

describe("PatientsView banner fold (audit round 2, 2026-09-21, F-8)", () => {
  // The scan/sort bar (and therefore any scan) only exists for a caseload
  // of 2+, so every case pairs its target with a quiet second patient.
  // Every once-queue below is fully consumed — a stray payload leaks into
  // the next test's scan (clearAllMocks does not clear once-queues).
  const calmScan = {
    stats: { patterns: [
      { kind: "temporal", label: "quiet", occurrences: 3, confidence: 0.4, detail: { pattern_pid: "t:quiet", evidence_dates: [] } },
    ] },
  };
  const sensitiveScan = {
    stats: { patterns: [
      { kind: "recurring_phrase", label: "heavy", occurrences: 2, confidence: 0.5, detail: { sensitive: true, pattern_pid: "r:heavy", evidence_dates: [] } },
    ] },
  };
  const second = { ...patient, user_id: "user-2", username: "patientb" };
  const view = async (pts: unknown[]) => {
    mockedApi.patients.mockResolvedValueOnce(pts as never);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    return root;
  };

  it("a FAILED scan does not hide the summary's sensitive flag from the banner", async () => {
    vi.mocked(mockedCrypto.decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: true, newest: "2026-09-18", forDate: "2026-09-19" });
    mockedApi.patientInsights.mockRejectedValueOnce(new Error("revoked mid-scan"));
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce(calmScan as never);
    const root = await view([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
      second,
    ]);
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
    await press(root, "Scan caseload for triage");
    await flush(8);
    // The target's scan failed (patterns -1): the banner must keep counting
    // the server summary's flag, exactly like the per-row display does.
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
    expect(textOf(root)).toContain("4 patterns as of 2026-09-19");
  });

  it("a successful scan that finds a sensitive card raises the banner over a calm summary", async () => {
    vi.mocked(mockedCrypto.decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: false, newest: "2026-09-18", forDate: "2026-09-19" });
    vi.mocked(mockedCrypto.decryptInsights)
      .mockResolvedValueOnce(sensitiveScan as never)
      .mockResolvedValueOnce(calmScan as never);
    const root = await view([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
      second,
    ]);
    expect(textOf(root)).not.toContain("sensitive card");
    await press(root, "Scan caseload for triage");
    await flush(8);
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
  });

  it("a successful scan that finds nothing sensitive drops the banner over a stale sensitive summary", async () => {
    vi.mocked(mockedCrypto.decryptCaseloadSummary)
      .mockResolvedValueOnce({ patterns: 4, sensitive: true, newest: "2026-09-18", forDate: "2026-09-19" });
    vi.mocked(mockedCrypto.decryptInsights)
      .mockResolvedValueOnce(calmScan as never)
      .mockResolvedValueOnce(calmScan as never);
    const root = await view([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
      second,
    ]);
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
    await press(root, "Scan caseload for triage");
    await flush(8);
    expect(textOf(root)).not.toContain("of your patients");
  });

  it("a patient known only from a scan row still counts toward the banner", async () => {
    vi.mocked(mockedCrypto.decryptInsights)
      .mockResolvedValueOnce(sensitiveScan as never)
      .mockResolvedValueOnce(calmScan as never);
    const root = await view([{ ...patient }, second]);
    expect(textOf(root)).not.toContain("sensitive card");
    await press(root, "Scan caseload for triage");
    await flush(8);
    // No summary ever decrypted; the scan row is the only evidence.
    expect(textOf(root)).toContain("1 of your patients has a sensitive card");
  });
});

describe("PatientsView caseload ordering (audit round 2, 2026-09-21, F-11)", () => {
  const threePatients = [
    { ...patient, username: "patienta", granted_at: "2026-09-10T10:00:00Z" },
    { ...patient, user_id: "user-2", username: "patientb", granted_at: "2026-09-01T10:00:00Z" },
    { ...patient, user_id: "user-3", username: "patientc", granted_at: "2026-09-05T10:00:00Z" },
  ];
  const namesInOrder = (root: Awaited<ReturnType<typeof render>>): string[] => {
    const text = textOf(root);
    return ["patienta", "patientb", "patientc"].sort((a, b) => text.indexOf(a) - text.indexOf(b));
  };
  const chooseSort = async (root: Awaited<ReturnType<typeof render>>, value: string): Promise<void> => {
    const select = root.root.find((n: { props?: Record<string, unknown> }) => n.props?.["aria-label"] === "Sort patients");
    await act(async () => { (select.props.onChange as (e: { target: { value: string } }) => void)({ target: { value } }); });
    await flush();
  };

  it("newest-share default, username ordering, and scan-based triage ordering all render in their order", async () => {
    mockedApi.patients.mockResolvedValueOnce(threePatients);
    // Scan payloads in patients-array order: a → 2 calm, b → 1 sensitive, c → 6 calm.
    vi.mocked(mockedCrypto.decryptInsights)
      .mockResolvedValueOnce({ stats: { patterns: [
        { kind: "temporal", label: "a1", occurrences: 2, confidence: 0.4, detail: { pattern_pid: "t:a1", evidence_dates: [] } },
        { kind: "temporal", label: "a2", occurrences: 2, confidence: 0.4, detail: { pattern_pid: "t:a2", evidence_dates: [] } },
      ] } } as never)
      .mockResolvedValueOnce({ stats: { patterns: [
        { kind: "recurring_phrase", label: "s1", occurrences: 1, confidence: 0.5, detail: { sensitive: true, pattern_pid: "r:s1", evidence_dates: [] } },
      ] } } as never)
      .mockResolvedValueOnce({
        stats: {
          patterns: [1, 2, 3, 4, 5, 6].map((i) => (
            { kind: "temporal", label: `c${i}`, occurrences: 1, confidence: 0.4, detail: { pattern_pid: `t:c${i}`, evidence_dates: [] } }
          )),
        },
      } as never);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    // Default: newest share first → a (09-10), c (09-05), b (09-01).
    expect(namesInOrder(root)).toEqual(["patienta", "patientc", "patientb"]);

    await chooseSort(root, "username");
    expect(namesInOrder(root)).toEqual(["patienta", "patientb", "patientc"]);

    await chooseSort(root, "triage");
    // No scan yet: triage falls back to newest-share order.
    expect(namesInOrder(root)).toEqual(["patienta", "patientc", "patientb"]);

    await press(root, "Scan caseload for triage");
    await flush(8);
    // With the scan: sensitive b first, then c (6 unreviewed) over a (2) —
    // a different order than every branch above, so the sort truly fired.
    expect(namesInOrder(root)).toEqual(["patientb", "patientc", "patienta"]);
  });
});

describe("PatientView per-context note drafts (audit round 2, 2026-09-21, F-11)", () => {
  const draftValue = (root: Awaited<ReturnType<typeof render>>, placeholder: string): string | undefined =>
    root.root.findAllByType("textarea").find((n) => n.props.placeholder === placeholder)?.props.value;

  it("general and pattern-anchored drafts stay isolated across context switches", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await typeTextarea(root, "Note about this patient…", "general draft");
    expect(draftValue(root, "Note about this patient…")).toBe("general draft");

    await openCard(root, "temporal — work");
    // The pattern composer starts clean: general text never leaks in.
    expect(draftValue(root, "Note about this pattern…")).toBe("");
    await typeTextarea(root, "Note about this pattern…", "pattern draft");

    await press(root, "Back to all patterns");
    // Back in the general context, the general draft survived the round trip.
    expect(draftValue(root, "Note about this patient…")).toBe("general draft");

    await openCard(root, "temporal — work");
    expect(draftValue(root, "Note about this pattern…")).toBe("pattern draft");
  });
});
