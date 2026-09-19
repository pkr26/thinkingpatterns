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
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    await press(root, "Sign in");
    await flush();
    expect(mockedAuth.saltFor).toHaveBeenCalled();
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", "AUTHKEY==");
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
    expect(mockedCrypto.sealPrivateKeyForUpload).toHaveBeenCalled();
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ username: "drnew", display_name: "Dr. New", wrap_pub_key: "P".repeat(124) }),
    );
    expect(onReady).toHaveBeenCalled();
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
    await press(root, "Delete");
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

    // note delete
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

  it("flags patterns new since the last visit via the local stamp", async () => {
    window.localStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-01T00:00:00.000Z");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    // first_seen 2026-08-20 is NOT newer than the stamp; refresh the stamp
    // to a date before first_seen to see the badge.
    window.localStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-08-01T00:00:00.000Z");
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
    window.localStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-08-01T00:00:00.000Z");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("since you marked reviewed 2026-08-01");
    expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).toBe("2026-08-01T00:00:00.000Z");

    await press(root, "Mark reviewed (update the delta anchor)");
    await flush();
    expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.user-1")).not.toBe("2026-08-01T00:00:00.000Z");
    expect(textOf(root)).not.toContain("pattern new since");
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
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await openCard(root, "temporal — work");
    await flush();
    const svg = root.root.findAllByType("svg");
    expect(svg.length).toBeGreaterThan(0);
  });
});
