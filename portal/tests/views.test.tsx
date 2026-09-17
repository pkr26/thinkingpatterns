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

const { auth, api } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const { LoginView } = await import("../src/views/LoginView");
const { PatientsView } = await import("../src/views/PatientsView");
const { PatientView } = await import("../src/views/PatientView");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const { render, flush, textOf, press, buttonByLabel, typeInto, typeTextarea } = await import(
  "./helpers/rtr"
);

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
  wrapKek: new Uint8Array(32),
  noteKey: new Uint8Array(32),
  privateKey: {} as CryptoKey,
  publicKeyB64: "P".repeat(124),
};

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
});

describe("LoginView", () => {
  it("signs in: salt -> derive -> login -> onReady", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    await typeInto(root, "Server", "https://api.example.com");
    await press(root, "Sign in");
    await flush();
    expect(mockedAuth.saltFor).toHaveBeenCalled();
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", "AUTHKEY==");
    expect(onReady).toHaveBeenCalledWith(
      expect.objectContaining({ username: "drportal", userId: "therapist-1" }),
      expect.objectContaining({ token: "tok" }),
      expect.any(String),
    );
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
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "one");
    await typeInto(root, "Repeat password", "one");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("username already taken");
  });

  it("a non-Error registration failure shows the generic fallback", async () => {
    mockedAuth.registerTherapist.mockRejectedValueOnce("nope");
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "one");
    await typeInto(root, "Repeat password", "one");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("registration failed");
  });

  it("registers: mismatched passwords blocked; happy path seals the key", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await press(root, "Create a therapist account instead");
    await typeInto(root, "Your name", "Dr. New");
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "one");
    await typeInto(root, "Repeat password", "two");
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("passwords do not match");

    await typeInto(root, "Repeat password", "one");
    await press(root, "Create account");
    await flush();
    expect(mockedCrypto.sealPrivateKeyForUpload).toHaveBeenCalled();
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ username: "drnew", display_name: "Dr. New", wrap_pub_key: "P".repeat(124) }),
    );
    expect(onReady).toHaveBeenCalled();
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
});

describe("PatientView", () => {
  it("renders pattern cards, the sensitive card non-quoting, and the drill-down", async () => {
    mockedApi.patientEntries.mockResolvedValueOnce([
      { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" },
      { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-08", received_at: "x" },
      { id: "3", client_entry_id: "e-3", blob: "b", entry_date: "2026-09-09", received_at: "x" }, // outside evidence
      { id: "4", client_entry_id: "e-4", blob: "b", entry_date: "2026-09-08", received_at: "x" },
    ]);
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

    await press(root, "See the evidence");
    await flush();
    expect(mockedApi.patientEntries).toHaveBeenCalledWith(
      "user-1",
      expect.objectContaining({ since: "2026-09-01", until: "2026-09-08" }),
    );
    // Only the pattern's evidence dates are kept (2026-09-09 dropped).
    expect(textOf(root)).toContain("decrypted e-1");
    expect(textOf(root)).toContain("decrypted e-2");
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

  it("shows an honest placeholder for notes it cannot decrypt", async () => {
    mockedApi.notes.mockResolvedValueOnce([
      { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
    ]);
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
    await press(root, "See the evidence"); // open the pattern so notes bind to it
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
    mockedApi.notes.mockResolvedValueOnce([
      { id: "nd", client_note_id: "cd", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
    ]);
    root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    mockedApi.deleteNote.mockRejectedValueOnce("offline");
    await press(root, "Delete");
    await flush();
    expect(textOf(root)).toContain("could not delete the note");
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
    expect(textOf(root2)).toContain("1 pattern new since your last visit");
    expect(textOf(root)).not.toContain("new since your last visit");
  });
});
