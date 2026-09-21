/**
 * Audit-fix regressions (2026-09-21, AUDIT_2026-09-21.md section 1.4):
 * FIX 15 — only the .print-only session summary prints; the evidence
 *           drill-down's decrypted journal text never reaches paper.
 * FIX 16 — multi-line notes and journal entries keep their line breaks
 *           on screen and in print (white-space: pre-wrap).
 * FIX 17 — failed loads offer an in-page retry instead of reload/sign-out.
 * FIX 18 — the login form submits on Enter; status notices are live regions.
 *
 * Same mocked api/crypto seams as views.test.tsx (the crypto itself is
 * pinned by tests/crypto.test.ts against the real WebCrypto).
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
      accessLog: vi.fn(async () => [
        { at: "2026-09-21T10:00:00Z", action: "read_notes", patient_name: "pat1" },
        { at: "2026-09-21T09:00:00Z", action: "wrap_key_rotate", patient_name: null },
      ]),
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
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({
      stats: {
        patterns: [
          { kind: "temporal", label: "work", occurrences: 9, confidence: 0.8, detail: { day: "Sunday", pattern_pid: "temporal:work", pattern_state: "confirmed", evidence_dates: ["2026-09-01", "2026-09-08"], first_seen: "2026-08-20", last_seen: "2026-09-08" } },
          { kind: "recurring_phrase", label: "can't sleep", occurrences: 4, confidence: 0.5, detail: { sensitive: true, pattern_pid: "recurring_phrase:x", evidence_dates: ["2026-09-02"] } },
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
const { render, flush, textOf, press, buttonByLabel, typeInto } = await import("./helpers/rtr");
const { act } = await import("react-test-renderer");

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

/** Joined text of a rendered subtree (react-test-renderer instances carry
 *  their children as strings or nested instances; CSS never applies here,
 *  so print assertions are class/stylesheet-based like the a11y ones). */
type NodeLike = { children?: unknown };
const deepText = (node: NodeLike): string => {
  const parts: string[] = [];
  const walk = (value: unknown): void => {
    if (typeof value === "string") parts.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value !== null && typeof value === "object" && "children" in value) {
      walk((value as NodeLike).children);
    }
  };
  walk(node.children);
  return parts.join("");
};

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("audit fixes 2026-09-21 (AUDIT_2026-09-21.md 1.4)", () => {
  it("FIX 15: the evidence drill-down's decrypted journal text is excluded from the print tree", async () => {
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(textOf(root)).toContain("decrypted e-1");

    // The PHI-bearing sections are explicitly marked non-printing…
    const evidence = root.root.findAllByType("section").find((n) => deepText(n).includes("Evidence entries"));
    expect(evidence?.props.className).toBe("no-print");
    const composer = root.root.findAllByType("section").find((n) => deepText(n).includes("Notes on this pattern"));
    expect(composer?.props.className).toBe("no-print");

    // …and the print stylesheet hides EVERY direct chart section except the
    // .print-only summary, so no card can reach paper even unmarked.
    const css = root.root.findAllByType("style").map((n) => deepText(n)).join("");
    expect(css).toContain("main > *:not(.print-only) { display: none !important; }");
    expect(css).toContain(".no-print, .no-print * { display: none !important; }");
    expect(css).toContain(".print-only { display: block !important; }");

    // The only printed subtree carries the summary — never the raw entries.
    const printOnly = root.root.findAllByType("div").find((n) => n.props.className === "print-only");
    expect(printOnly).toBeTruthy();
    expect(deepText(printOnly!)).toContain("MindPattern session summary — patienta");
    expect(deepText(printOnly!)).not.toContain("decrypted e-1");
    // Screen behavior is unchanged: the summary stays hidden outside print.
    expect(printOnly!.props.style.display).toBe("none");
  });

  it("FIX 15: print forces dark text on white — the inline dark theme cannot leak to paper", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    const css = root.root.findAllByType("style").map((n) => deepText(n)).join("");
    // <main> carries the inline dark colors (#0d1117 bg / #c3ccdb text);
    // only an !important author rule can override an inline style object.
    expect(css).toContain("body, main { background: #fff !important; color: #000 !important; }");
  });

  it("FIX 15: recorded measures print in the session summary", async () => {
    mockedApi.patientMeasures.mockResolvedValueOnce([
      { id: "1", client_measure_id: "m-1", blob: "B1==", measure_date: "2026-09-04", received_at: "x" },
      { id: "2", client_measure_id: "m-2", blob: "B2==", measure_date: "2026-09-11", received_at: "x" },
    ] as never);
    vi.mocked(mockedCrypto.decryptMeasure)
      .mockResolvedValueOnce({ measure: "phq9", score: 14, completedAt: null, measureDate: "2026-09-04" })
      .mockResolvedValueOnce({ measure: "phq9", score: 9, completedAt: null, measureDate: "2026-09-11" });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    const printOnly = root.root.findAllByType("div").find((n) => n.props.className === "print-only");
    expect(printOnly).toBeTruthy();
    expect(deepText(printOnly!)).toContain("Recorded measures");
    expect(deepText(printOnly!)).toContain("phq9: 2026-09-04: 14");
  });

  it("FIX 16: multi-line notes and journal entries keep their line breaks on screen and in print", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptNote).mockResolvedValueOnce("line one\n- bullet\nline three");
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptEntry).mockResolvedValueOnce({ text: "journal line one\njournal line two", sentiment: null });

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    // The rendered note keeps the typed line breaks…
    const noteP = root.root.findAllByType("p").find((n) => deepText(n).includes("line one"));
    expect(noteP?.props.style.whiteSpace).toBe("pre-wrap");
    // …including in the printed summary.
    const printOnly = root.root.findAllByType("div").find((n) => n.props.className === "print-only");
    const printedNoteP = printOnly!.findAllByType("p").find((n) => deepText(n).includes("line one"));
    expect(printedNoteP?.props.style.whiteSpace).toBe("pre-wrap");

    // Drill-down entries render pre-wrap as well.
    await press(root, "See the evidence");
    await flush();
    const entryP = root.root.findAllByType("p").find((n) => deepText(n).includes("journal line one"));
    expect(entryP?.props.style.whiteSpace).toBe("pre-wrap");
  });

  it("FIX 17: the patients list offers a retry that re-triggers the fetch", async () => {
    mockedApi.patients
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce([patient]);
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("network down");
    expect(buttonByLabel(root, "Retry loading patients")).toBe(true);

    await press(root, "Retry loading patients");
    await flush();
    expect(mockedApi.patients).toHaveBeenCalledTimes(2);
    expect(textOf(root)).toContain("patienta");
    expect(textOf(root)).not.toContain("network down");
  });

  it("FIX 17: the chart offers a retry that reloads patterns after a failed load", async () => {
    mockedApi.patientInsights.mockRejectedValueOnce(new Error("insights down"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("insights down");
    expect(buttonByLabel(root, "Retry loading this patient")).toBe(true);

    await press(root, "Retry loading this patient");
    await flush();
    expect(mockedApi.patientInsights).toHaveBeenCalledTimes(2);
    expect(textOf(root)).toContain("work");
    expect(textOf(root)).not.toContain("insights down");
    expect(buttonByLabel(root, "Retry loading this patient")).toBe(false);
  });

  it("FIX 17: a drill-down failure shows the banner WITHOUT the chart-retry affordance", async () => {
    mockedApi.patientEntries.mockRejectedValueOnce(new Error("offline"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await press(root, "See the evidence");
    await flush();
    expect(textOf(root)).toContain("offline");
    expect(buttonByLabel(root, "Retry loading this patient")).toBe(false);
  });

  it("FIX 18: Enter submits the login form (form submit with preventDefault)", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "right-password");
    const form = root.root.findAllByType("form");
    expect(form).toHaveLength(1);
    const preventDefault = vi.fn();
    await act(async () => { form[0]!.props.onSubmit({ preventDefault }); });
    await flush();
    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(mockedAuth.saltFor).toHaveBeenCalledWith(expect.any(String), "drportal");
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", expect.any(String));
    expect(onReady).toHaveBeenCalled();
  });

  it("FIX 18: submitting an incomplete form stays inert (the guard mirrors the disabled button)", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    const form = root.root.findAllByType("form")[0]!;
    await act(async () => { form.props.onSubmit({ preventDefault: vi.fn() }); });
    await flush();
    expect(mockedAuth.saltFor).not.toHaveBeenCalled();
    expect(mockedAuth.login).not.toHaveBeenCalled();
  });

  it("FIX 18: the registration form submits once its guards pass", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Your name", "Dr. New");
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    const form = root.root.findAllByType("form")[0]!;
    await act(async () => { form.props.onSubmit({ preventDefault: vi.fn() }); });
    await flush();
    expect(mockedAuth.registerTherapist).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ username: "drnew", display_name: "Dr. New" }),
    );
    expect(onReady).toHaveBeenCalled();
  });

  it("FIX 18: enrollment-policy status notices are live regions (role=status)", async () => {
    // Park the policy check so the transient "Checking…" notice stays up.
    mockedAuth.meta.mockImplementationOnce(() => new Promise(() => {}));
    let root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    const checking = root.root.findAllByType("p").find((n) => deepText(n).includes("Checking this server"));
    expect(checking?.props.role).toBe("status");

    mockedAuth.meta.mockResolvedValueOnce({ sharing_available: false });
    root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    const unavailable = root.root.findAllByType("p").find((n) => deepText(n).includes("New clinician enrollment is unavailable"));
    expect(unavailable?.props.role).toBe("status");
  });

  it("FIX F4: registration warns that a forgotten password is unrecoverable", async () => {
    // Login mode must not carry the warning; the register form must state
    // the irreversibility BEFORE the account exists (no reset path in v1).
    const loginRoot = await render(<LoginView onReady={vi.fn()} />);
    await flush();
    expect(textOf(loginRoot)).not.toContain("no password reset");

    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    expect(textOf(root)).toContain("There is no password reset and no account recovery");
    expect(textOf(root)).toContain("permanently unreadable");
  });

  it("FIX B-4: the therapist can read their own access history on demand", async () => {
    // Nothing loads until asked (the trail is a compliance read, not a
    // default panel); pressing load renders the audited actions.
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(mockedApi.accessLog).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("My access history");

    await press(root, "Load access history");
    await flush();
    expect(mockedApi.accessLog).toHaveBeenCalledTimes(1);
    const text = textOf(root);
    expect(text).toContain("read notes");
    expect(text).toContain("pat1");
    expect(text).toContain("wrap key rotate");
  });

  it("F-6: no empty-caseload flash before the first fetch resolves", async () => {
    // Park the first patients() call so the loading state is observable.
    mockedApi.patients.mockImplementationOnce(() => new Promise(() => {}));
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("Loading your caseload");
    expect(textOf(root)).not.toContain("No patients are sharing with you yet");
  });

  it("F-6: search filters the active list by username", async () => {
    mockedApi.patients.mockResolvedValueOnce([
      patient,
      { ...patient, user_id: "u2", username: "zeta" },
    ]);
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("zeta");
    await typeInto(root, "search", "pat");
    await flush();
    const text = textOf(root);
    expect(text).toContain("patienta");
    expect(text).not.toContain("zeta");
  });
});
