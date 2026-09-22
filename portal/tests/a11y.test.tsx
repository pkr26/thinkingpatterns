// @vitest-environment jsdom
/**
 * Per-view accessibility verification — audit H-9c / Phase 2 item 5
 * ("jest-axe a11y suite per view"), delivered 2026-09-22 after the
 * round-3 deferral. Unlike the node-environment suites (react-test-
 * renderer, no DOM), these tests mount each view into a REAL DOM via
 * react-dom/client and run axe-core over the rendered tree, so label
 * association, heading structure, live-region semantics, and control
 * naming are verified exactly as a browser + screen reader see them.
 *
 * The api/crypto layers are mocked with the same fixtures as the
 * behavioral suites: a11y structure is under test, not network behavior.
 */
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { axe, toHaveNoViolations } from "jest-axe";

expect.extend(toHaveNoViolations as unknown as Parameters<typeof expect.extend>[0]);

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
      patients: vi.fn(async () => [
        {
          user_id: "user-1",
          username: "patienta",
          status: "active",
          granted_at: "2026-09-01T10:00:00Z",
          revoked_at: null,
          ephemeral_pub: "E".repeat(124),
          wrapped_key: "W==",
        },
        {
          user_id: "user-2",
          username: "patientb",
          status: "active",
          granted_at: "2026-09-02T10:00:00Z",
          revoked_at: null,
          ephemeral_pub: "E".repeat(124),
          wrapped_key: "W==",
        },
      ]),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==" })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({
        notes: [
          { id: "note-1", client_note_id: "c1", pattern_pid: null, blob: "NB==", created_at: "2026-09-10T00:00:00Z", updated_at: "2026-09-10T00:00:00Z" },
        ],
        nextOffset: null,
      })),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => []),
      accessLog: vi.fn(async () => []),
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
      sentiment: null,
    })),
    encryptNote: vi.fn(async () => ({ blobB64: "SEALEDNOTE==" })),
    decryptNote: vi.fn(async () => "existing note text"),
  };
});

// react-dom act() requires this flag outside react-test-renderer.
(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;

const { LoginView } = await import("../src/views/LoginView");
const { PatientsView } = await import("../src/views/PatientsView");
const { PatientView } = await import("../src/views/PatientView");

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

let mountedRoot: Root | null = null;
let mountedContainer: HTMLElement | null = null;

/** Mount a view into document.body, flush async effects, return the
 *  container axe should scan. Unmounted after each test. */
const mount = async (ui: React.ReactElement): Promise<HTMLElement> => {
  const container = document.createElement("div");
  document.body.appendChild(container);
  mountedContainer = container;
  await act(async () => {
    mountedRoot = createRoot(container);
    mountedRoot.render(ui);
  });
  for (let i = 0; i < 8; i += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
  return container;
};

const clickButton = async (container: HTMLElement, label: string): Promise<void> => {
  const buttons = [...container.querySelectorAll("button")];
  const target = buttons.find((b) => (b.textContent ?? "").includes(label));
  if (!target) throw new Error(`no button labeled "${label}"`);
  await act(async () => {
    target.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  for (let i = 0; i < 4; i += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
};

beforeEach(() => {
  vi.clearAllMocks();
  document.body.innerHTML = "";
});

afterEach(async () => {
  const root = mountedRoot;
  if (root) {
    await act(async () => {
      root.unmount();
    });
    mountedRoot = null;
  }
  mountedContainer?.remove();
  mountedContainer = null;
});

describe("per-view axe scans (audit H-9c, delivered 2026-09-22)", () => {
  it("LoginView — sign-in mode — has no accessibility violations", async () => {
    const container = await mount(<LoginView onReady={vi.fn()} />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("LoginView — register mode (incl. the irrecoverability warning) — has no violations", async () => {
    const container = await mount(<LoginView onReady={vi.fn()} />);
    await clickButton(container, "Create a therapist account instead");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("PatientsView — caseload with rows, search/sort controls — has no violations", async () => {
    const container = await mount(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it("PatientsView — account-security panel (credential rotation forms) — has no violations", async () => {
    const container = await mount(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await clickButton(container, "Show account security");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("PatientView — pattern cards, sensitive card, notes, measures — has no violations", async () => {
    const container = await mount(
      <PatientView patient={patient} session={session} onBack={vi.fn()} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
