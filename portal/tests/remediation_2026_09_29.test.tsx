/**
 * 2026-09-29 independent-audit follow-up pins.
 *
 * The 2026-09-28 portal wave shipped F1–F10 live-verified but left four
 * things unpinned or regressed, found by the independent audit of commit
 * efe1b5f:
 *   - F10's Show/Hide password reveal toggle had ZERO automated coverage
 *     (its handler was the uncovered line in ui.tsx) — pinned here end to
 *     end, including the independent-state contract of two password rows.
 *   - F5's native <details> Disclosure had no structural pin — pinned as
 *     a component and in the login screen.
 *   - F2's highlight normalization missed the engine's ASCII folding
 *     ("café" → "cafe" in labels, accents kept in entries) — pinned with
 *     an accented match AND a non-match.
 *   - F8's kind map skipped the legacy recurring_phrase pid and the three
 *     coupling/sensemaking/diversity kinds — every pid prefix the engine
 *     emits (brain.py) is pinned.
 *   - the test press() helper fired onSubmit for DISABLED submit buttons
 *     (a browser does nothing) — the helper contract is pinned.
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
      me: vi.fn(async () => ({ username: "drportal", display_name: "Dr. Portal", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==" })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7 })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async () => null),
      updateNote: vi.fn(async () => null),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      rotateCredential: vi.fn(async () => null),
      rotateWrapKey: vi.fn(async () => null),
      totpSetup: vi.fn(async () => ({ secret_base32: "SECRET", otpauth_uri: "otpauth://x" })),
      totpEnable: vi.fn(async () => null),
      totpDisable: vi.fn(async () => null),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  const decryptNoteMock = vi.fn(async () => "existing note text");
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
      noteKeyV2: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } } as unknown as CryptoKey)),
    unlockWrapPrivateKeyWithNotesKey: vi.fn(async () => ({
      privateKey: { algorithm: { name: "ECDH" } } as unknown as CryptoKey,
      noteKeyV2: new Uint8Array(32),
    })),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({ state_seq: 7, stats: { patterns: [] } })),
    decryptEntry: vi.fn(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
      text: `decrypted ${entry.client_entry_id}`,
      sentiment: null,
    })),
    encryptNote: vi.fn(async () => ({ clientNoteId: "c", blobB64: "SEALEDNOTE==" })),
    decryptNote: decryptNoteMock,
    decryptNoteAny: vi.fn(async (...args: unknown[]) =>
      decryptNoteMock(...(args.slice(1) as Parameters<typeof decryptNoteMock>)),
    ),
    keyFingerprint: vi.fn(async () => "AABB CCDD"),
    openSealedPrivateKey: vi.fn(async () => new Uint8Array(138)),
    sealPrivateKeyForUpload: vi.fn(async () => "SEALED=="),
  };
});

const { auth } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const realApi = await vi.importActual<typeof import("../src/api")>("../src/api");
const ui = await import("../src/ui");
const { LoginView } = await import("../src/views/LoginView");
const { PatientView, patternAnchorLabel } = await import("../src/views/PatientView");
const { render, flush, textOf, textOfNode, press, typeInto } = await import("./helpers/rtr");
type PatternPayload = import("../src/crypto").PatternPayload;

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
      noteKeyV2: new Uint8Array(32),
  privateKey: {} as CryptoKey,
  publicKeyB64: "P".repeat(124),
};

beforeEach(() => {
  vi.clearAllMocks();
  mockedAuth.meta.mockReset().mockResolvedValue({ sharing_available: true });
  mockedAuth.saltFor.mockReset().mockResolvedValue({ salt: "QUJDREVGR0hJSktMTU5P" });
  mockedAuth.login.mockReset().mockResolvedValue({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" });
  mockedCrypto.deriveMasterKey.mockReset().mockResolvedValue(new Uint8Array(32));
  mockedCrypto.derivePortalKeys.mockReset().mockResolvedValue({ authKey: new Uint8Array(32), wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) });
  mockedCrypto.unwrapPatientDataKey.mockReset().mockResolvedValue(new Uint8Array(32));
  mockedCrypto.decryptInsights.mockReset().mockResolvedValue({ state_seq: 7, stats: { patterns: [] } });
  mockedCrypto.decryptEntry.mockReset().mockImplementation(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
    text: `decrypted ${entry.client_entry_id}`,
    sentiment: null,
  }));
  realApi.clearSession();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

// ---------------------------------------------------------------------------
// F10 pin: the password reveal toggle (uncovered since 2026-09-28)
// ---------------------------------------------------------------------------

describe("2026-09-29 follow-up: password reveal toggle (F10)", () => {
  it("flips the input to text and back, and is never a submit button", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "dromega");
    await typeInto(root, "Password", "hunter2");
    await flush();

    const passwordInput = () =>
      root.root.findAllByType("input").find((n) => n.props.autoComplete === "current-password")!;
    expect(passwordInput().props.type).toBe("password");

    const toggle = () =>
      root.root.findAllByType("button").find((n) => textOfNode(n) === "Show password" || textOfNode(n) === "Hide password")!;
    // The reveal toggle must never carry its form's submission.
    expect(toggle().props.type).toBe("button");

    await press(root, "Show password");
    await flush();
    expect(passwordInput().props.type).toBe("text");
    expect(textOf(root)).toContain("Hide password");

    await press(root, "Hide password");
    await flush();
    expect(passwordInput().props.type).toBe("password");
    expect(textOf(root)).toContain("Show password");
  });

  it("register mode: two password rows, each with its own independent toggle state", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush(3);

    // The <label> wraps the toggle button too, so match on the label's
    // FIRST child (the field__label span) for an exact comparison.
    const inputWithFieldLabel = (labelText: string) =>
      root.root.findAllByType("input").find((n) => {
        const label = root.root.findAllByType("label").find(node => node.props.htmlFor === n.props.id);
        return label ? textOfNode(label) === labelText : false;
      })!;
    const mainPw = inputWithFieldLabel("Password")!;
    const repeatPw = inputWithFieldLabel("Repeat password")!;
    expect(mainPw).toBeDefined();
    expect(repeatPw).toBeDefined();
    expect(mainPw.props.type).toBe("password");
    expect(repeatPw.props.type).toBe("password");

    // Two independent toggles exist; flipping the FIRST leaves the second masked.
    const toggles = root.root.findAllByType("button").filter((n) => textOfNode(n) === "Show password");
    expect(toggles.length).toBe(2);
    await press(root, "Show password");
    await flush();
    expect(mainPw.props.type).toBe("text");
    expect(repeatPw.props.type).toBe("password");
  });
});

// ---------------------------------------------------------------------------
// F5 pin: the native <details> Disclosure
// ---------------------------------------------------------------------------

describe("2026-09-29 follow-up: Disclosure (F5)", () => {
  it("renders native details/summary semantics with the body as a muted note", async () => {
    const root = await render(<ui.Disclosure summary="How it works">The long honest paragraph.</ui.Disclosure>);
    const details = root.root.findAllByType("details");
    expect(details.length).toBe(1);
    expect(details[0]!.props.className).toBe("disclose");
    const summary = root.root.findAllByType("summary");
    expect(summary.length).toBe(1);
    expect(textOfNode(summary[0]!)).toBe("How it works");
    const body = root.root.findAll((n) => n.props.className === "disclose__body");
    expect(body.length).toBe(1);
    // The body text stays in the tree (react-test-renderer ignores the
    // closed state; the browser hides it until opened).
    expect(textOf(root)).toContain("The long honest paragraph.");
  });

  it("the login screen carries the crypto-honesty disclosure", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await flush(3);
    const summary = root.root.findAllByType("summary").map((n) => textOfNode(n));
    expect(summary).toContain("How your password is protected");
    // The honest text itself must still exist one click away.
    expect(textOf(root)).toContain("Your password never leaves this page");
  });
});

// ---------------------------------------------------------------------------
// F2 pin: highlight matching survives the engine's ASCII folding
// ---------------------------------------------------------------------------

describe("2026-09-29 follow-up: evidence highlighting folds diacritics (F2)", () => {
  const pattern = (label: string): PatternPayload =>
    ({
      kind: "phrase",
      label,
      occurrences: 3,
      confidence: 0.5,
      // openDrilldown fetches only evidence_dates and keeps rows whose
      // entry_date is in that set — the fixture must match the entries.
      detail: { pattern_pid: `phrase:${label.slice(0, 6)}`, evidence_dates: ["2026-09-01", "2026-09-02"] },
    });

  it("a label the engine ASCII-folded still marks the accented entry; a different entry stays unmarked", async () => {
    // The engine folds labels to ASCII ("café" → "cafe"); entries keep
    // their accents and punctuation. Exactly one entry matches.
    mockedCrypto.decryptInsights.mockResolvedValueOnce({
      state_seq: 7,
      stats: { patterns: [pattern("no puedo dormir cafe cafeina y ansiedad")], total_entries: 2, active_days: 2 },
    });
    const { api } = await import("../src/api");
    const mockedApi = vi.mocked(api);
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-02", received_at: "x" },
      ],
      nextOffset: null,
    });
    mockedCrypto.decryptEntry.mockImplementation(async (_k: unknown, _u: string, entry: { client_entry_id: string }) =>
      entry.client_entry_id === "e-1"
        ? { text: "No puedo dormir: café, cafeína y ansiedad por la mañana.", sentiment: null }
        : { text: "Hoy dormí bien y desayuné con calma.", sentiment: null });

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(8);

    const marks = root.root.findAllByType("mark");
    expect(marks.length).toBe(1);
    expect(textOfNode(marks[0]!)).toContain("café");
    // The non-matching accented entry renders plain, not marked.
    expect(textOf(root)).toContain("Hoy dormí bien");
  });

  it("a punctuation-only label never marks anything (the normalized-needle guard)", async () => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({
      state_seq: 7,
      stats: { patterns: [pattern("!!! ???")], total_entries: 1, active_days: 1 },
    });
    const { api } = await import("../src/api");
    const mockedApi = vi.mocked(api);
    mockedApi.patientEntries.mockResolvedValue({
      entries: [{ id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" }],
      nextOffset: null,
    });
    mockedCrypto.decryptEntry.mockResolvedValue({ text: "cualquier cosa", sentiment: null });

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(8);
    expect(root.root.findAllByType("mark").length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// F8 pin: every pid kind the engine emits maps to human terms
// ---------------------------------------------------------------------------

describe("2026-09-29 follow-up: patternAnchorLabel covers every engine kind (F8)", () => {
  it.each([
    ["phrase:a4adc4d084fc", "a recurring phrase"],
    ["rumination:legacy-pid", "a recurring phrase"],
    ["recurring_phrase:legacy-pid", "a recurring phrase"],
    ["temporal:work-sunday", "a day-of-week pattern"],
    ["topic:money", "a topic pattern"],
    ["link:drained-sunday", "a day-after pattern"],
    ["mood_correlation:sleep", "a mood correlation"],
    ["mood_shift:higher", "a mood shift"],
    ["instability:mood", "a mood-swing pattern"],
    ["avoidance:family", "an avoidance pattern"],
    ["cadence:rhythm", "a writing-rhythm pattern"],
    ["coupling:energy_mood", "an energy–mood coupling"],
    ["sensemaking:causal_insight", "a sense-making pattern"],
    ["diversity:activity_tags", "an activity-variety pattern"],
    [null, "a pattern"],
    ["somethingnew:digest", "a pattern"],
  ] as [string | null, string][])("%s → %s", (pid, expected) => {
    expect(patternAnchorLabel(pid)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// Helper contract: press() honors the disabled state of submit buttons
// ---------------------------------------------------------------------------

describe("2026-09-29 follow-up: press() never submits through a disabled submit button", () => {
  it("rejects with a clear error instead of firing the form onSubmit", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await flush(3);
    // Empty form → canSignIn false → the Sign-in button is disabled; a
    // real browser does nothing on click or Enter.
    await expect(press(root, "Sign in")).rejects.toThrow(/disabled/);
    // And nothing happened: no error banner, no busy state.
    expect(textOf(root)).not.toContain("Sign-in failed");
  });
});
