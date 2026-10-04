/**
 * View behavior with mocked api/crypto layers (the crypto itself is
 * pinned by tests/crypto.test.ts against the real WebCrypto): login and
 * registration flows, the patients list + pairing code, and the patient
 * view — pattern cards, the sensitive non-quoting card, the evidence
 * drill-down, and notes.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    auth: {
      meta: vi.fn(async () => ({ sharing_available: true })),
      saltFor: vi.fn(async () => ({ salt: "QUJDREVGR0hJSktMTU5P" })),
      login: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
      logoutBearer: vi.fn(async () => null),
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
      patientInsights: vi.fn(async () => ({
        phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==",
        // 2026-09-26 audit L: the echoed generation now travels with every
        // insights summary; the default payload below decrypts to seq 7.
        state_seq: 7,
      })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      pairingSas: vi.fn(async () => ({ sas: "482 913", wrap_key_fingerprint: "a1b2c3d4e5f60718", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      totpSetup: vi.fn(async () => ({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:test" })),
      totpEnable: vi.fn(async () => ({ backup_codes: ["ABCDE12345", "FGHIJ67890"] })),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  const decryptNoteMock = vi.fn(async () => "existing note text");
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    // Audit fix P-1 (2026-09-20): the verifier is raw bytes (base64 derived
    // only at the send); key generation returns the sealed blob directly.
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
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } })),
    unlockWrapPrivateKeyWithNotesKey: vi.fn(async () => ({
      privateKey: { algorithm: { name: "ECDH" } } as unknown as CryptoKey,
      noteKeyV2: new Uint8Array(32),
    })),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({
      // 2026-09-26 audit L: matches the default patientInsights echo above.
      state_seq: 7,
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
    decryptNote: decryptNoteMock,
    decryptNoteAny: vi.fn(async (...args: unknown[]) =>
      decryptNoteMock(...(args.slice(1,6) as Parameters<typeof decryptNoteMock>)),
    ),
  };
});

const { auth, api, ApiError } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const { LoginView, passwordPolicyError } = await import("../src/views/LoginView");
const { PatientsView, resetScanConfirmation } = await import("../src/views/PatientsView");
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

async function confirmMinimumAge(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  const checkbox = root.root.findAllByType("input").find((node) => node.props.type === "checkbox");
  if (!checkbox) throw new Error("minimum-age confirmation checkbox is missing");
  await act(async () => { checkbox.props.onChange({ target: { checked: true } }); });
}

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
  window.localStorage.clear();
  // L-75 (2026-09-20): delta anchors now live in per-tab sessionStorage
  // (the shim provides it), so tests that pin anchor behavior seed it there.
  window.sessionStorage.clear();
  // 2026-09-26 audit round (M, UX copy): the scan confirmation's
  // "don't ask again" latch is module state — every test starts un-asked,
  // exactly like a fresh page load.
  resetScanConfirmation();
});

describe("LoginView", () => {
  it("drops the setup secret and verifier after MFA enable, and revokes an abandoned handoff", async () => {
    mockedAuth.login.mockResolvedValueOnce({ token: "unenrolled-token", user_id: "therapist-1", expires_in: 900, role: "therapist", mfa_enrollment_required: true });
    const onReady = vi.fn(async () => { throw new Error("local portal unlock failed"); });
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "pw");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("JBSWY3DPEHPK3PXP");
    expect(textOf(root)).toContain("otpauth://");

    await typeInto(root, "Authenticator code", "123456");
    await press(root, "Enable two-factor authentication");
    await flush();
    expect(textOf(root)).toContain("ABCDE12345");
    expect(textOf(root)).not.toContain("JBSWY3DPEHPK3PXP");
    expect(textOf(root)).not.toContain("otpauth://");

    await press(root, "I saved the codes — continue");
    await flush();
    expect(mockedAuth.logoutBearer).toHaveBeenCalledWith(expect.any(String), "unenrolled-token");
    expect(textOf(root)).toContain("Two-factor authentication is enabled");
    expect(textOf(root)).toContain("ABCDE12345");
    expect(textOf(root)).toContain("I saved the codes — return to sign in");
    expect(textOf(root)).not.toContain("JBSWY3DPEHPK3PXP");

    await press(root, "I saved the codes — return to sign in");
    await flush();
    expect(textOf(root)).toContain("Sign in");
    expect(textOf(root)).not.toContain("ABCDE12345");
  });

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
    expect(mockedAuth.login).toHaveBeenCalledWith(expect.any(String), "drportal", expectedVerifier, undefined);
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
    // 2026-09-28 audit F6: the raw server detail is mapped to actionable copy.
    expect(textOf(root)).toContain("Sign-in failed — check your username and password.");
  });

  it("never renders hostile or non-English API detail during sign-in", async () => {
    const hostile = "<script>alert(1)</script> credenciales rechazadas";
    mockedAuth.login.mockRejectedValueOnce(new ApiError(400, hostile, "unexpected"));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "wrong");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("Sign-in failed — check your details and try again.");
    expect(textOf(root)).not.toContain(hostile);
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
    await confirmMinimumAge(root);
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
    await confirmMinimumAge(root);
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("registration failed");
  });

  it("maps registration API failures to stable client copy without rendering server detail", async () => {
    const hostile = "<img src=x onerror=alert(1)> usuario ya existe";
    mockedAuth.registerTherapist.mockRejectedValueOnce(new ApiError(409, hostile, "conflict"));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Username", "drnew");
    await typeInto(root, "Password", "Strong!pass123");
    await typeInto(root, "Repeat password", "Strong!pass123");
    await confirmMinimumAge(root);
    await press(root, "Create account");
    await flush();
    expect(textOf(root)).toContain("That username is already in use.");
    expect(textOf(root)).not.toContain(hostile);
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
    await confirmMinimumAge(root);
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
    await confirmMinimumAge(root);
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
    await confirmMinimumAge(root);
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

  it("E (2026-09-26): entering the patient's id pulls the SAS beside the code, with compare-out-of-band copy", async () => {
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    await press(root, "Generate pairing code");
    await flush();
    expect(textOf(root)).toContain("7X2KQM4N");
    // The SAS block (and its field) appear only once a live code exists;
    // the button stays disabled until the patient-supplied id is typed.
    expect(buttonByLabel(root, "Show verification code")).toBe(true);
    await typeInto(root, "Patient's account id (shown in their app)", "0123456789abcdef0123456789abcdef");
    await press(root, "Show verification code");
    await flush();
    expect(mockedApi.pairingSas).toHaveBeenCalledWith("0123456789abcdef0123456789abcdef", "7X2KQM4N");
    expect(textOf(root)).toContain("482 913");
    expect(textOf(root)).toContain("a1b2c3d4e5f60718");
    // The honest comparison instruction, including the stop-on-mismatch.
    expect(textOf(root)).toContain("matches EXACTLY");
    expect(textOf(root)).toContain("generate a new code and do not proceed");
  });

  it("E: a flat 404 on the SAS read explains the dead/unknown code; a fresh code retires the comparison", async () => {
    mockedApi.pairingSas.mockRejectedValueOnce(new ApiError(404, "pairing code not found", "not_found"));
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    await press(root, "Generate pairing code");
    await flush();
    await typeInto(root, "Patient's account id (shown in their app)", "0123456789abcdef0123456789abcdef");
    await press(root, "Show verification code");
    await flush();
    expect(textOf(root)).toContain("pairing code not found or expired");
    expect(textOf(root)).not.toContain("482 913");
    // A new code is a NEW pairing session — the stale comparison (and its
    // error) must not survive into it.
    mockedApi.newPairingCode.mockResolvedValueOnce({ code: "ZZ99ZZ99", expires_in: 900 });
    await press(root, "Generate pairing code");
    await flush();
    expect(textOf(root)).not.toContain("pairing code not found or expired");
    expect(textOf(root)).not.toContain("482 913");
  });

  // --- independent audit 2026-09-27: local wrap-key fingerprint cross-check ---

  /** Drive the SAS flow on a session-backed view and return the root. */
  const sasWithSession = async (): Promise<Awaited<ReturnType<typeof render>>> => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await press(root, "Generate pairing code");
    await flush();
    await typeInto(root, "Patient's account id (shown in their app)", "0123456789abcdef0123456789abcdef");
    await press(root, "Show verification code");
    await flush(6);
    return root;
  };

  it("a server fingerprint that MATCHES the locally computed one renders no warning", async () => {
    // The server value is derived from the SAME SPKI DER the portal holds —
    // the honest-server case. serverWrapKeyFingerprint is the real (unmocked)
    // implementation, so the test computes exactly what the view should.
    const honest = await mockedCrypto.serverWrapKeyFingerprint(session.publicKeyB64);
    mockedApi.pairingSas.mockResolvedValueOnce({ sas: "482 913", wrap_key_fingerprint: honest, expires_in: 900 });
    const root = await sasWithSession();
    expect(textOf(root)).toContain("482 913");
    expect(textOf(root)).toContain(`key id ${honest}`);
    expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");
  });

  it("a server fingerprint that DIFFERS from the locally computed one renders the visible mismatch warning", async () => {
    // The default mock value ("a1b2c3d4e5f60718") is a well-formed server
    // fingerprint of some OTHER key — a substituted-key or lying server.
    const honest = await mockedCrypto.serverWrapKeyFingerprint(session.publicKeyB64);
    expect("a1b2c3d4e5f60718").not.toBe(honest); // the fixture really is foreign
    const root = await sasWithSession();
    expect(textOf(root)).toContain("KEY FINGERPRINT MISMATCH");
    expect(textOf(root)).toContain("does not match the one this portal computed");
    expect(textOf(root)).toContain("generate a new code and do not proceed");
  });

  it("a missing/malformed server fingerprint is treated as absent — no warning, no free-form render, honest copy", async () => {
    mockedApi.pairingSas.mockResolvedValueOnce({ sas: "482 913", wrap_key_fingerprint: "NOT-16-HEX!!", expires_in: 900 });
    const root = await sasWithSession();
    expect(textOf(root)).toContain("482 913");
    // Invalid shape never renders as a "key id" and never raises the
    // mismatch alarm (nothing was compared); the note says so honestly.
    expect(textOf(root)).toContain("sent no valid key fingerprint");
    expect(textOf(root)).not.toContain("NOT-16-HEX!!");
    expect(textOf(root)).not.toContain("key id");
    expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");
  });

  it("L-10 (2026-09-28): a present server fingerprint with NO local digest says the local cross-check could not run", async () => {
    // Digest-failure path: the session exists, but the portal could not
    // compute its own wrap-key fingerprint — the cross-check must not
    // silently no-op behind the "(key id …)" render.
    const digest = vi.spyOn(mockedCrypto, "serverWrapKeyFingerprint")
      .mockRejectedValueOnce(new Error("digest unavailable"));
    try {
      let root = await sasWithSession();
      expect(textOf(root)).toContain("482 913");
      // The server value is present and well-formed, so it still renders as
      // the key id — now with the honest caveat beside it, never as a
      // silently skipped check.
      expect(textOf(root)).toContain("key id a1b2c3d4e5f60718");
      expect(textOf(root)).toContain("cross-check against the server's key id could not run");
      expect(textOf(root)).toContain("only the out-of-band");
      // Nothing was compared, so no mismatch alarm fires.
      expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");
      // With the digest restored, a genuinely foreign server fingerprint
      // still raises the visible mismatch warning (unchanged behavior).
      root = await sasWithSession();
      expect(textOf(root)).toContain("KEY FINGERPRINT MISMATCH");
    } finally {
      digest.mockRestore();
    }
  });

  it("L-10: with no session prop the same honest could-not-run note renders beside the key id", async () => {
    // No session → no local wrap-key digest at all, while the server's
    // fingerprint is present: the local cross-check is skipped, and the
    // panel must say so instead of rendering the key id as if verified.
    const root = await render(<PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush();
    await press(root, "Generate pairing code");
    await flush();
    await typeInto(root, "Patient's account id (shown in their app)", "0123456789abcdef0123456789abcdef");
    await press(root, "Show verification code");
    await flush();
    expect(textOf(root)).toContain("482 913");
    expect(textOf(root)).toContain("key id a1b2c3d4e5f60718");
    expect(textOf(root)).toContain("cross-check against the server's key id could not run");
    expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");
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
    await startScan(root);
    await flush(6);

    expect([...firstKey]).toEqual(new Array(32).fill(0));
    expect([...secondKey]).toEqual(new Array(32).fill(0));
  });
});

/** 2026-09-26 audit round (M, UX copy): every scan begins with the one-time
 *  confirmation naming the access footprint; this helper arms and confirms
 *  it in one step (the confirmation's own copy/cancel/don't-ask behavior is
 *  pinned in its own describe below). */
async function startScan(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  await press(root, "Scan caseload for triage");
  await press(root, "Start the triage scan");
}

/** 2026-09-17: cards render in REVIEW ORDER (sensitive/down-shifts lead),
 *  so tests open a specific card by title fragment instead of position. */
async function openCard(root: Awaited<ReturnType<typeof render>>, titlePart: string): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const titles = root.root.findAllByType("h2").map((n) => String(n.props.children)).join("|");
    if (titles.includes(titlePart)) return;
    const buttons = root.root.findAllByType("button").filter((n) => joinedLabel(n) === "See the evidence");
    const target = buttons[attempt];
    if (!target) break;
    await act(async () => { target.props.onClick(); });
    await flush();
    const nowTitles = root.root.findAllByType("h2").map((n) => String(n.props.children)).join("|");
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
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("baseline phase");
    expect(mockedCrypto.unwrapPatientDataKey).not.toHaveBeenCalled();
  });

  it("loads private notes page-by-page during baseline and explains their scope", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
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
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
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
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
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
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
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
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [] } });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("No recurring pattern has enough evidence yet");
  });

  it("covers the remaining describe arms: inertia, instability, topic, default, quoted phrase", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      state_seq: 7,
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
    expect(textOf(root)).toContain("steady presence");
    expect(textOf(root)).toContain("3 mentions");
    expect(textOf(root)).toContain("'feeling better' has returned 3 times");
  });

  it("handles a non-insight phase without a blob, dead key material, and string failures", async () => {
    // Neither insight-phase nor a blob -> the honest no-data line.
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "locked", active_days: 40, streak: 0, days_remaining: 0, blob: null, state_seq: 0,
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
      state_seq: 7,
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
    const titles = root.root.findAllByType("h2").map((n) => String(n.props.children));
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
    expect(textOf(root)).toContain("Fathom session summary — patienta");
  });

  it("note editing round-trips through the PATCH endpoint", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z", version: 4 },
      ],
      nextOffset: null,
    });
    mockedApi.updateNote.mockResolvedValueOnce({
      id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-17T00:00:00Z", version: 5,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("existing note text");
    await press(root, "Edit");
    await typeTextarea(root, "Editing note…", "Edited session note.");
    await press(root, "Save edit");
    await flush();
    // Deep-audit 2026-09-28: the edit must carry the version it was based
    // on — the server 400s a body without base_version.
    expect(mockedApi.updateNote).toHaveBeenCalledWith("n0", "SEALEDNOTE==", 4);
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
      state_seq: 7,
    } as never);
    mockedApi.patientMeasures.mockResolvedValueOnce({
      measures: [
        { id: "1", client_measure_id: "m-1", blob: "B1==", measure_date: "2026-09-04", received_at: "2026-09-04T00:00:00Z" },
        { id: "2", client_measure_id: "m-2", blob: "B2==", measure_date: "2026-09-11", received_at: "2026-09-11T00:00:00Z" },
      ],
      nextOffset: null,
    } as never);
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
      state_seq: 7,
    } as never);
    mockedApi.patientMeasures.mockResolvedValueOnce({ measures: [], nextOffset: null } as never);
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).not.toContain("Recorded measures");
  });
});

/** Item 9 (clinical review 2026-09-27): an endorsed PHQ-9 item 9 mandates
 *  clinical follow-up regardless of the total — the raw response rides
 *  the payload now, and the measures card (plus the printed summary)
 *  surfaces it as a bordered fact row. No score interpretation, no
 *  diagnosis language; item9=0/absent and gad7 render nothing extra. */
describe("PatientView item-9 surfacing (2026-09-27)", () => {
  const insightsOk = (): void => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "insight",
      active_days: 45,
      streak: 3,
      days_remaining: 0,
      blob: "BLOB==",
      state_seq: 7,
    } as never);
  };
  const oneMeasure = (reading: Record<string, unknown>): void => {
    mockedApi.patientMeasures.mockResolvedValueOnce({
      measures: [
        { id: "1", client_measure_id: "m-1", blob: "B1==", measure_date: "2026-09-11", received_at: "x" },
      ],
      nextOffset: null,
    } as never);
    vi.mocked(mockedCrypto.decryptMeasure).mockResolvedValueOnce(reading as never);
  };
  const flagNodes = (root: Awaited<ReturnType<typeof rtr.render>>, type: "div" | "p", cls: string): number =>
    root.root.findAllByType(type).filter((n) => String(n.props.className ?? "").split(/\s+/).includes(cls)).length;

  it("an endorsed item 9 renders the bordered safety row on screen AND in the printed summary", async () => {
    insightsOk();
    oneMeasure({ measure: "phq9", score: 6, item9: 2, completedAt: "2026-09-11", measureDate: "2026-09-11" });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    const text = rtr.textOf(root);
    expect(text).toContain("Recorded measures (1)");
    expect(text).toContain("2026-09-11: PHQ-9 item 9 endorsed (self-harm question)");
    expect(text).toContain("follow your clinical protocol");
    expect(text).toContain("C-SSRS follow-up recommended");
    // Exactly one bordered row on screen and one in the print-only block.
    expect(flagNodes(root, "div", "measure-flag")).toBe(1);
    expect(flagNodes(root, "p", "print-flag")).toBe(1);
    // A LOW total (6) next to the flag is the entire point: the item, not
    // the score, drives follow-up — and no interpretation rides along.
    expect(text).toContain("2026-09-11: 6");
    expect(text).not.toMatch(/severe|moderate|mild depression/i);
  });

  it("item9 = 0 (explicitly unendorsed) renders nothing extra — the row is the fact, not the field", async () => {
    insightsOk();
    oneMeasure({ measure: "phq9", score: 20, item9: 0, completedAt: "2026-09-11", measureDate: "2026-09-11" });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).not.toContain("item 9 endorsed");
    expect(flagNodes(root, "div", "measure-flag")).toBe(0);
    expect(flagNodes(root, "p", "print-flag")).toBe(0);
  });

  it("a legacy payload (item9 absent) renders exactly as before", async () => {
    insightsOk();
    oneMeasure({ measure: "phq9", score: 14, completedAt: "2026-09-11", measureDate: "2026-09-11" });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).toContain("Recorded measures (1)");
    expect(rtr.textOf(root)).not.toContain("item 9 endorsed");
    expect(flagNodes(root, "div", "measure-flag")).toBe(0);
  });

  it("gad7 never shows the notice, even if the field somehow rides the reading", async () => {
    insightsOk();
    oneMeasure({ measure: "gad7", score: 5, item9: 2, completedAt: "2026-09-11", measureDate: "2026-09-11" });
    const root = await rtr.render(
      <PatientView patient={patient} session={session as never} onBack={vi.fn()} />,
    );
    await rtr.flush();
    expect(rtr.textOf(root)).toContain("GAD-7 (anxiety): 2026-09-11: 5");
    expect(rtr.textOf(root)).not.toContain("item 9 endorsed");
    expect(flagNodes(root, "div", "measure-flag")).toBe(0);
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
    await startScan(root);
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
    // The therapist can still write against their own record.  F1 follow-up:
    // the response must be contract-shaped (NoteOut carries id/created_at) —
    // the notes-only chart now renders the appended note too, so a bare {}
    // mock would render an id-less row.
    mockedApi.createNote.mockResolvedValueOnce({
      id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    });
    await typeTextarea(root, "Note about this patient…", "post-revoke follow-up");
    await press(root, "Save note");
    await flush();
    expect(mockedApi.createNote).toHaveBeenCalledWith("user-1", expect.objectContaining({ blob: "SEALEDNOTE==" }));
    // F1: the saved note is part of the whole-chart list in notes-only mode.
    expect(textOf(root)).toContain("post-revoke follow-up");
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

  // F1 (GUI drill 2026-09-28): a revoke removes the pattern selector but
  // NOT the therapist's pattern-anchored notes — the API serves the whole
  // chart at any consent status, and the list row promises the notes stay.
  // The notes-only chart must therefore render anchored notes too, each
  // carrying its pid as the one surviving anchor.
  it("F1: pattern-anchored notes render in the notes-only chart with their pid anchor", async () => {
    const stopped = {
      ...patient,
      status: "revoked",
      revoked_at: "2026-09-10T00:00:00Z",
      ephemeral_pub: null,
      wrapped_key: null,
    };
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "ng", client_note_id: "cg", pattern_pid: null, blob: "b", created_at: "2026-09-15T00:00:00Z", updated_at: "2026-09-15T00:00:00Z" },
        { id: "np", client_note_id: "cp", pattern_pid: "phrase:a4adc4d084fc", blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={stopped} session={session} onBack={vi.fn()} />);
    await flush();
    // Both notes render — the anchored one is no longer invisible — under
    // the whole-chart title, and its pid rides along as the anchor.
    expect(textOf(root)).toContain("My notes about this patient");
    expect(textOf(root)).toContain("existing note text");
    // 2026-09-28 audit F8: the anchor renders in human terms, not the raw pid.
    expect(textOf(root)).toContain("on a recurring phrase");
    // The anchored note keeps the full affordances of its own record:
    // pressing Edit opens the editor (Save edit / Cancel mount).
    await press(root, "Edit");
    await flush();
    expect(buttonByLabel(root, "Save edit")).toBe(true);
    expect(buttonByLabel(root, "Cancel")).toBe(true);
  });

  it("F1: the active chart's general notes card still excludes anchored notes (unchanged behavior)", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "ng2", client_note_id: "cg2", pattern_pid: null, blob: "b", created_at: "2026-09-15T00:00:00Z", updated_at: "2026-09-15T00:00:00Z" },
        { id: "np2", client_note_id: "cp2", pattern_pid: "temporal:work", blob: "b", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(4);
    // Without a selected pattern the ACTIVE chart's general card shows only
    // the general note; the anchored one surfaces via its pattern card's
    // composer, not here. No pid anchor labels exist on the active chart.
    expect(textOf(root)).toContain("General notes about this patient");
    expect(textOf(root)).not.toContain("on pattern");
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
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7,
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
      .mockResolvedValueOnce({ measures: Array.from({ length: 100 }, (_, i) => rowFor(i)), nextOffset: 100, revision: "4" } as never)
      .mockResolvedValueOnce({ measures: Array.from({ length: 50 }, (_, i) => rowFor(100 + i)), nextOffset: null, revision: "4" } as never);
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
    // Continuation is cursor-based under one pinned snapshot revision; the
    // second page proves it belongs to the same snapshot as the first.
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(1, "user-1", { offset: 0 });
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(2, "user-1", { offset: 100, expectedRevision: "4" });
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
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7,
    } as never);
    const dateFor = (n: number): string =>
      new Date(Date.UTC(2026, 0, 1) + n * 86_400_000).toISOString().slice(0, 10);
    mockedApi.patientMeasures.mockResolvedValueOnce({
      measures: [
        { id: "m-0", client_measure_id: "m-0", blob: "B==", measure_date: dateFor(0), received_at: "x" },
        { id: "m-1", client_measure_id: "m-1", blob: "B==", measure_date: dateFor(1), received_at: "x" },
        { id: "m-2", client_measure_id: "m-2", blob: "B==", measure_date: dateFor(2), received_at: "x" },
        { id: "m-3", client_measure_id: "m-3", blob: "B==", measure_date: dateFor(3), received_at: "x" },
      ],
      nextOffset: null,
    } as never);
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
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
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
      state_seq: 7,
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

  it("L-82 (2026-09-26 round): link and mood_shift without a direction render the honest unknown too", async () => {
    // The already-fixed mood_correlation arm had two neighbors still
    // fabricating a clinical direction: `?? "lower"` invented a down-shift
    // for an undefined direction. Both must read "?" like mood_correlation.
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      state_seq: 7,
      stats: {
        patterns: [
          { kind: "link", label: "sleep", occurrences: 5, confidence: 0.6, detail: { lag_days: 2, pattern_pid: "link:sleep", evidence_dates: [] } },
          { kind: "mood_shift", label: "", occurrences: 1, confidence: 0.3, detail: { pattern_pid: "mood_shift:none", evidence_dates: [] } },
        ],
      },
    } as never);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(textOf(root)).toContain("About 2 day(s) after 'sleep' comes up, entries read ?");
    expect(textOf(root)).not.toContain("entries read lower");
    expect(textOf(root)).toContain("Entries have read ? than the patient's own baseline");
    expect(textOf(root)).not.toContain("read lower than the patient's own baseline");
  });
});

// --- Audit round 2 (2026-09-21): F-8 banner fold + F-11 unpinned fixes --------

describe("PatientsView banner fold (audit round 2, 2026-09-21, F-8)", () => {
  // The scan/sort bar (and therefore any scan) only exists for a caseload
  // of 2+, so every case pairs its target with a quiet second patient.
  // Every once-queue below is fully consumed — a stray payload leaks into
  // the next test's scan (clearAllMocks does not clear once-queues).
  const calmScan = {
    // 2026-09-26 follow-up (portal N-1): scan payloads carry the same
    // generation the chart guard checks; the echo default is 7.
    state_seq: 7,
    stats: { patterns: [
      { kind: "temporal", label: "quiet", occurrences: 3, confidence: 0.4, detail: { pattern_pid: "t:quiet", evidence_dates: [] } },
    ] },
  };
  const sensitiveScan = {
    state_seq: 7,
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
    await startScan(root);
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
    await startScan(root);
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
    await startScan(root);
    await flush(8);
    expect(textOf(root)).not.toContain("of your patients");
  });

  it("2026-09-26 follow-up (portal N-1): a replayed OLDER insights blob degrades to the error row, not stale triage data", async () => {
    const { resetInsightsFreshness } = await import("../src/views/PatientView");
    resetInsightsFreshness();
    try {
      const summary = (seq: number) => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: seq });
      // The scan bar exists only for a caseload of 2+: pair the target
      // (whose generation rolls back) with a quiet second patient that
      // stays at generation 7 across both scans. Every once-queue below is
      // fully consumed (a stray payload leaks into the next test's scan).
      mockedApi.patientInsights
        .mockResolvedValueOnce(summary(5))
        .mockResolvedValueOnce(summary(7))
        .mockResolvedValueOnce(summary(3))
        .mockResolvedValueOnce(summary(7));
      vi.mocked(mockedCrypto.decryptInsights)
        .mockResolvedValueOnce({ state_seq: 5, stats: calmScan.stats } as never)
        .mockResolvedValueOnce({ state_seq: 7, stats: calmScan.stats } as never)
        .mockResolvedValueOnce({ state_seq: 3, stats: sensitiveScan.stats } as never)
        .mockResolvedValueOnce({ state_seq: 7, stats: calmScan.stats } as never);
      const root = await view([{ ...patient }, second]);
      await startScan(root);
      await flush(8);
      // First scan at generation 5 lands the quiet pattern count.
      expect(textOf(root)).toContain("1 pattern");
      // A server replaying generation 3 (below the session's high-water
      // mark) must NOT feed its sensitive flag into the sort/banner — the
      // row degrades to the honest could-not-scan blank instead.
      await startScan(root);
      await flush(8);
      expect(textOf(root)).not.toContain("sensitive card");
      // Two patients scanned twice: four insight fetches total.
      expect(mockedApi.patientInsights).toHaveBeenCalledTimes(4);
    } finally {
      resetInsightsFreshness();
    }
  });

  it("a patient known only from a scan row still counts toward the banner", async () => {
    vi.mocked(mockedCrypto.decryptInsights)
      .mockResolvedValueOnce(sensitiveScan as never)
      .mockResolvedValueOnce(calmScan as never);
    const root = await view([{ ...patient }, second]);
    expect(textOf(root)).not.toContain("sensitive card");
    await startScan(root);
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
      .mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [
        { kind: "temporal", label: "a1", occurrences: 2, confidence: 0.4, detail: { pattern_pid: "t:a1", evidence_dates: [] } },
        { kind: "temporal", label: "a2", occurrences: 2, confidence: 0.4, detail: { pattern_pid: "t:a2", evidence_dates: [] } },
      ] } } as never)
      .mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [
        { kind: "recurring_phrase", label: "s1", occurrences: 1, confidence: 0.5, detail: { sensitive: true, pattern_pid: "r:s1", evidence_dates: [] } },
      ] } } as never)
      .mockResolvedValueOnce({
        state_seq: 7,
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

    await startScan(root);
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

// --- 2026-09-26 audit round (portal): scan footprint confirmation, dead-view
// cancellation, honest history failure, idempotent note creation --------------

describe("PatientsView triage-scan confirmation (2026-09-26 audit round, M/UX)", () => {
  const second = { ...patient, user_id: "user-2", username: "patientb" };
  const view = async (pts: unknown[]) => {
    mockedApi.patients.mockResolvedValueOnce(pts as never);
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    return root;
  };

  it("the first press asks instead of scanning, naming the access footprint in plain language", async () => {
    const root = await view([{ ...patient }, second]);
    await press(root, "Scan caseload for triage");
    await flush();
    // Nothing was fetched yet — no audit rows exist.
    expect(mockedApi.patientInsights).not.toHaveBeenCalled();
    // The footprint is named: full pattern data, one audit entry per patient.
    expect(textOf(root)).toContain("downloads and decrypts every active patient's pattern data");
    expect(textOf(root)).toContain("one request and one audit entry per patient");
    expect(buttonByLabel(root, "Start the triage scan")).toBe(true);
    expect(buttonByLabel(root, "Cancel")).toBe(true);
  });

  it("Cancel disarms the confirmation without scanning", async () => {
    const root = await view([{ ...patient }, second]);
    await press(root, "Scan caseload for triage");
    await press(root, "Cancel");
    await flush();
    expect(mockedApi.patientInsights).not.toHaveBeenCalled();
    expect(textOf(root)).not.toContain("one audit entry per patient");
    // And the button re-arms the confirmation, not the scan.
    await press(root, "Scan caseload for triage");
    expect(mockedApi.patientInsights).not.toHaveBeenCalled();
    expect(buttonByLabel(root, "Start the triage scan")).toBe(true);
  });

  it("'don't ask again' lasts for the browser session only (module state, never storage)", async () => {
    const root = await view([{ ...patient }, second]);
    await press(root, "Scan caseload for triage");
    // Tick the session-scoped latch, then start.
    const box = root.root.findAllByType("input").find((n) => n.props["aria-label"] === "Do not ask again in this browser session");
    expect(box).toBeTruthy();
    await act(async () => { box!.props.onChange({ target: { checked: true } }); });
    await press(root, "Start the triage scan");
    await flush(8);
    expect(mockedApi.patientInsights).toHaveBeenCalledTimes(2);

    // A fresh mount in the SAME session skips the question…
    const root2 = await view([{ ...patient }, second]);
    await press(root2, "Scan caseload for triage");
    await flush(8);
    expect(buttonByLabel(root2, "Start the triage scan")).toBe(false);
    expect(mockedApi.patientInsights).toHaveBeenCalledTimes(4);
    // …and nothing was persisted to any storage.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});

describe("PatientsView dead-view cancellation (2026-09-26 audit round, M)", () => {
  const second = { ...patient, user_id: "user-2", username: "patientb" };

  it("unmounting mid-scan stops the per-patient fetch/decrypt loop", async () => {
    let resolveFirst!: (value: unknown) => void;
    mockedApi.patients.mockResolvedValueOnce([{ ...patient }, second] as never);
    mockedApi.patientInsights.mockImplementationOnce(
      () => new Promise((resolve) => { resolveFirst = resolve; }) as never,
    );
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    await press(root, "Scan caseload for triage");
    await press(root, "Start the triage scan");
    await flush();
    expect(mockedApi.patientInsights).toHaveBeenCalledTimes(1);

    // Navigate away while the first patient's insights fetch is parked.
    await act(async () => { root.unmount(); });
    resolveFirst({ phase: "insight", active_days: 1, streak: 1, days_remaining: 0, blob: "B==", state_seq: 7 });
    for (let i = 0; i < 4; i += 1) {
      await act(async () => { await Promise.resolve(); });
    }
    // The stale loop bailed before the SECOND patient: no further fetch
    // (each one would write a server audit row), and no decrypt ran.
    expect(mockedApi.patientInsights).toHaveBeenCalledTimes(1);
    expect(mockedCrypto.decryptInsights).not.toHaveBeenCalled();
  });

  it("unmounting mid-summary-decrypt stops the decrypt loop before the next patient", async () => {
    let resolveFirst!: (value: unknown) => void;
    mockedApi.patients.mockResolvedValueOnce([
      { ...patient, summary_blob: "SB==", summary_eph_pub: "SE==" },
      { ...patient, user_id: "user-2", username: "patientb", summary_blob: "SB2==", summary_eph_pub: "SE2==" },
    ] as never);
    mockedCrypto.decryptCaseloadSummary.mockImplementationOnce(
      () => new Promise((resolve) => { resolveFirst = resolve; }) as never,
    );
    const root = await render(
      <PatientsView displayName="Dr. Portal" onOpen={vi.fn()} onSignOut={vi.fn()} session={session as never} />,
    );
    await flush();
    expect(mockedCrypto.decryptCaseloadSummary).toHaveBeenCalledTimes(1);

    await act(async () => { root.unmount(); });
    resolveFirst(null);
    for (let i = 0; i < 4; i += 1) {
      await act(async () => { await Promise.resolve(); });
    }
    // The cancelled effect never decrypts the second patient's summary.
    expect(mockedCrypto.decryptCaseloadSummary).toHaveBeenCalledTimes(1);
  });
});

describe("PatientView authoritative note edit indicators", () => {
  it.each([
    { label: "version 1 with separate create defaults", version: 1, updated: "2026-09-10T00:00:00.000002Z", edited: false },
    { label: "version 2 with equal timestamps", version: 2, updated: "2026-09-10T00:00:00.000001Z", edited: true },
    { label: "legacy edited row", version: undefined, updated: "2026-09-12T00:00:00Z", edited: true },
    { label: "legacy unedited row", version: undefined, updated: "2026-09-10T00:00:00.000001Z", edited: false },
    { label: "invalid provided version", version: 0, updated: "2026-09-12T00:00:00Z", edited: false },
  ])("uses the canonical version and legacy fallback for $label", async ({ version, updated, edited }) => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [{ id: "versioned-note", client_note_id: "versioned-client", pattern_pid: null, blob: "current", created_at: "2026-09-10T00:00:00.000001Z", updated_at: updated, ...(version === undefined ? {} : { version }) }],
      nextOffset: null,
    });
    mockedCrypto.decryptNote.mockResolvedValueOnce("Canonical current note");
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    try {
      await flush(6);
      expect(buttonByLabel(root, "View history")).toBe(edited);
      const printedMarkers = root.root.findAllByType("span").filter((node) => node.props.className === "print-edited" && rtr.textOfNode(node) === "edited");
      expect(printedMarkers).toHaveLength(edited ? 1 : 0);
      expect(mockedApi.noteRevisions).not.toHaveBeenCalled();
      if (edited) {
        mockedApi.noteRevisions.mockResolvedValueOnce([{ id: "prior-version", blob: "earlier", created_at: "2026-09-10T00:00:00Z" }]);
        mockedCrypto.decryptNote.mockResolvedValueOnce("Actual earlier clinical text");
        await press(root, "View history");
        await flush(8);
        expect(mockedApi.noteRevisions).toHaveBeenCalledWith("versioned-note");
        expect(textOf(root)).toContain("previous (1): Actual earlier clinical text");
        const printOnly = root.root.findAllByType("div").find((node) => node.props.className === "print-only");
        expect(rtr.textOfNode(printOnly!)).toContain("previous (1): Actual earlier clinical text");
      }
    } finally {
      await act(async () => root.unmount());
    }
  });
});

describe("PatientView note history decrypt failure (2026-09-26 audit round, L)", () => {
  it("a revision blob that fails to decrypt is NOT rendered as 'no earlier text recorded'", async () => {
    // One edited note; the live blob decrypts, the revision blob does not
    // (the cross-key/corrupt-history case the audit found).
    mockedApi.notes.mockResolvedValueOnce({
      notes: [
        { id: "n0", client_note_id: "c0", pattern_pid: null, blob: "b", created_at: "2026-09-10T00:00:00Z", updated_at: "2026-09-12T00:00:00Z" },
      ],
      nextOffset: null,
    });
    mockedApi.noteRevisions.mockResolvedValueOnce([
      { id: "r1", blob: "CORRUPT", created_at: "2026-09-11T00:00:00Z" },
    ]);
    mockedCrypto.decryptNote
      .mockResolvedValueOnce("live note text")
      .mockRejectedValueOnce(new Error("blob failed authentication"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);

    const warned = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await press(root, "View history");
      await flush(8);
      expect(textOf(root)).toContain("(earlier versions could not be decrypted)");
      expect(textOf(root)).not.toContain("no earlier text recorded");
      // And the failure is logged, not silently swallowed.
      expect(warned).toHaveBeenCalledWith("note_history_decrypt_failed");
      expect(JSON.stringify(warned.mock.calls)).not.toContain("n0");
      expect(JSON.stringify(warned.mock.calls)).not.toContain("TamperError");
      // The print-only summary is equally honest about the failure.
      const printOnly = root.root.findAllByType("div").find((n) => n.props.className === "print-only");
      expect(rtr.textOfNode(printOnly!)).toContain("(earlier versions could not be decrypted)");
    } finally {
      warned.mockRestore();
    }
  });
});

describe("PatientView idempotent note creation (2026-09-26 audit round, L)", () => {
  it("a failed save retries with the SAME client_note_id; success produces exactly one note; the next note mints a fresh id", async () => {
    const noteRow = (id: string, clientNoteId: string) => ({
      id, client_note_id: clientNoteId, pattern_pid: null, blob: "b",
      created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
    });
    // First attempt: timeout-shaped failure. Retry: the backend's
    // idempotent-retry answer (the existing row).
    mockedApi.createNote
      .mockRejectedValueOnce(new Error("request timed out"))
      .mockResolvedValueOnce(noteRow("n1", "captured-at-send"))
      .mockResolvedValueOnce(noteRow("n2", "captured-at-send-2"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();

    await typeTextarea(root, "Note about this patient…", "Session note text.");
    await press(root, "Save note");
    await flush();
    expect(textOf(root)).toContain("request timed out");
    // The draft survives a failed save; the user presses Save again.
    await press(root, "Save note");
    await flush();
    expect(textOf(root)).toContain("Session note text.");

    const calls = mockedApi.createNote.mock.calls as unknown as [string, { client_note_id: string }][];
    expect(calls.length).toBeGreaterThanOrEqual(2);
    expect(calls[0]![1].client_note_id).toBe(calls[1]![1].client_note_id);
    // Exactly one note rendered in the interactive notes card — the retry
    // rewrote nothing. (The print-only summary mirrors the note too; scope
    // the count to the interactive card's .note paragraphs.)
    const onScreenNotes = root.root.findAllByType("p").filter(
      (n) => String(n.props.className ?? "").split(" ").includes("note")
        && rtr.textOfNode(n).includes("Session note text."),
    );
    expect(onScreenNotes.length).toBe(1);

    // A NEW note after a successful save mints a fresh id.
    await typeTextarea(root, "Note about this patient…", "Second session note.");
    await press(root, "Save note");
    await flush();
    const third = (mockedApi.createNote.mock.calls as unknown as [string, { client_note_id: string }][])[2]!;
    expect(third![1].client_note_id).not.toBe(calls[0]![1].client_note_id);
  });

  it("a 409 conflict burns the id — the next attempt mints a fresh one", async () => {
    mockedApi.createNote
      .mockRejectedValueOnce(new ApiError(409, "note id already used for another patient", "conflict"))
      .mockResolvedValueOnce({
        id: "n1", client_note_id: "fresh", pattern_pid: null, blob: "b",
        created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
      });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await typeTextarea(root, "Note about this patient…", "Conflict then retry.");
    await press(root, "Save note");
    await flush();
    expect(textOf(root)).toContain("note id already used for another patient");
    // The conflicted id is burned: the retry mints a fresh one and lands.
    await press(root, "Save note");
    await flush();
    const calls = mockedApi.createNote.mock.calls as unknown as [string, { client_note_id: string }][];
    expect(calls[1]![1].client_note_id).not.toBe(calls[0]![1].client_note_id);
    expect(textOf(root)).toContain("Conflict then retry.");
  });

  it("M-2 (2026-09-28): a 409 version_conflict burns the id too — the retry mints a FRESH client_note_id and succeeds", async () => {
    // A manual re-press re-encrypts with a fresh GCM nonce, so the uploaded
    // bytes differ from the stored note and the backend (commit 7b7337a)
    // answers 409 version_conflict instead of rewriting in place — mirror
    // the differing ciphertext per attempt.
    mockedCrypto.encryptNote
      .mockResolvedValueOnce({ clientNoteId: "pending-1", blobB64: "SEALEDNOTE-1==" })
      .mockResolvedValueOnce({ clientNoteId: "pending-2", blobB64: "SEALEDNOTE-2==" });
    mockedApi.createNote
      .mockRejectedValueOnce(
        new ApiError(
          409,
          "a different note with this client_note_id already exists; edit it with PATCH and a base_version",
          "version_conflict",
        ),
      )
      .mockResolvedValueOnce({
        id: "n1", client_note_id: "fresh-after-version-conflict", pattern_pid: null, blob: "b",
        created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z",
      });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    await typeTextarea(root, "Note about this patient…", "Version conflict then retry.");
    await press(root, "Save note");
    await flush();
    expect(textOf(root)).toContain("a different note with this client_note_id already exists");
    // The version-conflicted id is burned: the second press mints a FRESH
    // client_note_id (different bytes underneath it) and the draft is
    // savable again — not wedged on the dead id forever.
    await press(root, "Save note");
    await flush();
    const calls = mockedApi.createNote.mock.calls as unknown as [string, { client_note_id: string; blob: string }][];
    expect(calls.length).toBe(2);
    expect(calls[1]![1].client_note_id).not.toBe(calls[0]![1].client_note_id);
    expect(calls[1]![1].blob).toBe("SEALEDNOTE-2==");
    expect(textOf(root)).toContain("Version conflict then retry.");
  });
});

it("a stale note edit preserves its draft, displays the winning version, and retries against the refreshed custody-fenced version", async () => {
 const note={id:'conflicted-note',client_note_id:'client-conflict',pattern_pid:null,blob:'old',created_at:'2026-09-16T00:00:00Z',updated_at:'2026-09-16T00:00:00Z',version:4};
 mockedApi.notes.mockResolvedValueOnce({notes:[note],nextOffset:null}).mockResolvedValueOnce({notes:[{...note,version:5,blob:'winning'}],nextOffset:null});
 mockedCrypto.decryptNote.mockResolvedValueOnce('original saved note').mockResolvedValueOnce('current colleague note');
 mockedApi.updateNote.mockRejectedValueOnce(new ApiError(409,'version conflict','version_conflict')).mockResolvedValueOnce({...note,version:6});
 const root=await render(<PatientView patient={patient} session={{...session,custodyVersion:3}} onBack={vi.fn()}/>);await flush(6);
 await press(root,'Edit');await typeTextarea(root,'Editing note…','my preserved draft');await press(root,'Save edit');await flush(6);
 expect(root.root.findAllByType('textarea').find(node=>node.props.placeholder==='Editing note…')!.props.value).toBe('my preserved draft');expect(textOf(root)).toContain('current colleague note');
 await press(root,'Save edit');await flush(6);expect(mockedApi.updateNote).toHaveBeenLastCalledWith('conflicted-note','SEALEDNOTE==',5,3);expect(textOf(root)).toContain('my preserved draft');
});

it("does not dispatch an encrypted note edit after the chart has unmounted", async () => {
  const note = { id: "retired-note", client_note_id: "retired-client", pattern_pid: null, blob: "old", created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:00Z", version: 1 };
  mockedApi.notes.mockResolvedValueOnce({ notes: [note], nextOffset: null });
  const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
  await flush(6);
  let release!: (sealed: { clientNoteId: string; blobB64: string }) => void;
  mockedCrypto.encryptNote.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await press(root, "Edit");
  await typeTextarea(root, "Editing note…", "private pending edit");
  await press(root, "Save edit");
  await act(async () => root.unmount());
  await act(async () => release({ clientNoteId: note.client_note_id, blobB64: "SEALEDNOTE==" }));
  await flush(4);
  expect(mockedApi.updateNote).not.toHaveBeenCalled();
});

it("does not create a note after the chart unmounts during durable draft publication", async () => {
  const kv = (await import("../src/kvstore")).kv;
  const originalSet = kv.setItem.bind(kv);
  let blocked = false;
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
  await flush(6);
  await typeTextarea(root, "Note about this patient…", "private pending creation");
  const spy = vi.spyOn(kv, "setItem").mockImplementation(async (key, value) => {
    if (key.startsWith("portal.draft.")) { blocked = true; await gate; }
    await originalSet(key, value);
  });
  try {
    await press(root, "Save note");
    await vi.waitFor(() => expect(blocked).toBe(true));
    await act(async () => root.unmount());
    await act(async () => release());
    await flush(12);
    expect(mockedApi.createNote).not.toHaveBeenCalled();
    const { loadPortalDraft } = await import("../src/noteDrafts");
    const saved = await loadPortalDraft(session.userId, patient.user_id, [session.noteKeyV2]);
    expect(saved?.text.general).toBe("private pending creation");
    expect(saved?.pending.general?.blob).toBe("SEALEDNOTE==");
  } finally { release(); spy.mockRestore(); }
});

it("preserves the writing without publishing a note if its chart unmounts during encryption", async () => {
  const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
  await flush(6);
  let release!: (sealed: { clientNoteId: string; blobB64: string }) => void;
  mockedCrypto.encryptNote.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await typeTextarea(root, "Note about this patient…", "writing interrupted during encryption");
  await press(root, "Save note");
  await act(async () => root.unmount());
  await act(async () => release({ clientNoteId: "retired-create", blobB64: "SEALEDNOTE==" }));
  await flush(6);
  expect(mockedApi.createNote).not.toHaveBeenCalled();
  const { loadPortalDraft } = await import("../src/noteDrafts");
  const saved = await loadPortalDraft(session.userId, patient.user_id, [session.noteKeyV2]);
  expect(saved?.text.general).toBe("writing interrupted during encryption");
  expect(saved?.pending.general).toBeUndefined();
});
