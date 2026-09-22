/**
 * NEW-3 / F.4 (2026-09-22): the portal-side surface for the backend's
 * verifier-gated rotation routes — PUT /therapist/wrap-key and
 * PUT /account/credential. Pins:
 *   - the password-change ORDERING (wrap-key re-wrap strictly before the
 *     credential PUT, the backend's both-passwords-derivable window),
 *   - the payload shapes (verifier/salt/verifier base64, 16-byte fresh
 *     salt, re-sealed blob under the NEW wrap KEK),
 *   - the credential PUT's bounded retry on network/5xx and its absence
 *     on a 403 (wrong current password),
 *   - the interrupted-change recovery request shape,
 *   - the compromise rotation payload (fresh pair, current KEK),
 *   - sign-out through onSessionsEnded after success, and the P-1
 *     zeroization of every derived key byte,
 *   plus the note-edit-history UI gap (api.noteRevisions + the printed
 *     summary's "view history" button) that had no tests at all.
 *
 * Same mocked api/crypto seams as audit_2026_09_21.test.tsx; derivation is
 * tagged (master 1=current / 2=intended-new) so each assertion can tell
 * the two password-derived KEKs apart.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

const h = vi.hoisted(() => {
  /** Every key set derivePortalKeys has handed out, so tests can assert
   * the view zeroized them all (the LoginView wipeKeys idiom). */
  const derivedKeySets: Array<{
    authKey: Uint8Array<ArrayBuffer>;
    wrapKek: Uint8Array<ArrayBuffer>;
    noteKey: Uint8Array<ArrayBuffer>;
  }> = [];
  /** KEK tags snapshot AT CALL TIME: the view hands the same (mutable)
   * arrays to seal/open/generate and zeroizes them when the flow ends, so
   * reading the recorded arguments later would only ever see zeros. */
  const kekTags = { open: [] as number[], seal: [] as number[], generate: [] as number[] };
  const tag = (n: number): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(32);
    bytes.fill(n);
    return bytes;
  };
  return { derivedKeySets, kekTags, tag };
});

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
        // Openable by the mocked openSealedPrivateKey only under the
        // CURRENT wrap KEK (tag 10) — the at-rest state.
        wrap_key_blob: "BLOB-SEALED-CURRENT",
      })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==" })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => []),
      accessLog: vi.fn(async () => []),
      rotateCredential: vi.fn(async () => null),
      rotateWrapKey: vi.fn(async () => null),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return {
    ...actual,
    // Tagged derivation: master 1 = the current password, 2 = the
    // intended-new password. Subkeys inherit distinguishable tags so the
    // KEK a seal/open used is visible in the recorded arguments.
    deriveMasterKey: vi.fn(async (password: string) =>
      h.tag(password === "intended-new-2!Strong" ? 2 : 1)),
    derivePortalKeys: vi.fn(async (master: Uint8Array) => {
      const fresh = master[0] === 2
        ? { authKey: h.tag(22), wrapKek: h.tag(20), noteKey: h.tag(23) }
        : { authKey: h.tag(11), wrapKek: h.tag(10), noteKey: h.tag(13) };
      h.derivedKeySets.push(fresh);
      return fresh;
    }),
    /** Opens only the blob actually sealed under the passed KEK tag
     * (10 = current, 20 = intended-new); returns sentinel DER (tag 99). */
    openSealedPrivateKey: vi.fn(async (wrapKek: Uint8Array, blobB64: string) => {
      const kekTag = wrapKek[0] ?? 0;
      h.kekTags.open.push(kekTag);
      if (blobB64 === "BLOB-SEALED-CURRENT" && kekTag === 10) return h.tag(99);
      if (blobB64 === "BLOB-SEALED-NEW" && kekTag === 20) return h.tag(99);
      return null;
    }),
    sealPrivateKeyForUpload: vi.fn(async (wrapKek: Uint8Array, pkcs8: Uint8Array, username: string) => {
      const kekTag = wrapKek[0] ?? 0;
      h.kekTags.seal.push(kekTag);
      return `RESEALED-kek${kekTag}-pk${pkcs8[0] ?? 0}-${username}`;
    }),
    generateTherapistKeyPair: vi.fn(async (wrapKek: Uint8Array) => {
      h.kekTags.generate.push(wrapKek[0] ?? 0);
      return {
        publicKeySpkiB64: "FRESHPUB" + "P".repeat(116),
        wrapKeyBlobB64: "FRESH-SEALED-BLOB",
      };
    }),
    decryptNote: vi.fn(async (_key: unknown, _t: string, _u: string, _id: string, blob: string) =>
      blob === "LIVEBLOB" ? "current note text"
        : blob === "REV1" ? "earlier draft one"
        : blob === "REV2" ? "earlier draft two"
        : "existing note text"),
  };
});

const { auth, api, ApiError } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const { PatientsView } = await import("../src/views/PatientsView");
const { PatientView } = await import("../src/views/PatientView");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const { render, flush, textOf, press, buttonByLabel, typeInto } = await import("./helpers/rtr");
const { act } = await import("react-test-renderer");

const session = {
  username: "drportal",
  userId: "therapist-1",
  noteKey: new Uint8Array(32),
  privateKey: {} as CryptoKey,
  publicKeyB64: "P".repeat(124),
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

/** Decode a recorded base64 argument to its (tag, length) fingerprint. */
const decoded = (b64: string): { tag: number; length: number } => {
  const bin = atob(b64);
  return { tag: bin.charCodeAt(0), length: bin.length };
};
const expectWiped = (bytes: Uint8Array): void => {
  expect([...bytes].every((b) => b === 0)).toBe(true);
};

const openSecurityPanel = async (
  root: Awaited<ReturnType<typeof render>>,
): Promise<void> => {
  await press(root, "Show account security");
  await flush();
};

beforeEach(() => {
  vi.clearAllMocks();
  h.derivedKeySets.length = 0;
  h.kekTags.open.length = 0;
  h.kekTags.seal.length = 0;
  h.kekTags.generate.length = 0;
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("NEW-3/F.4: the Account security panel is on-demand", () => {
  it("renders collapsed by default and opens only when asked", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    expect(textOf(root)).toContain("Account security");
    expect(buttonByLabel(root, "Show account security")).toBe(true);
    // Collapsed: no form fields, and nothing fetched or derived yet.
    expect(buttonByLabel(root, "Change password")).toBe(false);
    expect(mockedApi.accessLog).not.toHaveBeenCalled();
    expect(mockedAuth.saltFor).not.toHaveBeenCalled();
    expect(h.derivedKeySets).toHaveLength(0);

    await openSecurityPanel(root);
    expect(buttonByLabel(root, "Change password")).toBe(true);
    expect(buttonByLabel(root, "Recover sharing key")).toBe(true);
    expect(buttonByLabel(root, "Rotate sharing key")).toBe(true);
    // Still nothing derived: opening the panel only reveals the forms.
    expect(mockedAuth.saltFor).not.toHaveBeenCalled();
  });

  it("states the honest no-recovery limit when no interrupted change is remembered", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    expect(textOf(root)).toContain("No interrupted change is remembered in this tab");
    const recover = root.root.findAllByType("button").find((n) => n.children.join("") === "Recover sharing key")!;
    expect(recover.props.disabled).toBe(true);
  });
});

describe("NEW-3/F.4: change password", () => {
  const runHappyChange = async () => {
    const onSessionsEnded = vi.fn();
    const onSignOut = vi.fn();
    const root = await render(
      <PatientsView
        displayName="Dr. Portal"
        session={session}
        onOpen={vi.fn()}
        onSignOut={onSignOut}
        onSessionsEnded={onSessionsEnded}
      />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(14);
    return { root, onSessionsEnded, onSignOut };
  };

  it("re-wraps the SAME key under the NEW KEK, then rotates the credential — in that order", async () => {
    const { root, onSessionsEnded, onSignOut } = await runHappyChange();

    // The stored blob is opened with the CURRENT wrap KEK (tag 10)…
    expect(mockedCrypto.openSealedPrivateKey).toHaveBeenCalledWith(
      expect.anything(),
      "BLOB-SEALED-CURRENT",
      "drportal",
    );
    expect(h.kekTags.open[0]).toBe(10);
    // …and re-sealed under the NEW wrap KEK (tag 20), with the public half
    // unchanged: a password change re-wraps custody, it does not rekey.
    expect(mockedCrypto.sealPrivateKeyForUpload).toHaveBeenCalledTimes(1);
    expect(h.kekTags.seal[0]).toBe(20);
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(1);
    expect(mockedApi.rotateWrapKey.mock.calls[0]).toEqual([
      expect.any(String), // verifier = b64(current auth key), pinned below
      "P".repeat(124), // me().wrap_pub_key, unchanged
      "RESEALED-kek20-pk99-drportal", // the DER re-sealed under the NEW KEK
    ]);
    // Ordering contract (backend rotate_wrap_key docstring): the wrap-key
    // PUT strictly precedes the credential PUT.
    expect(mockedApi.rotateWrapKey.mock.invocationCallOrder[0])
      .toBeLessThan(mockedApi.rotateCredential.mock.invocationCallOrder[0]!);
    expect(mockedApi.rotateCredential).toHaveBeenCalledTimes(1);
    const [verifierB64, newSaltB64, newVerifierB64] = mockedApi.rotateCredential.mock.calls[0]!;
    // Base64 shapes: current verifier 32 bytes (tag 11 = current auth key)…
    expect(decoded(verifierB64)).toEqual({ tag: 11, length: 32 });
    expect(decoded(mockedApi.rotateWrapKey.mock.calls[0]![0])).toEqual({ tag: 11, length: 32 });
    // …fresh 16-byte salt that is NOT the account's standing salt…
    expect(decoded(newSaltB64).length).toBe(16);
    expect(newSaltB64).not.toBe("QUJDREVGR0hJSktMTU5P");
    // …and the NEW password's 32-byte auth key as the new verifier.
    expect(decoded(newVerifierB64)).toEqual({ tag: 22, length: 32 });
    // Success signs the user out through the sessions-ended path.
    expect(onSessionsEnded).toHaveBeenCalledTimes(1);
    expect(onSignOut).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Every session — including this one — has ended");
  });

  it("zeroizes every derived key set when the flow ends (the wipeKeys idiom)", async () => {
    await runHappyChange();
    // Two derivations ran (current + intended-new); every authKey, wrapKek,
    // and noteKey byte array the view received must leave zeroed.
    expect(h.derivedKeySets.length).toBeGreaterThanOrEqual(2);
    for (const set of h.derivedKeySets) {
      expectWiped(set.authKey);
      expectWiped(set.wrapKek);
      expectWiped(set.noteKey);
    }
  });

  it("retries the final credential PUT on 5xx and completes the change", async () => {
    mockedApi.rotateCredential
      .mockRejectedValueOnce(new ApiError(500, "request failed (500)"))
      .mockRejectedValueOnce(new ApiError(500, "request failed (500)"));
    const onSessionsEnded = vi.fn();
    const root = await render(
      <PatientsView
        displayName="Dr. Portal"
        session={session}
        onOpen={vi.fn()}
        onSignOut={vi.fn()}
        onSessionsEnded={onSessionsEnded}
      />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(18);
    // Two 500s then success: three credential PUTs, ONE wrap-key PUT.
    expect(mockedApi.rotateCredential).toHaveBeenCalledTimes(3);
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(1);
    expect(onSessionsEnded).toHaveBeenCalledTimes(1);
  });

  it("retries network failures up to three times, then surfaces the interrupted-change window", async () => {
    mockedApi.rotateCredential.mockRejectedValue(new ApiError(0, "server unreachable"));
    const onSessionsEnded = vi.fn();
    const root = await render(
      <PatientsView
        displayName="Dr. Portal"
        session={session}
        onOpen={vi.fn()}
        onSignOut={vi.fn()}
        onSessionsEnded={onSessionsEnded}
      />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(20);
    // One initial attempt plus the three permitted retries.
    expect(mockedApi.rotateCredential).toHaveBeenCalledTimes(4);
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(1);
    expect(onSessionsEnded).not.toHaveBeenCalled();
    const text = textOf(root);
    expect(text).toContain("Recover it with");
    expect(text).toContain("BEFORE leaving this page");
  });

  it("a wrong-current-password 403 stops at the wrap-key PUT: no credential PUT, no sign-out, no retries", async () => {
    mockedApi.rotateWrapKey.mockRejectedValueOnce(new ApiError(403, "invalid credentials"));
    const onSessionsEnded = vi.fn();
    const root = await render(
      <PatientsView
        displayName="Dr. Portal"
        session={session}
        onOpen={vi.fn()}
        onSignOut={vi.fn()}
        onSessionsEnded={onSessionsEnded}
      />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "not-the-password");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(14);
    expect(mockedApi.rotateCredential).not.toHaveBeenCalled();
    expect(mockedApi.rotateCredential.mock.calls).toHaveLength(0);
    expect(onSessionsEnded).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("invalid credentials");
    // The failure was BEFORE the re-wrap, so no interrupted-change state:
    // recovery stays disabled (nothing was re-wrapped).
    const recover = root.root.findAllByType("button").find((n) => n.children.join("") === "Recover sharing key")!;
    expect(recover.props.disabled).toBe(true);
  });

  it("a current password that cannot unlock the stored blob fails before any PUT", async () => {
    mockedApi.me.mockResolvedValueOnce({
      username: "drportal",
      display_name: "Dr. Portal",
      wrap_pub_key: "P".repeat(124),
      wrap_key_blob: "SEALED-BY-ANOTHER-ACCOUNT",
    });
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(14);
    expect(mockedApi.rotateWrapKey).not.toHaveBeenCalled();
    expect(mockedApi.rotateCredential).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("did not unlock your stored sharing key");
  });

  it("enforces the registration password policy before deriving anything", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "short");
    await typeInto(root, "Repeat new password", "short");
    await press(root, "Change password");
    await flush();
    expect(mockedAuth.saltFor).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Use at least 12 characters.");
  });

  it("rejects mismatched new passwords before any request", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "a-different-3!Strong");
    await press(root, "Change password");
    await flush();
    expect(mockedAuth.saltFor).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("the two new passwords do not match");
  });
});

describe("NEW-3/F.4: recover sharing key (interrupted-change window)", () => {
  /** Drive a change whose credential PUT always fails, leaving the
   *  interrupted salt retained, then run the recovery form. */
  const runInterruptedThenRecover = async () => {
    mockedApi.rotateCredential.mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "Current password", "current-pass-1!Strong");
    await typeInto(root, "New password", "intended-new-2!Strong");
    await typeInto(root, "Repeat new password", "intended-new-2!Strong");
    await press(root, "Change password");
    await flush(20);
    // The window is armed: the wrap-key PUT landed, the credential did not.
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(1);
    // The stored blob is now the one sealed under the intended-new KEK.
    mockedApi.me.mockResolvedValueOnce({
      username: "drportal",
      display_name: "Dr. Portal",
      wrap_pub_key: "P".repeat(124),
      wrap_key_blob: "BLOB-SEALED-NEW",
    });
    await typeInto(root, "the one you sign in with", "current-pass-1!Strong");
    await typeInto(root, "The password you were changing to", "intended-new-2!Strong");
    await press(root, "Recover sharing key");
    await flush(14);
    return root;
  };

  it("opens the blob with the intended-new KEK, re-seals under the CURRENT KEK, and PUTs with the current verifier", async () => {
    const root = await runInterruptedThenRecover();
    // The open used the intended-new wrap KEK (tag 20) on the re-wrapped blob.
    const openCalls = mockedCrypto.openSealedPrivateKey.mock.calls;
    expect(h.kekTags.open[h.kekTags.open.length - 1]).toBe(20);
    expect(openCalls[openCalls.length - 1]![1]).toBe("BLOB-SEALED-NEW");
    // The re-seal went under the CURRENT wrap KEK (tag 10)…
    expect(h.kekTags.seal[h.kekTags.seal.length - 1]).toBe(10);
    // …and the recovery PUT carried the CURRENT verifier (tag 11) with the
    // unchanged public half.
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(2);
    expect(mockedApi.rotateWrapKey.mock.calls[1]).toEqual([
      expect.any(String),
      "P".repeat(124),
      "RESEALED-kek10-pk99-drportal",
    ]);
    expect(decoded(mockedApi.rotateWrapKey.mock.calls[1]![0])).toEqual({ tag: 11, length: 32 });
    expect(textOf(root)).toContain("sealed under your current sign-in password again");
  });
});

describe("NEW-3/F.4: rotate sharing key (compromise)", () => {
  it("requires the confirm checkbox, then publishes a FRESH pair sealed under the CURRENT KEK", async () => {
    const root = await render(
      <PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />,
    );
    await flush();
    await openSecurityPanel(root);
    await typeInto(root, "to authorize rotation", "current-pass-1!Strong");
    const rotateButton = root.root.findAllByType("button").find((n) => n.children.join("") === "Rotate sharing key")!;
    // The copy states the trade-off before the checkbox exists to agree to.
    expect(textOf(root)).toContain("grants that never re-wrap are intentionally lost");
    // Unconfirmed: the rotation stays inert.
    expect(rotateButton.props.disabled).toBe(true);
    const checkbox = root.root.findAllByType("input").find((n) => n.props.type === "checkbox")!;
    await act(async () => { checkbox.props.onChange({ target: { checked: true } }); });
    await flush();

    await press(root, "Rotate sharing key");
    await flush(12);
    // A fresh pair under the CURRENT wrap KEK (tag 10) — nothing from the
    // possibly-compromised old key is reused — published verbatim.
    expect(mockedCrypto.generateTherapistKeyPair).toHaveBeenCalledTimes(1);
    expect(h.kekTags.generate[0]).toBe(10);
    expect(mockedCrypto.generateTherapistKeyPair.mock.calls[0]![1]).toBe("drportal");
    expect(mockedApi.rotateWrapKey).toHaveBeenCalledTimes(1);
    expect(mockedApi.rotateWrapKey.mock.calls[0]).toEqual([
      expect.any(String),
      "FRESHPUB" + "P".repeat(116),
      "FRESH-SEALED-BLOB",
    ]);
    expect(decoded(mockedApi.rotateWrapKey.mock.calls[0]![0])).toEqual({ tag: 11, length: 32 });
    // The credential is untouched by a compromise rotation.
    expect(mockedApi.rotateCredential).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Sharing key rotated");
    // The compromise flow zeroizes its single derived key set too.
    for (const set of h.derivedKeySets) {
      expectWiped(set.wrapKek);
      expectWiped(set.authKey);
      expectWiped(set.noteKey);
    }
  });
});

describe("P3 (2026-09-21): note edit history in the printed summary", () => {
  const editedNotesPage = {
    notes: [
      // Unedited: no history affordance may exist for this row.
      { id: "note-8", client_note_id: "c8", pattern_pid: null, blob: "LIVEBLOB", created_at: "2026-09-10T00:00:00Z", updated_at: "2026-09-10T00:00:00Z" },
      // Edited (updated_at > created_at): the "view history" button shows.
      { id: "note-9", client_note_id: "c9", pattern_pid: null, blob: "LIVEBLOB", created_at: "2026-09-10T00:00:00Z", updated_at: "2026-09-12T00:00:00Z" },
    ],
    nextOffset: null,
  };

  const renderChart = async () => {
    mockedApi.notes.mockResolvedValueOnce(editedNotesPage);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    return root;
  };

  it("offers the history button only for edited notes, then renders the decrypted prior texts", async () => {
    mockedApi.noteRevisions.mockResolvedValueOnce([
      { id: "r1", blob: "REV1", created_at: "2026-09-11T00:00:00Z" },
      { id: "r2", blob: "REV2", created_at: "2026-09-12T00:00:00Z" },
    ]);
    const root = await renderChart();
    // Exactly one history affordance — the edited note's.
    const historyButtons = root.root.findAllByType("button").filter((n) =>
      n.children.join("").includes("view history"));
    expect(historyButtons).toHaveLength(1);
    expect(mockedApi.noteRevisions).not.toHaveBeenCalled();

    await press(root, "edited — view history");
    await flush(8);
    // The revisions endpoint is keyed by the server note id…
    expect(mockedApi.noteRevisions).toHaveBeenCalledWith("note-9");
    // …each prior blob is decrypted with the SAME note AAD context as the
    // live note (the mock decrypts per blob)…
    const blobs = mockedCrypto.decryptNote.mock.calls.map((c) => c[c.length - 1]);
    expect(blobs).toContain("REV1");
    expect(blobs).toContain("REV2");
    // …and the printed summary renders them in order.
    const text = textOf(root);
    expect(text).toContain("previous (1): earlier draft one");
    expect(text).toContain("previous (2): earlier draft two");
    // Once loaded, the affordance collapses to "edited".
    expect(buttonByLabel(root, "edited — view history")).toBe(false);
  });

  it("degrades a failed revisions fetch to the honest empty history", async () => {
    mockedApi.noteRevisions.mockRejectedValueOnce(new Error("revisions down"));
    const root = await renderChart();
    await press(root, "edited — view history");
    await flush(8);
    expect(textOf(root)).toContain("no earlier text recorded");
  });
});
