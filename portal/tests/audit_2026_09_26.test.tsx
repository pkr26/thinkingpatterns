/**
 * Audit fixes 2026-09-26 (AUDIT_FULL_CODEBASE_2026-09-26.md, portal):
 *
 *  M-P1 — every lock boundary (sign-out, idle lock, 401 expiry, bfcache
 *         restore) fires POST /auth/logout best-effort before the local
 *         teardown, so a copied bearer dies with the lock instead of its
 *         full 24h TTL. (App-level coverage lives in app.test.tsx; api
 *         wire coverage in api.test.ts.)
 *  L    — the insights state_seq rollback guard: the response echo must
 *         equal the seq inside the decrypted payload and never decrease
 *         within the session; a violation is an honest chart load error.
 *  L    — the measures traversal runs the snapshot-revision contract
 *         (X-Measures-Revision pinning, one collection_changed restart,
 *         bounded terminal probe) instead of the silent id-dedupe.
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
      logout: vi.fn(async () => null),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({
        phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7,
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
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({
      // Matches the default patientInsights echo above (state_seq 7).
      state_seq: 7,
      stats: {
        patterns: [
          { kind: "temporal", label: "work", occurrences: 9, confidence: 0.8, detail: { day: "Sunday", pattern_pid: "temporal:work", pattern_state: "confirmed", evidence_dates: ["2026-09-01", "2026-09-08"], first_seen: "2026-08-20", last_seen: "2026-09-08" } },
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

const { api, ApiError } = await import("../src/api");
const mockedApi = vi.mocked(api);
const { PatientView, resetInsightsFreshness } = await import("../src/views/PatientView");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const rtr = await import("./helpers/rtr");
const { render, flush, textOf, press, buttonByLabel } = rtr;

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
  window.sessionStorage.clear();
  // The freshness high-water mark is module state spanning renders; every
  // test starts from a clean mark exactly like a fresh page load.
  resetInsightsFreshness();
});

// ---------------------------------------------------------------------------
// L — the insights state_seq rollback guard
// ---------------------------------------------------------------------------

describe("2026-09-26 audit L: insights state_seq guard", () => {
  it("a MATCHING seq loads the chart, and the drill-down still renders after the guard", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(root)).toContain("work");
    expect(rtr.textOf(root)).not.toContain("freshness");

    // The drill-down path (entries + per-entry decrypt) is untouched by the
    // guard: the evidence behind the pattern still renders.
    mockedApi.patientEntries.mockResolvedValue({
      entries: [{ id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" }],
      nextOffset: null,
    });
    await press(root, "See the evidence");
    await flush();
    expect(rtr.textOf(root)).toContain("decrypted e-1");
  });

  it("a MISMATCH between the payload seq and the response echo is an honest load error", async () => {
    // The replayed blob decrypts fine (AES-GCM is valid!) but carries seq 3
    // while the row echoes 7 — exactly the rollback the backend documents.
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      state_seq: 3,
      stats: { patterns: [] },
    } as never);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(root)).toContain("failed its freshness check");
    // Honest load-error UX, same as any failed chart load: banner + retry,
    // and no pattern content rendered from the replayed blob.
    expect(buttonByLabel(root, "Retry loading this patient")).toBe(true);
    expect(rtr.textOf(root)).not.toContain("concentrates on certain days");
  });

  it("a payload with NO embedded seq fails closed rather than rendering unverifiable data", async () => {
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValueOnce({
      stats: { patterns: [] },
    } as never);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(root)).toContain("failed its freshness check");
  });

  it("a REGRESSING seq (matched pair, older than this session's mark) fails closed", async () => {
    // First load at seq 7 succeeds and raises the session's high-water mark.
    const first = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(first)).toContain("work");

    // A later load serves a self-consistent but OLDER generation (a
    // both-copies rollback): echo and payload agree at 4, below the mark.
    mockedApi.patientInsights.mockResolvedValue({
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 4,
    } as never);
    vi.mocked(mockedCrypto.decryptInsights).mockResolvedValue({
      state_seq: 4,
      stats: { patterns: [] },
    } as never);
    const second = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(second)).toContain("failed its freshness check");
    expect(rtr.textOf(second)).not.toContain("concentrates on certain days");
  });

  it("the baseline phase (no blob) never consults the guard", async () => {
    mockedApi.patientInsights.mockResolvedValueOnce({
      phase: "baseline", active_days: 3, streak: 0, days_remaining: 27, blob: null, state_seq: 0,
    } as never);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush();
    expect(rtr.textOf(root)).toContain("baseline phase");
    expect(mockedCrypto.decryptInsights).not.toHaveBeenCalled();
  });

  it("the notes-only (stopped consent) view renders without any insights read", async () => {
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
    expect(rtr.textOf(root)).toContain("sharing ended 2026-09-10");
    expect(rtr.textOf(root)).toContain("existing note text");
  });
});

// ---------------------------------------------------------------------------
// L — the measures snapshot-revision traversal
// ---------------------------------------------------------------------------

describe("2026-09-26 audit L: measures snapshot-revision traversal", () => {
  const row = (id: string, date: string) => ({
    id, client_measure_id: id, blob: "B==", measure_date: date, received_at: "x",
  });

  it("a 409 collection_changed mid-traversal restarts exactly once from offset zero", async () => {
    mockedApi.patientMeasures
      .mockResolvedValueOnce({ measures: [row("stale", "2026-09-01")], nextOffset: 1, revision: "41" } as never)
      .mockRejectedValueOnce(new ApiError(409, "measures changed while paging; retry the request", "collection_changed"))
      .mockResolvedValueOnce({ measures: [row("fresh", "2026-09-02")], nextOffset: 1, revision: "42" } as never)
      .mockResolvedValueOnce({ measures: [], nextOffset: null, revision: "42" } as never);
    vi.mocked(mockedCrypto.decryptMeasure).mockImplementation(
      async (_k: Uint8Array<ArrayBuffer>, _u: string, m: { measure_date: string }) =>
        ({ measure: "phq9", score: 5, completedAt: null, measureDate: m.measure_date }),
    );

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);

    // Page one establishes the snapshot; page two pins it; the 409 discards
    // the stale snapshot entirely and restarts from zero against the new one.
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(1, "user-1", { offset: 0 });
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(2, "user-1", { offset: 1, expectedRevision: "41" });
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(3, "user-1", { offset: 0 });
    expect(mockedApi.patientMeasures).toHaveBeenNthCalledWith(4, "user-1", { offset: 1, expectedRevision: "42" });
    expect(mockedApi.patientMeasures).toHaveBeenCalledTimes(4);
    // The failed snapshot's row never reaches decryption; the chart renders
    // only the fresh snapshot's reading.
    expect(vi.mocked(mockedCrypto.decryptMeasure).mock.calls.map((c) => c[2].client_measure_id)).toEqual(["fresh"]);
    expect(rtr.textOf(root)).toContain("Recorded measures (1)");
    expect(rtr.textOf(root)).toContain("2026-09-02: 5");
  });

  it("persistent revision instability surfaces as an honest measures error WITHOUT blocking the chart", async () => {
    // The server keeps refusing the snapshot pin even after the one allowed
    // restart — the traversal gives up loudly instead of looping.
    mockedApi.patientMeasures.mockRejectedValue(
      new ApiError(409, "measures changed while paging; retry the request", "collection_changed"),
    );

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);

    expect(mockedApi.patientMeasures.mock.calls.length).toBe(2); // initial + exactly one restart
    expect(rtr.textOf(root)).toContain("Could not load this patient's recorded measures");
    expect(rtr.textOf(root)).toContain("changed while paging");
    // The rest of the chart is unaffected: patterns render, and this is NOT
    // a chart-level load failure (no retry-the-chart affordance appears).
    expect(rtr.textOf(root)).toContain("work");
    expect(buttonByLabel(root, "Retry loading this patient")).toBe(false);
  });

  it("an inconsistent revision mid-traversal fails closed (no mixed histories)", async () => {
    mockedApi.patientMeasures
      .mockResolvedValueOnce({ measures: [row("m1", "2026-09-01")], nextOffset: 1, revision: "5" } as never)
      .mockResolvedValueOnce({ measures: [], nextOffset: null, revision: "6" } as never);

    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);

    expect(rtr.textOf(root)).toContain("server returned an inconsistent measures snapshot revision");
    expect(rtr.textOf(root)).toContain("Could not load this patient's recorded measures");
    expect(rtr.textOf(root)).toContain("work"); // chart still renders
  });

  it("a pagination protocol that gains a revision mid-load fails closed", async () => {
    let call = 0;
    mockedApi.patientMeasures.mockImplementation(async () => {
      call += 1;
      return call === 1
        ? { measures: [row("m1", "2026-09-01")], nextOffset: 1 }
        : { measures: [], nextOffset: null, revision: "5" };
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(12);
    expect(rtr.textOf(root)).toContain("server changed the measures pagination protocol mid-load");
  });

  it("an exactly capped history is accepted after its empty terminal probe", async () => {
    // Twenty complete pages (the backend's 2_000-row quota) plus the
    // bounded empty probe: accepted, not an error.
    for (let page = 0; page < 20; page += 1) {
      mockedApi.patientMeasures.mockResolvedValueOnce({
        measures: [row(`m-${page}`, `2026-09-${String(page + 1).padStart(2, "0")}`)],
        nextOffset: page + 1,
      } as never);
    }
    mockedApi.patientMeasures.mockResolvedValueOnce({ measures: [], nextOffset: null } as never);
    vi.mocked(mockedCrypto.decryptMeasure).mockImplementation(
      async (_k: Uint8Array<ArrayBuffer>, _u: string, m: { measure_date: string }) =>
        ({ measure: "phq9", score: 5, completedAt: null, measureDate: m.measure_date }),
    );
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(30);
    expect(mockedApi.patientMeasures).toHaveBeenCalledTimes(21);
    expect(rtr.textOf(root)).toContain("Recorded measures (20)");
    expect(rtr.textOf(root)).not.toContain("safe page limit");
  });
});
