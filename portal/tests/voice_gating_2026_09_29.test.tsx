/**
 * Voice-playback gating pins (audit 2026-09-29, M-8): the patient view's
 * play button renders ONLY under the consent's share_voice grant (the
 * server refuses the fetch without it — 403 consent_voice_share_required),
 * playback failures surface as a VISIBLE status line instead of the old
 * silent `catch { dataKey.fill(0); release(); }`, and the retention
 * countdown renders from entry.audio.expires_at.
 *
 * Same mocked api/crypto seams as views.test.tsx (the crypto itself is
 * pinned by tests/crypto.test.ts and voice_crypto_2026_09_29.test.ts
 * against the real WebCrypto).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
      patientAudio: vi.fn(async () => {
        throw new Error("patientAudio must be reset per test");
      }),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async () => null),
      updateNote: vi.fn(async () => null),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return {
    ...actual,
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptInsights: vi.fn(async () => ({
      state_seq: 7,
      stats: {
        patterns: [
          {
            kind: "temporal",
            label: "work",
            occurrences: 9,
            confidence: 0.8,
            detail: { day: "Sunday", pattern_pid: "temporal:work", pattern_state: "confirmed", evidence_dates: ["2026-09-02"], first_seen: "2026-08-20", last_seen: "2026-09-02" },
          },
        ],
      },
    })),
    decryptEntry: vi.fn(async () => ({ text: "the patient's own words", sentiment: null })),
    decryptAudio: vi.fn(async () => new Uint8Array(64).fill(3)),
  };
});

const { api, ApiError } = await import("../src/api");
const mockedApi = vi.mocked(api);
const { PatientView } = await import("../src/views/PatientView");
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const { render, flush, textOf, textOfNode, press } = await import("./helpers/rtr");

const FAR_FUTURE = new Date(Date.now() + 30 * 86_400_000).toISOString();

const basePatient = {
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

/** Node has no URL.createObjectURL; install an observable pair and
 *  restore afterwards (the api client's `new URL` stays real). */
const createdUrls: string[] = [];
const revokedUrls: string[] = [];
const originalCreate = (URL as { createObjectURL?: unknown }).createObjectURL;
const originalRevoke = (URL as { revokeObjectURL?: unknown }).revokeObjectURL;

beforeEach(() => {
  vi.clearAllMocks();
  mockedApi.patientInsights.mockReset().mockResolvedValue({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7 } as never);
  mockedApi.patientEntries.mockReset().mockResolvedValue({
    entries: [
      {
        id: "1",
        client_entry_id: "e-1",
        blob: "b",
        entry_date: "2026-09-02",
        received_at: "x",
        audio: { attachment_id: "att-1", expires_at: FAR_FUTURE },
      },
    ],
    nextOffset: null,
  } as never);
  mockedApi.patientAudio.mockReset();
  mockedCrypto.decryptEntry.mockReset().mockResolvedValue({ text: "the patient's own words", sentiment: null } as never);
  mockedCrypto.decryptAudio.mockReset().mockResolvedValue(new Uint8Array(64).fill(3));
  mockedCrypto.unwrapPatientDataKey.mockReset().mockResolvedValue(new Uint8Array(32) as never);
  window.localStorage.clear();
  window.sessionStorage.clear();
  createdUrls.length = 0;
  revokedUrls.length = 0;
  (URL as { createObjectURL?: unknown }).createObjectURL = vi.fn(() => {
    const url = `blob:object-${createdUrls.length + 1}`;
    createdUrls.push(url);
    return url;
  });
  (URL as { revokeObjectURL?: unknown }).revokeObjectURL = vi.fn((url: string) => {
    revokedUrls.push(url);
  });
});
afterEach(() => {
  if (originalCreate === undefined) delete (URL as { createObjectURL?: unknown }).createObjectURL;
  else (URL as { createObjectURL?: unknown }).createObjectURL = originalCreate;
  if (originalRevoke === undefined) delete (URL as { revokeObjectURL?: unknown }).revokeObjectURL;
  else (URL as { revokeObjectURL?: unknown }).revokeObjectURL = originalRevoke;
});

/** Open the drill-down so the audio block is on screen. */
async function openEvidence(patient: typeof basePatient & { share_voice?: boolean }) {
  const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
  await flush();
  await press(root, "See the evidence");
  await flush();
  return root;
}

describe("patient-view voice gating (M-8, audit 2026-09-29)", () => {
  it("no share-voice grant: no play button, no audio fetch — retention line still renders", async () => {
    const root = await openEvidence(basePatient);
    expect(textOf(root)).toContain("the patient's own words");
    // The countdown (audit 2026-09-29) renders from expires_at.
    expect(textOf(root)).toContain("Recording available for 30 more day(s)");
    // The affordance is gone without the grant, and nothing was fetched.
    expect(root.root.findAllByType("button").some((n) => textOfNode(n) === "play recording")).toBe(false);
    expect(mockedApi.patientAudio).not.toHaveBeenCalled();
    expect(root.root.findAllByType("audio")).toHaveLength(0);
  });

  it("an ABSENT share_voice field (older backend) fails closed too", async () => {
    const root = await openEvidence({ ...basePatient, share_voice: false });
    expect(root.root.findAllByType("button").some((n) => textOfNode(n) === "play recording")).toBe(false);
  });

  it("granted but the fetch fails (403 share revoked): a visible status line names the failure", async () => {
    mockedApi.patientAudio.mockRejectedValue(
      new ApiError(403, "patient has not shared voice recordings", "consent_voice_share_required"),
    );
    const root = await openEvidence({ ...basePatient, share_voice: true });
    await press(root, "play recording");
    await flush();
    expect(textOf(root)).toContain("the patient has not shared voice recordings with you");
    expect(root.root.findAllByType("audio")).toHaveLength(0);
  });

  it("granted and the recording expired (410): the honest expiry line", async () => {
    mockedApi.patientAudio.mockRejectedValue(new ApiError(410, "recording expired", "audio_expired"));
    const root = await openEvidence({ ...basePatient, share_voice: true });
    await press(root, "play recording");
    await flush();
    expect(textOf(root)).toContain("this recording expired and was deleted");
  });

  it("granted and healthy: the recording decrypts to exactly one <audio> element", async () => {
    mockedApi.patientAudio.mockResolvedValue({
      id: "att-1",
      client_entry_id: "e-1",
      blob: "B==",
      mime_type: "audio/webm",
      duration_seconds: 42,
      size_bytes: 64,
      created_at: "2026-09-29T00:00:00Z",
      expires_at: FAR_FUTURE,
    } as never);
    const root = await openEvidence({ ...basePatient, share_voice: true });
    await press(root, "play recording");
    await flush();
    const audio = root.root.findAllByType("audio");
    expect(audio).toHaveLength(1);
    expect(audio[0]!.props.src).toBe("blob:object-1");
    expect(textOf(root)).toContain("stop recording");
    // Stopping revokes the URL — nothing decrypted stays reachable.
    await press(root, "stop recording");
    await flush();
    expect(root.root.findAllByType("audio")).toHaveLength(0);
    expect(revokedUrls).toContain("blob:object-1");
  });
});
