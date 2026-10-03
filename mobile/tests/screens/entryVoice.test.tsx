/**
 * EntryScreen voice flow (VOICE_PLAN remediation, 2026-09-29): the record
 * confirmation over typed text (M3), the transcribe→editor→kept-audio
 * upload path, and the consent error's honest localized message. The
 * recorder seam runs against the expo-audio/fs mocks; the crypto and the
 * vault are REAL so the saved blob is asserted decrypted.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, TextInput } from "react-native";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actualApi = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actualApi, ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

class QueueFullError extends Error {
  constructor() {
    super("offline queue is full");
    this.name = "QueueFullError";
  }
}
class QueueAbandonedError extends Error {
  constructor() {
    super("the offline queue was wiped");
    this.name = "QueueAbandonedError";
  }
}
const recordMood = vi.fn(async () => {});
const recentMoods = vi.fn(async (): Promise<{ date: string; value: number }[]> => []);
const localStreak = vi.fn(async () => 0);
vi.mock("../../src/moodLog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/moodLog")>();
  return { ...actual, recordMood, recentMoods, localStreak, localDateISO: vi.fn(() => "2026-09-29") };
});
vi.mock("../../src/healthkit", () => ({ mirrorMoodCheckIn: vi.fn(async () => false) }));
vi.mock("../../src/offlineQueue", () => ({
  prepareQueueRekey: vi.fn(async () => []),
  pendingEntryIds: vi.fn(async () => []),
  abortInFlightFlush: vi.fn(),
  QueueFullError,
  QueueAbandonedError,
  enqueue: vi.fn(async () => {}),
  flushQueue: vi.fn(async () => 0),
}));

let sessionState: Record<string, unknown>;
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => sessionState };
});

const { api, ApiError } = await import("../../src/api/client");
const { decryptEntry } = await import("../../src/crypto/MindPatternCrypto");
const { EntryScreen } = await import("../../src/screens/EntryScreen");
const { vault } = await import("../../src/vault");
const { fakeRecorderStatus, recorderControls, __resetAudioMock } = await import("../helpers/expoAudioMock");
const fs = await import("../helpers/expoFsMock");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;
const {
  render,
  flush,
  allText,
  pressLabel,
  lastAlert,
  pressAlertButton,
  act,
  inputByPlaceholder,
} = await import("../helpers/rtr");

const keys = { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) };
const nav = { navigate: vi.fn() };
const touchActivity = vi.fn();
const TAKE_URI = "/tmp/mindpattern-test-cache/entry-take.m4a";

/** Drive the mic button through a finished take: record (empty editor →
 *  no confirmation), then Stop, letting the auto-transcribe effect run. */
async function recordAndStop(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  fs.__seedFile(TAKE_URI, "QUJDREVG");
  fakeRecorderStatus.url = TAKE_URI;
  fakeRecorderStatus.durationMillis = 4200;
  await pressLabel(root, "Record instead");
  await pressLabel(root, "Stop recording");
  await flush();
}

beforeEach(() => {
  resetApi(api as never);
  __resetAudioMock();
  fs.__resetFiles();
  Alert.alert.mockClear();
  nav.navigate.mockClear();
  touchActivity.mockClear();
  vault.lock();
  vault.unlock({ ...keys, masterKey: Buffer.alloc(32) }, "user-1");
  sessionState = { activeDays: 0, unlockDays: 30, touchActivity };
  storage.__reset();
});

describe("EntryScreen voice flow", () => {
  it("an empty editor records straight away; typed text demands confirmation first (M3)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    // Empty editor: no dialog, the permission flow starts immediately.
    await pressLabel(root, "Record instead");
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(recorderControls.record).toHaveBeenCalledTimes(1);
  });

  it("record over typed words confirms before replacing them (M3)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    const editor = inputByPlaceholder(root, "What's going on today?");
    await act(async () => {
      (editor.props as { onChangeText?: (t: string) => void }).onChangeText?.("typed words I keep");
    });
    await pressLabel(root, "Record instead");
    // The confirmation appears and NOTHING has started yet.
    expect(lastAlert()[0]).toBe("Record instead of typing?");
    expect(recorderControls.prepareToRecordAsync).not.toHaveBeenCalled();
    // Cancel keeps the typed text and never touches the mic.
    await pressAlertButton("Cancel");
    expect(recorderControls.prepareToRecordAsync).not.toHaveBeenCalled();
    expect((editor.props as { value?: string }).value).toBe("typed words I keep");
    // Confirming starts the recorder (the transcript will replace the text).
    await pressLabel(root, "Record instead");
    await pressAlertButton("Record instead");
    expect(recorderControls.prepareToRecordAsync).toHaveBeenCalledTimes(1);
    expect(recorderControls.record).toHaveBeenCalledTimes(1);
  });

  it("transcription populates the editor and the kept audio uploads on save (v3)", async () => {
    vi.mocked(api.transcribeAudio).mockResolvedValue({
      language: "es",
      language_raw: "es-ES",
      original_text: "Hoy fue un día difícil.",
      english_text: "Today was a hard day.",
    } as never);
    const root = await render(<EntryScreen navigation={nav} />);
    await recordAndStop(root);
    // The transcript lands in the editor; the review card names the
    // detected language and the keep toggle defaults to keeping.
    const editor = inputByPlaceholder(root, "What's going on today?");
    expect((editor.props as { value?: string }).value).toBe("Hoy fue un día difícil.");
    expect(allText(root).join(" ")).toContain("Detected language: es");
    expect(allText(root).join(" ")).toContain("Keep the recording for 30 days");
    // Saving sends the v3 entry and then the encrypted audio attachment.
    await pressLabel(root, "Save");
    await flush();
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    const [clientEntryId, blobB64] = vi.mocked(api.createEntry).mock.calls[0];
    const payload = decryptEntry({ dataKey: keys.dataKey }, "user-1", clientEntryId, blobB64, 1);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.transcript_lang).toBe("es");
    expect(payload.english_text).toBe("Today was a hard day.");
    expect(api.uploadAudioAttachment).toHaveBeenCalledWith(
      clientEntryId,
      expect.any(String),
      "audio/m4a",
      4, // the recorder's honest 4200 ms
      "http://localhost:8000", // origin-pinned outbox upload
    );
  });

  it("a consent error shows the localized message and discards the take", async () => {
    vi.mocked(api.transcribeAudio).mockRejectedValue(
      new ApiError(403, "voice consent required", "voice_consent_required"),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    await recordAndStop(root);
    expect(allText(root).join(" ")).toContain(
      "Voice journaling needs your permission first — turn it on in Settings.",
    );
    // The plaintext take does not survive a failed transcription.
    await flush();
    expect(fs.deleteAsync).toHaveBeenCalledWith(TAKE_URI, { idempotent: true });
    expect(fs.__hasFile(TAKE_URI)).toBe(false);
    expect(api.createEntry).not.toHaveBeenCalled();
  });
});


it("a full retained-recording queue stops before text commit and keeps the current take", async () => {
  const { enqueueAudio, MAX_AUDIO_QUEUE_ITEMS } = await import("../../src/audioQueue");
  for (let i = 0; i < MAX_AUDIO_QUEUE_ITEMS; i++) await enqueueAudio({ userId: "user-1", clientEntryId: `old-${i}`, blobB64: "encrypted-copy", mime: "audio/m4a", durationSeconds: 4 });
  vi.mocked(api.transcribeAudio).mockResolvedValue({ language: "en", language_raw: "en", original_text: "My words remain", english_text: null } as never);
  const root = await render(<EntryScreen navigation={nav} />); await recordAndStop(root);
  await pressLabel(root, "Save"); await flush();
  expect(api.createEntry).not.toHaveBeenCalled();
  expect((inputByPlaceholder(root, "What's going on today?").props as {value: string}).value).toBe("My words remain");
  expect(fs.__hasFile(TAKE_URI)).toBe(true);
});
