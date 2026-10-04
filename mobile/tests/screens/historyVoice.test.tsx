/**
 * HistoryScreen.saveEdit voice preservation (VOICE_PLAN remediation M4,
 * 2026-09-29): an edit of a voice entry must re-encrypt with the v3
 * channels — the kept audio attachment survives an edit, so a silent
 * downgrade to v1/v2 strands it. encryptEntry is spied (real behavior
 * preserved) so the re-encrypt's voice argument is asserted directly, and
 * the translations endpoint is watched for the re-translation.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actualApi = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError, ENTRY_PAGE_BYTES } = await import("../helpers/apiMock");
  return { ...actualApi, ApiError, api: makeApiMock(), ENTRY_PAGE_BYTES };
});

// Spied, real implementation preserved: the decrypted replacement blob is
// asserted end to end AND the voice argument is observable per call.
vi.mock("../../src/crypto/journalCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/journalCrypto")>();
  return { ...actual, encryptEntry: vi.fn(actual.encryptEntry) };
});

const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { encryptEntry, decryptEntry, encryptAudio } = await import("../../src/crypto/journalCrypto");
const { HistoryScreen } = await import("../../src/screens/HistoryScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { render, flush, pressLabel, firePress, act } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;
const { playerControls, __resetAudioMock } = await import("../helpers/expoAudioMock");
const fs = await import("../helpers/expoFsMock");
const { __resetLocalKeyLifecycleForTests, changeLocalSessionOwner, freezeLocalKeyWrites, installLocalDataKey } = await import("../../src/localWriteGuard");

const dataKey = Buffer.alloc(32, 5);
const nav = { navigate: vi.fn() };

/** A synced v3 (voice) row exactly the way the Entry screen writes one. */
function voiceRow(clientEntryId: string, text: string, englishText: string | null) {
  const payload = JSON.stringify({
    v: 3,
    text,
    sentiment: null,
    created_at: "2026-09-29T10:00:00.000Z",
    input_mode: "voice",
    transcript_lang: "es",
    english_text: englishText,
  });
  return {
    id: `srv-${clientEntryId}`,
    client_entry_id: clientEntryId,
    blob: encrypt(dataKey, Buffer.from(payload), buildAad("entry", "user-1", clientEntryId, "1")).toString("base64"),
    entry_date: "2026-09-29",
    received_at: "2026-09-29T10:00:00.000Z",
    content_version: 1,
  };
}

/** A synced typed (v1) row for the no-voice-args regression side. */
function typedRow(clientEntryId: string, text: string) {
  const payload = JSON.stringify({ v: 1, text, sentiment: null, created_at: "2026-09-29T10:00:00.000Z" });
  return {
    id: `srv-${clientEntryId}`,
    client_entry_id: clientEntryId,
    blob: encrypt(dataKey, Buffer.from(payload), buildAad("entry", "user-1", clientEntryId, "1")).toString("base64"),
    entry_date: "2026-09-29",
    received_at: "2026-09-29T10:00:00.000Z",
    content_version: 1,
  };
}

/** list → detail → editor with `next` typed in. */
async function editTo(root: Awaited<ReturnType<typeof render>>, snippet: string, next: string, waitSave = true): Promise<void> {
  await pressLabel(root, snippet);
  await pressLabel(root, "Edit this entry");
  const { TextInput } = await import("react-native");
  const editor = root.root.findAllByType(TextInput).find((n) => n.props.accessibilityLabel === "Edit entry");
  if (!editor) throw new Error("editor not open");
  await act(async () => {
    (editor.props as { onChangeText?: (t: string) => void }).onChangeText?.(next);
  });
  await (waitSave ? pressLabel : firePress)(root, "Save changes");
  await flush();
}

beforeEach(() => {
  __resetLocalKeyLifecycleForTests();
  resetApi(api as never);
  __resetAudioMock();
  fs.__resetFiles();
  // mockClear keeps the real implementation (the module mock wrapped it);
  // only the call history resets between tests.
  vi.mocked(encryptEntry).mockClear();
  Alert.alert.mockClear();
  touchActivity.mockClear();
  nav.navigate.mockClear();
  storage.__reset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
});

describe("HistoryScreen.saveEdit preserves v3 voice channels (M4)", () => {
  it("rejects a replacement owner returned by an edit's suspended first lookup", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([voiceRow("e-voice-1", "Texto original", "Old translation")] as never);
    const root = await render(<HistoryScreen navigation={nav} />); await flush();
    let release!: () => void;
    vi.mocked(api.getUserId).mockImplementationOnce(async () => { await new Promise<void>(resolve => { release = resolve; }); return "user-2"; });
    await editTo(root, "Texto original", "Texto editado", false); expect(release).toBeTypeOf("function");
    changeLocalSessionOwner("user-2");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 8) }, "user-2");
    await act(async () => release()); await flush();
    expect(api.updateEntry).not.toHaveBeenCalled(); expect(api.translateText).not.toHaveBeenCalled();
    await act(async () => root.unmount());
  });
  it("does not send an edit retained under an old key after delayed translation spans rotation", async () => {
    installLocalDataKey("user-1", dataKey);
    vi.mocked(api.listEntries).mockResolvedValue([voiceRow("e-voice-1", "Texto original", "Old translation")] as never);
    let release!: () => void;
    vi.mocked(api.translateText).mockImplementation(async () => {
      await new Promise<void>(resolve => { release = resolve; }); return { english_text: "New translation" } as never;
    });
    const root = await render(<HistoryScreen navigation={nav} />); await flush();
    await editTo(root, "Texto original", "Texto editado", false); expect(release).toBeTypeOf("function");
    freezeLocalKeyWrites("user-1"); installLocalDataKey("user-1", Buffer.alloc(32, 6));
    await act(async () => release()); await flush();
    expect(api.updateEntry).not.toHaveBeenCalled();
    const { TextInput } = await import("react-native");
    expect(root.root.findAllByType(TextInput).find(n => n.props.accessibilityLabel === "Edit entry")?.props.value).toBe("Texto editado");
    await act(async () => root.unmount());
  });
  it("re-translates the edited text and re-encrypts with the voice argument", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([voiceRow("e-voice-1", "Texto original", "Old translation")] as never);
    vi.mocked(api.translateText).mockResolvedValue({ english_text: "New translation" } as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await editTo(root, "Texto original", "Texto editado");
    // The translations endpoint ran for the EDITED text with the payload's
    // detected language — mirroring EntryScreen's save path.
    expect(api.translateText).toHaveBeenCalledWith("Texto editado", "es");
    // The replacement carries the v3 channels: input mode, transcript
    // language, and the UPDATED English text.
    const voiceArg = vi.mocked(encryptEntry).mock.calls.at(-1)?.[8];
    expect(voiceArg).toEqual({ inputMode: "voice", transcriptLang: "es", englishText: "New translation" });
    expect(vi.mocked(encryptEntry).mock.calls.at(-1)?.[7]).toBe(2); // next content generation
    // The uploaded blob itself decrypts back to a v3 voice payload.
    const [entryId, blobB64] = vi.mocked(api.updateEntry).mock.calls[0];
    expect(entryId).toBe("e-voice-1");
    const payload = decryptEntry({ dataKey }, "user-1", "e-voice-1", blobB64, 2);
    expect(payload.v).toBe(3);
    expect(payload.input_mode).toBe("voice");
    expect(payload.text).toBe("Texto editado");
    expect(payload.english_text).toBe("New translation");
  });

  it("a failed re-translation degrades english_text to null — never a v1/v2 downgrade", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([voiceRow("e-voice-2", "Texto original", "Old translation")] as never);
    vi.mocked(api.translateText).mockRejectedValue(new Error("offline"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await editTo(root, "Texto original", "Texto editado");
    const voiceArg = vi.mocked(encryptEntry).mock.calls.at(-1)?.[8];
    expect(voiceArg).toEqual({ inputMode: "voice", transcriptLang: "es", englishText: null });
    const [, blobB64] = vi.mocked(api.updateEntry).mock.calls[0];
    const payload = decryptEntry({ dataKey }, "user-1", "e-voice-2", blobB64, 2);
    expect(payload.v).toBe(3);
    expect(payload.english_text).toBeNull();
  });

  it("a voice entry without an English channel never calls the translations endpoint", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([voiceRow("e-voice-3", "Texto original", null)] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await editTo(root, "Texto original", "Texto editado");
    expect(api.translateText).not.toHaveBeenCalled();
    const voiceArg = vi.mocked(encryptEntry).mock.calls.at(-1)?.[8];
    expect(voiceArg).toEqual({ inputMode: "voice", transcriptLang: "es", englishText: null });
  });

  it("a typed entry keeps re-encrypting WITHOUT voice args (no v3 leak)", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([typedRow("e-typed-1", "Typed words")] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await editTo(root, "Typed words", "Typed words edited");
    expect(api.translateText).not.toHaveBeenCalled();
    expect(vi.mocked(encryptEntry).mock.calls.at(-1)?.[8]).toBeUndefined();
    const [, blobB64] = vi.mocked(api.updateEntry).mock.calls[0];
    const payload = decryptEntry({ dataKey }, "user-1", "e-typed-1", blobB64, 2);
    expect([1, 2]).toContain(payload.v);
    expect(payload.input_mode).toBeUndefined();
  });
});

describe("HistoryScreen kept-recording playback failure (audit M1)", () => {
  it("a player failure releases the scratch file and clears the ref — the next attempt starts clean", async () => {
    const { blobB64 } = encryptAudio({ dataKey }, "user-1", "e-voice-play", Buffer.alloc(64, 9));
    vi.mocked(api.listEntries).mockResolvedValue([
      {
        ...voiceRow("e-voice-play", "Texto de voz", null),
        audio: { attachment_id: "att-1", expires_at: "2026-10-29T00:00:00Z" },
      },
    ] as never);
    vi.mocked(api.fetchAudioAttachment).mockResolvedValue({
      blob: blobB64,
      mime_type: "audio/m4a",
      duration_seconds: 4,
    } as never);
    // The first player dies AFTER the decrypted scratch file exists.
    playerControls.play.mockImplementationOnce(() => {
      throw new Error("player died");
    });
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Play recording");
    await flush();
    // The decrypted scratch file was written to the cache dir...
    const scratch = fs.writeAsStringAsync.mock.calls[0]?.[0];
    expect(scratch).toContain("voice-");
    expect(scratch).toContain(".m4a");
    // ...and the failure path DELETED it instead of orphaning it.
    expect(fs.deleteAsync).toHaveBeenCalledWith(scratch, { idempotent: true });
    expect(fs.__hasFile(scratch!)).toBe(false);
    // The stale ref is gone: the next tap starts a fresh fetch+play (the
    // button flips to Stop playback), it does not swallow the attempt.
    await pressLabel(root, "Play recording");
    await flush();
    expect(api.fetchAudioAttachment).toHaveBeenCalledTimes(2);
    const { allText } = await import("../helpers/rtr");
    expect(allText(root).join(" ")).toContain("Stop playback");
  });
});
