/** Voice-path view regressions (voice-audit remediation 2026-09-29):
 *  - H2: History mounts exactly ONE <audio> element, keyed to the entry
 *    whose attachment is playing; pressing play on B switches playback
 *    (A stops, its object URL is revoked).
 *  - L-3: the retention countdown renders from entry.audio.expires_at.
 *  - M-7: editing a voice entry re-translates and preserves the v3 voice
 *    channels in the re-encrypted blob (spy on encryptEntry).
 *  - H3 fallout: an ApiError carrying code "stt_unavailable" renders the
 *    localized Settings branch (the code is now allowlisted).
 *
 * Entries and attachments are encrypted with the REAL patient crypto; the
 * fetch edge and URL.createObjectURL are stubbed. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactTestInstance } from "react-test-renderer";
import { encryptAudio, encryptEntry } from "../src/crypto/patient";
import { HistoryView } from "../src/views/History";
import { SettingsView } from "../src/views/Settings";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, pressSwitch, render, settle, textOf, typeArea } from "./helpers/rtr";

// The submitEdit pin needs to spy on encryptEntry while keeping every
// other export (decryptEntry included) the shipping implementation.
vi.mock("../src/crypto/patient", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/patient")>();
  return { ...actual, encryptEntry: vi.fn(actual.encryptEntry) };
});

const mockedEncryptEntry = vi.mocked(encryptEntry);

const ORIGIN = "http://localhost:5173";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(9);
const USER = "user-1";
const FAR_FUTURE = new Date(Date.now() + 30 * 86_400_000).toISOString();

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
  };
};

interface Fixture {
  id: string;
  date: string;
  text: string;
  version: number;
  voice?: { lang: string; english: string };
  audio?: { attachment_id: string; expires_at: string };
}

async function encryptedRow(fixture: Fixture): Promise<Record<string, unknown>> {
  const { blobB64 } = await mockedEncryptEntry(
    DATA_KEY,
    USER,
    fixture.id,
    fixture.text,
    `${fixture.date}T12:00:00Z`,
    null,
    undefined,
    fixture.version,
    fixture.voice
      ? { inputMode: "voice", transcriptLang: fixture.voice.lang, englishText: fixture.voice.english }
      : undefined,
  );
  return {
    id: `row-${fixture.id}`,
    client_entry_id: fixture.id,
    blob: blobB64,
    entry_date: fixture.date,
    received_at: `${fixture.date}T12:00:01Z`,
    content_version: fixture.version,
    ...(fixture.audio ? { audio: fixture.audio } : {}),
  };
}

function entriesResponse(rows: Record<string, unknown>[]): Response {
  return jsonResponse(rows, {
    headers: { "X-Entries-Revision": "7", ...(rows.length > 0 ? { "X-Next-Offset": String(rows.length) } : {}) },
  });
}

/** The encrypted attachment bodies behind the Play buttons. */
async function attachmentBody(clientEntryId: string): Promise<Record<string, unknown>> {
  const { blobB64 } = await encryptAudio(DATA_KEY, USER, clientEntryId, new Uint8Array(64).fill(3));
  return {
    id: `att-${clientEntryId}`,
    client_entry_id: clientEntryId,
    blob: blobB64,
    mime_type: "audio/webm",
    duration_seconds: 42,
    size_bytes: 64,
    created_at: "2026-09-29T00:00:00Z",
    expires_at: FAR_FUTURE,
  };
}

/** Joined text of a rendered subtree (host children carry strings). */
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

/** The text of the entry card (<article>) an audio element sits in. */
const articleTextOf = (node: ReactTestInstance): string => {
  let current: ReactTestInstance | null = node;
  while (current !== null && current.type !== "article") current = current.parent;
  return current === null ? "" : deepText(current);
};

// Node has no URL.createObjectURL; install an observable pair and restore.
const createdUrls: string[] = [];
const revokedUrls: string[] = [];

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(9);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
  mockedEncryptEntry.mockClear();
  createdUrls.length = 0;
  revokedUrls.length = 0;
  (URL as { createObjectURL?: unknown }).createObjectURL = vi.fn((_blob: Blob) => {
    const url = `blob:object-${createdUrls.length + 1}`;
    createdUrls.push(url);
    return url;
  });
  (URL as { revokeObjectURL?: unknown }).revokeObjectURL = vi.fn((url: string) => {
    revokedUrls.push(url);
  });
});
afterEach(() => {
  delete (URL as { createObjectURL?: unknown }).createObjectURL;
  delete (URL as { revokeObjectURL?: unknown }).revokeObjectURL;
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("History kept-recording playback (H2, audit 2026-09-29)", () => {
  it("starting playback mounts exactly ONE audio element, on the pressed entry", async () => {
    const attA = await attachmentBody("e-a");
    const attB = await attachmentBody("e-b");
    const rows = [
      await encryptedRow({ id: "e-a", date: "2026-09-24", text: "alpha take by the river", version: 1, audio: { attachment_id: "att-a", expires_at: FAR_FUTURE } }),
      await encryptedRow({ id: "e-b", date: "2026-09-25", text: "bravo take after the meeting", version: 1, audio: { attachment_id: "att-b", expires_at: FAR_FUTURE } }),
    ];
    const fetchMock = stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith("/audio/attachments/att-a")) return jsonResponse(attA);
      if (url.endsWith("/audio/attachments/att-b")) return jsonResponse(attB);
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    // Two Play buttons, zero audio elements before any press.
    expect(root.root.findAllByType("button").filter((n) => deepText(n) === "Play recording")).toHaveLength(2);
    expect(root.root.findAllByType("audio")).toHaveLength(0);
    // L-3: the retention countdown renders from expires_at (30 days out).
    expect(textOf(root)).toContain("Recording available for 30 more day(s)");

    await press(root, "Play recording");
    await settle(40, 4);
    const audio = root.root.findAllByType("audio");
    expect(audio).toHaveLength(1);
    expect(audio[0]!.props.src).toBe("blob:object-1");
    expect(articleTextOf(audio[0]!)).toContain("alpha take by the river");
    // The pressed entry's button flips to the stop label; the other keeps Play.
    expect(root.root.findAllByType("button").filter((n) => deepText(n) === "Stop playback")).toHaveLength(1);
    expect(root.root.findAllByType("button").filter((n) => deepText(n) === "Play recording")).toHaveLength(1);
    expect(fetchMock.mock.calls.filter(([url]) => url.endsWith("/audio/attachments/att-a"))).toHaveLength(1);
  });

  it("pressing play on B while A plays STOPS A and starts B (one element, old URL revoked)", async () => {
    const attA = await attachmentBody("e-a");
    const attB = await attachmentBody("e-b");
    const rows = [
      await encryptedRow({ id: "e-a", date: "2026-09-24", text: "alpha take by the river", version: 1, audio: { attachment_id: "att-a", expires_at: FAR_FUTURE } }),
      await encryptedRow({ id: "e-b", date: "2026-09-25", text: "bravo take after the meeting", version: 1, audio: { attachment_id: "att-b", expires_at: FAR_FUTURE } }),
    ];
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith("/audio/attachments/att-a")) return jsonResponse(attA);
      if (url.endsWith("/audio/attachments/att-b")) return jsonResponse(attB);
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Play recording"); // entry A renders first
    await settle(40, 4);
    // A is playing; B's is the only remaining "Play recording" button.
    await press(root, "Play recording");
    await settle(40, 4);
    const audio = root.root.findAllByType("audio");
    expect(audio).toHaveLength(1);
    expect(audio[0]!.props.src).toBe("blob:object-2");
    expect(articleTextOf(audio[0]!)).toContain("bravo take after the meeting");
    expect(revokedUrls).toContain("blob:object-1");

    // Stop unmounts the last element and revokes its URL.
    await press(root, "Stop playback");
    await settle(40, 2);
    expect(root.root.findAllByType("audio")).toHaveLength(0);
    expect(revokedUrls).toContain("blob:object-2");
  });
});

describe("History submitEdit on a voice entry (M-7, audit 2026-09-29)", () => {
  it("re-translates the edited text and re-encrypts with the v3 voice channels", async () => {
    const rows = [
      await encryptedRow({
        id: "e-voice",
        date: "2026-09-24",
        text: "Texto original",
        version: 2,
        voice: { lang: "es", english: "Original English translation" },
      }),
    ];
    const calls: string[] = [];
    stubFetch((url, init) => {
      calls.push(`${init.method} ${url}`);
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url === `${ORIGIN}/api/v1/entries/e-voice` && init.method === "PUT") {
        return jsonResponse({ id: "row-e-voice" });
      }
      if (url === `${ORIGIN}/api/v1/audio/translations` && init.method === "POST") {
        return jsonResponse({ english_text: "Edited English translation" });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "Texto editado");
    await press(root, "Save edit");
    await settle(40, 6);

    // The re-translation rode the translations endpoint before the PUT.
    const translationsAt = calls.findIndex((call) => call === `POST ${ORIGIN}/api/v1/audio/translations`);
    const putAt = calls.findIndex((call) => call === `PUT ${ORIGIN}/api/v1/entries/e-voice`);
    expect(translationsAt).toBeGreaterThanOrEqual(0);
    expect(putAt).toBeGreaterThan(translationsAt);

    const encryptCall = mockedEncryptEntry.mock.calls.at(-1)!;
    // (dataKey, userId, clientEntryId, text, createdAt, sentiment, structured, contentVersion, voice)
    expect(encryptCall[2]).toBe("e-voice");
    expect(encryptCall[3]).toBe("Texto editado");
    expect(encryptCall[7]).toBe(3); // contentVersion 2 → 3
    expect(encryptCall[8]).toEqual({
      inputMode: "voice",
      transcriptLang: "es",
      englishText: "Edited English translation",
    });
  });

  it("a typed entry's edit never touches the translations endpoint", async () => {
    const rows = [
      await encryptedRow({ id: "e-typed", date: "2026-09-24", text: "typed words", version: 1 }),
    ];
    stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url === `${ORIGIN}/api/v1/entries/e-typed` && init.method === "PUT") {
        return jsonResponse({ id: "row-e-typed" });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "typed words, edited");
    await press(root, "Save edit");
    await settle(40, 6);
    const encryptCall = mockedEncryptEntry.mock.calls.at(-1)!;
    expect(encryptCall[8]).toBeUndefined(); // no voice channels on a typed edit
  });
});

describe("Settings stt_unavailable branch (H3, audit 2026-09-29)", () => {
  it("an ApiError with the allowlisted code renders the localized not-offered branch", async () => {
    stubFetch((url, init) => {
      if (url.endsWith("/meta")) {
        return jsonResponse({
          version: "1",
          api_version: "v1",
          unlock_days: 30,
          llm_available: true,
          sharing_available: true,
          sharing_disclosure_version: "v2",
          audio_available: true,
          stt_provider_name: "Whisper",
        });
      }
      if (url.endsWith("/llm-consent") && init.method === "GET") return jsonResponse({ enabled: false });
      if (url.endsWith("/account/voice-consent") && init.method === "GET") {
        return jsonResponse({ enabled: true, active_for_current_policy: true, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
      }
      if (url.endsWith("/account/voice-consent") && init.method === "PUT") {
        // The backend's shape when STT is not configured (account.py):
        // 409 + code stt_unavailable — previously degraded by
        // sanitizeCode, leaving Settings' branch dead.
        return jsonResponse(
          { detail: "voice transcription is not configured on this server", code: "stt_unavailable" },
          { status: 409 },
        );
      }
      if (url.endsWith("/access-log")) return jsonResponse([]);
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "1" } });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<SettingsView onLockdown={vi.fn()} />);
    await settle(40, 6);
    // The voice consent switch rendered (meta says audio_available).
    expect(textOf(root)).toContain("Voice journaling on");
    await pressSwitch(root, "Voice journaling on");
    await settle(40, 6);
    expect(textOf(root)).toContain("Voice journaling is not offered by this server.");
  });
});
