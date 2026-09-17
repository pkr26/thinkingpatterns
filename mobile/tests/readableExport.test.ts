/**
 * Readable journal export (2026-09-17): the human-readable Markdown copy
 * next to the encrypted backup. Pins the document format, on-device
 * decryption (never plaintext over the network), and the skip-counting of
 * undecryptable blobs.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  getUserId: vi.fn(),
  listEntries: vi.fn(),
}));

vi.mock("../src/api/client", () => ({ api: apiMock }));
// Real crypto path: encrypt fixtures with the app's own envelope so the
// decrypt side is the shipping code.
const { encryptEntry } = await import("../src/crypto/MindPatternCrypto");
const { vault } = await import("../src/vault");
const { buildReadableExport, moodWord } = await import("../src/readableExport");

const DATA_KEY = Buffer.alloc(32, 7);
const USER = "user-1";

function encryptedEntry(text: string, date: string, sentiment: number | null, id: string): string {
  return encryptEntry({ dataKey: DATA_KEY }, USER, id, text, date, sentiment).blobB64;
}

beforeEach(() => {
  apiMock.getUserId.mockResolvedValue(USER);
  apiMock.listEntries.mockReset();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: DATA_KEY }, USER);
});

describe("buildReadableExport", () => {
  it("renders oldest-first Markdown with dates, text, and mood lines", async () => {
    apiMock.listEntries.mockResolvedValue([
      // newest first (server order) — the document reverses it
      { id: "2", client_entry_id: "e2", blob: encryptedEntry("second day calm", "2026-09-02", 0.5, "e2"), entry_date: "2026-09-02", received_at: "2026-09-02T10:00:00Z" },
      { id: "1", client_entry_id: "e1", blob: encryptedEntry("first day heavy", "2026-09-01", -0.8, "e1"), entry_date: "2026-09-01", received_at: "2026-09-01T10:00:00Z" },
    ]);
    const out = await buildReadableExport(new Date("2026-09-17T00:00:00Z"));
    expect(out.entryCount).toBe(2);
    expect(out.skippedCount).toBe(0);
    const first = out.markdown.indexOf("first day heavy");
    const second = out.markdown.indexOf("second day calm");
    expect(first).toBeGreaterThan(-1);
    expect(second).toBeGreaterThan(first); // oldest first
    expect(out.markdown).toContain("# MindPattern journal");
    expect(out.markdown).toContain("## 2026-09-01");
    expect(out.markdown).toContain("_mood: Heavy_");
    expect(out.markdown).toContain("_mood: Good_");
    expect(out.markdown).toContain("2 entries");
  });

  it("skips undecryptable blobs and counts them honestly", async () => {
    apiMock.listEntries.mockResolvedValue([
      { id: "1", client_entry_id: "e1", blob: encryptedEntry("good", "2026-09-01", null, "e1"), entry_date: "2026-09-01", received_at: "x" },
      { id: "2", client_entry_id: "e2", blob: Buffer.from("garbage").toString("base64"), entry_date: "2026-09-02", received_at: "x" },
    ]);
    const out = await buildReadableExport();
    expect(out.entryCount).toBe(1);
    expect(out.skippedCount).toBe(1);
    expect(out.markdown).toContain("1 entry could not be decrypted");
    expect(out.markdown).not.toContain("garbage");
  });

  it("fails loudly without a user id (never exports an empty shell)", async () => {
    apiMock.getUserId.mockResolvedValue(null);
    await expect(buildReadableExport()).rejects.toThrow("account id missing");
  });

  it("entries without a mood pick render with no mood line", async () => {
    apiMock.listEntries.mockResolvedValue([
      { id: "1", client_entry_id: "e1", blob: encryptedEntry("plain", "2026-09-01", null, "e1"), entry_date: "2026-09-01", received_at: "x" },
    ]);
    const out = await buildReadableExport();
    expect(out.markdown).not.toContain("_mood:");
  });
});

describe("moodWord", () => {
  it("maps the 5-point check-in scale to its labels", () => {
    expect(moodWord(-1)).toBe("Heavy");
    expect(moodWord(-0.5)).toBe("Low");
    expect(moodWord(0)).toBe("Okay");
    expect(moodWord(0.5)).toBe("Good");
    expect(moodWord(1)).toBe("Light");
    expect(moodWord(null)).toBeNull();
    expect(moodWord(undefined)).toBeNull();
    expect(moodWord(Number.NaN)).toBeNull();
  });
});
