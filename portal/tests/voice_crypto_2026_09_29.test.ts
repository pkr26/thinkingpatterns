/**
 * Voice-remediation crypto pins (audit 2026-09-29, M-8b): the portal's
 * decryptEntry now carries the SAME payload-version guard the web client
 * has — v1/v2/v3 decrypt, anything else throws LOUDLY instead of being
 * silently miscast as today's shape (a future v4 misread is how a schema
 * roll corrupts the clinical chart with wrong-typed fields).
 *
 * Real WebCrypto, no mocks — the guard is the shipping decrypt path.
 */
import { describe, expect, it } from "vitest";
import { decryptEntry, encrypt, toBase64 } from "../src/crypto";
import { buildAad } from "../src/aad";

const DATA_KEY = new Uint8Array(32).fill(7);
const USER = "user-1";

async function sealedEntry(payload: Record<string, unknown>, contentVersion = 1): Promise<string> {
  const blob = await encrypt(
    DATA_KEY,
    new TextEncoder().encode(JSON.stringify(payload)),
    buildAad("entry", USER, "e-1", String(contentVersion)),
  );
  return toBase64(blob);
}

describe("decryptEntry payload-version guard (M-8b, audit 2026-09-29)", () => {
  it("v1, v2 and v3 payloads decrypt through the guard", async () => {
    const v1 = await sealedEntry({ v: 1, text: "plain day", sentiment: 0.2, created_at: "2026-09-29T00:00:00Z" });
    const v2 = await sealedEntry({ v: 2, text: "structured day", sentiment: null, created_at: "2026-09-29T00:00:00Z", energy: 3 });
    const v3 = await sealedEntry({
      v: 3,
      text: "día con voz",
      sentiment: null,
      created_at: "2026-09-29T00:00:00Z",
      input_mode: "voice",
      transcript_lang: "es",
      english_text: "day with voice",
    });
    expect((await decryptEntry(DATA_KEY, USER, { client_entry_id: "e-1", blob: v1, content_version: 1 })).text).toBe("plain day");
    expect((await decryptEntry(DATA_KEY, USER, { client_entry_id: "e-1", blob: v2, content_version: 1 })).text).toBe("structured day");
    const voice = await decryptEntry(DATA_KEY, USER, { client_entry_id: "e-1", blob: v3, content_version: 1 });
    expect(voice.input_mode).toBe("voice");
    expect(voice.english_text).toBe("day with voice");
  });

  it("a v4 blob throws loudly — never rendered as today's shape", async () => {
    const v4 = await sealedEntry({ v: 4, text: "future schema", sentiment: null });
    await expect(
      decryptEntry(DATA_KEY, USER, { client_entry_id: "e-1", blob: v4, content_version: 1 }),
    ).rejects.toThrow("unsupported entry payload version: 4");
  });

  it("a version-less blob (tampered/foreign) throws, not silently decrypts", async () => {
    const noVersion = await sealedEntry({ text: "no version field" });
    await expect(
      decryptEntry(DATA_KEY, USER, { client_entry_id: "e-1", blob: noVersion, content_version: 1 }),
    ).rejects.toThrow("unsupported entry payload version: undefined");
  });
});
