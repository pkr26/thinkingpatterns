/**
 * Readable journal export (2026-09-17).
 *
 * The audit's finding: the only export was the raw ciphertext JSON bundle
 * that just a Node CLI (tools/decrypt_export.mjs) can read — a dead end
 * for a normal user, and data portability is the #1 trust criterion in
 * journaling communities. This module decrypts the account's entries
 * ON-DEVICE with the session data key (never a network round-trip of
 * plaintext) and renders them into a shareable Markdown document.
 *
 * The encrypted bundle export stays: it is the true backup (re-importable
 * with the password); this is the human-readable copy.
 */
import { api } from "./api/client";
import { decryptEntry } from "./crypto/MindPatternCrypto";
import { vault } from "./vault";

/** Same share-sheet ceiling as the encrypted export. */
export const MAX_READABLE_CHARS = 4_000_000;

export interface ReadableExport {
  markdown: string;
  entryCount: number;
  skippedCount: number;
}

/** Mood-tag words for the optional per-entry line (matches MOOD_OPTIONS
 *  wording, derived from the payload sentiment value). */
export function moodWord(sentiment: number | null | undefined): string | null {
  if (typeof sentiment !== "number" || !Number.isFinite(sentiment)) return null;
  if (sentiment <= -0.75) return "Heavy";
  if (sentiment <= -0.25) return "Low";
  if (sentiment < 0.25) return "Okay";
  if (sentiment < 0.75) return "Good";
  return "Light";
}

/** Decrypt every entry this account holds and render Markdown.
 *  Tampered/undecryptable blobs are skipped and counted — never rendered
 *  raw, never fatal. */
export async function buildReadableExport(now = new Date()): Promise<ReadableExport> {
  const userId = await api.getUserId();
  if (!userId) throw new Error("account id missing — sign in again");
  const keys = vault.get();
  const rows = await api.listEntries();
  // listEntries returns newest-first pages; the document reads oldest-first.
  const ordered = [...rows].reverse();
  const parts: string[] = [];
  let skipped = 0;
  for (const row of ordered) {
    try {
      const payload = decryptEntry(keys, userId, row.client_entry_id, row.blob);
      const text = typeof payload.text === "string" ? payload.text.trim() : "";
      if (!text && !row.entry_date) continue;
      const mood = moodWord(payload.sentiment);
      parts.push(
        `## ${row.entry_date || "undated"}\n\n${text || "_(empty entry)_"}${mood ? `\n\n_mood: ${mood}_` : ""}`,
      );
    } catch {
      skipped += 1;
    }
  }
  const header =
    `# MindPattern journal\n\nExported ${now.toISOString().slice(0, 10)} · ` +
    `${parts.length} ${parts.length === 1 ? "entry" : "entries"}` +
    (skipped > 0 ? ` · ${skipped} ${skipped === 1 ? "entry could" : "entries could"} not be decrypted` : "") +
    `\n\n_Decrypted on this device. Observations only — never a diagnosis._\n`;
  return {
    markdown: `${header}\n${parts.join("\n\n---\n\n")}\n`,
    entryCount: parts.length,
    skippedCount: skipped,
  };
}
