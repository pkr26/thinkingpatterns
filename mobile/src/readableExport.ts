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
/** Leave room for the fixed, locally generated header and a final newline.
 * This makes the content budget strict without repeatedly joining a nearly
 * four-megabyte array just to discover it is too large. The final defensive
 * trim below remains the authority if the header ever grows. */
const HEADER_RESERVE_CHARS = 512;
const ENTRY_SEPARATOR = "\n\n---\n\n";

export interface ReadableExport {
  markdown: string;
  entryCount: number;
  /** Ciphertexts that could not be authenticated/decrypted. */
  skippedCount: number;
  /** Valid entries deliberately left out once the share-sheet cap is hit. */
  truncatedCount: number;
}

function plural(count: number, singular: string, pluralForm: string): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

function renderMarkdown(parts: readonly string[], skipped: number, truncated: number, now: Date): string {
  const notes = [
    skipped > 0 ? `${plural(skipped, "entry", "entries")} could not be decrypted` : "",
    truncated > 0 ? `${plural(truncated, "entry", "entries")} omitted to keep this export under 4 MB` : "",
  ].filter(Boolean);
  const header =
    `# MindPattern journal\n\nExported ${now.toISOString().slice(0, 10)} · ` +
    `${plural(parts.length, "entry", "entries")}` +
    (notes.length > 0 ? ` · ${notes.join(" · ")}` : "") +
    `\n\n_Decrypted on this device. Observations only — never a diagnosis._\n`;
  return `${header}\n${parts.join(ENTRY_SEPARATOR)}\n`;
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
  let truncated = 0;
  let contentLength = 0;
  for (const [index, row] of ordered.entries()) {
    try {
      const payload = decryptEntry(keys, userId, row.client_entry_id, row.blob);
      const text = typeof payload.text === "string" ? payload.text.trim() : "";
      if (!text && !row.entry_date) continue;
      const mood = moodWord(payload.sentiment);
      const part =
        `## ${row.entry_date || "undated"}\n\n${text || "_(empty entry)_"}${mood ? `\n\n_mood: ${mood}_` : ""}`;
      const separatorLength = parts.length === 0 ? 0 : ENTRY_SEPARATOR.length;
      // Preserve the oldest-first ordering rather than producing a
      // surprising sparse chronology. Once one valid entry will not fit,
      // count it and every remaining row as omitted without decrypting or
      // allocating more plaintext.
      if (contentLength + separatorLength + part.length > MAX_READABLE_CHARS - HEADER_RESERVE_CHARS) {
        truncated += ordered.length - index;
        break;
      }
      parts.push(part);
      contentLength += separatorLength + part.length;
    } catch {
      skipped += 1;
    }
  }
  let markdown = renderMarkdown(parts, skipped, truncated, now);
  // The reserve above is deliberately generous, but this remains a
  // fail-closed size boundary if header copy is ever expanded.
  while (markdown.length > MAX_READABLE_CHARS && parts.length > 0) {
    parts.pop();
    truncated += 1;
    markdown = renderMarkdown(parts, skipped, truncated, now);
  }
  if (markdown.length > MAX_READABLE_CHARS) {
    throw new Error("readable export header exceeds the safe share-sheet limit");
  }
  return {
    markdown,
    entryCount: parts.length,
    skippedCount: skipped,
    truncatedCount: truncated,
  };
}
