/**
 * History (WEB_PLAN P4.5/4.6): the account's decrypted journal — byte-paged
 * under one revision snapshot, searchable, with the mood calendar, honest
 * version-conflict editing ("reload theirs / reapply mine" — never a silent
 * overwrite), delete, and the entry-version rollback guard (a rolled-back
 * row is skipped and counted, exactly like a tampered blob).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, listEntriesWalk, type ListedEntry } from "../api/client";
import { decryptEntry, encryptEntry, type EntryPayload } from "../crypto/patient";
import { forgetEntryVersion, observeEntryVersions } from "../entryVersions";
import { filterEntries, monthGrid, monthLabel, stepMonth } from "../historyFind";
import { removeMoodDay } from "../moodLog";
import { localDateISO } from "../dates";
import { moodLabel } from "../mood";
import { vault } from "../vault";
import { theme, Button, Card, ErrorBanner, Field, Note, TextArea } from "../ui";

interface DecodedEntry {
  clientEntryId: string;
  entryDate: string;
  contentVersion: number;
  payload: EntryPayload;
}

export function HistoryView(): React.JSX.Element {
  const [entries, setEntries] = useState<DecodedEntry[] | null>(null);
  const [rolledBack, setRolledBack] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState<{ year: number; month: number }>(() => {
    const now = new Date();
    return { year: now.getFullYear(), month: now.getMonth() + 1 };
  });
  const [editing, setEditing] = useState<DecodedEntry | null>(null);
  const [editText, setEditText] = useState("");
  const [conflict, setConflict] = useState<{ theirs: DecodedEntry; mine: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) {
      setError("Your session locked — sign in again.");
      return;
    }
    setEntries(null);
    setError("");
    try {
      const listed = await listEntriesWalk();
      if (generation.current !== run) return;
      const decoded: DecodedEntry[] = [];
      const tampered: string[] = [];
      for (const row of listed) {
        try {
          const payload = await decryptEntry(keys.dataKey, owner, row.client_entry_id, row.blob, row.content_version ?? undefined);
          decoded.push({
            clientEntryId: row.client_entry_id,
            entryDate: row.entry_date,
            contentVersion: row.content_version ?? 1,
            payload,
          });
        } catch {
          // A tampered/undecryptable row is skipped and counted — never
          // rendered as truth, never fatal to the list.
          tampered.push(row.client_entry_id);
        }
      }
      const observation = await observeEntryVersions(
        owner,
        keys.dataKey,
        decoded.map((entry) => ({ clientEntryId: entry.clientEntryId, contentVersion: entry.contentVersion })),
      );
      if (generation.current !== run) return;
      const rolled = observation.rolledBack;
      setRolledBack(rolled);
      setEntries(decoded.filter((entry) => !rolled.includes(entry.clientEntryId)));
      if (tampered.length > 0 || rolled.length > 0) {
        setError(`${tampered.length + rolled.length} entr${tampered.length + rolled.length === 1 ? "y" : "ies"} could not be verified and were hidden — they may have been tampered with.`);
      }
    } catch (err) {
      if (generation.current !== run) return;
      if (err instanceof ApiError && err.status === 0 && vault.isUnlocked()) {
        setError("Could not load history — check your connection and try again.");
        setEntries([]);
      }
    }
  }, []);

  useEffect(() => {
    if (vault.isUnlocked()) void load();
    else setError("Your session locked — sign in again.");
  }, [load]);

  const visible = useMemo(() => {
    if (!entries) return null;
    return filterEntries(
      entries.map((entry) => ({ clientEntryId: entry.clientEntryId, entryDate: entry.entryDate, text: entry.payload.text })),
      query,
    ).map((hit) => entries.find((entry) => entry.clientEntryId === hit.clientEntryId)!);
  }, [entries, query]);

  const calendar = useMemo(() => {
    if (!entries) return null;
    const byDate = new Map(entries.map((entry) => [entry.entryDate, entry]));
    return monthGrid(cursor.year, cursor.month).map((day) => ({
      iso: day.iso, // null = leading blank
      day: day.day,
      value: day.iso !== null ? (byDate.get(day.iso)?.payload.sentiment ?? null) : null,
    }));
  }, [entries, cursor]);

  const startEdit = (entry: DecodedEntry): void => {
    setEditing(entry);
    setEditText(entry.payload.text);
    setConflict(null);
  };

  const submitEdit = async (theirsOverride?: DecodedEntry): Promise<void> => {
    const target = theirsOverride ?? editing;
    if (!target) return;
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) return;
    setBusy(true);
    try {
      const nextVersion = target.contentVersion + 1;
      const { blobB64 } = await encryptEntry(
        keys.dataKey,
        owner,
        target.clientEntryId,
        editText,
        new Date().toISOString(),
        editText.trim() ? (target.payload.sentiment ?? null) : null,
        {
          ...(target.payload.energy != null ? { energy: target.payload.energy } : {}),
          ...(target.payload.sleep != null ? { sleep: target.payload.sleep } : {}),
          ...(target.payload.tags != null ? { tags: target.payload.tags } : {}),
          ...(target.payload.tod != null ? { tod: target.payload.tod } : {}),
        },
        nextVersion,
      );
      await api.updateEntry(target.clientEntryId, blobB64, target.entryDate, nextVersion);
      setEditing(null);
      setConflict(null);
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === "version_conflict") {
        // Another device edited first. Refetch their version and show both
        // texts — the user decides; nothing is silently overwritten.
        try {
          const fresh = await api.getEntry(target.clientEntryId);
          const freshPayload = await decryptEntry(keys.dataKey, owner, fresh.client_entry_id, fresh.blob, fresh.content_version ?? undefined);
          setConflict({
            theirs: {
              clientEntryId: fresh.client_entry_id,
              entryDate: fresh.entry_date,
              contentVersion: fresh.content_version ?? 1,
              payload: freshPayload,
            },
            mine: editText,
          });
          setEditing(null);
        } catch {
          setError("This entry changed on another device and could not be reloaded — copy your text, then reload.");
        }
      } else if (err instanceof ApiError && err.status === 404) {
        // Deleted on another device (S-4): the pending edit is quarantined
        // for review — shown verbatim, never resurrected silently.
        setConflict({
          theirs: { ...target, payload: { ...target.payload, text: "(this entry was deleted on another device)" } },
          mine: editText,
        });
        setEditing(null);
      } else {
        setError(err instanceof Error ? err.message : "Could not save the edit.");
      }
    } finally {
      setBusy(false);
    }
  };

  const applyMineOnTop = async (): Promise<void> => {
    if (!conflict) return;
    setEditText(conflict.mine);
    await submitEdit(conflict.theirs);
  };

  const remove = async (entry: DecodedEntry): Promise<void> => {
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) return;
    setBusy(true);
    try {
      await api.deleteEntry(entry.clientEntryId);
      await forgetEntryVersion(owner, keys.dataKey, entry.clientEntryId);
      await removeMoodDay(keys.dataKey, owner, entry.entryDate).catch(() => undefined);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the entry.");
    } finally {
      setBusy(false);
    }
  };

  const today = localDateISO();
  const moodColor = (value: number | null): string => {
    if (value === null) return theme.cardDeep;
    if (value > 0.3) return "#8fc7a8";
    if (value > 0.05) return "#c7dfc1";
    if (value > -0.05) return "#e3e6ea";
    if (value > -0.3) return "#e6cbc2";
    return "#dba89c";
  };

  return (
    <>
      <Card title="Mood calendar">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Button label="‹" onPress={() => setCursor(stepMonth(cursor.year, cursor.month, -1))} small />
          <Note>{monthLabel(cursor.year, cursor.month)}</Note>
          <Button label="›" onPress={() => setCursor(stepMonth(cursor.year, cursor.month, 1))} small />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 4 }}>
          {calendar?.map((day) => (
            <div
              key={day.iso ?? `blank-${day.day}`}
              title={day.iso ?? ""}
              style={{
                aspectRatio: "1",
                borderRadius: 6,
                backgroundColor: day.iso !== null ? moodColor(day.value) : "transparent",
                border: `1px solid ${day.iso === today ? theme.accent : theme.border}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 11,
                color: theme.muted,
              }}
            >
              {day.iso !== null ? day.day : ""}
            </div>
          ))}
        </div>
        <Note tone="muted">Each tile is the day's on-device sentiment read — computed locally from the decrypted entry, never synced separately.</Note>
      </Card>

      <Card title="History">
        <Field label="Search" value={query} onChange={setQuery} placeholder="Search your words, or an exact date (YYYY-MM-DD)" />
        {rolledBack.length > 0 && <Note tone="warn">{`${rolledBack.length} hidden by the rollback guard.`}</Note>}
        <ErrorBanner message={error} />
        {visible === null && <Note role="status">Loading…</Note>}
        {visible?.length === 0 && <Note>No entries{query ? " match that search" : " yet — today is a fine day to start"}.</Note>}
        {visible?.map((entry) => (
          <section key={entry.clientEntryId} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
              <strong style={{ fontSize: 13, color: theme.text }}>{entry.entryDate}</strong>
              <Note tone="muted">
                {entry.payload.sentiment != null ? moodLabel(entry.payload.sentiment) : "no read"}
                {entry.contentVersion > 1 ? ` · edited ×${entry.contentVersion - 1}` : ""}
              </Note>
            </div>
            <Note>{entry.payload.text.length > 240 ? `${entry.payload.text.slice(0, 240)}…` : entry.payload.text}</Note>
            <div style={{ display: "flex", gap: 8 }}>
              <Button label="Edit" onPress={() => startEdit(entry)} small disabled={busy || editing !== null || conflict !== null} />
              <Button label="Delete" onPress={() => void remove(entry)} small danger disabled={busy} />
            </div>
          </section>
        ))}
      </Card>

      {editing && (
        <Card title={`Edit ${editing.entryDate}`}>
          <TextArea label="Your entry" value={editText} onChange={setEditText} rows={8} />
          <div style={{ display: "flex", gap: 8 }}>
            <Button label={busy ? "Saving…" : "Save edit"} onPress={() => void submitEdit()} disabled={busy} />
            <Button label="Cancel" onPress={() => setEditing(null)} small />
          </div>
        </Card>
      )}

      {conflict && (
        <Card title="This entry changed on another device">
          <Note tone="warn">{"Their version (saved first):"}</Note>
          <Note>{conflict.theirs.payload.text}</Note>
          <Note tone="warn">{"Your version:"}</Note>
          <Note>{conflict.mine}</Note>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Button label="Keep their version" onPress={() => { setConflict(null); void load(); }} small />
            <Button label="Apply mine on top" onPress={() => void applyMineOnTop()} small />
          </div>
          <Note tone="muted">Nothing was overwritten automatically — you choose.</Note>
        </Card>
      )}
    </>
  );
}
