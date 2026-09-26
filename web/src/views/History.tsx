/**
 * History (WEB_PLAN P4.5/4.6): the account's decrypted journal — byte-paged
 * under one revision snapshot, searchable, with the mood calendar, honest
 * version-conflict editing ("reload theirs / reapply mine" — never a silent
 * overwrite), delete, and the entry-version rollback guard (a rolled-back
 * row is skipped and counted, exactly like a tampered blob).
 *
 * H-5 (audit 2026-09-26): the payload's sentiment is only ever an explicit
 * check-in pick now, so the mood calendar sources like mobile — payload
 * pick first, the device-local mood log's day value as fallback.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, listEntriesWalk } from "../api/client";
import { decryptEntry, encryptEntry, type EntryPayload } from "../crypto/patient";
import { forgetEntryVersion, observeEntryVersions } from "../entryVersions";
import { filterEntries, monthGrid, monthLabel, stepMonth } from "../historyFind";
import { recentMoods, removeMoodDay } from "../moodLog";
import { localDateISO } from "../dates";
import { moodLabel } from "../mood";
import { t } from "../strings";
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
  // The device-local mood log's day values — the calendar's fallback source
  // (H-5: payload pick first, log value second), like mobile's logMoods.
  const [logMoods, setLogMoods] = useState<Record<string, number>>({});
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) {
      setError(t("common.sessionLocked"));
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
      // The mood-log fallback is disposable metadata: a failed read leaves
      // the calendar on payload picks alone, never blocks the list.
      const logDays = await recentMoods(keys.dataKey, owner, 400).catch(() => []);
      if (generation.current !== run) return;
      const moods: Record<string, number> = {};
      for (const day of logDays) moods[day.date] = day.value;
      setLogMoods(moods);
      const rolled = observation.rolledBack;
      setRolledBack(rolled);
      setEntries(decoded.filter((entry) => !rolled.includes(entry.clientEntryId)));
      if (tampered.length > 0 || rolled.length > 0) {
        setError(t(tampered.length + rolled.length === 1 ? "history.hiddenOne" : "history.hiddenMany", { count: tampered.length + rolled.length }));
      }
    } catch (err) {
      if (generation.current !== run) return;
      // Every terminal failure leaves the screen honest — never a permanent
      // "Loading…" (audit 2026-09-25: only status-0 used to surface).
      setEntries([]);
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
      } else if (err instanceof ApiError && err.status === 0) {
        setError(t("history.loadOffline"));
      } else {
        setError(err instanceof Error ? err.message : t("history.loadFailed"));
      }
    }
  }, []);

  useEffect(() => {
    if (vault.isUnlocked()) void load();
    else setError(t("common.sessionLocked"));
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
      // H-5 (audit 2026-09-26): the explicit payload pick wins; days
      // without one fall back to the mood log's device-local estimate
      // (mobile MoodCalendar parity — the log is recorded on every save).
      value: day.iso !== null ? (byDate.get(day.iso)?.payload.sentiment ?? logMoods[day.iso] ?? null) : null,
    }));
  }, [entries, cursor, logMoods]);

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
          setError(t("history.conflictReloadFailed"));
        }
      } else if (err instanceof ApiError && err.status === 404) {
        // Deleted on another device (S-4): the pending edit is quarantined
        // for review — shown verbatim, never resurrected silently.
        setConflict({
          theirs: { ...target, payload: { ...target.payload, text: t("history.deletedElsewhere") } },
          mine: editText,
        });
        setEditing(null);
      } else {
        setError(err instanceof Error ? err.message : t("history.editFailed"));
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
      setError(err instanceof Error ? err.message : t("history.deleteFailed"));
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
      <Card title={t("history.calendarTitle")}>
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
        <Note tone="muted">{t("history.calendarNote")}</Note>
      </Card>

      <Card title={t("history.title")}>
        <Field label={t("history.search")} value={query} onChange={setQuery} placeholder={t("history.searchPlaceholderWeb")} />
        {rolledBack.length > 0 && <Note tone="warn">{t(rolledBack.length === 1 ? "history.rollbackOne" : "history.rollbackMany", { count: rolledBack.length })}</Note>}
        <ErrorBanner message={error} />
        {visible === null && !error && <Note role="status">{t("common.loading")}</Note>}
        {visible?.length === 0 && <Note>{query ? t("history.noMatch") : t("history.empty")}</Note>}
        {visible?.map((entry) => (
          <section key={entry.clientEntryId} style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
              <strong style={{ fontSize: 13, color: theme.text }}>{entry.entryDate}</strong>
              <Note tone="muted">
                {entry.payload.sentiment != null ? moodLabel(entry.payload.sentiment) : t("history.noRead")}
                {entry.contentVersion > 1 ? ` · ${t("history.editedTimes", { count: entry.contentVersion - 1 })}` : ""}
              </Note>
            </div>
            <Note>{entry.payload.text.length > 240 ? `${entry.payload.text.slice(0, 240)}…` : entry.payload.text}</Note>
            <div style={{ display: "flex", gap: 8 }}>
              <Button label={t("history.edit")} onPress={() => startEdit(entry)} small disabled={busy || editing !== null || conflict !== null} />
              <Button label={t("common.delete")} onPress={() => void remove(entry)} small danger disabled={busy} />
            </div>
          </section>
        ))}
      </Card>

      {editing && (
        <Card title={t("history.editTitle", { date: editing.entryDate })}>
          <TextArea label={t("history.yourEntry")} value={editText} onChange={setEditText} rows={8} />
          <div style={{ display: "flex", gap: 8 }}>
            <Button label={busy ? t("entry.saving") : t("history.saveEdit")} onPress={() => void submitEdit()} disabled={busy} />
            <Button label={t("common.cancel")} onPress={() => setEditing(null)} small />
          </div>
        </Card>
      )}

      {conflict && (
        <Card title={t("history.conflictTitle")}>
          <Note tone="warn">{t("history.conflictTheirs")}</Note>
          <Note>{conflict.theirs.payload.text}</Note>
          <Note tone="warn">{t("history.conflictMine")}</Note>
          <Note>{conflict.mine}</Note>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Button label={t("history.keepTheirs")} onPress={() => { setConflict(null); void load(); }} small />
            <Button label={t("history.applyMine")} onPress={() => void applyMineOnTop()} small />
          </div>
          <Note tone="muted">{t("history.noOverwriteNote")}</Note>
        </Card>
      )}
    </>
  );
}
