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
 *
 * Redesign 2026-09-26: the calendar gains weekday headers, a color legend,
 * a month entry count, and tap-a-day filtering; entries render as cards
 * with a mood rail; delete is a two-step arm/confirm (matching the portal's
 * pattern) instead of a single unconfirmed press.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, listEntriesWalk } from "../api/client";
import { decryptEntry, encryptEntry, type EntryPayload } from "../crypto/patient";
import { forgetEntryVersion, observeEntryVersions } from "../entryVersions";
import { filterEntries, monthGrid, monthLabel, stepMonth } from "../historyFind";
import { recentMoods, removeMoodDay } from "../moodLog";
import { localDateISO } from "../dates";
import { moodLabel } from "../mood";
import { dateLocaleTag, t } from "../strings";
import { vault } from "../vault";
import { moodFill, moodInk, currentPalette, usePaletteVersion } from "../tokens";
import { Button, Card, Chip, ErrorBanner, Field, Icon, Note, Skeleton, TextArea } from "../ui";

interface DecodedEntry {
  clientEntryId: string;
  entryDate: string;
  contentVersion: number;
  payload: EntryPayload;
}

/** Locale-aware weekday initials (Mon..Sun order, matching monthGrid). */
function weekdayLabels(): string[] {
  const formatter = new Intl.DateTimeFormat(dateLocaleTag(), { weekday: "short" });
  // 2023-01-02 was a Monday — walk one full week from it.
  const monday = new Date(Date.UTC(2023, 0, 2));
  return Array.from({ length: 7 }, (_, index) => {
    const day = new Date(monday.getTime() + index * 86_400_000);
    return formatter.format(day).slice(0, 3);
  });
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
  const [selectedDay, setSelectedDay] = useState<string | null>(null);
  const [editing, setEditing] = useState<DecodedEntry | null>(null);
  const [editText, setEditText] = useState("");
  const [conflict, setConflict] = useState<{ theirs: DecodedEntry; mine: string } | null>(null);
  const [armedDelete, setArmedDelete] = useState<string | null>(null);
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
    let pool = entries;
    if (selectedDay) pool = pool.filter((entry) => entry.entryDate === selectedDay);
    return filterEntries(
      pool.map((entry) => ({ clientEntryId: entry.clientEntryId, entryDate: entry.entryDate, text: entry.payload.text })),
      query,
    ).map((hit) => entries.find((entry) => entry.clientEntryId === hit.clientEntryId)!);
  }, [entries, query, selectedDay]);

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
      hasEntry: day.iso !== null && byDate.has(day.iso),
    }));
  }, [entries, cursor, logMoods]);

  const monthEntryCount = useMemo(() => {
    if (!entries) return 0;
    const prefix = `${cursor.year}-${String(cursor.month).padStart(2, "0")}`;
    return entries.filter((entry) => entry.entryDate.startsWith(prefix)).length;
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
      setArmedDelete(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("history.deleteFailed"));
    } finally {
      setBusy(false);
    }
  };

  const today = localDateISO();
  // Re-render the JS-drawn fills/inks when the theme flips (auto mode).
  usePaletteVersion();
  const palette = currentPalette();
  const weekdays = useMemo(weekdayLabels, []);

  return (
    <>
      <Card title={t("history.calendarTitle")}>
        <div className="cal-toolbar">
          <button
            type="button"
            className="cal-arrow"
            aria-label={t("history.prevMonth")}
            onClick={() => setCursor(stepMonth(cursor.year, cursor.month, -1))}
          >
            <Icon name="chevron-left" size={17} />
          </button>
          <span className="cal-month">{monthLabel(cursor.year, cursor.month)}</span>
          <button
            type="button"
            className="cal-arrow"
            aria-label={t("history.nextMonth")}
            onClick={() => setCursor(stepMonth(cursor.year, cursor.month, 1))}
          >
            <Icon name="chevron-right" size={17} />
          </button>
        </div>
        {/* role=group, not grid: the cells are independent day buttons
            (no rows/roving cells), and a mis-announced "grid" is worse
            than an honest group (audit 2026-09-26 fix). */}
        <div className="cal-grid" role="group" aria-label={t("history.calendarTitle")}>
          {weekdays.map((label) => (
            <span key={label} className="cal-weekday" aria-hidden="true">{label}</span>
          ))}
          {calendar?.map((day, index) => {
            // Leading blanks share day===0 — the index keys them apart
            // (the old `blank-${day.day}` collided on most months).
            if (day.iso === null) return <span key={`blank-${index}`} />;
            const filled = day.hasEntry || day.value !== null;
            const fill = filled ? moodFill(day.value) : undefined;
            const selected = selectedDay === day.iso;
            return (
              <button
                key={day.iso}
                type="button"
                className={[
                  "cal-day",
                  day.hasEntry ? "cal-day--entry" : "",
                  day.iso === today ? "cal-day--today" : "",
                  selected ? "cal-day--selected" : "",
                ].filter(Boolean).join(" ")}
                style={fill !== undefined ? { backgroundColor: fill, color: moodInk(day.value) } : undefined}
                aria-label={`${day.iso}${day.hasEntry ? ` — ${t("history.dayHasEntry")}` : ""}${day.iso === today ? ` — ${t("history.todayA11y")}` : ""}`}
                aria-pressed={selected}
                onClick={() => day.hasEntry && setSelectedDay(selected ? null : day.iso)}
                disabled={!day.hasEntry}
              >
                {day.day}
              </button>
            );
          })}
        </div>
        <div className="row row--wrap row--between">
          <span className="cal-legend">
            <span className="cal-legend__swatch" style={{ background: palette.mood2 }} aria-hidden="true" />
            {t("history.legendLighter")}
            <span className="cal-legend__swatch" style={{ background: palette.moodMinus2, marginLeft: 8 }} aria-hidden="true" />
            {t("history.legendHeavier")}
          </span>
          <span className="cal-legend">
            {monthEntryCount > 0 ? t(monthEntryCount === 1 ? "history.monthEntriesOne" : "history.monthEntriesMany", { count: monthEntryCount }) : ""}
          </span>
        </div>
        <Note tone="muted">{t("history.calendarNote")}</Note>
      </Card>

      <Card title={t("history.title")}>
        {selectedDay && (
          <div className="row row--wrap">
            <Chip label={t("history.showingDay", { date: selectedDay })} selected onPress={() => setSelectedDay(null)} icon="x" />
          </div>
        )}
        <Field label={t("history.search")} value={query} onChange={setQuery} placeholder={t("history.searchPlaceholderWeb")} />
        {rolledBack.length > 0 && <Note tone="warn">{t(rolledBack.length === 1 ? "history.rollbackOne" : "history.rollbackMany", { count: rolledBack.length })}</Note>}
        <ErrorBanner message={error} />
        {visible === null && !error && (
          <>
            <Note role="status">{t("common.loading")}</Note>
            <Skeleton lines={4} title />
          </>
        )}
        {visible?.length === 0 && <Note>{query ? t("history.noMatch") : t("history.empty")}</Note>}
        {visible?.map((entry) => (
          <article key={entry.clientEntryId} className="entry-card">
            <div className="entry-card__head">
              <span className="row" style={{ gap: 8 }}>
                <span className="mood-dot" style={{ background: moodFill(entry.payload.sentiment ?? null) }} aria-hidden="true" />
                <span className="entry-card__date">{entry.entryDate}</span>
              </span>
              <span className="mood-badge">
                {entry.payload.sentiment != null ? moodLabel(entry.payload.sentiment) : t("history.noRead")}
                {entry.contentVersion > 1 ? ` · ${t("history.editedTimes", { count: entry.contentVersion - 1 })}` : ""}
              </span>
            </div>
            <Note>{entry.payload.text.length > 240 ? `${entry.payload.text.slice(0, 240)}…` : entry.payload.text}</Note>
            <div className="row">
              <Button label={t("history.edit")} onPress={() => startEdit(entry)} small variant="ghost" disabled={busy || editing !== null || conflict !== null} />
              {armedDelete === entry.clientEntryId ? (
                <>
                  <Button label={t("common.deletePermanently")} onPress={() => void remove(entry)} small danger disabled={busy} />
                  <Button label={t("common.cancel")} onPress={() => setArmedDelete(null)} small variant="ghost" />
                </>
              ) : (
                <Button label={t("common.delete")} onPress={() => setArmedDelete(entry.clientEntryId)} small danger disabled={busy} />
              )}
            </div>
          </article>
        ))}
      </Card>

      {editing && (
        <Card title={t("history.editTitle", { date: editing.entryDate })}>
          <TextArea label={t("history.yourEntry")} value={editText} onChange={setEditText} rows={8} />
          <div className="row">
            <Button label={busy ? t("entry.saving") : t("history.saveEdit")} onPress={() => void submitEdit()} disabled={busy} />
            <Button label={t("common.cancel")} onPress={() => setEditing(null)} small variant="ghost" />
          </div>
        </Card>
      )}

      {conflict && (
        <Card title={t("history.conflictTitle")}>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="section-label">{t("history.conflictTheirs")}</span>
            <Note>{conflict.theirs.payload.text}</Note>
          </div>
          <hr className="divider" />
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="section-label">{t("history.conflictMine")}</span>
            <Note>{conflict.mine}</Note>
          </div>
          <div className="row row--wrap">
            <Button label={t("history.keepTheirs")} onPress={() => { setConflict(null); void load(); }} small variant="ghost" />
            <Button label={t("history.applyMine")} onPress={() => void applyMineOnTop()} small />
          </div>
          <Note tone="muted">{t("history.noOverwriteNote")}</Note>
        </Card>
      )}
    </>
  );
}
