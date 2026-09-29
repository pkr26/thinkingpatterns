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
 *
 * Audit 2026-09-26 LOW: search maps hits back through a Map<id, entry>
 * built once per source (was entries.find per hit, O(n²)), the list
 * renders through a growing window with a "Show more" sentinel, and the
 * decrypt loop yields to the host periodically — the mood calendar's
 * sourcing is untouched.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, listEntriesWalk } from "../api/client";
import { zeroize } from "../crypto/core";
import { decryptEntry, encryptEntry, type EntryPayload } from "../crypto/patient";
import { playAttachment, type PlayingAudio } from "../audio/player";
import { detectCrisisLanguage } from "../crisisDetect";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { forgetEntryVersion, observeEntryVersions } from "../entryVersions";
import { filterEntries, monthGrid, monthLabel, stepMonth } from "../historyFind";
import { recentMoods, removeMoodDay } from "../moodLog";
import { localDateISO } from "../dates";
import { moodLabel } from "../mood";
import { dateLocaleTag, t } from "../strings";
import { vault } from "../vault";
import { moodFill, moodInk, currentPalette, usePaletteVersion } from "../tokens";
import { Button, Card, Chip, ErrorBanner, Field, Icon, Note, Skeleton, TextArea } from "../ui";

/** The client-side entry length cap (2026-09-28 audit MEDIUM): the
 *  server's blob ceiling is far higher, so without a client gate a
 *  pathological paste could park a megabyte of ciphertext in the queue
 *  and silently die against entryDraft.ts's 100k parse bound. Mobile's
 *  EntryScreen.tsx contract — the same constant, the same honest copy. */
const MAX_ENTRY_CHARS = 100_000;

interface DecodedEntry {
  clientEntryId: string;
  entryDate: string;
  contentVersion: number;
  payload: EntryPayload;
  /** Unexpired kept-recording metadata from the listing (VOICE_PLAN
   *  2026-09-29); null/absent on entries without audio. */
  audio?: { attachment_id: string; expires_at: string } | null;
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

/** How many entry cards render before the "Show more" sentinel (audit
 *  2026-09-26 LOW): a whole decrypted journal must not hit the DOM at
 *  once — a plain growing slice, the Settings access-log idiom, not a
 *  virtualization dependency. */
const HISTORY_WINDOW = 30;

/** Coarse UI yield while decrypting (same audit item): decrypt-every-row
 *  stays sequential by design (WebCrypto has no batch API), but the loop
 *  hands the host a beat every so often — requestIdleCallback where the
 *  platform has it, a macrotask otherwise — so a long account does not
 *  freeze painting. */
const DECRYPT_YIELD_EVERY = 25;

function yieldToHost(): Promise<void> {
  return new Promise((resolve) => {
    const idle = (globalThis as { requestIdleCallback?: (callback: () => void) => number }).requestIdleCallback;
    if (typeof idle === "function") {
      idle(() => resolve());
      return;
    }
    setTimeout(resolve, 0);
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
  // Kept-recording playback (VOICE_PLAN 2026-09-29): fetch → decrypt in
  // memory → revocable object URL; nothing cached at rest, one at a time.
  const [playing, setPlaying] = useState<PlayingAudio | null>(null);
  const [audioBusyId, setAudioBusyId] = useState<string | null>(null);

  useEffect(() => () => playing?.release(), [playing]);

  const toggleRecording = async (entry: DecodedEntry): Promise<void> => {
    if (!entry.audio) return;
    if (playing) {
      playing.release();
      setPlaying(null);
      return;
    }
    if (!vault.isUnlocked()) return;
    setAudioBusyId(entry.audio.attachment_id);
    try {
      const keys = vault.get();
      const owner = vault.ownerUserId();
      if (!owner) return;
      const current = await playAttachment({
        fetchBlob: () => api.fetchAudioAttachment(entry.audio!.attachment_id),
        dataKey: keys.dataKey,
        userId: owner,
        clientEntryId: entry.clientEntryId,
      });
      setPlaying(current);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("history.loadFailed"));
    } finally {
      setAudioBusyId(null);
    }
  };

  const removeRecording = async (entry: DecodedEntry): Promise<void> => {
    if (!entry.audio) return;
    setAudioBusyId(entry.audio.attachment_id);
    setError("");
    try {
      await api.deleteAudioAttachment(entry.audio.attachment_id);
      if (playing) {
        playing.release();
        setPlaying(null);
      }
      setEntries((list) =>
        (list ?? []).map((item) => (item.clientEntryId === entry.clientEntryId ? { ...item, audio: null } : item)),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : t("history.loadFailed"));
    } finally {
      setAudioBusyId(null);
    }
  };
  const [busy, setBusy] = useState(false);
  // H-6 (audit 2026-09-28, mobile parity): the edit path's post-save
  // crisis prompt card — the same tier the Entry tab runs pre-save.
  const [crisisPrompt, setCrisisPrompt] = useState(false);
  // The windowed-render count (audit 2026-09-26 LOW): how many of the
  // filtered entries are actually on screen.
  const [shownCount, setShownCount] = useState(HISTORY_WINDOW);
  // The device-local mood log's day values — the calendar's fallback source
  // (H-5: payload pick first, log value second), like mobile's logMoods.
  const [logMoods, setLogMoods] = useState<Record<string, number>>({});
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const owner = vault.ownerUserId();
    if (!owner) {
      setError(t("common.sessionLocked"));
      return;
    }
    setEntries(null);
    setError("");
    try {
      // Immediate re-check inside the try (audit 2026-09-26 LOW, the
      // Patterns guard pattern): a lock landing between the owner check
      // and the key fetch — or between any two awaits below — must be a
      // quiet no-op, never vault.get()'s throw as an unhandled rejection.
      if (!vault.isUnlocked()) return;
      const keys = vault.get();
      const listed = await listEntriesWalk();
      if (generation.current !== run) return;
      const decoded: DecodedEntry[] = [];
      const tampered: string[] = [];
      for (const row of listed) {
        if (decoded.length > 0 && decoded.length % DECRYPT_YIELD_EVERY === 0) {
          await yieldToHost();
          if (generation.current !== run) return;
        }
        // 2026-09-28 audit (LOW): re-check the lock inside the per-row
        // loop — keys.dataKey is the vault's SHARED buffer, and a lock
        // landing mid-walk zeroizes it, so every remaining row would
        // fail GCM and be COUNTED TAMPERED. A locked vault stops the
        // walk with the honest locked message instead; the rows already
        // decrypted still render.
        if (!vault.isUnlocked()) {
          setEntries(decoded);
          setError(t("common.sessionLocked"));
          return;
        }
        try {
          const payload = await decryptEntry(keys.dataKey, owner, row.client_entry_id, row.blob, row.content_version ?? undefined);
          decoded.push({
            clientEntryId: row.client_entry_id,
            entryDate: row.entry_date,
            contentVersion: row.content_version ?? 1,
            payload,
            audio: row.audio ?? null,
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
    // Map<id, entry> built ONCE per source (audit 2026-09-26 LOW): mapping
    // the search hits back used entries.find per hit — O(n²) over the whole
    // decrypted journal on every keystroke.
    const byId = new Map(entries.map((entry) => [entry.clientEntryId, entry]));
    let pool = entries;
    if (selectedDay) pool = pool.filter((entry) => entry.entryDate === selectedDay);
    return filterEntries(
      pool.map((entry) => ({ clientEntryId: entry.clientEntryId, entryDate: entry.entryDate, text: entry.payload.text })),
      query,
    ).map((hit) => byId.get(hit.clientEntryId)!);
  }, [entries, query, selectedDay]);

  // A new filter source starts the window over (the sentinel grows it).
  useEffect(() => {
    setShownCount(HISTORY_WINDOW);
  }, [query, selectedDay]);

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
    // A fresh edit starts the crisis tier over (H-6): the prompt that
    // closed with the previous edit must not suppress the next one's.
    setCrisisPrompt(false);
  };

  const submitEdit = async (theirsOverride?: DecodedEntry): Promise<void> => {
    const target = theirsOverride ?? editing;
    if (!target) return;
    // Empty-text parity with mobile (HistoryScreen.tsx, 2026-09-28 audit
    // MEDIUM): an edit that says nothing must be refused client-side —
    // the server would accept the ciphertext, and the row would render
    // as a saved blank day.
    if (!editText.trim()) {
      setError(t("entry.empty"));
      return;
    }
    // The same client-side length cap as the create path (2026-09-28
    // audit MEDIUM): MAX_ENTRY_CHARS gates the editor, not just the
    // server's blob ceiling.
    if (editText.trim().length > MAX_ENTRY_CHARS) {
      setError(t("entry.tooLongBody", { max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()) }));
      return;
    }
    const owner = vault.ownerUserId();
    // Guarded like load() (audit 2026-09-26 LOW): a lock that raced the
    // press is a quiet no-op, never vault.get()'s throw.
    if (!owner || !vault.isUnlocked()) return;
    const keys = vault.get();
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
      // H-6 (2026-09-28 audit, mobile HistoryScreen parity): the EDIT path
      // runs the same on-device crisis detection as a new entry. The server
      // only ever sees ciphertext, so this detector is the only net for a
      // user who edits yesterday's entry into crisis language — the same
      // text as a NEW entry gets the dialog, an edited one must too. Never
      // before or instead of saving: the replacement is already committed
      // server-side at this point. Same per-day throttle stamp (session-
      // scoped, fail toward showing) and calm copy as the Entry tab.
      if (detectCrisisLanguage(editText) && !crisisPrompt) {
        const today = localDateISO();
        const shownToday = await crisisDialogShownOn(owner, today).catch(() => false);
        if (!shownToday) {
          await recordCrisisDialogShown(owner, today).catch(() => undefined);
          setCrisisPrompt(true);
        }
      }
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
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) return; // guarded like submitEdit
    setBusy(true);
    // independent audit 2026-09-27 (P2): snapshot the data key BEFORE the
    // delete await — the old code reused the vault's SHARED buffer after
    // it, so a lock mid-delete zeroized it and the local maintenance below
    // ran under an all-zero key. The copy is zeroized in finally.
    const keys = vault.get();
    const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
    dataKey.set(keys.dataKey);
    try {
      await api.deleteEntry(entry.clientEntryId);
      // A lock mid-delete: the entry is gone server-side; the local
      // hygiene (version mark, mood day) is disposable metadata — quietly
      // skipped, never an unhandled rejection, never a write under a dead
      // session.
      if (vault.isUnlocked()) {
        await forgetEntryVersion(owner, dataKey, entry.clientEntryId);
        await removeMoodDay(dataKey, owner, entry.entryDate).catch(() => undefined);
      }
      setArmedDelete(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("history.deleteFailed"));
    } finally {
      zeroize(dataKey);
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
      {/* H-6 (2026-09-28 audit): the edit path's crisis tier — the same
          calm card the Entry tab shows, surfaced AFTER the replacement
          committed server-side (mobile Alert parity). */}
      {crisisPrompt && (
        <Card title={t("entry.crisisPromptTitle")} tone="sensitive">
          <Note tone="danger">{t("entry.crisisPromptBody")}</Note>
          <Note tone="muted">{t("entry.crisisPromptProceed")}</Note>
        </Card>
      )}

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
        {visible?.slice(0, shownCount).map((entry) => (
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
            {entry.payload.input_mode === "voice" && (
              <span className="row" style={{ gap: 6 }}>
                <Icon name="mic" size={12} />
                <span className="note note--muted">{t("history.voiceBadge")}</span>
              </span>
            )}
            {entry.audio && (
              <div className="stack" style={{ gap: "var(--space-2)" }}>
                <div className="row row--wrap">
                  <Button
                    label={playing ? t("history.playRecording") : t("history.playRecording")}
                    icon="play"
                    small
                    variant="ghost"
                    disabled={audioBusyId === entry.audio.attachment_id}
                    onPress={() => void toggleRecording(entry)}
                  />
                  <Button
                    label={t("history.deleteRecording")}
                    icon="trash"
                    small
                    variant="ghost"
                    disabled={audioBusyId === entry.audio.attachment_id}
                    onPress={() => void removeRecording(entry)}
                  />
                </div>
                {playing && (
                  <audio controls autoPlay src={playing.url} style={{ width: "100%" }} onEnded={() => { playing.release(); setPlaying(null); }} />
                )}
              </div>
            )}
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
        {/* The windowed-render sentinel (audit 2026-09-26 LOW): one more
            window per press, the Settings access-log idiom — the rest of
            the journal stays off-DOM until asked for. */}
        {visible !== null && visible.length > shownCount && (
          <Button
            label={t("settings.showMore")}
            onPress={() => setShownCount((count) => count + HISTORY_WINDOW)}
            small
            variant="ghost"
          />
        )}
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
