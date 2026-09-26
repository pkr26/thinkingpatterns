/**
 * Journal history: past entries, decrypted on this device only.
 *
 * The server stores ciphertext; reading history pulls the entry list and
 * decrypts each blob locally with the vault's data key — plaintext never
 * leaves the phone. Reads need a connection (this device holds no copy of
 * entries written elsewhere): offline, the screen says so honestly rather
 * than showing a stale or misleadingly empty list — today's writing always
 * works offline either way.
 *
 * DELETE and EDIT also run against the server: the offline queue carries
 * only new-entry uploads, so deletes cannot be queued — both actions
 * require connectivity and say so when there is none. Deleting is a calm
 * double confirmation.
 *
 * Editing uses the server's atomic replacement endpoint. The client entry id
 * stays stable and the old ciphertext is never deleted until the replacement
 * transaction commits, so a transient network failure cannot erase a journal
 * entry.
 */
import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  BackHandler,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { api, ApiError, ENTRY_PAGE_BYTES } from "../api/client";
import { decryptEntry, encryptEntry } from "../crypto/MindPatternCrypto";
import { forgetEntryVersion, observeEntryVersions } from "../entryVersions";
import { MoodCalendar } from "../components/MoodCalendar";
import { filterEntries } from "../historyFind";
import { vault } from "../vault";
import { useSession } from "../store";
import { recordMood, recentMoods, removeMoodDay, localDateISO } from "../moodLog";
import { localSentiment, moodLabel } from "../mood";
import { detectCrisisLanguage } from "../crisisDetect";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { useTheme } from "../theme";
import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { requestFailureCopy } from "../components/errors";
import { t as tr, dateLocaleTag } from "../strings";

/** History reveals in calm batches instead of one endless scroll. */
const PAGE_SIZE = 50;
/** One request's item-count ceiling; the server also applies a 2 MiB blob cap. */
const SERVER_PAGE_SIZE = 100;
/** Keep manual history loading genuinely bounded: at most 500 ciphertext
 * rows / five requests can become decrypted plaintext in this screen. */
const MAX_HISTORY_SERVER_PAGES = 5;
const MAX_HISTORY_ROWS = SERVER_PAGE_SIZE * MAX_HISTORY_SERVER_PAGES;
const SNIPPET_CHARS = 140;
/** Same payload cap as the Entry screen. */
const MAX_ENTRY_CHARS = 100_000;
const SHOW_COUNT_ABOVE = 90_000;
const STATUS_MS = 2_600;

interface HistoryEntry {
  clientEntryId: string;
  entryDate: string;
  receivedAt: string;
  /** Server-declared content generation (M-2, 2026-09-20); null on legacy
   *  servers that do not send content_version. */
  contentVersion: number | null;
  text: string;
  /** The day's explicit check-in pick, when one was made (else null). */
  sentiment: number | null;
  /** The v2 structured channels, preserved through an edit (else default). */
  energy: number | null;
  sleep: number | null;
  tags: string[];
}

type Mode =
  | { kind: "list" }
  | { kind: "detail"; entry: HistoryEntry }
  | { kind: "edit"; entry: HistoryEntry };

/** Decrypt one server page with the M-2 version ladder: the v2
 *  (version-bound) AAD first, the legacy binding as fallback, then the
 *  per-entry high-water check — a row whose declared generation moved
 *  BACKWARDS is treated exactly like a tampered blob (skipped, counted),
 *  never rendered as today's truth. */
async function decryptRowsWithVersions(
  userId: string,
  dataKey: Buffer,
  rows: ReadonlyArray<{
    client_entry_id: string;
    blob: string;
    entry_date?: unknown;
    received_at?: unknown;
    content_version?: number;
  }>,
): Promise<{ decrypted: HistoryEntry[]; failed: number }> {
  const decrypted: HistoryEntry[] = [];
  let failed = 0;
  const versioned: { clientEntryId: string; contentVersion: number }[] = [];
  for (const row of rows) {
    try {
      const payload = decryptEntry(
        { dataKey },
        userId,
        row.client_entry_id,
        row.blob,
        typeof row.content_version === "number" ? row.content_version : undefined,
      );
      decrypted.push({
        clientEntryId: row.client_entry_id,
        entryDate: typeof row.entry_date === "string" ? row.entry_date : "",
        receivedAt: typeof row.received_at === "string" ? row.received_at : "",
        contentVersion: typeof row.content_version === "number" ? row.content_version : null,
        text: typeof payload.text === "string" ? payload.text : "",
        sentiment: sanitizeSentiment(payload.sentiment),
        energy: sanitizeEnergy(payload.energy),
        sleep: sanitizeSleep(payload.sleep),
        tags: sanitizeTags(payload.tags),
      });
      if (typeof row.content_version === "number") {
        versioned.push({ clientEntryId: row.client_entry_id, contentVersion: row.content_version });
      }
    } catch {
      failed += 1;
    }
  }
  if (versioned.length > 0) {
    const { rolledBack } = await observeEntryVersions(userId, dataKey, versioned);
    if (rolledBack.length > 0) {
      const rolled = new Set(rolledBack);
      const kept = decrypted.filter((entry) => !rolled.has(entry.clientEntryId));
      failed += decrypted.length - kept.length;
      return { decrypted: kept, failed };
    }
  }
  return { decrypted, failed };
}

/** "2026-09-03" → "Thursday, September 3, 2026" (es: "jueves, 3 de
 *  septiembre de 2026") per the app locale; a garbage date falls back to
 *  the raw string instead of crashing the row. */
export function formatEntryDate(iso: string): string {
  const parsed = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleDateString(dateLocaleTag(), { weekday: "long", year: "numeric", month: "long", day: "numeric" });
}

function snippetOf(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > SNIPPET_CHARS ? `${flat.slice(0, SNIPPET_CHARS)}…` : flat;
}

/** The payload's sentiment rides inside the encrypted blob, but the server
 *  held the data key once (processing sessions) — treat the field like any
 *  other rendered value: type-check, clamp. */
function sanitizeSentiment(value: unknown): number | null {
  // Stryker disable next-line LogicalOperator,ConditionalExpression: value arrives JSON-parsed from the entry blob; Number.isFinite is false for every non-number, so || vs && and dropping the typeof arm differ only for NaN/Infinity numbers, which JSON cannot encode
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.max(-1, Math.min(1, value));
}

/** The v2 structured channels get the same type-check-and-clamp treatment:
 *  they ride back through encryptEntry on every edit, so a malformed value
 *  must degrade to "absent", never to a payload the server would reject. */
function sanitizeEnergy(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.max(-1, Math.min(1, value));
}

function sanitizeSleep(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.round(value) >= 1 && Math.round(value) <= 5 ? Math.round(value) : null;
}

/** Mirrors the server's tag cleaning (insights.py): strip, lowercase,
 * truncate to 24, drop empties and duplicates, cap at 8 — everything that
 * survives can round-trip through a re-encrypt without rejection. */
function sanitizeTags(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const cleaned: string[] = [];
  for (const tag of value) {
    if (typeof tag !== "string") continue;
    const clean = tag.trim().toLowerCase().slice(0, 24);
    if (clean && !cleaned.includes(clean)) cleaned.push(clean);
    if (cleaned.length >= 8) break;
  }
  return cleaned;
}

export function HistoryScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  // Stryker disable next-line ObjectLiteral,StringLiteral: nothing ever compares mode.kind to "list" — {} / {kind:""} fail the edit and detail checks identically and fall through to the same list return
  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  // Stryker disable next-line BooleanLiteral: the pre-effect first commit is unobservable in tests — react-test-renderer defers the initial render to act's drain, where load()'s setLoading(true) lands in the same flush (outside act nothing commits at all)
  const [loading, setLoading] = useState(true);
  // Stryker disable next-line BooleanLiteral: same test seam as loading — the load effect's setOffline(false) corrects the initial value in the very first act flush, so only that corrected value is ever observable
  const [offline, setOffline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unreadable, setUnreadable] = useState(0);
  const [shown, setShown] = useState(PAGE_SIZE);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [historyLimitReached, setHistoryLimitReached] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [logMoods, setLogMoods] = useState<Record<string, number>>({});
  /** Search + calendar filter (2026-09-17): plain-text query and a tapped
   *  calendar day narrow the DECRYPTED on-device list — neither leaves the
   *  phone. Both reset on reload. */
  const [query, setQuery] = useState("");
  const [dayFilter, setDayFilter] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  // Stryker disable next-line StringLiteral: status starts null (InlineStatus renders nothing) and every setStatus(message) in showStatus is batched with setStatusTone, so the initial tone value is never rendered
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("neutral");
  // Stryker disable next-line StringLiteral: every path into edit mode goes through startEdit, which sets draft first — the initial draft value is never rendered or read
  const [draft, setDraft] = useState("");
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Double-tap guard: two presses inside one frame both pass a state-only
  // check (the Entry screen's savingRef pattern) — the ref is synchronous.
  const busyRef = useRef(false);
  const loadingMoreRef = useRef(false);
  /** Synchronous guard for a stale native tap while a fresh page-one request
   * is pending. State alone is batched, so it cannot protect that window. */
  const historyReloadingRef = useRef(false);
  // These are mutable mirrors of the history cap. State updates are batched,
  // so refs close the brief post-response window where a rapid extra tap
  // could otherwise start a sixth request before the disabled UI commits.
  const loadedServerPagesRef = useRef(0);
  const loadedCiphertextRowsRef = useRef(0);
  const historyLimitRef = useRef(false);
  /** A modern server gives every page in one history walk the same strict
   * decimal revision. Null means the connected (older) server is headerless
   * and we intentionally use the established pagination fallback. */
  const entriesRevisionRef = useRef<string | null>(null);
  /** Invalidates an older load-more response when a full reload begins, so a
   * stale page can never be appended to a freshly restarted snapshot. */
  const historyLoadEpochRef = useRef(0);

  /** Transient confirmation ("Entry deleted"); replaces itself cleanly. */
  const showStatus = (message: string, tone: InlineStatusTone) => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
    setStatusTone(tone);
    setStatus(message);
    statusTimer.current = setTimeout(() => setStatus(null), STATUS_MS);
  };

  const load = useCallback(async (afterRevisionConflict = false) => {
    const loadEpoch = ++historyLoadEpochRef.current;
    // Initial pages deliberately do not carry expected_revision: they obtain
    // the snapshot token for this walk. A legacy server returns no token.
    entriesRevisionRef.current = null;
    historyReloadingRef.current = true;
    setLoading(true);
    setError(null);
    setOffline(false);
    // An initial request replaces the paging walk. Hide its old continuation
    // synchronously so it cannot append to the new page-one snapshot.
    setNextOffset(null);
    setHasMore(false);
    setHistoryLimitReached(false);
    loadedServerPagesRef.current = 0;
    loadedCiphertextRowsRef.current = 0;
    historyLimitRef.current = false;
    if (afterRevisionConflict) {
      // Never retain a mixture of the old and new snapshot while the restart
      // is in flight. The person sees an explicit status below rather than a
      // plausible-looking but incomplete journal.
      setEntries([]);
      setUnreadable(0);
      setShown(PAGE_SIZE);
      setQuery("");
      setDayFilter(null);
      setLogMoods({});
    }
    try {
      const userId = await api.getUserId();
      if (loadEpoch !== historyLoadEpochRef.current) return;
      if (!userId) throw new Error(tr("common.accountMissing"));
      const page = await api.listEntriesPage({
        limit: SERVER_PAGE_SIZE,
        offset: 0,
        pageBytes: ENTRY_PAGE_BYTES,
      });
      if (loadEpoch !== historyLoadEpochRef.current) return;
      const rows = page.entries;
      // Tampered, wrong-key and rolled-back blobs are skipped (never
      // rendered raw) and counted so the user knows the list is short by
      // exactly that many.
      const { decrypted, failed } = await decryptRowsWithVersions(userId, vault.get().dataKey, rows);
      // WEB_PLAN S-8 (2026-09-25): EVERY row failing to decrypt with a live
      // session is the remote-rekey signature — the data key changed on
      // another device. Surface the actionable funnel instead of an empty
      // journal that looks like data loss.
      if (rows.length > 0 && failed === rows.length) {
        showStatus(tr("history.rekeyedElsewhere"), "neutral");
      }
      // Newest day first; same-day entries order by server arrival.
      decrypted.sort((a, b) => b.entryDate.localeCompare(a.entryDate) || b.receivedAt.localeCompare(a.receivedAt));
      setEntries(decrypted);
      setUnreadable(failed);
      setShown(PAGE_SIZE);
      setNextOffset(page.nextOffset);
      setHasMore(page.nextOffset !== null);
      entriesRevisionRef.current = page.revision ?? null;
      loadedServerPagesRef.current = 1;
      loadedCiphertextRowsRef.current = rows.length;
      historyLimitRef.current = page.nextOffset !== null && rows.length >= MAX_HISTORY_ROWS;
      setHistoryLimitReached(historyLimitRef.current);
      setQuery("");
      setDayFilter(null);
      // Badge fallback: entries saved before the check-in existed carry no
      // payload mood, but the device-local log usually has the day's value.
      try {
        const days = await recentMoods(vault.get().dataKey, userId, 400);
        if (loadEpoch !== historyLoadEpochRef.current) return;
        const map: Record<string, number> = {};
        for (const day of days) map[day.date] = day.value;
        setLogMoods(map);
      } catch {
        if (loadEpoch === historyLoadEpochRef.current) setLogMoods({});
      }
    } catch (err) {
      if (loadEpoch !== historyLoadEpochRef.current) return;
      entriesRevisionRef.current = null;
      if (err instanceof ApiError && err.status === 0) {
        // No connection: an honest explanation beats a fake-empty list.
        setOffline(true);
        setEntries([]);
        setHasMore(false);
        loadedServerPagesRef.current = 0;
        loadedCiphertextRowsRef.current = 0;
        historyLimitRef.current = false;
        setHistoryLimitReached(false);
      } else if (err instanceof ApiError && err.status === 409) {
        setError(tr("history.revisionConflict"));
      } else {
        setError(requestFailureCopy(err));
      }
    } finally {
      if (loadEpoch === historyLoadEpochRef.current) {
        historyReloadingRef.current = false;
        setLoading(false);
      }
    }
    }, // Stryker disable next-line ArrayDeclaration: the literal dep never changes between renders and the callback closes over no render-scope values, so identity and behavior are identical
     []);

  useEffect(() => {
    void load();
    // Returning from another screen (e.g. after writing) reloads — but the
    // focus event also fires on first mount, so skip exactly that one.
    let firstFocus = true;
    const focusSub = typeof navigation?.addListener === "function"
      ? (navigation.addListener("focus", () => {
          if (firstFocus) {
            firstFocus = false;
            return;
          }
          void load();
        }) as (() => void) | undefined)
      : undefined;
    return () => {
      focusSub?.();
      // Stryker disable next-line ConditionalExpression,CallExpression: on an unmounted component the later setStatus(null) is a silent no-op in React 18 and clearTimeout(null) is a no-op, so skipping this cleanup has no observable effect
      if (statusTimer.current) clearTimeout(statusTimer.current);
    };
    }, // Stryker disable next-line ArrayDeclaration: load is stable (useCallback over constant deps) and the navigation object identity is stable for the screen's lifetime, so the effect body runs exactly once either way
     [load, navigation]);

  // Android hardware back (2026-09-17): in detail/edit mode it must return
  // to the list, not pop the screen — the custom Mode state machine sits
  // below the navigator, which never learned about it. The handler lives
  // only while THIS screen is focused: native-stack keeps History mounted
  // beneath pushed screens, so a mode-only listener would swallow the back
  // press on whatever screen is on top.
  const backSub = useRef<{ remove: () => void } | null>(null);
  useEffect(() => {
    if (mode.kind === "list") return;
    const onBack = () => {
      setMode({ kind: "list" });
      return true;
    };
    const addBack = () => {
      backSub.current?.remove();
      backSub.current = BackHandler.addEventListener("hardwareBackPress", onBack);
    };
    const removeBack = () => {
      backSub.current?.remove();
      backSub.current = null;
    };
    addBack(); // the mode left "list" while this screen was focused
    const subs: Array<() => void> = [];
    if (typeof navigation?.addListener === "function") {
      subs.push(
        navigation.addListener("focus", addBack) as () => void,
        navigation.addListener("blur", removeBack) as () => void,
      );
    }
    return () => {
      for (const off of subs) off();
      removeBack();
    };
  }, [mode.kind, navigation]);

  /** Fetch another bounded page only when the person explicitly asks. Search
   * and calendar labels below make clear that they cover downloaded history,
   * rather than silently decrypting a whole account in the background. */
  const loadOlder = async () => {
    if (historyReloadingRef.current || loadingMoreRef.current || !hasMore || nextOffset === null) return;
    const remainingRows = MAX_HISTORY_ROWS - loadedCiphertextRowsRef.current;
    if (
      historyLimitRef.current ||
      loadedServerPagesRef.current >= MAX_HISTORY_SERVER_PAGES ||
      remainingRows <= 0
    ) {
      historyLimitRef.current = true;
      setHistoryLimitReached(true);
      return;
    }
    loadingMoreRef.current = true;
    setLoadingMore(true);
    const loadEpoch = historyLoadEpochRef.current;
    const expectedRevision = entriesRevisionRef.current;
    try {
      const userId = await api.getUserId();
      if (loadEpoch !== historyLoadEpochRef.current) return;
      if (!userId) throw new Error(tr("common.accountMissing"));
      const offset = nextOffset;
      const page = await api.listEntriesPage({
        limit: Math.min(SERVER_PAGE_SIZE, remainingRows),
        offset,
        pageBytes: ENTRY_PAGE_BYTES,
        ...(expectedRevision === null ? {} : { expectedRevision }),
      });
      if (loadEpoch !== historyLoadEpochRef.current) return;
      const receivedRevision = page.revision ?? null;
      // A PINNED continuation must land on the exact snapshot it pinned:
      // anything else means the journal moved under the walk, and the only
      // safe rendering is a restart from page one (offsets are meaningless
      // against a different snapshot).
      // An UNPINNED continuation (legacy headerless server, or the token
      // this screen itself dropped after an edit/delete — L-67) ADOPTS the
      // revision this page reports instead of restarting: that is how the
      // initial load obtains its token, and it preserves the user's
      // search/day filters across their own edits instead of 409-wiping
      // them. The append trades a page possibly drawn from a moved
      // snapshot (deduped by clientEntryId below) — the same trade the
      // legacy fallback always made.
      if (expectedRevision !== null && receivedRevision !== expectedRevision) {
        // The page client normally catches this first. Retain a UI-level
        // guard so a future alternate client/mock cannot append a page from a
        // different snapshot (including a mixed legacy/modern deployment).
        showStatus(tr("history.snapshotReload"), "neutral");
        void load(true);
        return;
      }
      const rows = page.entries;
      const { decrypted: incoming, failed } = await decryptRowsWithVersions(
        userId,
        vault.get().dataKey,
        rows,
      );
      setEntries((previous) => {
        const byId = new Map(previous.map((entry) => [entry.clientEntryId, entry]));
        for (const entry of incoming) byId.set(entry.clientEntryId, entry);
        return [...byId.values()].sort((a, b) => b.entryDate.localeCompare(a.entryDate) || b.receivedAt.localeCompare(a.receivedAt));
      });
      setUnreadable((previous) => previous + failed);
      setNextOffset(page.nextOffset);
      setHasMore(page.nextOffset !== null);
      entriesRevisionRef.current = receivedRevision;
      const nextPageCount = loadedServerPagesRef.current + 1;
      const nextRowCount = loadedCiphertextRowsRef.current + rows.length;
      loadedServerPagesRef.current = nextPageCount;
      loadedCiphertextRowsRef.current = nextRowCount;
      historyLimitRef.current =
        page.nextOffset !== null &&
        (nextPageCount >= MAX_HISTORY_SERVER_PAGES || nextRowCount >= MAX_HISTORY_ROWS);
      setHistoryLimitReached(historyLimitRef.current);
      // Reveal the just loaded rows, rather than making a second tap feel
      // like nothing happened.
      setShown((previous) => previous + SERVER_PAGE_SIZE);
    } catch (err) {
      if (loadEpoch !== historyLoadEpochRef.current) return;
      if (err instanceof ApiError && err.status === 409) {
        showStatus(tr("history.snapshotReload"), "neutral");
        void load(true);
      } else {
        Alert.alert(tr("history.loadOlderFailedTitle"), requestFailureCopy(err));
      }
    } finally {
      loadingMoreRef.current = false;
      setLoadingMore(false);
    }
  };

  /** Badge value: the entry's own check-in pick first, the mood log's day
   *  value as fallback; undefined = no badge (never a verdict). */
  const badgeValue = (entry: HistoryEntry): number | undefined =>
    entry.sentiment ?? logMoods[entry.entryDate];

  /** The local revision token is dead the moment THIS device edits or
   *  deletes an entry: the server mints a fresh one, so the next "Load
   *  older" pinned to the stale token would 409-restart from page one and
   *  wipe the user's search/day filters (audit L-67). Dropping it here
   *  sends the next continuation UNPINNED, which re-acquires the current
   *  snapshot token from that page's response instead of restarting. */
  const invalidateEntriesRevision = () => {
    entriesRevisionRef.current = null;
  };

  /** After a delete, the device-local mood log must not keep counting the
   *  erased day (audit L-68): the local streak/trend and the calendar's
   *  badge fallback all read that value. Fire-and-forget — a failed
   *  hygiene write must never fail the (already committed) server action.
   *  removeMoodDay snapshots the key at ITS call time, and vault.get()
   *  throws when a lock landed mid-delete — both degrade quietly here. */
  const forgetLocalMoodDay = (entry: HistoryEntry) => {
    void (async () => {
      try {
        const userId = await api.getUserId();
        if (!userId || !vault.isUnlocked()) return;
        await removeMoodDay(vault.get().dataKey, userId, entry.entryDate);
      } catch {
        // Locked vault or dead storage: disposable metadata, not an error.
      }
    })();
    // The badge/calendar state drops the day immediately, whatever the
    // disk write does.
    setLogMoods((prev) => {
      if (!(entry.entryDate in prev)) return prev;
      const next = { ...prev };
      delete next[entry.entryDate];
      return next;
    });
  };

  const runDelete = async (entry: HistoryEntry) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await api.deleteEntry(entry.clientEntryId);
      // M-2: the row is gone; forget its version mark so a later recreate
      // of the same id (legitimately version 1 again) does not false-alarm.
      await forgetEntryVersion(
        (await api.getUserId()) ?? "",
        vault.get().dataKey,
        entry.clientEntryId,
      ).catch(() => {});
      // L-67: this device just moved the collection revision; the walk's
      // token must be re-acquired or the next "Load older" 409-restarts
      // and wipes the filters.
      invalidateEntriesRevision();
      // L-68: the local mood log stops counting the deleted day.
      forgetLocalMoodDay(entry);
      setEntries((prev) => prev.filter((e) => e.clientEntryId !== entry.clientEntryId));
      // Stryker disable next-line ObjectLiteral,StringLiteral: nothing compares mode.kind to "list" — the mutated state fails the edit/detail checks and falls through to the identical list return
      setMode({ kind: "list" });
      // Stryker disable next-line StringLiteral: InlineStatus only branches on tone === "ok"; tone "" colors exactly like "neutral"
      showStatus(tr("history.entryDeleted"), "neutral");
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Already gone server-side: the end state the user asked for.
        invalidateEntriesRevision(); // the server state moved all the same
        forgetLocalMoodDay(entry);
        setEntries((prev) => prev.filter((e) => e.clientEntryId !== entry.clientEntryId));
        // Stryker disable next-line ObjectLiteral,StringLiteral: nothing compares mode.kind to "list" — the mutated state falls through to the identical list return
        setMode({ kind: "list" });
        // Stryker disable next-line StringLiteral: InlineStatus only branches on tone === "ok"; tone "" colors exactly like "neutral"
        showStatus(tr("history.entryDeleted"), "neutral");
      } else if (err instanceof ApiError && err.status === 0) {
        Alert.alert(tr("history.needsConnectionTitle"), tr("history.deleteOfflineBody"));
      } else {
        Alert.alert(tr("history.couldNotDeleteTitle"), requestFailureCopy(err));
      }
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  /** Calm double confirmation: scope first ("every device"), permanence
   *  second. Neither dialog rushes or shames. */
  const confirmDelete = (entry: HistoryEntry) => {
    Alert.alert(tr("history.deleteConfirmTitle"), tr("history.deleteConfirmBody"), [
      { text: tr("common.cancel"), style: "cancel" },
      {
        text: tr("common.delete"),
        style: "destructive",
        onPress: () =>
          Alert.alert(tr("common.finalConfirmation"), tr("history.finalConfirmBody"), [
            { text: tr("common.cancel"), style: "cancel" },
            {
              text: tr("common.deletePermanently"),
              style: "destructive",
              onPress: () => void runDelete(entry),
            },
          ]),
      },
    ]);
  };

  const startEdit = (entry: HistoryEntry) => {
    setDraft(entry.text);
    setMode({ kind: "edit", entry });
  };

  const saveEdit = async (entry: HistoryEntry) => {
    const trimmed = draft.trim();
    if (!trimmed || busyRef.current) return;
    if (trimmed.length > MAX_ENTRY_CHARS) {
      Alert.alert(
        tr("history.tooLongTitle"),
        tr("history.tooLongBody", { max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()) }),
      );
      return;
    }
    // Nothing actually changed: back to the entry, no server round-trip.
    if (trimmed === entry.text.trim()) {
      setMode({ kind: "detail", entry });
      return;
    }
    busyRef.current = true;
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert(tr("common.sessionDamagedTitle"), tr("history.sessionDamagedBody"));
        return;
      }
      // The same id is deliberately retained: it is part of the ciphertext
      // AAD, and the backend replaces this one record atomically. The v2
      // structured channels (energy/sleep/tags) ride along unchanged — an
      // edit fixes WORDS, it must not silently erase the day's check-ins
      // (the pre-2026-09-19 bug this line closes).
      // M-2 (2026-09-20): the replacement is encrypted under the NEXT
      // content generation's version-bound AAD. Another device's concurrent
      // edit answers 409 version_conflict; one refetch-and-retry recovers
      // the race, a second conflict is surfaced honestly.
      const encryptFor = (version: number): string =>
        encryptEntry(
          vault.get(),
          userId,
          entry.clientEntryId,
          trimmed,
          entry.entryDate,
          entry.sentiment,
          { energy: entry.energy, sleep: entry.sleep, tags: entry.tags },
          version,
        ).blobB64;
      let nextVersion = (entry.contentVersion ?? 0) + 1;
      // The first encryption stays OUTSIDE the network try: a local vault
      // failure keeps its own honest message (the pre-M-2 contract).
      let blobB64 = encryptFor(nextVersion);
      const applyEdit = async (): Promise<void> => {
        await api.updateEntry(entry.clientEntryId, blobB64, entry.entryDate, nextVersion);
      };
      try {
        try {
          await applyEdit();
        } catch (err) {
          if (err instanceof ApiError && err.code === "version_conflict") {
            // WEB_PLAN S-3 (two-writer honesty, 2026-09-25): before
            // retrying over the other device's edit, DECRYPT their saved
            // text and — when it differs — show both versions and let the
            // user choose. Overwriting silently is data loss wearing a
            // success message.
            const current = await api.getEntry(entry.clientEntryId);
            const serverVersion = typeof current.content_version === "number" ? current.content_version : 0;
            let theirText: string | null = null;
            try {
              theirText = decryptEntry(
                vault.get(),
                userId,
                current.client_entry_id,
                current.blob,
                typeof current.content_version === "number" ? current.content_version : undefined,
              ).text;
            } catch {
              theirText = null; // undecryptable: cannot compare — fall through to the retry
            }
            const retry = (): void => {
              nextVersion = serverVersion + 1;
              blobB64 = encryptFor(nextVersion);
              void applyEdit()
                .then(() => {
                  entry.contentVersion = nextVersion;
                  void observeEntryVersions(userId, vault.get().dataKey, [
                    { clientEntryId: entry.clientEntryId, contentVersion: nextVersion },
                  ]).catch(() => {});
                  showStatus(tr("history.savedStatus"), "ok");
                })
                .catch((retryErr: unknown) => {
                  Alert.alert(
                    tr("history.couldNotUpdateTitle"),
                    tr("history.updateFailedBody", { reason: requestFailureCopy(retryErr) }),
                  );
                });
            };
            if (theirText !== null && theirText !== trimmed) {
              Alert.alert(
                tr("history.conflictTitle"),
                tr("history.conflictBody", { theirs: theirText, yours: trimmed }),
                [
                  { text: tr("history.conflictKeepTheirs"), style: "cancel", onPress: (): void => undefined },
                  { text: tr("history.conflictOverwrite"), style: "destructive", onPress: retry },
                ],
                { cancelable: true },
              );
              return; // the user decides; nothing was overwritten
            }
            retry();
          } else if (err instanceof ApiError && err.status === 404) {
            // WEB_PLAN S-4: deleted on another device — the edit is not
            // saved and the user learns why.
            Alert.alert(tr("history.deletedElsewhereTitle"), tr("history.deletedElsewhereBody"));
            return;
          } else {
            throw err;
          }
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) {
          Alert.alert(tr("history.needsConnectionTitle"), tr("history.updateOfflineBody"));
        } else {
          Alert.alert(
            tr("history.couldNotUpdateTitle"),
            tr("history.updateFailedBody", { reason: requestFailureCopy(err) }),
          );
        }
        return;
      }
      entry.contentVersion = nextVersion;
      await observeEntryVersions(userId, vault.get().dataKey, [
        { clientEntryId: entry.clientEntryId, contentVersion: nextVersion },
      ]).catch(() => {});
      // L-67: the replacement moved the collection revision on the server;
      // drop the walk's token so the next "Load older" re-acquires it
      // instead of 409-restarting (which would wipe the filters).
      invalidateEntriesRevision();
      // Keep the device-local mood log in step with the day's newest text.
      void recordMood(vault.get().dataKey, userId, entry.entryDate, entry.sentiment ?? localSentiment(trimmed)).catch(
        () => {},
      );
      const updated: HistoryEntry = { ...entry, text: trimmed };
      setEntries((prev) => prev.map((e) => (e.clientEntryId === entry.clientEntryId ? updated : e)));
      setMode({ kind: "detail", entry: updated });
      showStatus(tr("history.updated"), "ok");
      // H-6 (2026-09-20 audit): the EDIT path runs the same on-device crisis
      // detection as a new entry. The server only ever sees ciphertext, so
      // this detector is the only net for a user who edits yesterday's
      // entry into crisis language — the same text as a NEW entry gets the
      // dialog, an edited one must too. Never before or instead of saving:
      // the replacement is already committed server-side at this point.
      // Same per-day throttle stamp and calm copy as EntryScreen.
      if (detectCrisisLanguage(trimmed)) {
        const today = localDateISO();
        const flagged = await crisisDialogShownOn(userId, today).catch(() => false);
        if (!flagged) {
          await recordCrisisDialogShown(userId, today).catch(() => {});
          Alert.alert(tr("entry.crisisAlertTitle"), tr("entry.crisisAlertBody"), [
            { text: tr("entry.crisisViewResources"), onPress: () => navigation.navigate("Crisis") },
            { text: tr("common.notNow"), style: "cancel" },
          ]);
        }
      }
    } catch (err) {
      Alert.alert(tr("history.couldNotUpdateTitle"), requestFailureCopy(err));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  const badge = (entry: HistoryEntry): React.JSX.Element | null => {
    const value = badgeValue(entry);
    if (value === undefined) return null;
    const label = moodLabel(value);
    return (
      <View
        style={[styles.badge, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md }]}
        accessibilityRole="text"
        accessibilityLabel={tr("history.moodBadgeA11y", { label })}
      >
        <Text style={{ color: t.colors.accent, fontSize: t.type.meta.fontSize }}>{label}</Text>
      </View>
    );
  };

  if (mode.kind === "edit") {
    const { entry } = mode;
    return (
      <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <ScrollView
          style={[styles.flex, { backgroundColor: t.colors.bg }]}
          contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
          keyboardDismissMode="on-drag"
          keyboardShouldPersistTaps="handled"
        >
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {formatEntryDate(entry.entryDate)}
          </Text>
          <TextInput
            style={[
              styles.input,
              {
                backgroundColor: t.colors.card,
                color: t.colors.text,
                borderRadius: t.radius.lg,
                padding: t.spacing.lg,
                fontSize: t.type.bodyLarge.fontSize,
              },
            ]}
            multiline
            value={draft}
            editable={!busy}
            onChangeText={(next) => {
              touchActivity();
              setDraft(next);
            }}
            accessibilityLabel={tr("history.editA11y")}
            // Privacy: keep journal text out of keyboard suggestion caches.
            autoCorrect={false}
            spellCheck={false}
            autoCapitalize="sentences"
            textContentType="none"
          />
          {draft.length > SHOW_COUNT_ABOVE && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "right" }}>
              {tr("history.charCount", {
                current: draft.length.toLocaleString(dateLocaleTag()),
                max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()),
              })}
            </Text>
          )}
          <PrimaryButton
            label={tr("history.saveChanges")}
            onPress={() => void saveEdit(entry)}
            disabled={!draft.trim()}
            busy={busy}
          />
          <GhostButton label={tr("common.cancel")} onPress={() => setMode({ kind: "detail", entry })} disabled={busy} />
          <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
        </ScrollView>
      </KeyboardAvoidingView>
    );
  }

  if (mode.kind === "detail") {
    const { entry } = mode;
    return (
      <ScrollView
        style={[styles.flex, { backgroundColor: t.colors.bg }]}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
        onTouchStart={touchActivity}
      >
        <View style={styles.detailHeader}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {formatEntryDate(entry.entryDate)}
          </Text>
          {badge(entry)}
        </View>
        <Text style={{ color: t.colors.text, fontSize: t.type.bodyLarge.fontSize, lineHeight: 24 }}>{entry.text}</Text>
        <PrimaryButton label={tr("history.editThisEntry")} onPress={() => startEdit(entry)} disabled={busy} />
        <PrimaryButton label={tr("history.deleteThisEntry")} onPress={() => confirmDelete(entry)} busy={busy} danger />
        <GhostButton
          // Stryker disable next-line ObjectLiteral, StringLiteral: nothing compares mode.kind to "list" — the mutated state falls through to the identical list return
          onPress={() => setMode({ kind: "list" })}
          label={tr("history.backToHistory")}
          disabled={busy}
        />
        <InlineStatus message={status} tone={statusTone} />
        <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    );
  }

  // The list the user sees: search + tapped-day filters applied to the
  // decrypted list, in display order. It is intentionally bounded by the
  // pages the person chose to load; plaintext history is not bulk-loaded.
  const visibleEntries = filterEntries(
    dayFilter !== null ? entries.filter((e) => e.entryDate === dayFilter) : entries,
    query,
  );
  const journaledDays = new Set(entries.map((e) => e.entryDate).filter((d) => d !== ""));
  return (
    // E-9 (2026-09-21): the list is a WINDOWED FlatList, not a plain
    // ScrollView — up to 500 decrypted rows used to stay mounted (and
    // rendered) forever. The FlatList keeps the header (search + calendar)
    // and footer (older-entries affordances) as list chrome and unmounts
    // far-offscreen rows, so the decrypted plaintext held in the VIEW tree
    // is bounded by the window, not the history length. (The decrypted
    // strings themselves remain in screen state until the screen closes —
    // decrypt-on-demand per row is the Phase 3 on-device-brain follow-up.)
    <FlatList
      style={[styles.flex, { backgroundColor: t.colors.bg }]}
      contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.md, flexGrow: 1 }}
      data={visibleEntries.slice(0, shown)}
      keyExtractor={(entry) => entry.clientEntryId}
      renderItem={({ item: entry }) => (
        <TouchableOpacity
          style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, minHeight: t.minTouch }]}
          onPress={() => setMode({ kind: "detail", entry })}
          accessibilityRole="button"
          accessibilityLabel={tr("history.entryA11y", { date: formatEntryDate(entry.entryDate) })}
        >
          <View style={styles.rowHeader}>
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>{entry.entryDate}</Text>
            {badge(entry)}
          </View>
          <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 21 }}>
            {snippetOf(entry.text)}
          </Text>
        </TouchableOpacity>
      )}
      ListHeaderComponent={
        <>
          {loading && entries.length === 0 && !offline && !error && (
            <ActivityIndicator color={t.colors.primaryBright} size="large" />
          )}
          {error && (
            <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
              <Text style={{ color: t.colors.error, fontSize: t.type.bodySmall.fontSize }} accessibilityRole="alert">
                {error}
              </Text>
              <GhostButton
                label={tr("common.tryAgain")}
                onPress={() => void load()}
                accessibilityLabel={tr("history.tryAgainA11y")}
              />
            </View>
          )}
          {!loading && offline && (
            <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
              <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 22 }}>
                {tr("history.offlineBody")}
              </Text>
              <GhostButton
                label={tr("common.tryAgain")}
                onPress={() => void load()}
                accessibilityLabel={tr("history.tryAgainA11y")}
              />
            </View>
          )}
          {!loading && !offline && !error && entries.length === 0 && (
            <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
              <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 22 }}>
                {tr("history.emptyBody")}
              </Text>
            </View>
          )}
          {!loading && !offline && !error && entries.length > 0 && (
            <>
              {/* Search: filters the decrypted on-device list; never sent anywhere. */}
              <TextInput
                style={{
                  backgroundColor: t.colors.card,
                  color: t.colors.text,
                  borderRadius: t.radius.md,
                  padding: 12,
                  fontSize: t.type.body.fontSize,
                }}
                placeholder={tr("history.searchPlaceholder")}
                placeholderTextColor={t.colors.placeholder}
                value={query}
                onChangeText={(next) => {
                  touchActivity();
                  setQuery(next);
                  setShown(PAGE_SIZE);
                }}
                accessibilityLabel={tr("history.searchPlaceholder")}
                autoCorrect={false}
                spellCheck={false}
                autoCapitalize="none"
                textContentType="none"
              />
              <MoodCalendar
                dayMoods={logMoods}
                journaledDays={journaledDays}
                selectedDay={dayFilter}
                onSelectDay={(iso) => {
                  touchActivity();
                  setDayFilter(iso);
                  setShown(PAGE_SIZE);
                }}
              />
              {(query.trim() !== "" || dayFilter !== null) && (
                <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
                  {visibleEntries.length === 1
                    ? tr("history.matchOne", { count: visibleEntries.length })
                    : tr("history.matchMany", { count: visibleEntries.length })}
                  {dayFilter !== null ? tr("history.filterDay", { date: dayFilter }) : ""}
                  {query.trim() !== "" ? tr("history.filterSearch") : ""}
                  {hasMore ? tr("history.filterLoaded") : ""}
                </Text>
              )}
            </>
          )}
        </>
      }
      ListFooterComponent={
        <>
          {visibleEntries.length > shown && (
            <GhostButton
              label={tr("history.showOlder", { count: visibleEntries.length - shown })}
              onPress={() => {
                touchActivity();
                setShown(shown + PAGE_SIZE);
              }}
            />
          )}
          {visibleEntries.length <= shown && hasMore && !historyLimitReached && query.trim() === "" && dayFilter === null && (
            <GhostButton
              label={loadingMore ? tr("history.loadingOlder") : tr("history.loadOlder")}
              onPress={() => void loadOlder()}
              disabled={loadingMore}
              accessibilityLabel={tr("history.loadOlderA11y")}
            />
          )}
          {historyLimitReached && hasMore && (
            <Text accessibilityRole="alert" style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "center" }}>
              {tr("history.limitReached", { rows: MAX_HISTORY_ROWS, pages: MAX_HISTORY_SERVER_PAGES })}
            </Text>
          )}
          {!loading && !offline && !error && entries.length > 0 && visibleEntries.length === 0 && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize, textAlign: "center" }}>
              {query.trim() !== "" ? tr("history.noMatchSearch") : tr("history.noMatchDay")}
            </Text>
          )}
          {unreadable > 0 && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "center" }}>
              {unreadable === 1
                ? tr("history.unreadableOne", { count: unreadable })
                : tr("history.unreadableMany", { count: unreadable })}
            </Text>
          )}
          <InlineStatus message={status} tone={statusTone} />
          <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
        </>
      }
      onTouchStart={touchActivity}
      refreshControl={
        <RefreshControl
          refreshing={loading}
          onRefresh={() => void load()}
          tintColor={t.colors.primaryBright}
          colors={[t.colors.primaryBright]}
        />
      }
      initialNumToRender={PAGE_SIZE}
      windowSize={7}
    />
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  card: { padding: 16, gap: 10 },
  rowHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", gap: 10 },
  detailHeader: { flexDirection: "row", alignItems: "center", gap: 10 },
  badge: { paddingVertical: 4, paddingHorizontal: 10 },
  input: { minHeight: 140, textAlignVertical: "top" },
});
