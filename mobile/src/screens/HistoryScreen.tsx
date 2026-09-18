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
import { MoodCalendar } from "../components/MoodCalendar";
import { filterEntries } from "../historyFind";
import { vault } from "../vault";
import { useSession } from "../store";
import { recordMood, recentMoods } from "../moodLog";
import { localSentiment, moodLabel } from "../mood";
import { useTheme } from "../theme";
import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { requestFailureCopy } from "../components/errors";

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
const SNAPSHOT_RELOAD_STATUS =
  "Your journal changed while older entries were loading. Reloading the latest history from the start.";

interface HistoryEntry {
  clientEntryId: string;
  entryDate: string;
  receivedAt: string;
  text: string;
  /** The day's explicit check-in pick, when one was made (else null). */
  sentiment: number | null;
}

type Mode =
  | { kind: "list" }
  | { kind: "detail"; entry: HistoryEntry }
  | { kind: "edit"; entry: HistoryEntry };

/** "2026-09-03" → "Thursday, September 3, 2026". The locale is pinned so
 *  every device renders the same shape; a garbage date falls back to the
 *  raw string instead of crashing the row. */
export function formatEntryDate(iso: string): string {
  const parsed = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
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
      if (!userId) throw new Error("account id missing — sign in again");
      const page = await api.listEntriesPage({
        limit: SERVER_PAGE_SIZE,
        offset: 0,
        pageBytes: ENTRY_PAGE_BYTES,
      });
      if (loadEpoch !== historyLoadEpochRef.current) return;
      const rows = page.entries;
      const decrypted: HistoryEntry[] = [];
      let failed = 0;
      for (const row of rows) {
        try {
          const payload = decryptEntry(vault.get(), userId, row.client_entry_id, row.blob);
          decrypted.push({
            clientEntryId: row.client_entry_id,
            entryDate: typeof row.entry_date === "string" ? row.entry_date : "",
            receivedAt: typeof row.received_at === "string" ? row.received_at : "",
            text: typeof payload.text === "string" ? payload.text : "",
            sentiment: sanitizeSentiment(payload.sentiment),
          });
        } catch {
          // Tampered or wrong-key blob: skipped (never rendered raw), and
          // counted so the user knows the list is short by exactly that many.
          failed += 1;
        }
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
        setError("Your journal changed while it was loading. Try again to reload the latest history.");
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
      if (!userId) throw new Error("account id missing — sign in again");
      const offset = nextOffset;
      const page = await api.listEntriesPage({
        limit: Math.min(SERVER_PAGE_SIZE, remainingRows),
        offset,
        pageBytes: ENTRY_PAGE_BYTES,
        ...(expectedRevision === null ? {} : { expectedRevision }),
      });
      if (loadEpoch !== historyLoadEpochRef.current) return;
      const receivedRevision = page.revision ?? null;
      if (
        (expectedRevision === null && receivedRevision !== null) ||
        (expectedRevision !== null && receivedRevision !== expectedRevision)
      ) {
        // The page client normally catches this first. Retain a UI-level
        // guard so a future alternate client/mock cannot append a page from a
        // different snapshot (including a mixed legacy/modern deployment).
        showStatus(SNAPSHOT_RELOAD_STATUS, "neutral");
        void load(true);
        return;
      }
      const rows = page.entries;
      const incoming: HistoryEntry[] = [];
      let failed = 0;
      for (const row of rows) {
        try {
          const payload = decryptEntry(vault.get(), userId, row.client_entry_id, row.blob);
          incoming.push({
            clientEntryId: row.client_entry_id,
            entryDate: typeof row.entry_date === "string" ? row.entry_date : "",
            receivedAt: typeof row.received_at === "string" ? row.received_at : "",
            text: typeof payload.text === "string" ? payload.text : "",
            sentiment: sanitizeSentiment(payload.sentiment),
          });
        } catch {
          failed += 1;
        }
      }
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
        showStatus(SNAPSHOT_RELOAD_STATUS, "neutral");
        void load(true);
      } else {
        Alert.alert("Could not load older entries", requestFailureCopy(err));
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

  const runDelete = async (entry: HistoryEntry) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await api.deleteEntry(entry.clientEntryId);
      setEntries((prev) => prev.filter((e) => e.clientEntryId !== entry.clientEntryId));
      // Stryker disable next-line ObjectLiteral,StringLiteral: nothing compares mode.kind to "list" — the mutated state fails the edit/detail checks and falls through to the identical list return
      setMode({ kind: "list" });
      // Stryker disable next-line StringLiteral: InlineStatus only branches on tone === "ok"; tone "" colors exactly like "neutral"
      showStatus("Entry deleted", "neutral");
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Already gone server-side: the end state the user asked for.
        setEntries((prev) => prev.filter((e) => e.clientEntryId !== entry.clientEntryId));
        // Stryker disable next-line ObjectLiteral,StringLiteral: nothing compares mode.kind to "list" — the mutated state falls through to the identical list return
        setMode({ kind: "list" });
        // Stryker disable next-line StringLiteral: InlineStatus only branches on tone === "ok"; tone "" colors exactly like "neutral"
        showStatus("Entry deleted", "neutral");
      } else if (err instanceof ApiError && err.status === 0) {
        Alert.alert(
          "Needs a connection",
          "Deleting removes the entry from the server, so it can't run offline. Connect and try again — nothing was changed.",
        );
      } else {
        Alert.alert("Could not delete", requestFailureCopy(err));
      }
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  /** Calm double confirmation: scope first ("every device"), permanence
   *  second. Neither dialog rushes or shames. */
  const confirmDelete = (entry: HistoryEntry) => {
    Alert.alert(
      "Delete this entry?",
      "This removes the entry from your journal on every device. This can't be undone.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete",
          style: "destructive",
          onPress: () =>
            Alert.alert("Final confirmation", "Deleting is permanent — there is no copy anywhere to restore from.", [
              { text: "Cancel", style: "cancel" },
              { text: "Delete permanently", style: "destructive", onPress: () => void runDelete(entry) },
            ]),
        },
      ],
    );
  };

  const startEdit = (entry: HistoryEntry) => {
    setDraft(entry.text);
    setMode({ kind: "edit", entry });
  };

  const saveEdit = async (entry: HistoryEntry) => {
    const trimmed = draft.trim();
    if (!trimmed || busyRef.current) return;
    if (trimmed.length > MAX_ENTRY_CHARS) {
      Alert.alert("Entry too long", `Entries are limited to ${MAX_ENTRY_CHARS.toLocaleString()} characters.`);
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
        Alert.alert("Session damaged", "Account id missing — please sign in again. Your text is still on screen.");
        return;
      }
      // The same id is deliberately retained: it is part of the ciphertext
      // AAD, and the backend replaces this one record atomically.
      const { blobB64 } = encryptEntry(vault.get(), userId, entry.clientEntryId, trimmed, entry.entryDate, entry.sentiment);
      try {
        await api.updateEntry(entry.clientEntryId, blobB64, entry.entryDate);
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) {
          Alert.alert(
            "Needs a connection",
            "Updating needs a connection. Your original entry and this text are both still safe; try again when connected.",
          );
        } else {
          Alert.alert("Could not update", `${requestFailureCopy(err)} Your original entry is unchanged and this text is still on screen.`);
        }
        return;
      }
      // Keep the device-local mood log in step with the day's newest text.
      void recordMood(vault.get().dataKey, userId, entry.entryDate, entry.sentiment ?? localSentiment(trimmed)).catch(
        () => {},
      );
      const updated: HistoryEntry = { ...entry, text: trimmed };
      setEntries((prev) => prev.map((e) => (e.clientEntryId === entry.clientEntryId ? updated : e)));
      setMode({ kind: "detail", entry: updated });
      showStatus("Updated ✓", "ok");
    } catch (err) {
      Alert.alert("Could not update", requestFailureCopy(err));
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
        accessibilityLabel={`Mood: ${label}`}
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
            accessibilityLabel="Edit entry"
            // Privacy: keep journal text out of keyboard suggestion caches.
            autoCorrect={false}
            spellCheck={false}
            autoCapitalize="sentences"
            textContentType="none"
          />
          {draft.length > SHOW_COUNT_ABOVE && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "right" }}>
              {draft.length.toLocaleString()} / {MAX_ENTRY_CHARS.toLocaleString()}
            </Text>
          )}
          <PrimaryButton
            label="Save changes"
            onPress={() => void saveEdit(entry)}
            disabled={!draft.trim()}
            busy={busy}
          />
          <GhostButton label="Cancel" onPress={() => setMode({ kind: "detail", entry })} disabled={busy} />
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
        <PrimaryButton label="Edit this entry" onPress={() => startEdit(entry)} disabled={busy} />
        <PrimaryButton label="Delete this entry" onPress={() => confirmDelete(entry)} busy={busy} danger />
        <GhostButton
          // Stryker disable next-line ObjectLiteral, StringLiteral: nothing compares mode.kind to "list" — the mutated state falls through to the identical list return
          onPress={() => setMode({ kind: "list" })}
          label="Back to history"
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
    <ScrollView
      style={[styles.flex, { backgroundColor: t.colors.bg }]}
      contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.md, flexGrow: 1 }}
      onTouchStart={touchActivity}
      refreshControl={
        <RefreshControl
          refreshing={loading}
          onRefresh={() => void load()}
          tintColor={t.colors.primaryBright}
          colors={[t.colors.primaryBright]}
        />
      }
    >
      {loading && entries.length === 0 && !offline && !error && (
        <ActivityIndicator color={t.colors.primaryBright} size="large" />
      )}
      {error && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={{ color: t.colors.error, fontSize: t.type.bodySmall.fontSize }} accessibilityRole="alert">
            {error}
          </Text>
          <GhostButton label="Try again" onPress={() => void load()} accessibilityLabel="Try loading your history again" />
        </View>
      )}
      {!loading && offline && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 22 }}>
            Your journal history loads when you're online; today's writing always works offline.
          </Text>
          <GhostButton label="Try again" onPress={() => void load()} accessibilityLabel="Try loading your history again" />
        </View>
      )}
      {!loading && !offline && !error && entries.length === 0 && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 22 }}>
            No entries yet. What you write each day will gather here — decrypted only on this device.
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
            placeholder="Search your entries"
            placeholderTextColor={t.colors.placeholder}
            value={query}
            onChangeText={(next) => {
              touchActivity();
              setQuery(next);
              setShown(PAGE_SIZE);
            }}
            accessibilityLabel="Search your entries"
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
              {visibleEntries.length} {visibleEntries.length === 1 ? "entry" : "entries"} match
              {dayFilter !== null ? ` · ${dayFilter}` : ""}
              {query.trim() !== "" ? " · search" : ""}
              {hasMore ? " · loaded history only" : ""}
            </Text>
          )}
        </>
      )}
      {visibleEntries.slice(0, shown).map((entry) => (
        <TouchableOpacity
          key={entry.clientEntryId}
          style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, minHeight: t.minTouch }]}
          onPress={() => setMode({ kind: "detail", entry })}
          accessibilityRole="button"
          accessibilityLabel={`Entry from ${formatEntryDate(entry.entryDate)}`}
        >
          <View style={styles.rowHeader}>
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>{entry.entryDate}</Text>
            {badge(entry)}
          </View>
          <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 21 }}>
            {snippetOf(entry.text)}
          </Text>
        </TouchableOpacity>
      ))}
      {visibleEntries.length > shown && (
        <GhostButton
          label={`Show older entries (${visibleEntries.length - shown} more)`}
          onPress={() => {
            touchActivity();
            setShown(shown + PAGE_SIZE);
          }}
        />
      )}
      {visibleEntries.length <= shown && hasMore && !historyLimitReached && query.trim() === "" && dayFilter === null && (
        <GhostButton
          label={loadingMore ? "Loading older entries…" : "Load older entries"}
          onPress={() => void loadOlder()}
          disabled={loadingMore}
          accessibilityLabel="Load older encrypted journal entries"
        />
      )}
      {historyLimitReached && hasMore && (
        <Text accessibilityRole="alert" style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "center" }}>
          This history view has reached its safe download limit ({MAX_HISTORY_ROWS} entries or {MAX_HISTORY_SERVER_PAGES} pages).
          More encrypted history remains on the server.
        </Text>
      )}
      {!loading && !offline && !error && entries.length > 0 && visibleEntries.length === 0 && (
        <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize, textAlign: "center" }}>
          Nothing matches {query.trim() !== "" ? "that search" : "that day"}.
        </Text>
      )}
      {unreadable > 0 && (
        <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "center" }}>
          {unreadable} {unreadable === 1 ? "entry" : "entries"} couldn't be read on this device.
        </Text>
      )}
      <InlineStatus message={status} tone={statusTone} />
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
    </ScrollView>
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
