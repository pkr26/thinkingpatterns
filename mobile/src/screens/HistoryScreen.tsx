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
 * Entries are immutable server-side (a re-upload 409s), so EDITING means
 * replacing: the old entry is deleted and the updated text goes up under a
 * fresh id — same date, the day's chosen mood preserved. The delete runs
 * FIRST so a failed replacement can never leave two copies; if the create
 * then fails, the text stays in the editor and a retry skips the
 * already-done delete (404 = the goal state).
 */
import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
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
import { api, ApiError } from "../api/client";
import { decryptEntry, encryptEntry } from "../crypto/MindPatternCrypto";
import { vault } from "../vault";
import { useSession } from "../store";
import { recordMood, recentMoods } from "../moodLog";
import { newClientEntryId } from "../entryId";
import { localSentiment, moodLabel } from "../mood";
import { useTheme } from "../theme";
import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { requestFailureCopy } from "../components/errors";

/** History reveals in calm batches instead of one endless scroll. */
const PAGE_SIZE = 50;
const SNIPPET_CHARS = 140;
/** Same payload cap as the Entry screen. */
const MAX_ENTRY_CHARS = 100_000;
const SHOW_COUNT_ABOVE = 90_000;
const STATUS_MS = 2_600;

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
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.max(-1, Math.min(1, value));
}

export function HistoryScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unreadable, setUnreadable] = useState(0);
  const [shown, setShown] = useState(PAGE_SIZE);
  const [logMoods, setLogMoods] = useState<Record<string, number>>({});
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("neutral");
  const [draft, setDraft] = useState("");
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Double-tap guard: two presses inside one frame both pass a state-only
  // check (the Entry screen's savingRef pattern) — the ref is synchronous.
  const busyRef = useRef(false);

  /** Transient confirmation ("Entry deleted"); replaces itself cleanly. */
  const showStatus = (message: string, tone: InlineStatusTone) => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
    setStatusTone(tone);
    setStatus(message);
    statusTimer.current = setTimeout(() => setStatus(null), STATUS_MS);
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setOffline(false);
    try {
      const userId = await api.getUserId();
      if (!userId) throw new Error("account id missing — sign in again");
      const rows = await api.listEntries();
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
      // Badge fallback: entries saved before the check-in existed carry no
      // payload mood, but the device-local log usually has the day's value.
      try {
        const days = await recentMoods(vault.get().dataKey, userId, 400);
        const map: Record<string, number> = {};
        for (const day of days) map[day.date] = day.value;
        setLogMoods(map);
      } catch {
        setLogMoods({});
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        // No connection: an honest explanation beats a fake-empty list.
        setOffline(true);
        setEntries([]);
      } else {
        setError(requestFailureCopy(err));
      }
    } finally {
      setLoading(false);
    }
  }, []);

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
      if (statusTimer.current) clearTimeout(statusTimer.current);
    };
  }, [load, navigation]);

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
      setMode({ kind: "list" });
      showStatus("Entry deleted", "neutral");
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Already gone server-side: the end state the user asked for.
        setEntries((prev) => prev.filter((e) => e.clientEntryId !== entry.clientEntryId));
        setMode({ kind: "list" });
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
      // Replace step 1: the old entry goes. 404 means a previous attempt
      // already did this — the goal state — so the save simply proceeds.
      try {
        await api.deleteEntry(entry.clientEntryId);
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          // already removed — continue to the create
        } else if (err instanceof ApiError && err.status === 0) {
          Alert.alert(
            "Needs a connection",
            "Updating replaces the entry on the server, so it can't run offline. Connect and try again — nothing was changed.",
          );
          return;
        } else {
          Alert.alert("Could not update", requestFailureCopy(err));
          return;
        }
      }
      // Replace step 2: the update goes up as a NEW entry under a fresh id
      // (entries are immutable server-side) — same date, same chosen mood.
      const newId = newClientEntryId(entry.entryDate);
      const { blobB64 } = encryptEntry(vault.get(), userId, newId, trimmed, entry.entryDate, entry.sentiment);
      try {
        await api.createEntry(newId, blobB64, entry.entryDate);
      } catch (err) {
        // The old version is gone and the new one is not saved — say exactly
        // that, and keep the text in the editor so a retry finishes the job.
        Alert.alert(
          "Old version removed — update not saved",
          `${requestFailureCopy(err)} Your text is still on this screen; try again to finish.`,
        );
        return;
      }
      // Keep the device-local mood log in step with the day's newest text.
      void recordMood(vault.get().dataKey, userId, entry.entryDate, entry.sentiment ?? localSentiment(trimmed)).catch(
        () => {},
      );
      const updated: HistoryEntry = { ...entry, clientEntryId: newId, text: trimmed };
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
        <GhostButton label="Back to history" onPress={() => setMode({ kind: "list" })} disabled={busy} />
        <InlineStatus message={status} tone={statusTone} />
        <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    );
  }

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
      {entries.slice(0, shown).map((entry) => (
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
      {entries.length > shown && (
        <GhostButton
          label={`Show older entries (${entries.length - shown} more)`}
          onPress={() => {
            touchActivity();
            setShown(shown + PAGE_SIZE);
          }}
        />
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
