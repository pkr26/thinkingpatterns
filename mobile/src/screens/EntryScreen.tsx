/**
 * Daily entry: type (or paste speech-to-text output), encrypt on-device,
 * sync. Entries are encrypted before they leave the phone; the save flow
 * queues locally when offline and retries on next launch.
 */
import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { api, ApiError } from "../api/client";
import { encryptEntry } from "../crypto/MindPatternCrypto";
import { vault } from "../vault";
import { useSession } from "../store";
import { enqueue, flushQueue, QueueFullError } from "../offlineQueue";
import { localDateISO, recordMood } from "../moodLog";
import { detectCrisisLanguage } from "../crisisDetect";

/** Keeps the encrypted payload comfortably under the server's ~1 MiB cap. */
const MAX_ENTRY_CHARS = 100_000;

/** A 401 save locks the vault, and the lock swaps the whole screen stack —
 *  this screen unmounts and its state dies with it. The draft waits here
 *  (memory-only, account-bound) so re-unlocking restores it for another
 *  save attempt. A different account on the same device never sees it. */
let stashedDraft: { userId: string; text: string } | null = null;

export function EntryScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const { activeDays, unlockDays, touchActivity } = useSession();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const userId: Promise<string | null> = api.getUserId();
    userId.then((id) => {
      if (id) flushQueue(id).catch(() => {});
      // Restore the draft a 401-forced lock stashed before the unmount —
      // only for the same account it was written under.
      const stash = stashedDraft;
      stashedDraft = null;
      if (stash && id === stash.userId) setText(stash.text);
    });
    // NOTE (privacy hardening): this screen no longer triggers the daily
    // mini-brain recompute. That refresh SHIPS THE DATA KEY to the server
    // — after the red-team audit it is only ever sent as an explicit act
    // (the Question screen's button), never automatically after a sync.
  }, []);

  const save = async () => {
    const trimmed = text.trim();
    if (!trimmed) return;
    if (trimmed.length > MAX_ENTRY_CHARS) {
      Alert.alert("Entry too long", `Entries are limited to ${MAX_ENTRY_CHARS.toLocaleString()} characters.`);
      return;
    }
    setBusy(true);
    try {
      const keys = vault.get();
      const userId = await api.getUserId();
      if (!userId) {
        // AAD-binding an entry to "" would make it permanently undecryptable.
        Alert.alert("Session damaged", "Account id missing — please sign in again. Your entry is still on screen.");
        return;
      }
      // LOCAL calendar day: the UTC day is wrong for non-UTC users in the
      // evening (it feeds entry ids, dates and the mood log).
      const today = localDateISO();
      const clientEntryId = `e-${today}-${Date.now().toString(36)}`;
      // sentiment: null — analysis sentiment is computed by the server's
      // graded engine at recompute time. The client's quick score below is
      // display/local-log only and never rides in the encrypted payload.
      const { blobB64 } = encryptEntry(keys, userId, clientEntryId, trimmed, today, null);
      // The local mood log powers the baseline-phase trend view; it is
      // device-only metadata, encrypted under the data key, and never
      // leaves the phone.
      void recordMood(keys.dataKey, userId, today, localSentiment(trimmed)).catch(() => {});
      // Crisis detection is ON-DEVICE and pre-encryption by necessity: the
      // server only ever sees ciphertext, so it cannot notice a crisis.
      // The result is never stored or transmitted — it only decides whether
      // to point at support resources after the entry is safely saved.
      const crisisLanguage = detectCrisisLanguage(trimmed);
      try {
        await api.createEntry(clientEntryId, blobB64, today);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          // Session expired: lock the vault so navigation gates back to
          // the Unlock screen on its own (re-saving would just re-fail
          // with the same dead session). The draft is stashed for the
          // re-unlock remount — it is NOT lost.
          stashedDraft = { userId, text: trimmed };
          vault.lock();
          Alert.alert("Session expired", "Please unlock again — your entry will still be here.");
          return;
        }
        if (err instanceof ApiError && err.status === 422) {
          // The server permanently rejects this blob; queueing it would
          // poison the offline queue with an entry that can never sync.
          Alert.alert("Entry rejected", `${err.message} — your entry is still on screen.`);
          return;
        }
        // Offline, 5xx or throttled: queue the SAME encrypted entry —
        // the AAD is already bound to this clientEntryId and this account.
        try {
          await enqueue({ userId, clientEntryId, blobB64, entryDate: today });
          Alert.alert("Saved offline", "This entry will sync when you're back online.");
        } catch (queueErr) {
          if (queueErr instanceof QueueFullError) {
            Alert.alert(
              "Offline storage full",
              "Your oldest unsynced entries are protected — connect and sync before writing more. This entry is still on screen.",
            );
            return;
          }
          throw queueErr;
        }
      }
      setText("");
      // Never before or instead of saving: the entry is already safe
      // (synced or queued) before this dialog appears. Safe-messaging
      // tone — acknowledge, point at humans, no diagnosis.
      if (crisisLanguage) {
        Alert.alert(
          "Support is available",
          "Some of what you wrote sounds like a really heavy moment. Whatever you are carrying, you do not have to carry it alone — free, confidential help is one tap away.",
          [
            { text: "View support resources", onPress: () => navigation.navigate("Crisis") },
            { text: "Not now", style: "cancel" },
          ],
        );
      }
    } catch (err) {
      Alert.alert("Could not save", err instanceof Error ? err.message : "unknown error");
    } finally {
      setBusy(false);
    }
  };

  // unlockDays comes from server metadata (clamped in the store, but a
  // hostile value of 0 must never produce NaN/Infinity styling here).
  const progress = unlockDays > 0 ? Math.min(1, activeDays / unlockDays) : 1;

  return (
    <ScrollView style={styles.container} contentContainerStyle={{ padding: 20, gap: 16 }}>
      <View style={styles.progressRow}>
        <Text style={styles.progressLabel}>
          {activeDays >= unlockDays ? "Patterns unlocked" : `${activeDays}/${unlockDays} days to your patterns`}
        </Text>
        <View style={styles.progressTrack}>
          <View style={[styles.progressFill, { width: `${progress * 100}%` }]} />
        </View>
      </View>
      <TextInput
        style={styles.input}
        multiline
        placeholder="What's going on today?"
        placeholderTextColor="#5c6370"
        value={text}
        onChangeText={(next) => {
          touchActivity(); // typing resets the inactivity auto-lock
          setText(next);
        }}
      />
      <TouchableOpacity style={styles.button} onPress={save} disabled={busy || !text.trim()}>
        {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Save entry</Text>}
      </TouchableOpacity>
      <View style={styles.navRow}>
        <NavButton label="Patterns" onPress={() => navigation.navigate("Insights")} />
        <NavButton label="Question" onPress={() => navigation.navigate("Question")} />
        <NavButton label="Settings" onPress={() => navigation.navigate("Settings")} />
        <NavButton label="Get help" onPress={() => navigation.navigate("Crisis")} />
      </View>
    </ScrollView>
  );
}

function NavButton({ label, onPress }: { label: string; onPress: () => void }): React.JSX.Element {
  return (
    <TouchableOpacity style={styles.navButton} onPress={onPress}>
      <Text style={styles.navText}>{label}</Text>
    </TouchableOpacity>
  );
}

/** Quick client-side mood estimate: drives the local (device-only) trend
 * view before patterns unlock. Never sent as plaintext metadata and never
 * stored in the encrypted payload — the server's graded engine re-scores
 * the text at analysis time. */
function localSentiment(text: string): number {
  const positive = (text.toLowerCase().match(/\b(good|great|happy|calm|grateful|relaxed|excited|proud|hopeful)\b/g) ?? []).length;
  const negative = (text.toLowerCase().match(/\b(bad|sad|anxious|anxiety|stressed|angry|worried|tired|lonely|overwhelmed)\b/g) ?? []).length;
  // When positive == negative the ratio below already evaluates to 0, so
  // `-` and `+` agree on every reachable input.
  // Stryker disable ArithmeticOperator
  if (positive + negative === 0) return 0;
  // Stryker restore ArithmeticOperator
  return Number(((positive - negative) / (positive + negative)).toFixed(2));
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f1115" },
  progressRow: { gap: 6 },
  progressLabel: { color: "#8a91a3", fontSize: 13 },
  progressTrack: { height: 6, borderRadius: 3, backgroundColor: "#1a1e26", overflow: "hidden" },
  progressFill: { height: 6, borderRadius: 3, backgroundColor: "#4f7cff" },
  input: { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 12, padding: 16, fontSize: 16, minHeight: 220, textAlignVertical: "top" },
  button: { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  navRow: { flexDirection: "row", gap: 10 },
  navButton: { flex: 1, backgroundColor: "#1a1e26", borderRadius: 10, padding: 14, alignItems: "center" },
  navText: { color: "#7f9bff", fontSize: 14, fontWeight: "600" },
});
