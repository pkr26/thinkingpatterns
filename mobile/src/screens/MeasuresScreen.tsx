/**
 * Wellbeing measures (MBC, 2026-09-19): a standard questionnaire the
 * patient completes, stored as an opaque encrypted blob and — when
 * therapist sharing is active — readable by their clinician through the
 * same consent as patterns and entries.
 *
 * The app's charter holds on this screen: no severity bands, no
 * interpretation, no advice. The score travels encrypted; the patient
 * sees their own recorded history and the plain statement that a
 * clinician reads and interprets.
 *
 * SAFETY: item 9 (self-harm thoughts) endorsement gently points at the
 * offline crisis resources AFTER the response is safely saved — the same
 * never-before-saving discipline as the entry crisis dialog, throttled
 * through the same per-day stamp.
 */
import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Alert, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { api, ApiError } from "../api/client";
import { buildAad, decrypt, encrypt } from "../crypto/envelope";
import { engine } from "../crypto/engine";
import { vault } from "../vault";
import { useSession } from "../store";
import { localDateISO } from "../moodLog";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { detectCrisisLanguage } from "../crisisDetect";
import {
  PHQ9_ITEMS,
  PHQ9_OPTIONS,
  PHQ9_ITEM9_INDEX,
  phq9Complete,
  phq9Item9Endorsed,
  phq9Payload,
} from "../phq9";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { MainShell } from "../components/BottomNav";
import { requestFailureCopy } from "../components/errors";

interface MeasureRow {
  client_measure_id: string;
  blob: string;
  measure_date: string;
}

interface Reading {
  date: string;
  score: number;
}

function newMeasureId(date: string): string {
  const suffix = engine.randomBytes(9).toString("base64url");
  return `m-${date}-${suffix}`;
}

/** Decrypt one history row (the patient's own key). Wrong shapes degrade
 *  to a skipped row — history is honest about what it can read. */
function decryptReading(dataKey: Buffer, userId: string, row: MeasureRow): Reading | null {
  try {
    const plain = decrypt(
      dataKey,
      Buffer.from(row.blob, "base64"),
      buildAad("measure", userId, row.client_measure_id),
    );
    const parsed = JSON.parse(plain.toString("utf8")) as { score?: unknown };
    if (typeof parsed.score !== "number" || !Number.isFinite(parsed.score)) return null;
    return { date: row.measure_date, score: Math.max(0, Math.min(27, Math.round(parsed.score))) };
  } catch {
    return null;
  }
}

export function MeasuresScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [readings, setReadings] = useState<Reading[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** The in-progress questionnaire: one pick per item, null = unanswered. */
  const [responses, setResponses] = useState<Array<number | null>>(
    () => PHQ9_ITEMS.map(() => null),
  );
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("ok");

  const showStatus = (message: string, tone: InlineStatusTone) => {
    setStatusTone(tone);
    setStatus(message);
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const userId = await api.getUserId();
      if (!userId) throw new Error("account id missing — sign in again");
      const rows = (await api.listMeasures()) as MeasureRow[];
      if (!vault.isUnlocked()) throw new Error("vault is locked");
      const dataKey = vault.get().dataKey;
      const decrypted: Reading[] = [];
      for (const row of rows) {
        const reading = decryptReading(dataKey, userId, row);
        if (reading) decrypted.push(reading);
      }
      setReadings(decrypted); // newest first from the server
      setOffline(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        setOffline(true);
        setReadings(null);
      } else {
        setError(err instanceof ApiError ? requestFailureCopy(err) : "Could not load your measures.");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const submit = async () => {
    if (busy || !phq9Complete(responses)) return;
    setBusy(true);
    const item9 = phq9Item9Endorsed(responses);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert("Session damaged", "Account id missing — please sign in again.");
        return;
      }
      if (!vault.isUnlocked()) {
        Alert.alert("Locked", "Your keys are locked — unlock and try again.");
        return;
      }
      const today = localDateISO();
      const clientMeasureId = newMeasureId(today);
      const blob = encrypt(
        vault.get().dataKey,
        Buffer.from(phq9Payload(responses, today), "utf8"),
        buildAad("measure", userId, clientMeasureId),
      ).toString("base64");
      await api.createMeasure(clientMeasureId, blob, today);
      setResponses(PHQ9_ITEMS.map(() => null));
      showStatus("Recorded — encrypted, as always.", "ok");
      await load();
      // SAFETY: only after the response is safely stored. Same throttle
      // stamp and calm copy as the entry crisis dialog.
      if (item9) {
        const flagged = await crisisDialogShownOn(userId, today).catch(() => false);
        if (!flagged) {
          await recordCrisisDialogShown(userId, today).catch(() => {});
          Alert.alert(
            "Support is available",
            "Some of what you marked sounds heavy. Whatever you are carrying, you do not have to carry it alone — free, confidential help is one tap away.",
            [
              { text: "View support resources", onPress: () => navigation.navigate("Crisis") },
              { text: "Not now", style: "cancel" },
            ],
          );
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        showStatus("Already recorded — refreshing.", "neutral");
        await load();
        return;
      }
      const copy =
        err instanceof ApiError && err.status === 0
          ? "Recording needs a connection right now. Your picks are still on screen."
          : "Could not record just now. Your picks are still on screen.";
      Alert.alert("Not recorded", copy);
    } finally {
      setBusy(false);
    }
  };

  return (
    <MainShell current="Settings" navigation={navigation}>
      <ScrollView
        style={{ flex: 1, backgroundColor: t.colors.bg }}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
        keyboardShouldPersistTaps="handled"
      >
        <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
          A standard wellbeing questionnaire (PHQ-9), completed by you. MindPattern stores the
          score encrypted and never interprets it — reading it is your clinician's job, and it
          is shared only through your existing therapist consent.
        </Text>

        {loading && <ActivityIndicator color={t.colors.primaryBright} />}
        {offline && (
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            Your recorded history needs a connection to load. Completing the questionnaire
            also needs one — nothing here works offline yet.
          </Text>
        )}
        {error && (
          <Text style={{ color: t.colors.error, fontSize: t.type.bodySmall.fontSize }} accessibilityRole="alert">
            {error}
          </Text>
        )}
        {readings !== null && readings.length > 0 && (
          <View style={[styles.historyCard, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
            <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, fontWeight: "600" }}>
              Your recorded scores
            </Text>
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
              {readings.map((r) => `${r.date}: ${r.score}`).join("   ·   ")}
            </Text>
          </View>
        )}
        {readings !== null && readings.length === 0 && !loading && (
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            Nothing recorded yet.
          </Text>
        )}

        <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, fontWeight: "600" }}>
          Over the last 2 weeks, how often have you been bothered by:
        </Text>
        {PHQ9_ITEMS.map((item, index) => (
          <View key={index} style={{ gap: t.spacing.sm }}>
            <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize }}>
              {index + 1}. {item.text}
              {index === PHQ9_ITEM9_INDEX ? " (safety item — support is always one tap away)" : ""}
            </Text>
            <View style={styles.optionRow} accessibilityLabel={`Question ${index + 1}`}>
              {PHQ9_OPTIONS.map((option) => {
                const selected = responses[index] === option.value;
                return (
                  <TouchableOpacity
                    key={option.value}
                    style={[
                      styles.option,
                      {
                        backgroundColor: selected ? t.colors.primary : t.colors.card,
                        borderRadius: t.radius.md,
                      },
                    ]}
                    onPress={() => {
                      touchActivity();
                      const next = [...responses];
                      next[index] = option.value;
                      setResponses(next);
                    }}
                    accessibilityRole="radio"
                    accessibilityState={{ selected }}
                    accessibilityLabel={`Question ${index + 1}: ${option.label}`}
                  >
                    <Text
                      numberOfLines={2}
                      style={{
                        color: selected ? t.colors.onPrimary : t.colors.body,
                        fontSize: t.type.meta.fontSize,
                        textAlign: "center",
                      }}
                    >
                      {option.label}
                    </Text>
                  </TouchableOpacity>
                );
              })}
            </View>
          </View>
        ))}

        <PrimaryButton
          label="Record this check-in"
          onPress={submit}
          disabled={!phq9Complete(responses)}
          busy={busy}
        />
        <InlineStatus message={status} tone={statusTone} />
        <GhostButton label="Back to settings" onPress={() => navigation.goBack()} center={false} />
        <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </MainShell>
  );
}

const styles = StyleSheet.create({
  historyCard: { padding: 16, gap: 8 },
  optionRow: { flexDirection: "row", gap: 6 },
  option: { flex: 1, alignItems: "center", justifyContent: "center", paddingVertical: 10, paddingHorizontal: 4, minHeight: 44 },
});
